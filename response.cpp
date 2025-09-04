#include "main.h"

using namespace std;
//======================================================================
static Connect *list_start = NULL;
static Connect *list_end = NULL;

static std::mutex mtx_list, mtx_thr;
static std::condition_variable cond_list, cond_thr;
static int num_thr = 0, thr_exit = 0, max_thr = 0, work_thr = 0, size_list = 0;
static unsigned long all_req = 0;
//======================================================================
static void thread_set_response();
static int set_response(Connect *req);
static int send_file(Connect *req);
static int send_multypart(Connect *req);
//======================================================================
long long file_size(const char *s)
{
    struct stat st;

    if (!stat(s, &st))
        return st.st_size;
    else
        return -1;
}
//======================================================================
int fastcgi(Connect* r, const char* uri)
{
    const char *p = strrchr(uri, '/');
    if (!p)
        return -RS404;
    fcgi_list_addr *i = conf->fcgi_list;
    for (; i; i = i->next)
    {
        if (i->script_name[0] == '~')
        {
            if (!strcmp(p, i->script_name.c_str() + 1))
                break;
        }
        else
        {
            if (uri == i->script_name)
                break;
        }
    }

    if (!i)
        return -RS404;

    r->cgi.script_path = &i->addr;
    if (i->type == FASTCGI)
        r->cgi.cgi_type = FASTCGI;
    else if (i->type == SCGI)
        r->cgi.cgi_type = SCGI;
    else
        return -RS404;
    r->cgi.scriptName = i->script_name;
    push_cgi(r);
    return 0;
}
//======================================================================
void push_resp_list(Connect *req)
{
lock_guard<mutex> lk(mtx_list);
    req->next = NULL;
    req->prev = list_end;
    if (list_start)
    {
        list_end->next = req;
        list_end = req;
    }
    else
        list_start = list_end = req;
    ++all_req;
    ++size_list;
    cond_list.notify_one();
    if ((num_thr - work_thr) == size_list)
        cond_thr.notify_one();
}
//======================================================================
static Connect *pop_resp_list()
{
unique_lock<mutex> lk(mtx_list);
    while ((list_start == NULL) && !thr_exit)
    {
        cond_list.wait(lk);
    }
    if (thr_exit)
    {
        print_err("<%s:%d> *** Exit parse_request_thread, num=%d ***\n", __func__, __LINE__, num_thr);
        --num_thr;
        return NULL;
    }

    Connect *req = list_start;
    if (list_start->next)
    {
        list_start->next->prev = NULL;
        list_start = list_start->next;
    }
    else
        list_start = list_end = NULL;
    ++work_thr;
    --size_list;
    return req;
}
//======================================================================
void close_threads_manager()
{
lock_guard<mutex> lk(mtx_list);
    thr_exit = 1;
    cond_list.notify_all();
    cond_thr.notify_one();
}
//======================================================================
unsigned long get_all_request()
{
    return all_req;
}
//======================================================================
int get_max_thr()
{
    return max_thr;
}
//======================================================================
int is_maxthr()
{
unique_lock<mutex> lk(mtx_thr);
    while (((num_thr >= conf->MaxParseReqThreads) || ((num_thr - work_thr) > size_list)) && 
        !(num_thr < conf->MinParseReqThreads) && !thr_exit)
    {
        cond_thr.wait(lk);
    }
    
    if (thr_exit)
        return thr_exit;
    num_thr++;
    if (num_thr > max_thr)
        max_thr = num_thr;

    return thr_exit;
}
//======================================================================
int exit_thread(Connect *req)
{
    int ret = 0;
    if (req)
        end_response(req);
mtx_thr.lock();
    --work_thr;
    if ((num_thr > conf->MinParseReqThreads) && ((num_thr - work_thr) >= 1))
    {
        num_thr--;
        ret = 1;
    }
mtx_thr.unlock();
    return ret;
}
//======================================================================
void threads_manager()
{
    print_err("<%s:%d> --- run threads_manager ---max_thr=%d\n", __func__, __LINE__, max_thr);
    thread t;
    int i = 0;
    for (; i < conf->MinParseReqThreads; ++i)
    {
        try
        {
            t = thread(thread_set_response);
        }
        catch(...)
        {
            print_err("<%s:%d> Error create thread: %s\n", __func__, __LINE__, strerror(errno));
            abort();
        }

        t.detach();
        ++num_thr;
    }
    printf(" ParseReqThreads=%d\n", num_thr);
    while (1)
    {
        if (is_maxthr())
            break;

        try
        {
            t = thread(thread_set_response);
        }
        catch(...)
        {
            print_err("<%s:%d> Error create thread: %s; num_thr=%d\n", __func__, __LINE__, strerror(errno), num_thr);
            abort();
        }

        t.detach();
    }
    print_err("<%s:%d> ***** exit threads_manager *****\n", __func__, __LINE__);
}
//======================================================================
void thread_set_response()
{
    while (1)
    {
        Connect *req = pop_resp_list();
        if (!req)
        {
            break;
        }

        req->err = set_response(req);
        if (req->err < 0)
        {
            if (exit_thread(req))
                return;
        }
        else
        {
            if (exit_thread(NULL))
                return;
        }
    }
}
//======================================================================
int set_response(Connect *req)
{
    req->err = parse_headers(req);
    if (req->err < 0)
    {
        print_err(req, "<%s:%d> Error parse_headers(): %d\n", __func__, __LINE__, req->err);
        return req->err;
    }

    if ((req->reqMethod != M_GET) &&
        (req->reqMethod != M_HEAD) &&
        (req->reqMethod != M_POST) &&
        (req->reqMethod != M_OPTIONS))
    {
        return -RS501;
    }
#ifdef TCP_CORK_
    if (conf->TcpCork)
    {
    #if defined(LINUX_)
        int optval = 1;
        setsockopt(req->clientSocket, SOL_TCP, TCP_CORK, &optval, sizeof(optval));
    //#elif defined(FREEBSD_)
    #else
        int optval = 1;
        setsockopt(req->clientSocket, IPPROTO_TCP, TCP_NOPUSH, &optval, sizeof(optval));
    #endif
    }
#endif
    if (req->numReq >= (unsigned int)conf->MaxRequestsPerClient || (req->httpProt == HTTP10))
        req->connKeepAlive = 0;
    else if (req->req_hd.iConnection == -1)
        req->connKeepAlive = 1;

    const char *p;
    if ((p = strchr(req->uri, '?')))
    {
        req->uriLen = p - req->uri;
        req->sReqParam = p + 1;
    }
    else
        req->sReqParam = NULL;

    int len = decode(req->uri, req->uriLen, req->decodeUri, sizeof(req->decodeUri));
    if (len <= 0)
    {
        print_err(req, "<%s:%d> Error: decode URI\n", __func__, __LINE__);
        return -RS404;
    }

    if ((len = clean_path(req->decodeUri, len)) <= 0)
    {
        req->lenDecodeUri = 0;
        if (len == 0)
            return -RS400;
        else
            return len;
    }
    else
        req->lenDecodeUri = len;

    if ((req->reqMethod == M_OPTIONS) && (!strcmp(req->uri, "*")))
        return options(req);

    if (strstr(req->uri, ".php") && (conf->UsePHP != "php-cgi") && (conf->UsePHP != "php-fpm"))
    {
        print_err(req, "<%s:%d> Error UsePHP=%s\n", __func__, __LINE__, conf->UsePHP.c_str());
        return -RS404;
    }

    if (req->req_hd.iUpgrade >= 0)
    {
        print_err(req, "<%s:%d> req->upgrade: %s\n", __func__, __LINE__, req->reqHdValue[req->req_hd.iUpgrade]);
        return -RS505;
    }

    struct stat st;
    p = strstr(req->decodeUri, ".php");
    if (p && (*(p + 4) == 0))
    {
        struct stat st;
        if (stat(req->decodeUri + 1, &st) == -1)
        {
            print_err(req, "<%s:%d> script (%s) not found\n", __func__, __LINE__, req->decodeUri);
            return -RS404;
        }

        if (conf->UsePHP == "php-fpm")
        {
            req->cgi.scriptName = req->decodeUri;
            req->cgi.script_path = &conf->PathPHP;
            req->cgi.cgi_type = PHPFPM;
            push_cgi(req);
            return 0;
        }
        else if (conf->UsePHP == "php-cgi")
        {
            req->cgi.scriptName = req->decodeUri;
            req->cgi.cgi_type = PHPCGI;
            push_cgi(req);
            return 0;
        }

        return -RS500;
    }

    if (!strncmp(req->decodeUri, "/cgi-bin/", 9) || !strncmp(req->decodeUri, "/cgi/", 5))
    {
        req->cgi.cgi_type = CGI;
        req->cgi.scriptName = req->decodeUri;
        push_cgi(req);
        return 0;
    }
    //------------------------------------------------------------------
    string path;
//  path.reserve(req->conf->DocumentRoot.size() + req->lenDecodeUri + 256);
//  path = req->conf->DocumentRoot;

    path.reserve(req->lenDecodeUri + 257);
    path += '.';
    path += req->decodeUri;
    int ret;
    if (path[path.size() - 1] == '/')
        ret = lstat(path.substr(0, path.size() - 1).c_str(), &st);
    else
        ret = lstat(path.c_str(), &st);
    if (ret == -1)
    {
        if (errno == EACCES)
            return -RS403;
        return fastcgi(req, req->decodeUri);
    }
    else
    {
        if ((!S_ISDIR(st.st_mode)) && (!S_ISREG(st.st_mode)))
        {
            print_err(req, "<%s:%d> Error: file (!S_ISDIR && !S_ISREG) \n", __func__, __LINE__);
            return -RS403;
        }
    }
    //------------------------------------------------------------------
    if (S_ISDIR(st.st_mode))
    {
        if (req->reqMethod == M_POST)
            return -RS404;
        else if (req->reqMethod == M_OPTIONS)
        {
            req->respContentType = "text/html; charset=utf-8";
            return options(req);
        }

        if (req->decodeUri[req->lenDecodeUri - 1] != '/')
        {
            req->respStatus = RS301;

            String location(req->lenDecodeUri * 3);
            if (conf->Protocol == HTTPS)
                location = "https://";
            else
                location = "http://";
            location += req->reqHdValue[req->req_hd.iHost];

            String s(req->lenDecodeUri * 3 + 64);
            if (encode(req->decodeUri, s) == 0)
            {
                print_err(req, "<%s:%d> Error\n", __func__, __LINE__);
                return -RS500;
            }

            location += s;
            location += '/';

            req->hdrs.reserve(req->lenDecodeUri * 3 + 16);
            req->hdrs << "Location: " << location << "\r\n";
            if (req->hdrs.error())
            {
                print_err(req, "<%s:%d> Error\n", __func__, __LINE__);
                return -RS500;
            }

            s = "The document has moved <a href=\"";
            s << location << "\">here</a>.";
            if (s.error())
            {
                req->hdrs = "";
                print_err(req, "<%s:%d> Error\n", __func__, __LINE__);
                return -RS500;
            }

            return send_message(req, s.c_str());
        }
        //--------------------------------------------------------------
        int len = path.size();
        path += "/index.html";
        if ((stat(path.c_str(), &st) != 0) || (conf->index_html == false))
        {
            errno = 0;
            path.resize(len);

            if ((conf->UsePHP != "off") && (conf->index_php))
            {
                path += "/index.php";
                if (!stat(path.c_str(), &st))
                {
                    req->cgi.scriptName = "";
                    req->cgi.scriptName << req->decodeUri << "index.php";
                    if (conf->UsePHP == "php-fpm")
                    {
                        req->cgi.script_path = &conf->PathPHP;
                        req->cgi.cgi_type = PHPFPM;
                        push_cgi(req);
                        return 0;
                    }
                    else if (conf->UsePHP == "php-cgi")
                    {
                        req->cgi.cgi_type = PHPCGI;
                        push_cgi(req);
                        return 0;
                    }

                    return -RS500;
                }
                path.resize(len);
            }

            if (conf->index_pl)
            {
                req->cgi.cgi_type = CGI;
                req->cgi.scriptName = "/cgi-bin/index.pl";
                push_cgi(req);
                return 0;
            }
            else if (conf->index_fcgi)
            {
                req->cgi.cgi_type = FASTCGI;
                req->cgi.scriptName = "/index.fcgi";
                push_cgi(req);
                return 0;
            }

            path.reserve(path.capacity() + 256);
            if (conf->AutoIndex)
            {
                return index_dir(req, path);
            }
            else
                return -RS403;
        }
    }
    //--------------------- send file ----------------------------------
    req->fileSize = file_size(path.c_str());
    req->numPart = 0;
    req->respContentType = content_type(path.c_str());
    if (req->reqMethod == M_OPTIONS)
        return options(req);
    //------------------------------------------------------------------
    req->fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (req->fd == -1)
    {
        if (errno == EACCES)
            return -RS403;
        else
        {
            print_err(req, "<%s:%d> Error open(%s): %s\n", __func__, __LINE__,
                                    path.c_str(), strerror(errno));
            return -RS404;
        }
    }
    path.reserve(0);

    ret = send_file(req);
    if (ret < 0)
    {
        close(req->fd);
        req->fd = -1;
    }

    return ret;
}
//======================================================================
int send_file(Connect *req)
{
    if (req->req_hd.iRange >= 0)
    {
        int err;

        req->rg.init(req->sRange, req->fileSize);
        if ((err = req->rg.error()))
        {
            print_err(req, "<%s:%d> Error init Ranges\n", __func__, __LINE__);
            return err;
        }

        req->numPart = req->rg.size();
        req->respStatus = RS206;
        if (req->numPart > 1)
        {
            int n = send_multypart(req);
            return n;
        }
        else if (req->numPart == 1)
        {
            Range *pr = req->rg.get();
            if (pr)
            {
                req->offset = pr->start;
                req->respContentLength = pr->len;
            }
            else
                return -RS500;
        }
        else
        {
            print_err(req, "<%s:%d> ???\n", __func__, __LINE__);
            return -RS416;
        }
    }
    else
    {
        req->respStatus = RS200;
        req->offset = 0;
        req->respContentLength = req->fileSize;
    }

    if (create_response_headers(req))
        return -1;
    push_send_file(req);
    return 0;
}
//======================================================================
int create_multipart_head(Connect *req);
//======================================================================
int send_multypart(Connect *req)
{
    long long send_all_bytes = 0;
    char buf[1024];

    for ( ; (req->multipart.rg = req->rg.get()); )
    {
        send_all_bytes += (req->multipart.rg->len);
        send_all_bytes += create_multipart_head(req);
    }
    send_all_bytes += snprintf(buf, sizeof(buf), "\r\n--%s--\r\n", boundary);
    req->respContentLength = send_all_bytes;
    req->send_bytes = 0;

    req->hdrs.reserve(256);
    req->hdrs << "Content-Type: multipart/byteranges; boundary=" << boundary << "\r\n";
    req->hdrs << "Content-Length: " << send_all_bytes << "\r\n";
    if (req->hdrs.error())
    {
        print_err(req, "<%s:%d> Error create response headers\n", __func__, __LINE__);
        return -1;
    }

    req->rg.set_index();

    if (create_response_headers(req))
        return -1;
    push_send_multipart(req);
    return 0;
}
//======================================================================
int create_multipart_head(Connect *req)
{
    req->multipart.hdr = "";
    req->multipart.hdr << "\r\n--" << boundary << "\r\n";

    if (req->respContentType)
        req->multipart.hdr << "Content-Type: " << req->respContentType << "\r\n";
    else
        return 0;

    req->multipart.hdr << "Content-Range: bytes " << req->multipart.rg->start << "-" << req->multipart.rg->end << "/" << req->fileSize << "\r\n\r\n";

    return req->multipart.hdr.size();
}
//======================================================================
int options(Connect *r)
{
    r->respStatus = RS200;
    r->respContentLength = 0;
    if (create_response_headers(r))
        return -1;
    r->html.clear();
    push_send_html(r);
    return 0;
}
