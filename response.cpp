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
            t = thread(parse_request_thread);
        }
        catch(...)
        {
            print_err("<%s:%d> Error create thread: %s\n", __func__, __LINE__, strerror(errno));
            abort();
        }

        t.detach();
        ++num_thr;
    }
    printf("<%s:%d> ParseReqThreads=%d\n", __func__, __LINE__, num_thr);
    while (1)
    {
        if (is_maxthr())
            break;

        try
        {
            t = thread(parse_request_thread);
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
void parse_request_thread()
{
    while (1)
    {
        Connect *req = pop_resp_list();
        if (!req)
        {
            break;
        }
        //--------------------------------------------------------------
        req->err = parse_headers(req);
        if (req->err < 0)
        {
            print_err(req, "<%s:%d> Error parse_headers(): %d\n", __func__, __LINE__, req->err);
            if (exit_thread(req))
                return;
            continue;
        }
    #ifdef TCP_CORK_
        if (conf->TcpCork == 'y')
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
        //--------------------------------------------------------------
        if ((req->httpProt != HTTP10) && (req->httpProt != HTTP11))
        {
            req->err = -RS505;
            if (exit_thread(req))
                return;
            continue;
        }

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

        if (decode(req->uri, req->uriLen, req->decodeUri, sizeof(req->decodeUri)) <= 0)
        {
            print_err(req, "<%s:%d> Error: decode URI\n", __func__, __LINE__);
            req->err = -RS404;
            if (exit_thread(req))
                return;
            continue;
        }

        if (clean_path(req->decodeUri) <= 0)
        {
            print_err(req, "<%s:%d> Error URI=%s\n", __func__, __LINE__, req->decodeUri);
            req->lenDecodeUri = strlen(req->decodeUri);
            req->err = -RS400;
            if (exit_thread(req))
                return;
            continue;
        }
        req->lenDecodeUri = strlen(req->decodeUri);

        if (strstr(req->uri, ".php") && (conf->UsePHP != "php-cgi") && (conf->UsePHP != "php-fpm"))
        {
            print_err(req, "<%s:%d> Error UsePHP=%s\n", __func__, __LINE__, conf->UsePHP.c_str());
            req->err = -RS404;
            if (exit_thread(req))
                return;
            continue;
        }

        if (req->req_hd.iUpgrade >= 0)
        {
            print_err(req, "<%s:%d> req->upgrade: %s\n", __func__, __LINE__, req->reqHdValue[req->req_hd.iUpgrade]);
            req->err = -RS505;
            if (exit_thread(req))
                return;
            continue;
        }
        //--------------------------------------------------------------
        if ((req->reqMethod != M_GET) &&
            (req->reqMethod != M_HEAD) &&
            (req->reqMethod != M_POST) &&
            (req->reqMethod != M_OPTIONS))
        {
            req->err = -RS501;
            if (exit_thread(req))
                return;
            continue;
        }

        int ret = prepare_response(req);
        if (ret == CONNECTION_OWNERSHIP_ENDED)
        {
            if (exit_thread(NULL))
                return;
            continue;
        }
        else if (ret < 0)
        {
            req->err = ret;
        }
        else
        {
            print_err("<%s:%d> !!! prepare_response()=%d\n", __func__, __LINE__, ret);
            req->err = -1;
        }

        if (exit_thread(req))
            return;
    }
}
//======================================================================
int send_file(Connect *req);
int send_multypart(Connect *req);
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
int fastcgi(Connect* req, const char* uri)
{
    const char* p = strrchr(uri, '/');
    if (!p)
        return -RS404;
    fcgi_list_addr* i = conf->fcgi_list;
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

    if (i->type == FASTCGI)
        req->cgi_type = FASTCGI;
    else if (i->type == SCGI)
        req->cgi_type = SCGI;
    else
        return -RS404;
    req->scriptName = i->script_name.c_str();
    return push_cgi(req);
}
//======================================================================
int prepare_response(Connect *req)
{
    struct stat st;
    char *p = strstr(req->decodeUri, ".php");
    if (p && (*(p + 4) == 0))
    {
        if ((conf->UsePHP != "php-cgi") && (conf->UsePHP != "php-fpm"))
        {
            print_err(req, "<%s:%d> Not found: %s\n", __func__, __LINE__, req->decodeUri);
            return -RS404;
        }

        struct stat st;
        if (stat(req->decodeUri + 1, &st) == -1)
        {
            print_err(req, "<%s:%d> script (%s) not found\n", __func__, __LINE__, req->decodeUri);
            return -RS404;
        }

        if (conf->UsePHP == "php-fpm")
        {
            req->scriptName = req->decodeUri;
            req->cgi_type = PHPFPM;
            return push_cgi(req);
        }
        else if (conf->UsePHP == "php-cgi")
        {
            req->scriptName = req->decodeUri;
            req->cgi_type = PHPCGI;
            return push_cgi(req);
        }

        return -1;
    }

    if (!strncmp(req->decodeUri, "/cgi-bin/", 9) || !strncmp(req->decodeUri, "/cgi/", 5))
    {
        req->cgi_type = CGI;
        req->scriptName = req->decodeUri;
        return push_cgi(req);
    }
    //------------------------------------------------------------------
    string path;
//  path.reserve(req->conf->DocumentRoot.size() + req->lenDecodeUri + 256);
//  path = req->conf->DocumentRoot;

    path.reserve(1 + req->lenDecodeUri + 16);
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
            req->uri[req->uriLen] = '/';
            req->uri[req->uriLen + 1] = '\0';
            req->respStatus = RS301;

            req->hdrs.reserve(127);
            req->hdrs << "Location: " << req->uri << "\r\n";
            if (req->hdrs.error())
            {
                print_err(req, "<%s:%d> Error\n", __func__, __LINE__);
                return -RS500;
            }

            String s(256);
            s << "The document has moved <a href=\"" << req->uri << "\">here</a>.";
            if (s.error())
            {
                print_err(req, "<%s:%d> Error create_header()\n", __func__, __LINE__);
                return -RS500;
            }

            return send_message(req, s.c_str());
        }
        //--------------------------------------------------------------
        int len = path.size();
        path += "/index.html";
        if ((stat(path.c_str(), &st) != 0) || (conf->index_html != 'y'))
        {
            errno = 0;
            path.resize(len);

            if ((conf->UsePHP != "n") && (conf->index_php == 'y'))
            {
                path += "/index.php";
                if (!stat(path.c_str(), &st))
                {
                    req->scriptName = "";
                    req->scriptName << req->decodeUri << "index.php";
                    if (conf->UsePHP == "php-fpm")
                    {
                        req->cgi_type = PHPFPM;
                        return push_cgi(req);
                    }
                    else if (conf->UsePHP == "php-cgi")
                    {
                        req->cgi_type = PHPCGI;
                        return push_cgi(req);
                    }

                    return -1;
                }
                path.resize(len);
            }

            if (conf->index_pl == 'y')
            {
                req->cgi_type = CGI;
                req->scriptName = "/cgi-bin/index.pl";
                return push_cgi(req);
            }
            else if (conf->index_fcgi == 'y')
            {
                req->cgi_type = FASTCGI;
                req->scriptName = "/index.fcgi";
                return push_cgi(req);
            }

            path.reserve(path.capacity() + 256);
            if (conf->AutoIndex == 'y')
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
            return -RS500;
        }
    }
    path.reserve(0);

    ret = send_file(req);
    if (ret != 1)
        close(req->fd);

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

    return push_send_file(req);
}
//======================================================================
int create_multipart_head(Connect *req);
//======================================================================
int send_multypart(Connect *req)
{
    long long send_all_bytes = 0;
    char buf[1024];

    for ( ; (req->mp.rg = req->rg.get()); )
    {
        send_all_bytes += (req->mp.rg->len);
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

    return push_send_multipart(req);
}
//======================================================================
int create_multipart_head(Connect *req)
{
    req->mp.hdr = "";
    req->mp.hdr << "\r\n--" << boundary << "\r\n";

    if (req->respContentType)
        req->mp.hdr << "Content-Type: " << req->respContentType << "\r\n";
    else
        return 0;

    req->mp.hdr << "Content-Range: bytes " << req->mp.rg->start << "-" << req->mp.rg->end << "/" << req->fileSize << "\r\n\r\n";

    return req->mp.hdr.size();
}
//======================================================================
int options(Connect *r)
{
    r->respStatus = RS200;
    r->respContentLength = 0;
    if (create_response_headers(r))
        return -1;

    r->resp_headers.p = r->resp_headers.s.c_str();
    r->resp_headers.len = r->resp_headers.s.size();
    r->html.len = 0;
    return push_send_html(r);
}
