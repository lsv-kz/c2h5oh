#include "main.h"

using namespace std;
//======================================================================
const char *get_script_name(const char *name)
{
    const char *p;
    if (!name)
        return "";

    if ((p = strchr(name + 1, '/')))
        return p;

    return "";
}
//======================================================================
void EventHandlerClass::wait_pid(Connect *req)
{
    int n = waitpid(req->cgi.pid, NULL, WNOHANG); // no blocking
    if (n == -1)
    {
        //print_err(req, "<%s:%d> Error waitpid(%d): %s\n", __func__, __LINE__, req->cgi.pid, strerror(errno));
    }
    else if (n == 0)
    {
        if (kill(req->cgi.pid, SIGKILL) == 0)
            waitpid(req->cgi.pid, NULL, 0);
        else
            print_err(req, "<%s:%d> Error kill(%d): %s\n", __func__, __LINE__, req->cgi.pid, strerror(errno));
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_fork(Connect *r, int* serv_cgi, int* cgi_serv)
{
    struct stat st;

    if (r->reqMethod == M_POST)
    {
        if (r->req_hd.iReqContentType < 0)
        {
            print_err(r, "<%s:%d> Content-Type \?\n", __func__, __LINE__);
            return -RS400;
        }

        if (r->req_hd.reqContentLength < 0)
        {
            print_err(r, "<%s:%d> 411 Length Required\n", __func__, __LINE__);
            return -RS411;
        }

        if (r->req_hd.reqContentLength > conf->ClientMaxBodySize)
        {
            print_err(r, "<%s:%d> 413 Request entity too large: %lld\n", __func__, __LINE__, r->req_hd.reqContentLength);
            return -RS413;
        }
    }

    String path;
    switch (r->cgi_type)
    {
        case CGI:
            path << conf->ScriptPath << get_script_name(r->scriptName.c_str());
            break;
        case PHPCGI:
            path << conf->DocumentRoot << r->scriptName.c_str();
            break;
        default:
            print_err(r, "<%s:%d> ??? Error: CGI_TYPE=%s\n", __func__, __LINE__, get_cgi_type(r->cgi_type));
            r->connKeepAlive = 0;
            return -RS500;
    }
    
    if (stat(path.c_str(), &st) == -1)
    {
        print_err(r, "<%s:%d> script (%s) not found\n", __func__, __LINE__, path.c_str());
        r->connKeepAlive = 0;
        return -RS404;
    }
    //--------------------------- fork ---------------------------------
    pid_t pid = fork();
    if (pid < 0)
    {
        r->cgi.pid = pid;
        print_err(r, "<%s:%d> Error fork(): %s\n", __func__, __LINE__, strerror(errno));
        return -RS500;
    }
    else if (pid == 0)
    {
        //----------------------- child --------------------------------
        close(cgi_serv[0]);

        if (r->reqMethod == M_POST)
        {
            close(serv_cgi[1]);
            if (serv_cgi[0] != STDIN_FILENO)
            {
                if (dup2(serv_cgi[0], STDIN_FILENO) < 0)
                {
                    fprintf(stderr, "<%s:%d> Error dup2(): %s\n", __func__, __LINE__, strerror(errno));
                    exit(EXIT_FAILURE);
                }
                close(serv_cgi[0]);
            }
        }

        if (cgi_serv[1] != STDOUT_FILENO)
        {
            if (dup2(cgi_serv[1], STDOUT_FILENO) < 0)
            {
                fprintf(stderr, "<%s:%d> Error dup2(): %s\n", __func__, __LINE__, strerror(errno));
                exit(EXIT_FAILURE);
            }
            close(cgi_serv[1]);
        }
        
        if (r->cgi_type == PHPCGI)
            setenv("REDIRECT_STATUS", "true", 1);
        setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);
        setenv("SERVER_SOFTWARE", conf->ServerSoftware.c_str(), 1);
        setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
        setenv("DOCUMENT_ROOT", conf->DocumentRoot.c_str(), 1);
        setenv("REMOTE_ADDR", r->remoteAddr, 1);
        setenv("REMOTE_PORT", r->remotePort, 1);
        setenv("REQUEST_URI", r->uri, 1);
        setenv("REQUEST_METHOD", get_str_method(r->reqMethod), 1);
        setenv("SERVER_PROTOCOL", get_str_http_prot(r->httpProt), 1);
        if (r->req_hd.iHost >= 0)
            setenv("HTTP_HOST", r->reqHdValue[r->req_hd.iHost], 1);
        if (r->req_hd.iReferer >= 0)
            setenv("HTTP_REFERER", r->reqHdValue[r->req_hd.iReferer], 1);
        if (r->req_hd.iUserAgent >= 0)
            setenv("HTTP_USER_AGENT", r->reqHdValue[r->req_hd.iUserAgent], 1);

        setenv("SCRIPT_NAME", r->scriptName.c_str(), 1);
        setenv("SCRIPT_FILENAME", path.c_str(), 1);
        
        if (r->reqMethod == M_POST)
        {
            if (r->req_hd.iReqContentType >= 0)
                setenv("CONTENT_TYPE", r->reqHdValue[r->req_hd.iReqContentType], 1);
            if (r->req_hd.iReqContentLength >= 0)
                setenv("CONTENT_LENGTH", r->reqHdValue[r->req_hd.iReqContentLength], 1);
        }

        setenv("QUERY_STRING", r->sReqParam ? r->sReqParam : "", 1);

        int err_ = 0;
        if (r->cgi_type == CGI)
        {
            execl(path.c_str(), base_name(r->scriptName.c_str()), NULL);
            err_ = errno;
        }
        else if (r->cgi_type == PHPCGI)
        {
            if (conf->UsePHP == "php-cgi")
            {
                execl(conf->PathPHP.c_str(), base_name(conf->PathPHP.c_str()), NULL);
                err_ = errno;
            }
        }

        printf( "Status: 500 Internal Server Error\r\n"
                "Content-type: text/html; charset=UTF-8\r\n"
                "\r\n"
                "<!DOCTYPE html>\n"
                "<html>\n"
                " <head>\n"
                "  <title>500 Internal Server Error</title>\n"
                "  <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">\n"
                " </head>\n"
                " <body>\n"
                "  <h3>500 Internal Server Error</h3>\n"
                "  <p>%s</p>\n"
                "  <hr>\n"
                "  %s\n"
                " </body>\n"
                "</html>", strerror(err_), get_time().c_str());
        fclose(stdout);
        exit(EXIT_FAILURE);
    }
    else
    {
        r->cgi.pid = pid;
        if (r->req_hd.reqContentLength > 0)
        {
            r->sock_timer = 0;
            r->cgi.len_post = r->req_hd.reqContentLength - r->lenTail;
            r->cgi.op.cgi = CGI_STDIN;
            if (r->lenTail > 0)
            {
                r->io_direct = TO_CGI;
                r->cgi.p = r->tail;
                r->cgi.len_buf = r->lenTail;
                r->tail = NULL;
                r->lenTail = 0;
            }
            else
            {
                r->io_direct = FROM_CLIENT;
            }
        }
        else
        {
            cgi_set_status_readheaders(r);
        }

        r->tail = NULL;
        r->lenTail = 0;
        r->sock_timer = 0;

        r->mode_send = ((r->httpProt == HTTP11) && r->connKeepAlive) ? CHUNK : NO_CHUNK;
        int opt = 1;
        ioctl(cgi_serv[0], FIONBIO, &opt);
        ioctl(serv_cgi[1], FIONBIO, &opt);
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_create_proc(Connect *req)
{
    int serv_cgi[2], cgi_serv[2];

    int n = pipe(cgi_serv);
    if (n == -1)
    {
        print_err(req, "<%s:%d> Error pipe()=%d\n", __func__, __LINE__, n);
        req->connKeepAlive = 0;
        return -RS500;
    }

    if (ioctl(cgi_serv[0], FIOCLEX) == -1)
    {
        print_err("<%s:%d> Error ioctl(FIOCLEX): %s\n", __func__, __LINE__, strerror(errno));
        req->connKeepAlive = 0;
        close(cgi_serv[0]);
        close(cgi_serv[1]);
        return -RS500;
    }

    if (req->reqMethod == M_POST)
    {
        n = pipe(serv_cgi);
        if (n == -1)
        {
            print_err(req, "<%s:%d> Error pipe()=%d\n", __func__, __LINE__, n);
            req->connKeepAlive = 0;
            close(cgi_serv[0]);
            close(cgi_serv[1]);
            return -RS500;
        }

        if (ioctl(serv_cgi[1], FIOCLEX) == -1)
        {
            print_err("<%s:%d> Error ioctl(FIOCLEX): %s\n", __func__, __LINE__, strerror(errno));
            req->connKeepAlive = 0;
            close(cgi_serv[0]);
            close(cgi_serv[1]);
            
            close(serv_cgi[0]);
            close(serv_cgi[1]);
            return -RS500;
        }
    }
    else
    {
        serv_cgi[0] = -1;
        serv_cgi[1] = -1;
    }

    n = cgi_fork(req, serv_cgi, cgi_serv);
    if (n < 0)
    {
        if (req->reqMethod == M_POST)
        {
            close(serv_cgi[0]);
            close(serv_cgi[1]);
        }

        close(cgi_serv[0]);
        close(cgi_serv[1]);
        return n;
    }
    else
    {
        if (req->reqMethod == M_POST)
            close(serv_cgi[0]);
        close(cgi_serv[1]);
        
        req->cgi.from_script = cgi_serv[0];
        req->cgi.to_script = serv_cgi[1];
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_stdin(Connect *req)// return [ ERR_TRY_AGAIN | -1 | 0 ]
{
    if (req->io_direct == FROM_CLIENT)
    {
        int rd = (req->cgi.len_post > req->cgi.size_buf) ? req->cgi.size_buf : req->cgi.len_post;
        req->cgi.len_buf = read_from_client(req, req->cgi.buf, rd);
        if (req->cgi.len_buf < 0)
        {
            if (req->cgi.len_buf == ERR_TRY_AGAIN)
                return ERR_TRY_AGAIN;
            return -1;
        }
        else if (req->cgi.len_buf == 0)
        {
            print_err(req, "<%s:%d> Error read()=0\n", __func__, __LINE__);
            return -1;
        }

        req->cgi.len_post -= req->cgi.len_buf;
        req->io_direct = TO_CGI;
        req->cgi.p = req->cgi.buf;
    }
    else if (req->io_direct == TO_CGI)
    {
        int fd;
        if ((req->cgi_type == CGI) || (req->cgi_type == PHPCGI))
            fd = req->cgi.to_script;
        else if (req->cgi_type == SCGI)
            fd = req->fcgi.fd;
        else
        {
            print_err(req, "<%s:%d> ??? Error: CGI_TYPE=%s\n", __func__, __LINE__, get_cgi_type(req->cgi_type));
            return -1;
        }

        int n = write(fd, req->cgi.p, req->cgi.len_buf);
        if (n == -1)
        {
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            print_err(req, "<%s:%d> Error write(): %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }

        req->cgi.p += n;
        req->cgi.len_buf -= n;

        if (req->cgi.len_buf == 0)
        {
            if (req->cgi.len_post == 0)
            {
                if ((req->cgi_type == CGI) || (req->cgi_type == PHPCGI))
                {
                    close(req->cgi.to_script);
                    req->cgi.to_script = -1;
                    cgi_set_status_readheaders(req);
                }
                else if (req->cgi_type == SCGI)
                {
                    req->cgi.op.scgi = SCGI_READ_HTTP_HEADERS;
                    req->io_direct = FROM_CGI;
                    req->tail = NULL;
                    req->lenTail = 0;
                    req->p_newline = req->cgi.p = req->cgi.buf + 8;
                    req->cgi.len_buf = 0;
                }
                else
                {
                    print_err(req, "<%s:%d> ??? Error: CGI_TYPE=%s\n", __func__, __LINE__, get_cgi_type(req->cgi_type));
                    return -1;
                }
            }
            else
            {
                req->io_direct = FROM_CLIENT;
            }
        }
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_stdout(Connect *req)// return [ ERR_TRY_AGAIN | -1 | 0 | 1 | 0< ]
{
    if (req->io_direct == FROM_CGI)
    {
        int fd;
        if ((req->cgi_type == CGI) || (req->cgi_type == PHPCGI))
            fd = req->cgi.from_script;
        else
            fd = req->fcgi.fd;
        req->cgi.len_buf = read(fd, req->cgi.buf + 8, req->cgi.size_buf);
        if (req->cgi.len_buf == -1)
        {
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            print_err(req, "<%s:%d> Error read(): %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
        else if (req->cgi.len_buf == 0)
        {
            if (req->mode_send == CHUNK)
            {
                req->cgi.len_buf = 0;
                req->cgi.p = req->cgi.buf + 8;
                cgi_set_size_chunk(req);
                req->io_direct = TO_CLIENT;
                req->mode_send = CHUNK_END;
                return req->cgi.len_buf;
            }
            return 0;
        }

        req->io_direct = TO_CLIENT;
        if (req->mode_send == CHUNK)
        {
            req->cgi.p = req->cgi.buf + 8;
            if (cgi_set_size_chunk(req))
                return -1;
        }
        else
            req->cgi.p = req->cgi.buf + 8;
        return req->cgi.len_buf;
    }
    else if (req->io_direct == TO_CLIENT)
    {
        int ret = write_to_client(req, req->cgi.p, req->cgi.len_buf);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                return ERR_TRY_AGAIN;
            return -1;
        }

        req->cgi.p += ret;
        req->cgi.len_buf -= ret;
        req->send_bytes += ret;
        if (req->cgi.len_buf == 0)
        {
            if (req->mode_send == CHUNK_END)
                return 0;
            req->io_direct = FROM_CGI;
        }
    }

    return 1;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_find_empty_line(Connect *req)
{
    char *pCR, *pLF;
    while (req->lenTail > 0)
    {
        int i = 0, len_line = 0;
        pCR = pLF = NULL;
        while (i < req->lenTail)
        {
            char ch = *(req->p_newline + i);
            if (ch == '\r')// found CR
            {
                if (i == (req->lenTail - 1))
                    return 0;
                if (pCR)
                    return -RS502;
                pCR = req->p_newline + i;
            }
            else if (ch == '\n')// found LF
            {
                pLF = req->p_newline + i;
                if ((pCR) && ((pLF - pCR) != 1))
                    return -RS502;
                i++;
                break;
            }
            else
                len_line++;
            i++;
        }

        if (pLF) // found end of line '\n'
        {
            if (pCR == NULL)
                *pLF = 0;
            else
                *pCR = 0;

            if (len_line == 0)
            {
                req->lenTail -= i;
                if (req->lenTail > 0)
                    req->tail = pLF + 1;
                else
                    req->tail = NULL;
                return 1;
            }
///fprintf(stderr, "<%s:%d> [%s]\n", __func__, __LINE__, req->p_newline);
            if (!memchr(req->p_newline, ':', len_line))
            {
                //print_err(req, "<%s:%d> Error Line not header: [%s]\n", __func__, __LINE__, req->p_newline);
                return -RS502;
            }

            if (!strlcmp_case(req->p_newline, "Status", 6))
            {
                req->respStatus = atoi(req->p_newline + 7);
            }
            else
                req->hdrs << req->p_newline << "\r\n";

            req->lenTail -= i;
            req->p_newline = pLF + 1;
        }
        else if (pCR && (!pLF))
            return -RS502;
        else
            break;
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_read_http_headers(Connect *req)
{
    int num_read = req->cgi.size_buf - req->cgi.len_buf - 1;
    if (num_read <= 0)
        return -RS502;
    int fd;
    if ((req->cgi_type == CGI) || (req->cgi_type == PHPCGI))
        fd = req->cgi.from_script;
    else
        fd = req->fcgi.fd;

    int n = read(fd, req->cgi.p, num_read);
    if (n == -1)
    {
        if (errno == EAGAIN)
            return ERR_TRY_AGAIN;
        print_err(req, "<%s:%d> Error read(): %s\n", __func__, __LINE__, strerror(errno));
        return -1;
    }
    else if (n == 0)
    {
        print_err(req, "<%s:%d> Error read()=0\n", __func__, __LINE__);
        return -1;
    }

    req->lenTail += n;
    req->cgi.len_buf += n;
    req->cgi.p += n;
    *(req->cgi.p) = 0;

    n = cgi_find_empty_line(req);
    if (n == 1) // empty line found
        return req->cgi.len_buf;
    else if (n < 0) // error
        return n;

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_set_size_chunk(Connect *r)
{
    int size = r->cgi.len_buf;
    const char *hex = "0123456789ABCDEF";

    memcpy(r->cgi.p + r->cgi.len_buf, "\r\n", 2);
    int i = 7;
    *(--r->cgi.p) = '\n';
    *(--r->cgi.p) = '\r';
    i -= 2;
    for ( ; i >= 0; --i)
    {
        *(--r->cgi.p) = hex[size % 16];
        size /= 16;
        if (size == 0)
            break;
    }

    if (size != 0)
        return -1;
    r->cgi.len_buf += (8 - i + 2);

    return 0;
}
//----------------------------------------------------------------------
void EventHandlerClass::cgi_worker(Connect* r)
{
    if (r->cgi.op.cgi == CGI_CREATE_PROC)
    {
        int ret = cgi_create_proc(r);
        if (ret < 0)
        {
            print_err(r, "<%s:%d> Error cgi_create_proc()=%d\n", __func__, __LINE__, ret);
            r->err = ret;
            del_from_list(r);
            end_response(r);
        }
    }
    else if (r->cgi.op.cgi == CGI_STDIN)
    {
        int ret = cgi_stdin(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                r->io_status = WAIT;
            else
            {
                r->err = -RS502;
                del_from_list(r);
                end_response(r);
            }
        }
    }
    else if (r->cgi.op.cgi == CGI_READ_HTTP_HEADERS)
    {
        int ret = cgi_read_http_headers(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                r->io_status = WAIT;
            else
            {
                r->err = -RS502;
                del_from_list(r);
                end_response(r);
            }
        }
        else if (ret > 0)
        {
            if (create_response_headers(r))
            {
                print_err(r, "<%s:%d> Error create_response_headers()\n", __func__, __LINE__);
                r->err = -1;
                del_from_list(r);
                end_response(r);
            }
            else
            {
                r->resp_headers.p = r->resp_headers.s.c_str();
                r->resp_headers.len = r->resp_headers.s.size();
                r->cgi.op.cgi = CGI_SEND_HTTP_HEADERS;
                r->io_direct = TO_CLIENT;
                r->sock_timer = 0;
            }
        }
        else
            r->sock_timer = 0;
    }
    else if (r->cgi.op.cgi == CGI_SEND_HTTP_HEADERS)
    {
        if (r->resp_headers.len > 0)
        {
            int wr = write_to_client(r, r->resp_headers.p, r->resp_headers.len);
            if (wr < 0)
            {
                if (wr == ERR_TRY_AGAIN)
                    r->io_status = WAIT;
                else
                {
                    r->err = -1;
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                    close(r->cgi.from_script);
                    r->cgi.from_script = -1;
                    del_from_list(r);
                    end_response(r);
                }
            }
            else
            {
                r->resp_headers.p += wr;
                r->resp_headers.len -= wr;
                if (r->resp_headers.len == 0)
                {
                    if (r->reqMethod == M_HEAD)
                    {
                        close(r->cgi.from_script);
                        r->cgi.from_script = -1;
                        del_from_list(r);
                        end_response(r);
                    }
                    else
                    {
                        r->cgi.op.cgi = CGI_SEND_ENTITY;
                        r->sock_timer = 0;
                        if (r->lenTail > 0)
                        {
                            r->cgi.p = r->tail;
                            r->cgi.len_buf = r->lenTail;
                            r->lenTail = 0;
                            r->tail = NULL;
                            r->io_direct = TO_CLIENT;
                            if (r->mode_send == CHUNK)
                            {
                                if (cgi_set_size_chunk(r))
                                {
                                    r->err = -1;
                                    del_from_list(r);
                                    end_response(r);
                                }
                            }
                        }
                        else
                        {
                            r->cgi.len_buf = 0;
                            r->cgi.p = NULL;
                            r->io_direct = FROM_CGI;
                        }
                    }
                }
                else
                    r->sock_timer = 0;
            }
        }
        else
        {
            print_err(r, "<%s:%d> Error resp.len=%d\n", __func__, __LINE__, r->resp_headers.len);
            r->err = -1;
            r->req_hd.iReferer = MAX_HEADERS - 1;
            r->reqHdValue[r->req_hd.iReferer] = "Error send response headers";
            del_from_list(r);
            end_response(r);
        }
    }
    else if (r->cgi.op.cgi == CGI_SEND_ENTITY)
    {
        int ret = cgi_stdout(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                r->io_status = WAIT;
            else
            {
                r->err = -1;
                del_from_list(r);
                end_response(r);
            }
        }
        else if (ret == 0)
        {
            del_from_list(r);
            end_response(r);
        }
    }
    else
    {
        print_err(r, "<%s:%d> ??? Error: CGI_OPERATION=%s\n", __func__, __LINE__, get_cgi_operation(r->cgi.op.cgi));
        r->err = -1;
        del_from_list(r);
        end_response(r);
    }
}
//----------------------------------------------------------------------
void EventHandlerClass::cgi_set_status_readheaders(Connect *r)
{
    r->cgi.op.cgi = CGI_READ_HTTP_HEADERS;
    r->io_direct = FROM_CGI;
    r->tail = NULL;
    r->lenTail = 0;
    r->p_newline = r->cgi.p = r->cgi.buf + 8;
    r->cgi.len_buf = 0;
    r->sock_timer = 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::cgi_err(Connect *r)
{
    if ((r->cgi.op.cgi == CGI_STDIN) && (r->io_direct == TO_CGI))
        return -RS504;
    else if (r->cgi.op.cgi == CGI_READ_HTTP_HEADERS)
        return -RS504;
    else
        return -1;
}
//----------------------------------------------------------------------
/*void EventHandlerClass::cgi_add_work_list()
{
mtx_cgi.lock();
    if ((cgi_work < conf->MaxCgiProc) && cgi_wait_list_end)
    {
        int n_max = conf->MaxCgiProc - cgi_work;
        Connect *r = cgi_wait_list_end;

        for ( ; (n_max > 0) && r; r = cgi_wait_list_end, --n_max)
        {
            cgi_wait_list_end = r->prev;
            if (cgi_wait_list_end == NULL)
                cgi_wait_list_start = NULL;
            //--------------------------
            if ((r->cgi_type == CGI) || (r->cgi_type == PHPCGI))
            {
                r->cgi.to_script = -1;
                r->cgi.from_script = -1;
                r->cgi.op.cgi = CGI_CREATE_PROC;
            }
            else if ((r->cgi_type == PHPFPM) || (r->cgi_type == FASTCGI))
            {
                r->cgi.op.fcgi = FASTCGI_CONNECT;
            }
            else if (r->cgi_type == SCGI)
            {
                r->cgi.op.scgi = SCGI_CONNECT;
            }
            else
            {
                print_err(r, "<%s:%d> operation=%d, cgi_type=%s\n", __func__, __LINE__, r->operation, get_cgi_type(r->cgi_type));
                end_response(r);
                continue;
            }
            //--------------------------
            if (work_list_end)
                work_list_end->next = r;
            else
                work_list_start = r;

            r->prev = work_list_end;
            r->next = NULL;
            work_list_end = r;
            ++cgi_work;
        }
    }
mtx_cgi.unlock();
}*/
//----------------------------------------------------------------------
void EventHandlerClass::cgi_add_work_list()
{
    bool return_;
    int n_max;
    Connect *r;
mtx_cgi.lock();
    if ((cgi_work < (int)conf->MaxCgiProc) && cgi_wait_list_end)
    {
        n_max = conf->MaxCgiProc - cgi_work;
        r = cgi_wait_list_end;
        return_ = false;
    }
    else
        return_ = true;
mtx_cgi.unlock();
    if (return_)
        return;

    for ( ; (n_max > 0) && r;  --n_max)
    {
    mtx_cgi.lock();
        cgi_wait_list_end = r->prev;
        if (cgi_wait_list_end == NULL)
            cgi_wait_list_start = NULL;
    mtx_cgi.unlock();
        //--------------------------
        if ((r->cgi_type == CGI) || (r->cgi_type == PHPCGI))
        {
            r->cgi.to_script = -1;
            r->cgi.from_script = -1;
            r->cgi.op.cgi = CGI_CREATE_PROC;
        }
        else if ((r->cgi_type == PHPFPM) || (r->cgi_type == FASTCGI))
        {
            r->cgi.op.fcgi = FASTCGI_CONNECT;
        }
        else if (r->cgi_type == SCGI)
        {
            r->cgi.op.scgi = SCGI_CONNECT;
        }
        else
        {
            print_err(r, "<%s:%d> operation=%d, cgi_type=%s\n", __func__, __LINE__, r->operation, get_cgi_type(r->cgi_type));
            r->err = -RS500;
            end_response(r);
        mtx_cgi.lock();
            r = cgi_wait_list_end;
        mtx_cgi.unlock();
            continue;
        }
        //--------------------------
    //mtx_thr.lock();
        if (work_list_end)
            work_list_end->next = r;
        else
            work_list_start = r;

        r->prev = work_list_end;
        r->next = NULL;
        work_list_end = r;
    //mtx_thr.unlock();
    
    mtx_cgi.lock();
        ++cgi_work;
        r = cgi_wait_list_end;
    mtx_cgi.unlock();
    }
}
