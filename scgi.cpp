#include "main.h"

using namespace std;
//======================================================================
int EventHandlerClass::scgi_set_size_data(Connect* r)
{
    int size = r->cgi.len_buf;
    int i = 7;
    char *p = r->cgi.buf;
    p[i--] = ':';

    for ( ; i >= 0; --i)
    {
        p[i] = (size % 10) + '0';
        size /= 10;
        if (size == 0)
            break;
    }

    if (size != 0)
        return -1;

    r->cgi.buf[8 + r->cgi.len_buf] = ',';
    r->cgi.p = r->cgi.buf + i;
    r->cgi.len_buf += (8 - i + 1);

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::scgi_create_connect(Connect *r)
{
    r->io_direct = TO_CGI;
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

    r->cgi.fd = create_fcgi_socket(r, r->cgi.script_path->c_str());
    if (r->cgi.fd < 0)
    {
        print_err(r, "<%s:%d> Error connect to scgi\n", __func__, __LINE__);
        return r->cgi.fd;
    }

    int ret = scgi_create_params(r);
    if (ret < 0)
        return ret;
    else
    {
        r->cgi.op.scgi = SCGI_PARAMS;
        r->timeout = conf->TimeoutCGI;
        r->sock_timer = 0;
        r->io_direct = TO_CGI;
        r->io_status = WAIT;
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::scgi_create_params(Connect *r)
{
    int i = 0;
    Param param;
    r->cgi.vPar.clear();

    if (r->reqMethod == M_POST)
    {
        if (r->req_hd.iReqContentLength >= 0)
            param.val = r->reqHdValue[r->req_hd.iReqContentLength];
        else
        {
            fprintf(stderr, "<%s:%d> CONTENT_LENGTH ?\n", __func__, __LINE__);
            return -RS400;
        }

        param.name = "CONTENT_LENGTH";
        r->cgi.vPar.push_back(param);
        ++i;

        if (r->req_hd.iReqContentType >=0)
            param.val = r->reqHdValue[r->req_hd.iReqContentType];
        else
        {
            fprintf(stderr, "<%s:%d> CONTENT_TYPE ?\n", __func__, __LINE__);
            return -RS400;
        }

        param.name = "CONTENT_TYPE";
        r->cgi.vPar.push_back(param);
        ++i;
    }
    else
    {
        param.name = "CONTENT_LENGTH";
        param.val = "0";
        r->cgi.vPar.push_back(param);
        ++i;
        
        param.name = "CONTENT_TYPE";
        param.val = "";
        r->cgi.vPar.push_back(param);
        ++i;
    }

    param.name = "PATH";
    param.val = "/bin:/usr/bin:/usr/local/bin";
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "SERVER_SOFTWARE";
    param.val = conf->ServerSoftware;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "SCGI";
    param.val = "1";
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "DOCUMENT_ROOT";
    param.val = conf->DocumentRoot;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "REMOTE_ADDR";
    param.val = r->remoteAddr;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "REMOTE_PORT";
    param.val = r->remotePort;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "REQUEST_URI";
    param.val = r->uri;
    r->cgi.vPar.push_back(param);
    ++i;
    
    param.name = "DOCUMENT_URI";
    param.val = r->decodeUri;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "REQUEST_METHOD";
    param.val = get_str_method(r->reqMethod);
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "SERVER_PROTOCOL";
    param.val = get_str_http_prot(r->httpProt);
    r->cgi.vPar.push_back(param);
    ++i;
    
    param.name = "SERVER_PORT";
    param.val = conf->ServerPort;
    r->cgi.vPar.push_back(param);
    ++i;

    if (r->req_hd.iHost >= 0)
    {
        param.name = "HTTP_HOST";
        param.val = r->reqHdValue[r->req_hd.iHost];
        r->cgi.vPar.push_back(param);
        ++i;
    }

    if (r->req_hd.iReferer >= 0)
    {
        param.name = "HTTP_REFERER";
        param.val = r->reqHdValue[r->req_hd.iReferer];
        r->cgi.vPar.push_back(param);
        ++i;
    }

    if (r->req_hd.iUserAgent >= 0)
    {
        param.name = "HTTP_USER_AGENT";
        param.val = r->reqHdValue[r->req_hd.iUserAgent];
        r->cgi.vPar.push_back(param);
        ++i;
    }

    param.name = "HTTP_CONNECTION";
    if (r->connKeepAlive == 1)
        param.val = "keep-alive";
    else
        param.val = "close";
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "SCRIPT_NAME";
    param.val = r->decodeUri;
    r->cgi.vPar.push_back(param);
    ++i;

    param.name = "QUERY_STRING";
    if (r->sReqParam)
        param.val = r->sReqParam;
    else
        param.val = "";
    r->cgi.vPar.push_back(param);
    ++i;

    if (i != (int)r->cgi.vPar.size())
    {
        print_err(r, "<%s:%d> Error: create fcgi param list\n", __func__, __LINE__);
        return -1;
    }

    r->cgi.size_par = i;
    r->cgi.i_param = 0;

    int ret = scgi_set_param(r);
    if (ret <= 0)
    {
        fprintf(stderr, "<%s:%d> Error scgi_set_param()\n", __func__, __LINE__);
        return -RS502;
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::scgi_set_param(Connect *r)
{
    r->cgi.len_buf = 0;
    r->cgi.p = r->cgi.buf + 8;

    for ( ; r->cgi.i_param < r->cgi.size_par; ++r->cgi.i_param)
    {
        int len_name = r->cgi.vPar[r->cgi.i_param].name.size();
        if (len_name == 0)
        {
            print_err(r, "<%s:%d> Error: len_name=0\n", __func__, __LINE__);
            return -RS502;
        }

        int len_val = r->cgi.vPar[r->cgi.i_param].val.size();
        int len = len_name + len_val + 2;

        if (len > (r->cgi.size_buf - r->cgi.len_buf))
        {
            break;
        }

        memcpy(r->cgi.p, r->cgi.vPar[r->cgi.i_param].name.c_str(), len_name);
        r->cgi.p += len_name;
        
        memcpy(r->cgi.p, "\0", 1);
        r->cgi.p += 1;

        if (len_val > 0)
        {
            memcpy(r->cgi.p, r->cgi.vPar[r->cgi.i_param].val.c_str(), len_val);
            r->cgi.p += len_val;
        }

        memcpy(r->cgi.p, "\0", 1);
        r->cgi.p += 1;

        r->cgi.len_buf += len;
    }
    
    if(r->cgi.i_param < r->cgi.size_par)
    {
        print_err(r, "<%s:%d> Error: size of param > size of buf\n", __func__, __LINE__);
        return -RS502;
    }

    if (r->cgi.len_buf > 0)
    {      
        scgi_set_size_data(r);
    }
    else
    {
        print_err(r, "<%s:%d> Error: size param = 0\n", __func__, __LINE__);
        return -RS502;
    }

    return r->cgi.len_buf;
}
//----------------------------------------------------------------------
void EventHandlerClass::scgi_worker(Connect* r)
{
    if (r->cgi.op.scgi == SCGI_PARAMS)
    {
        int ret = write_to_fcgi(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                r->io_status = WAIT;
            else
            {
                r->err = -RS502;
                del_from_list(r);
            }

            return;
        }

        r->sock_timer = 0;
        if (r->cgi.len_buf == 0)
        {
            if (r->req_hd.reqContentLength > 0)
            {
                r->cgi.len_post = r->req_hd.reqContentLength - r->lenTail;
                r->cgi.op.scgi = SCGI_STDIN;
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
                    r->io_status = WORK;
                }
            }
            else
            {
                r->cgi.op.scgi = SCGI_READ_HTTP_HEADERS;
                r->io_direct = FROM_CGI;
                r->tail = NULL;
                r->lenTail = 0;
                r->p_newline = r->cgi.p = r->cgi.buf + 8;
                r->cgi.len_buf = 0;
            }
        }
    }
    else if (r->cgi.op.scgi == SCGI_STDIN)
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
            }
        }
        else
            r->sock_timer = 0;
    }
    else //==================== SCGI_STDOUT=============================
    {
        if (r->cgi.op.scgi == SCGI_READ_HTTP_HEADERS)
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
                }
            }
            else if (ret > 0)
            {
                r->mode_send = ((r->httpProt == HTTP11) && r->connKeepAlive) ? CHUNK : NO_CHUNK;
                if (create_response_headers(r))
                {
                    print_err(r, "<%s:%d> Error create_response_headers()\n", __func__, __LINE__);
                    r->err = -1;
                    del_from_list(r);
                }
                else
                {
                    r->resp_headers.p = r->resp_headers.s.c_str();
                    r->resp_headers.len = r->resp_headers.s.size();
                    r->cgi.op.scgi = SCGI_SEND_HTTP_HEADERS;
                    r->io_direct = TO_CLIENT;
                    r->sock_timer = 0;
                }
            }
            else // ret == 0
                r->sock_timer = 0;
        }
        else if (r->cgi.op.scgi == SCGI_SEND_HTTP_HEADERS)
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
                        del_from_list(r);
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
                            del_from_list(r);
                        }
                        else
                        {
                            if (r->respStatus == RS204)
                            {
                                del_from_list(r);
                                return;
                            }

                            r->cgi.op.scgi = SCGI_SEND_ENTITY;
                            r->sock_timer = 0;
                            if (r->lenTail > 0)
                            {
                                r->cgi.p = r->tail;
                                r->cgi.len_buf = r->lenTail;
                                r->tail = NULL;
                                r->lenTail = 0;
                                r->io_direct = TO_CLIENT;
                                if (r->mode_send == CHUNK)
                                {
                                    if (cgi_set_size_chunk(r))
                                    {
                                        r->err = -1;
                                        del_from_list(r);
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
            }
        }
        else if (r->cgi.op.scgi == SCGI_SEND_ENTITY)
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
                }
            }
            else if (ret == 0) // end SCGI_SEND_ENTITY
            {
                del_from_list(r);
            }
            else
                r->sock_timer = 0;
        }
        else
        {
            print_err(r, "<%s:%d> ??? Error: SCGI_OPERATION=%s\n", __func__, __LINE__, get_scgi_operation(r->cgi.op.scgi));
            r->err = -1;
            del_from_list(r);
        }
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::scgi_err(Connect *r)
{
    if (((r->cgi.op.scgi == SCGI_PARAMS) || (r->cgi.op.scgi == SCGI_STDIN)) && 
         (r->io_direct == TO_CGI))
        return -RS504;
    else if (r->cgi.op.scgi == SCGI_READ_HTTP_HEADERS)
        return -RS504;
    else
        return -1;
}
