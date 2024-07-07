#include "main.h"

using namespace std;

extern int fcgi_in_, fcgi_out_;
//======================================================================
#define FCGI_RESPONDER  1

#define FCGI_VERSION_1           1
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE            (FCGI_UNKNOWN_TYPE)
#define requestId               1
//======================================================================
void EventHandlerClass::fcgi_set_header(Connect* r, int type)
{
    r->fcgi.fcgi_type = type;
    r->fcgi.paddingLen = 0;
    char *p = r->cgi.buf;
    *p++ = FCGI_VERSION_1;
    *p++ = (unsigned char)type;
    *p++ = (unsigned char) ((1 >> 8) & 0xff);
    *p++ = (unsigned char) ((1) & 0xff);
    *p++ = (unsigned char) ((r->fcgi.dataLen >> 8) & 0xff);
    *p++ = (unsigned char) ((r->fcgi.dataLen) & 0xff);
    *p++ = r->fcgi.paddingLen;
    *p = 0;
    
    r->cgi.p = r->cgi.buf;
    r->cgi.len_buf += 8;
}
//----------------------------------------------------------------------
void EventHandlerClass::get_info_from_header(Connect* r, const char* p)
{
    r->fcgi.fcgi_type = (unsigned char)p[1];
    r->fcgi.paddingLen = (unsigned char)p[6];
    r->fcgi.dataLen = ((unsigned char)p[4]<<8) | (unsigned char)p[5];
    r->fcgi.len_buf -= 8;
}
//----------------------------------------------------------------------
void EventHandlerClass::fcgi_set_param(Connect *r)
{
    r->cgi.len_buf = 0;
    r->cgi.p = r->cgi.buf + 8;

    for ( ; r->fcgi.i_param < r->fcgi.size_par; ++r->fcgi.i_param)
    {
        int len_name = r->fcgi.vPar[r->fcgi.i_param].name.size();
        int len_val = r->fcgi.vPar[r->fcgi.i_param].val.size();
        int len = len_name + len_val;
        len += len_name > 127 ? 4 : 1;
        len += len_val > 127 ? 4 : 1;
        if (len > (r->cgi.size_buf - r->cgi.len_buf))
        {
            break;
        }

        if (len_name < 0x80)
            *(r->cgi.p++) = (unsigned char)len_name;
        else
        {
            *(r->cgi.p++) = (unsigned char)((len_name >> 24) | 0x80);
            *(r->cgi.p++) = (unsigned char)(len_name >> 16);
            *(r->cgi.p++) = (unsigned char)(len_name >> 8);
            *(r->cgi.p++) = (unsigned char)len_name;
        }

        if (len_val < 0x80)
            *(r->cgi.p++) = (unsigned char)len_val;
        else
        {
            *(r->cgi.p++) = (unsigned char)((len_val >> 24) | 0x80);
            *(r->cgi.p++) = (unsigned char)(len_val >> 16);
            *(r->cgi.p++) = (unsigned char)(len_val >> 8);
            *(r->cgi.p++) = (unsigned char)len_val;
        }

        memcpy(r->cgi.p, r->fcgi.vPar[r->fcgi.i_param].name.c_str(), len_name);
        r->cgi.p += len_name;
        if (len_val > 0)
        {
            memcpy(r->cgi.p, r->fcgi.vPar[r->fcgi.i_param].val.c_str(), len_val);
            r->cgi.p += len_val;
        }

        r->cgi.len_buf += len;
    }

    r->fcgi.dataLen = r->cgi.len_buf;
    fcgi_set_header(r, FCGI_PARAMS);
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_create_connect(Connect *r)
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

    if (r->cgi_type == PHPFPM)
        r->fcgi.fd = create_fcgi_socket(r, conf->PathPHP.c_str());
    else if (r->cgi_type == FASTCGI)
        r->fcgi.fd = get_sock_fcgi(r, r->scriptName.c_str());
    else
    {
        print_err(r, "<%s:%d> ? req->scriptType=%d\n", __func__, __LINE__, r->cgi_type);
        return -RS500;
    }

    if (r->fcgi.fd < 0)
    {
        return r->fcgi.fd;
    }

    r->fcgi.status = FCGI_READ_DATA;
    r->fcgi.len_buf = 0;
    r->fcgi.dataLen = r->cgi.len_buf = 8;
    fcgi_set_header(r, FCGI_BEGIN_REQUEST);
    char *p = r->cgi.buf + 8;
    *(p++) = (unsigned char) ((FCGI_RESPONDER >> 8) & 0xff);
    *(p++) = (unsigned char) (FCGI_RESPONDER        & 0xff);
    memcpy(p, "\0\0\0\0\0\0", 6);
    r->cgi.op.fcgi = FASTCGI_BEGIN;
    r->io_status = WAIT;

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_create_params(Connect *req)
{
    int i = 0;
    Param param;
    req->fcgi.vPar.clear();
    if (req->fcgi.vPar.capacity() < 45)
        req->fcgi.vPar.reserve(45);

    if (req->cgi_type == PHPFPM)
    {
        param.name = "REDIRECT_STATUS";
        param.val = "true";
        req->fcgi.vPar.push_back(param);
        ++i;
    }

    param.name = "PATH";
    param.val = "/bin:/usr/bin:/usr/local/bin";
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "SERVER_SOFTWARE";
    param.val = conf->ServerSoftware;
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "GATEWAY_INTERFACE";
    param.val = "CGI/1.1";
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "DOCUMENT_ROOT";
    param.val = conf->DocumentRoot;
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "REMOTE_ADDR";
    param.val = req->remoteAddr;
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "REMOTE_PORT";
    param.val = req->remotePort;
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "REQUEST_URI";
    param.val = req->uri;
    req->fcgi.vPar.push_back(param);
    ++i;
    
    param.name = "DOCUMENT_URI";
    param.val = req->decodeUri;
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "REQUEST_METHOD";
    param.val = get_str_method(req->reqMethod);
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "SERVER_PROTOCOL";
    param.val = get_str_http_prot(req->httpProt);
    req->fcgi.vPar.push_back(param);
    ++i;
    
    param.name = "SERVER_PORT";
    param.val = conf->ServerPort;
    req->fcgi.vPar.push_back(param);
    ++i;

    if (req->req_hd.iHost >= 0)
    {
        param.name = "HTTP_HOST";
        param.val = req->reqHdValue[req->req_hd.iHost];
        req->fcgi.vPar.push_back(param);
        ++i;
    }

    if (req->req_hd.iReferer >= 0)
    {
        param.name = "HTTP_REFERER";
        param.val = req->reqHdValue[req->req_hd.iReferer];
        req->fcgi.vPar.push_back(param);
        ++i;
    }

    if (req->req_hd.iUserAgent >= 0)
    {
        param.name = "HTTP_USER_AGENT";
        param.val = req->reqHdValue[req->req_hd.iUserAgent];
        req->fcgi.vPar.push_back(param);
        ++i;
    }

    param.name = "HTTP_CONNECTION";
    if (req->connKeepAlive == 1)
        param.val = "keep-alive";
    else
        param.val = "close";
    req->fcgi.vPar.push_back(param);
    ++i;

    param.name = "SCRIPT_NAME";
    param.val = req->decodeUri;
    req->fcgi.vPar.push_back(param);
    ++i;

    if (req->cgi_type == PHPFPM)
    {
        param.name = "SCRIPT_FILENAME";
        param.val = conf->DocumentRoot + req->scriptName.c_str();
        req->fcgi.vPar.push_back(param);
        ++i;
    }

    if (req->reqMethod == M_POST)
    {
        if (req->req_hd.iReqContentType >= 0)
        {
            param.name = "CONTENT_TYPE";
            param.val = req->reqHdValue[req->req_hd.iReqContentType];
            req->fcgi.vPar.push_back(param);
            ++i;
        }

        if (req->req_hd.iReqContentLength >= 0)
        {
            param.name = "CONTENT_LENGTH";
            param.val = req->reqHdValue[req->req_hd.iReqContentLength];
            req->fcgi.vPar.push_back(param);
            ++i;
        }
    }

    param.name = "QUERY_STRING";
    if (req->sReqParam)
        param.val = req->sReqParam;
    else
        param.val = "";
    req->fcgi.vPar.push_back(param);
    ++i;

    if (i != (int)req->fcgi.vPar.size())
    {
        print_err(req, "<%s:%d> Error: create fcgi param list\n", __func__, __LINE__);
        return -RS500;
    }

    req->fcgi.size_par = i;
    req->fcgi.i_param = 0;
    //----------------------------------------------
    req->io_direct = TO_CGI;
    req->sock_timer = 0;
    req->fcgi.http_headers_received = false;

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_stdin(Connect *r)// return [ ERR_TRY_AGAIN | -1 | 0 ]
{
    if (r->io_direct == FROM_CLIENT)
    {
        int rd = (r->cgi.len_post > r->cgi.size_buf) ? r->cgi.size_buf : r->cgi.len_post;
        r->cgi.len_buf = read_from_client(r, r->cgi.buf + 8, rd);
        if (r->cgi.len_buf < 0)
        {
            if (r->cgi.len_buf == ERR_TRY_AGAIN)
                return ERR_TRY_AGAIN;
            return -1;
        }
        else if (r->cgi.len_buf == 0)
        {
            print_err(r, "<%s:%d> Error read()=0\n", __func__, __LINE__);
            return -1;
        }

        r->cgi.len_post -= r->cgi.len_buf;
        r->fcgi.dataLen = r->cgi.len_buf;
        fcgi_set_header(r, FCGI_STDIN);
        r->io_direct = TO_CGI;
    }
    else if (r->io_direct == TO_CGI)
    {
        if ((r->lenTail > 0) && (r->cgi.len_buf == 0))
        {
            if (r->lenTail > r->cgi.size_buf)
                r->cgi.len_buf = r->cgi.size_buf;
            else
                r->cgi.len_buf = r->lenTail;
            memcpy(r->cgi.buf + 8, r->tail, r->cgi.len_buf);
            r->lenTail -= r->cgi.len_buf;
            r->cgi.len_post -= r->cgi.len_buf;
            if (r->lenTail == 0)
                r->tail = NULL;
            else
                r->tail += r->cgi.len_buf;
            r->fcgi.dataLen = r->cgi.len_buf;
            fcgi_set_header(r, FCGI_STDIN);
        }

        int n = write(r->fcgi.fd, r->cgi.p, r->cgi.len_buf);
        if (n == -1)
        {
            print_err(r, "<%s:%d> Error write(): %s\n", __func__, __LINE__, strerror(errno));
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            return -1;
        }

        r->cgi.p += n;
        r->cgi.len_buf -= n;
        if (r->cgi.len_buf == 0)
        {
            if (r->cgi.len_post <= 0)
            {
                if (r->fcgi.dataLen == 0)
                {
                    r->cgi.op.fcgi = FASTCGI_READ_HTTP_HEADERS;
                    r->fcgi.status = FCGI_READ_HEADER;
                    r->fcgi.len_buf = 0;
                    r->p_newline = r->cgi.p = r->cgi.buf + 8;
                    r->cgi.len_buf = 0;
                    r->tail = NULL;
                    
                    r->io_direct = FROM_CGI;
                }
                else
                {
                    r->cgi.len_buf = 0;
                    r->fcgi.dataLen = r->cgi.len_buf;
                    fcgi_set_header(r, FCGI_STDIN);  // post data = 0
                    r->io_direct = TO_CGI;
                }
            }
            else
            {
                if (r->lenTail > 0)
                {
                    r->io_direct = TO_CGI;
                }
                else
                {
                    r->io_direct = FROM_CLIENT;
                    r->io_status = WORK;
                }
            }
        }
    }

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_stdout(Connect *r)// return [ ERR_TRY_AGAIN | -1 | 0 | 1 | 0< ]
{
    if (r->io_direct == FROM_CGI)
    {
        if ((r->cgi.op.fcgi == FASTCGI_SEND_ENTITY) || 
            (r->cgi.op.fcgi == FASTCGI_READ_ERROR) ||
            (r->cgi.op.fcgi == FASTCGI_CLOSE))
        {
            if (r->fcgi.dataLen == 0)
            {
                r->fcgi.status = FCGI_READ_PADDING;
                return 1;
            }

            {
                int len = (r->fcgi.dataLen > r->cgi.size_buf) ? r->cgi.size_buf : r->fcgi.dataLen;
                int ret = read(r->fcgi.fd, r->cgi.buf + 8, len);
                if (ret == -1)
                {
                    print_err(r, "<%s:%d> Error read from script(fd=%d): %s(%d)\n", 
                            __func__, __LINE__, r->fcgi.fd, strerror(errno), errno);
                    if (errno == EAGAIN)
                        return ERR_TRY_AGAIN;
                    else
                        return -1;
                }
                else if (ret == 0)
                    return -1;

                r->cgi.len_buf = ret;
                r->cgi.p = r->cgi.buf + 8;
                r->fcgi.dataLen -= ret;
            }

            if (r->cgi.op.fcgi == FASTCGI_SEND_ENTITY)
            {
                r->io_direct = TO_CLIENT;
                if (r->mode_send == CHUNK)
                {
                    r->cgi.p = r->cgi.buf + 8;
                    if (cgi_set_size_chunk(r))
                        return -1;
                }
                else
                    r->cgi.p = r->cgi.buf + 8;
            }
            else if (r->cgi.op.fcgi == FASTCGI_READ_ERROR)
            {
                if (r->fcgi.dataLen == 0)
                {
                    r->fcgi.status = FCGI_READ_PADDING;
                }
                *(r->cgi.buf + 8 + r->cgi.len_buf) = 0;
                fprintf(stderr, "%s\n", r->cgi.buf + 8);
            }
            else if (r->cgi.op.fcgi == FASTCGI_CLOSE)
            {
                if (r->fcgi.dataLen == 0)
                {
                    if (r->mode_send == NO_CHUNK)
                    {
                        r->connKeepAlive = 0;
                        return 0;
                    }
                    else
                    {
                        r->mode_send = CHUNK_END;
                        r->cgi.len_buf = 0;
                        r->cgi.p = r->cgi.buf + 8;
                        cgi_set_size_chunk(r);
                        r->io_direct = TO_CLIENT;
                    }
                }
            }
        }
    }
    else if (r->io_direct == TO_CLIENT)
    {
        int ret = write_to_client(r, r->cgi.p, r->cgi.len_buf);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                return ERR_TRY_AGAIN;
            else
                return -1;
        }

        r->cgi.p += ret;
        r->cgi.len_buf -= ret;
        r->send_bytes += ret;
        if (r->cgi.len_buf == 0)
        {
            if (r->cgi.op.fcgi == FASTCGI_CLOSE)
            {
//print_err(r, "<%s:%d> all_read(%d)\n", __func__, __LINE__, r->fcgi.all_read);
                return 0;
            }

            if (r->fcgi.dataLen == 0)
            {
                if (r->fcgi.paddingLen == 0)
                {
                    r->fcgi.status = FCGI_READ_HEADER;
                    r->cgi.p = r->cgi.buf + 8;
                    r->cgi.len_buf = 0;
                }
                else
                {
                    r->fcgi.status = FCGI_READ_PADDING;
                }
            }

            r->io_direct = FROM_CGI;
        }
    }
    return 1;
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_read_http_headers(Connect *r)
{

    int num_read;
    if ((r->cgi.size_buf - r->cgi.len_buf - 1) >= r->fcgi.dataLen)
        num_read = r->fcgi.dataLen;
    else
        num_read = r->cgi.size_buf - r->cgi.len_buf - 1;
    if (num_read <= 0)
        return -1;

    int n = read(r->fcgi.fd, r->cgi.p, num_read);
    if (n == -1)
    {
        print_err(r, "<%s:%d> Error read(): %s\n", __func__, __LINE__, strerror(errno));
        if (errno == EAGAIN)
            return ERR_TRY_AGAIN;
        else
            return -1;
    }
    else if (n == 0)
        return -1;

    r->fcgi.dataLen -= n;
    r->lenTail += n;
    r->cgi.len_buf += n;
    r->cgi.p += n;

    *(r->cgi.p) = 0;

    int ret = cgi_find_empty_line(r);
    if (ret == 1) // empty line found
    {
        return r->cgi.len_buf;
    }
    else if (ret < 0) // error
        return -1;

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::write_to_fcgi(Connect* r)
{
    int ret = write(r->fcgi.fd, r->cgi.p, r->cgi.len_buf);
    if (ret == -1)
    {
        if (errno == EAGAIN)
            return ERR_TRY_AGAIN;
        else
        {
            print_err(r, "<%s:%d> Error write to fcgi: %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
    }
    else
    {
        r->cgi.len_buf -= ret;
        r->cgi.p += ret;
    }

    return ret;
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_read_header(Connect* r)
{
    if (r->fcgi.len_buf < 8)
    {
        int ret = read(r->fcgi.fd, r->fcgi.header, 8 - r->fcgi.len_buf);
        if (ret == -1)
        {
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            print_err(r, "<%s:%d> Error fcgi_read_header(): %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
        else if (ret == 0)
        {
            print_err(r, "<%s:%d> Error read from fcgi: read()=0, len=%d\n", __func__, __LINE__, 8 - r->fcgi.len_buf);
            return -1;
        }

        r->fcgi.len_buf += ret;
        if (r->fcgi.len_buf == 8)
        {
            get_info_from_header(r, r->fcgi.header);
            return 8;
        }
    }

    return 0;
}
//----------------------------------------------------------------------
void EventHandlerClass::fcgi_worker(Connect* r)
{
    if (r->cgi.op.fcgi == FASTCGI_BEGIN)
    {
        int ret = write_to_fcgi(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
            {
                print_err(r, "<%s:%d> Send param: ERR_TRY_AGAIN\n", __func__, __LINE__);
                r->io_status = WAIT;
            }
            else
            {
                r->err = -RS502;
                del_from_list(r);
            }
        }
        else if (ret > 0)
        {
            r->sock_timer = 0;
            if (r->cgi.len_buf == 0)
            {
                r->cgi.op.fcgi = FASTCGI_PARAMS;
                r->io_direct = TO_CGI;
                int ret = fcgi_create_params(r);
                if (ret < 0)
                {
                    r->err = ret;
                    del_from_list(r);
                }
            }
        }
    }
    else if (r->cgi.op.fcgi == FASTCGI_PARAMS)
    {
        if (r->cgi.len_buf == 0)
        {
            fcgi_set_param(r);
        }

        int ret = write_to_fcgi(r);
        if (ret > 0)
        {
            r->sock_timer = 0;
            if ((r->cgi.len_buf == 0) && (r->fcgi.dataLen == 0)) // end params
            {
                r->cgi.op.fcgi = FASTCGI_STDIN;
                if (r->req_hd.reqContentLength > 0)
                {
                    r->cgi.len_post = r->req_hd.reqContentLength;
                    r->sock_timer = 0;
                    if (r->lenTail > 0)
                    {
                        r->cgi.len_buf = 0;
                        r->io_direct = TO_CGI;
                    }
                    else
                    {
                        r->io_direct = FROM_CLIENT;
                        r->io_status = WORK;
                    }
                }
                else
                {
                    r->cgi.len_post = 0;
                    r->cgi.len_buf = 0;
                    r->fcgi.dataLen = r->cgi.len_buf;
                    fcgi_set_header(r, FCGI_STDIN);  // post data = 0
                    r->sock_timer = 0;
                    r->io_direct = TO_CGI;
                }
            }
        }
        else if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                r->io_status = WAIT;
            else
            {
                r->err = -RS502;
                del_from_list(r);
            }
        }
    }
    else if (r->cgi.op.fcgi == FASTCGI_STDIN)
    {
        int ret = fcgi_stdin(r);
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
    else//====================== FCGI_STDOUT============================
    {
        if (r->fcgi.status == FCGI_READ_HEADER)
        {
            int ret = fcgi_read_header(r);
            if (ret < 0)
            {
                if (ret == ERR_TRY_AGAIN)
                    r->io_status = WAIT;
                else
                {
                    if (r->cgi.op.fcgi <= FASTCGI_READ_HTTP_HEADERS)
                        r->err = -RS502;
                    else
                        r->err = -1;
                    del_from_list(r);
                }
            }
            else if (ret < 8)
                r->sock_timer = 0;
            else if (ret == 8)
            {
                r->sock_timer = 0;
                r->fcgi.status = FCGI_READ_DATA;
                switch (r->fcgi.fcgi_type)
                {
                    case FCGI_STDOUT:
                        if (r->fcgi.dataLen == 0)
                        {
                            r->fcgi.status = FCGI_READ_HEADER;
                            r->cgi.len_buf = 0;
                        }
                        else
                        {
                            if (r->fcgi.http_headers_received == true)
                                r->cgi.op.fcgi = FASTCGI_SEND_ENTITY;
                            else
                            {
                                r->cgi.op.fcgi = FASTCGI_READ_HTTP_HEADERS;
                                r->mode_send = ((r->httpProt == HTTP11) && r->connKeepAlive) ? CHUNK : NO_CHUNK;
                            }
                        }

                        r->io_direct = FROM_CGI;
                        break;
                    case FCGI_STDERR:
                        r->cgi.op.fcgi = FASTCGI_READ_ERROR;
                        r->io_direct = FROM_CGI;
                        break;
                    case FCGI_END_REQUEST:
                        r->cgi.op.fcgi = FASTCGI_CLOSE;
                        r->fcgi.len_buf = 0;
                        r->io_direct = FROM_CGI;
                        break;
                    default:
                        print_err(r, "<%s:%d> Error type=%d\n", __func__, __LINE__, r->fcgi.fcgi_type);
                        r->err = -1;
                        del_from_list(r);
                }
            }
            return;
        }
        else if (r->fcgi.status == FCGI_READ_PADDING)
        {
            int ret = read_padding(r);
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
            return;
        }

        if (r->cgi.op.fcgi == FASTCGI_READ_HTTP_HEADERS)
        {
            int ret = fcgi_read_http_headers(r);
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
                if (create_response_headers(r))
                {
                    print_err(r, "<%s:%d> Error create_response_headers()\n", __func__, __LINE__);
                    r->err = -1;
                    del_from_list(r);
                }
                else
                {
                    r->fcgi.http_headers_received = true;
                    r->resp_headers.p = r->resp_headers.s.c_str();
                    r->resp_headers.len = r->resp_headers.s.size();
                    r->cgi.op.fcgi = FASTCGI_SEND_HTTP_HEADERS;
                    r->io_direct = TO_CLIENT;
                    r->sock_timer = 0;
                }
            }
            else
            {
                r->sock_timer = 0;
                if (r->fcgi.dataLen == 0)
                {
                    if (r->fcgi.paddingLen == 0)
                    {
                        r->fcgi.status = FCGI_READ_HEADER;
                        r->cgi.p = r->cgi.buf + 8;
                        r->cgi.len_buf = 0;
                    }
                    else
                    {
                        r->fcgi.status = FCGI_READ_PADDING;
                    }
                }
            }
        }
        else if (r->cgi.op.fcgi == FASTCGI_SEND_HTTP_HEADERS)
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
                            r->cgi.op.fcgi = FASTCGI_SEND_ENTITY;
                            r->sock_timer = 0;
                            if (r->lenTail > 0)
                            {
                                r->cgi.p = r->tail;
                                r->cgi.len_buf = r->lenTail;
                                r->tail = NULL;
                                r->lenTail = 0;
                                
                                r->io_direct = TO_CLIENT;
                                r->sock_timer = 0;
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
                                r->io_direct = FROM_CGI;
                                r->sock_timer = 0;
                            }
                        }
                    }
                    else
                        r->sock_timer = 0;
                }
            }
        }
        else if ((r->cgi.op.fcgi == FASTCGI_SEND_ENTITY) ||
                 (r->cgi.op.fcgi == FASTCGI_READ_ERROR) ||
                 (r->cgi.op.fcgi == FASTCGI_CLOSE))
        {
            int ret = fcgi_stdout(r);
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
            else if (ret == 0)
            {
                del_from_list(r);
            }
            else
                r->sock_timer = 0;
        }
        else
        {
            print_err(r, "<%s:%d> ??? Error: FCGI_OPERATION=%s\n", __func__, __LINE__, get_fcgi_operation(r->cgi.op.fcgi));
            r->err = -1;
            del_from_list(r);
        }
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::fcgi_err(Connect *r)
{
    if (((r->cgi.op.fcgi == FASTCGI_BEGIN) || 
         (r->cgi.op.fcgi == FASTCGI_PARAMS) || 
         (r->cgi.op.fcgi == FASTCGI_STDIN)) && 
        (r->io_direct == TO_CGI))
        return -RS504;
    else if (r->cgi.op.fcgi == FASTCGI_READ_HTTP_HEADERS)
        return -RS504;
    else
        return -1;
}
//----------------------------------------------------------------------
int EventHandlerClass::read_padding(Connect *r)
{
    if (r->fcgi.paddingLen > 0)
    {
        char buf[256];

        int len = (r->fcgi.paddingLen > (int)sizeof(buf)) ? sizeof(buf) : r->fcgi.paddingLen;
        int n = read(r->fcgi.fd, buf, len);
        if (n == -1)
        {
            print_err(r, "<%s:%d> Error read from script(fd=%d): %s\n", 
                    __func__, __LINE__, r->fcgi.fd, strerror(errno));
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            else
            {
                r->err = -1;
                return -1;
            }
        }
        else if (n == 0)
        {
            r->err = -1;
            return -1;
        }
        else
        {
            r->fcgi.paddingLen -= n;
        }
    }

    if (r->fcgi.paddingLen == 0)
    {
        r->sock_timer = 0;
        r->fcgi.status = FCGI_READ_HEADER;
        r->cgi.len_buf = 0;
        r->io_direct = FROM_CGI;
    }

    return 0;
}
