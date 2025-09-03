#include "main.h"

#if defined(LINUX_)
    #include <sys/sendfile.h>
#elif defined(FREEBSD_)
    #include <sys/uio.h>
#endif

using namespace std;
//======================================================================
int create_multipart_head(Connect *req);

static EventHandlerClass *event_handler_cl;
//======================================================================
EventHandlerClass::~EventHandlerClass()
{
    print_err("<%s:%d> thread %d, all requests %lu\n", __func__, __LINE__, num_thr, num_request);
    if (work_list_start)
    {
        Connect *r = work_list_start, *next = NULL;
        for ( ; r; r = next)
        {
            next = r->next;
            close_con(r);
        }
    }

    delete [] poll_fd;
#if defined(SEND_FILE_) && (defined(LINUX_) || defined(FREEBSD_))
    if (conf->SendFile == false)
#endif
        if (snd_buf)
            delete [] snd_buf;
}
//----------------------------------------------------------------------
EventHandlerClass::EventHandlerClass()
{
    num_request = 0;
    close_thr = num_wait = num_work = cgi_work = 0;
    work_list_start = work_list_end = wait_list_start = wait_list_end = NULL;
    cgi_wait_list_start = cgi_wait_list_end = NULL;
    size_buf = conf->SndBufSize;
    snd_buf = NULL;
    
#if defined(SEND_FILE_) && (defined(LINUX_) || defined(FREEBSD_))
    if (conf->SendFile == false)
#endif
    {
        snd_buf = new (nothrow) char [size_buf];
        if (!snd_buf)
        {
            print_err("<%s:%d> Error malloc(): %s\n", __func__, __LINE__, strerror(errno));
            exit(1);
        }
    }

    poll_fd = new(nothrow) struct pollfd [conf->MaxConnectionPerThr];
    if (!poll_fd)
    {
        print_err("<%s:%d> Error malloc(): %s\n", __func__, __LINE__, strerror(errno));
        exit(1);
    }
}
//----------------------------------------------------------------------
void EventHandlerClass::init(int n)
{
    num_thr = n;
}
//----------------------------------------------------------------------
long EventHandlerClass::get_num_req()
{
    return num_request;
}
//----------------------------------------------------------------------
void EventHandlerClass::del_from_list(Connect *r)
{
    if (r->operation == DYN_PAGE)
    {
        if ((r->cgi.cgi_type == CGI) || 
            (r->cgi.cgi_type == PHPCGI))
        {
            if (r->cgi.from_script > 0)
            {
                close(r->cgi.from_script);
                r->cgi.from_script = -1;
            }

            if (r->cgi.to_script > 0)
            {
                close(r->cgi.to_script);
                r->cgi.to_script = -1;
            }

            kill_chld(r);
        }
        else if ((r->cgi.cgi_type == PHPFPM) || (r->cgi.cgi_type == FASTCGI))
        {
            if (r->cgi.fd > 0)
            {
                shutdown(r->cgi.fd, SHUT_RDWR);
                close(r->cgi.fd);
            }
        }
        else if (r->cgi.cgi_type == SCGI)
        {
            if (r->cgi.fd > 0)
            {
                shutdown(r->cgi.fd, SHUT_RDWR);
                close(r->cgi.fd);
            }
        }

        r->cgi.scriptName.clear();
        --cgi_work;
    }
    else
    {
        if ((r->source_entity == FROM_FILE) || (r->source_entity == MULTIPART_ENTITY))
            close(r->fd);
        else if (r->source_entity == FROM_DATA_BUFFER)
        {
            r->html.clear();
        }
    }

    if (r->prev && r->next)
    {
        r->prev->next = r->next;
        r->next->prev = r->prev;
    }
    else if (r->prev && !r->next)
    {
        r->prev->next = r->next;
        work_list_end = r->prev;
    }
    else if (!r->prev && r->next)
    {
        r->next->prev = r->prev;
        work_list_start = r->next;
    }
    else if (!r->prev && !r->next)
        work_list_start = work_list_end = NULL;
}
//----------------------------------------------------------------------
void EventHandlerClass::end_resp(Connect *r)
{
    del_from_list(r);
    r->headers.clear();
    end_response(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::close_con(Connect *r)
{
    del_from_list(r);
    close_connect(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::set_response(Connect *r)
{
    del_from_list(r);
    push_resp_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::add_work_list()
{
mtx_thr.lock();
    if (wait_list_start)
    {
        if (work_list_end)
            work_list_end->next = wait_list_start;
        else
            work_list_start = wait_list_start;

        wait_list_start->prev = work_list_end;
        work_list_end = wait_list_end;
        wait_list_start = wait_list_end = NULL;
    }
mtx_thr.unlock();
}
//----------------------------------------------------------------------
void EventHandlerClass::set_poll()
{
    num_work = num_wait = 0;
    time_t t = time(NULL);
    Connect *r = work_list_start, *next = NULL;
    for ( ; r; r = next)
    {
        next = r->next;

        if (r->sock_timer == 0)
            r->sock_timer = t;

        if ((t - r->sock_timer) >= r->timeout)
        {
            print_err(r, "<%s:%d> Timeout=%ld, %s\n", __func__, __LINE__, 
                        t - r->sock_timer, get_str_operation(r->operation));
            if (r->operation == DYN_PAGE)
            {
                if ((r->cgi.cgi_type == CGI) || (r->cgi.cgi_type == PHPCGI))
                    r->err = cgi_err(r);
                else if ((r->cgi.cgi_type == PHPFPM) || (r->cgi.cgi_type == FASTCGI))
                    r->err = fcgi_err(r);
                else if (r->cgi.cgi_type == SCGI)
                    r->err = scgi_err(r);
                else
                {
                    print_err(r, "<%s:%d> cgi_type=%s\n", __func__, __LINE__, get_cgi_type(r->cgi.cgi_type));
                    r->err = -1;
                }

                if (r->err == -1)
                {
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Timeout";
                }

                end_resp(r);
            }
            else
            {
                r->err = -1;
                if ((r->operation == SSL_ACCEPT) || 
                    (r->operation == SSL_SHUTDOWN))
                {
                    close_con(r);
                }
                else
                {
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Timeout";
                    end_resp(r);
                }
            }
        }
        else
        {
            if ((r->Protocol == HTTPS) && (r->io_direct == FROM_CLIENT))
            {
                int pend = SSL_pending(r->tls.ssl);
                if (pend)
                {
                    choose_worker(r);
                    continue;
                }
            }

            if (set_pollfd_array(r, &num_wait))
            {
                r->err = -1;
                end_resp(r);
            }
        }
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::poll_worker()
{
    int ret_poll = 0;
    if (num_wait > 0)
    {
        int time_poll = conf->TimeoutPoll;
        if (num_work > 0)
            time_poll = 0;
        ret_poll = poll(poll_fd, num_wait, time_poll);
        if (ret_poll == -1)
        {
            print_err("<%s:%d> Error poll(): %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
        else if (ret_poll == 0)
        {
            if (num_work == 0)
                return 0;
        }
    }
    else
    {
        if (num_work == 0)
            return 0;
    }

    int i = 0, all = ret_poll + num_work, n = 0;
    Connect *r = work_list_start, *next = NULL;
    for ( ; (n < all) && r; r = next)
    {
        next = r->next;

        if (poll_fd[i].revents & POLLIN)
        {
            ++n;
            choose_worker(r);
        }
        else if (poll_fd[i].revents == POLLOUT)
        {
            ++n;
            choose_worker(r);
        }
        else if (poll_fd[i].revents)
        {
            ++n;
            if (r->operation == DYN_PAGE)
            {
                if (poll_fd[i].fd == r->clientSocket)
                {
                    print_err(r, "<%s:%d> Error: fd=%d, events=0x%x(0x%x), send_bytes=%lld\n", 
                            __func__, __LINE__, r->clientSocket, poll_fd[i].events, poll_fd[i].revents, r->send_bytes);
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                    r->err = -1;
                    end_resp(r);
                }
                else
                {
                    switch (r->cgi.cgi_type)
                    {
                        case CGI:
                        case PHPCGI:
                            if ((r->cgi.op == CGI_STDOUT) && (r->io_direct == FROM_CGI))
                            {
                                if (r->mode_send == CHUNK)
                                {
                                    r->cgi.len_buf = 0;
                                    r->cgi.p = r->cgi.buf + 8;
                                    cgi_set_size_chunk(r);
                                    r->io_direct = TO_CLIENT;
                                    r->mode_send = CHUNK_END;
                                    r->sock_timer = 0;
                                }
                                else
                                {
                                    end_resp(r);
                                }
                            }
                            else
                            {
                                print_err(r, "<%s:%d> Error: events=0x%x(0x%x), %s/%s\n", __func__, __LINE__, 
                                       poll_fd[i].events, poll_fd[i].revents, get_cgi_operation(r->cgi.op), get_cgi_dir(r->io_direct));
                                if (r->cgi.op <= CGI_READ_HTTP_HEADERS)
                                    r->err = -RS502;
                                else
                                    r->err = -1;
                                end_resp(r);
                            }
                            break;
                        case PHPFPM:
                        case FASTCGI:
                            print_err(r, "<%s:%d> Error: events=0x%x(0x%x); %s\n", __func__, __LINE__, 
                                    poll_fd[i].events, poll_fd[i].revents, get_cgi_operation(r->cgi.op));
                            if (r->cgi.op < CGI_STDOUT)
                                r->err = -RS502;
                            else
                                r->err = -1;
                            end_resp(r);
                            break;
                        case SCGI:
                            if ((r->cgi.op == CGI_STDOUT) && (r->io_direct == FROM_CGI))
                            {
                                if (r->mode_send == CHUNK)
                                {
                                    r->cgi.len_buf = 0;
                                    r->cgi.p = r->cgi.buf + 8;
                                    cgi_set_size_chunk(r);
                                    r->io_direct = TO_CLIENT;
                                    r->mode_send = CHUNK_END;
                                    r->sock_timer = 0;
                                }
                                else
                                {
                                    end_resp(r);
                                }
                            }
                            else
                            {
                                print_err(r, "<%s:%d> Error: events=0x%x(0x%x), %s\n", __func__, __LINE__,
                                        poll_fd[i].events, poll_fd[i].revents, get_cgi_operation(r->cgi.op));
                                if (r->cgi.op <= CGI_READ_HTTP_HEADERS)
                                    r->err = -RS502;
                                else
                                    r->err = -1;
                                end_resp(r);
                            }
                            break;
                        default:
                            print_err(r, "<%s:%d> ??? Error: CGI_TYPE=%s\n", __func__, __LINE__, get_cgi_type(r->cgi.cgi_type));
                            r->err = -1;
                            end_resp(r);
                            break;
                    }
                }
            }
            else
            {
                print_err(r, "<%s:%d> Error: events=0x%x(0x%x)\n", __func__, __LINE__, poll_fd[i].events, poll_fd[i].revents);
                r->err = -1;
                if ((r->operation == SSL_ACCEPT) || 
                    (r->operation == SSL_SHUTDOWN))
                {
                    close_con(r);
                }
                else
                {
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                    end_resp(r);
                }
            }
        }
        ++i;
    }

    return i;
}
//----------------------------------------------------------------------
int EventHandlerClass::wait_conn()
{
    {
    unique_lock<mutex> lk(mtx_thr);
        while ((!work_list_start) && (!wait_list_start) && (!cgi_wait_list_start) && (!close_thr))
        {
            cond_thr.wait(lk);
        }
    }

    if (close_thr)
        return 1;
    return 0;
}
//----------------------------------------------------------------------
void EventHandlerClass::push_cgi(Connect *r)
{
    r->operation = DYN_PAGE;
    r->respStatus = RS200;
    r->sock_timer = 0;
    r->cgi.pid = -1;
    r->prev = NULL;
mtx_cgi.lock();
    r->next = cgi_wait_list_start;
    if (cgi_wait_list_start)
        cgi_wait_list_start->prev = r;
    cgi_wait_list_start = r;
    if (!cgi_wait_list_end)
        cgi_wait_list_end = r;
mtx_cgi.unlock();
    cond_thr.notify_one();
}
//----------------------------------------------------------------------
void EventHandlerClass::add_wait_list(Connect *r)
{
    r->sock_timer = 0;
    r->next = NULL;
mtx_thr.lock();
    r->prev = wait_list_end;
    if (wait_list_start)
    {
        wait_list_end->next = r;
        wait_list_end = r;
    }
    else
        wait_list_start = wait_list_end = r;
mtx_thr.unlock();
    cond_thr.notify_one();
}
//----------------------------------------------------------------------
void EventHandlerClass::push_send_file(Connect *r)
{
    r->io_direct = TO_CLIENT;
    r->source_entity = FROM_FILE;
    r->operation = SEND_RESP_HEADERS;
    lseek(r->fd, r->offset, SEEK_SET);
    add_wait_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::push_pollin_list(Connect *r)
{
    r->io_direct = FROM_CLIENT;
    r->source_entity = NO_ENTITY;
    add_wait_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::push_send_multipart(Connect *r)
{
    r->io_direct = TO_CLIENT;
    r->source_entity = MULTIPART_ENTITY;
    r->operation = SEND_RESP_HEADERS;
    add_wait_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::push_send_html(Connect *r)
{
    r->io_direct = TO_CLIENT;
    r->operation = SEND_RESP_HEADERS;
    r->source_entity = FROM_DATA_BUFFER;
    add_wait_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::push_ssl_shutdown(Connect *r)
{
    r->operation = SSL_SHUTDOWN;
    r->source_entity = NO_ENTITY;
    add_wait_list(r);
}
//----------------------------------------------------------------------
void EventHandlerClass::close_event_handler()
{
    close_thr = 1;
    cond_thr.notify_one();
}
//----------------------------------------------------------------------
int EventHandlerClass::send_html(Connect *r)
{
    if (r->html.size_remain() == 0)
        return 0;
    int ret = write_to_client(r, r->html.ptr_remain(), r->html.size_remain());
    if (ret < 0)
    {
        if (ret == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        return -1;
    }

    r->html.set_offset(ret);
    r->send_bytes += ret;
    if (r->html.size_remain() == 0)
        ret = 0;

    return ret;
}
//----------------------------------------------------------------------
void EventHandlerClass::set_part(Connect *r)
{
    if ((r->multipart.rg = r->rg.get()))
    {
        r->multipart.status = SEND_HEADERS;
        r->offset = r->multipart.rg->start;
        r->respContentLength = r->multipart.rg->len;
        lseek(r->fd, r->offset, SEEK_SET);
    }
    else
    {
        r->multipart.status = SEND_END;
        r->multipart.hdr = "";
        r->multipart.hdr << "\r\n--" << boundary << "--\r\n";
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::send_headers(Connect *r)
{
    int wr = write_to_client(r, r->headers.ptr_remain(), r->headers.size_remain());
    if (wr < 0)
    {
        if (wr == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        else
        {
            r->err = -1;
            r->req_hd.iReferer = MAX_HEADERS - 1;
            r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
            end_resp(r);
            return -1;
        }
    }
    else if (wr > 0)
    {
        r->headers.set_offset(wr);
        r->sock_timer = 0;
    }

    return wr;
}
//----------------------------------------------------------------------
void EventHandlerClass::choose_worker(Connect *r)
{
    if (r->operation == DYN_PAGE)
    {
        if ((r->cgi.cgi_type == CGI) || (r->cgi.cgi_type == PHPCGI))
        {
            cgi_worker(r);
        }
        else if ((r->cgi.cgi_type == PHPFPM) || (r->cgi.cgi_type == FASTCGI))
        {
            fcgi_worker(r);
        }
        else if (r->cgi.cgi_type == SCGI)
        {
            scgi_worker(r);
        }
    }
    else
    {
        worker(r);
    }
}
//----------------------------------------------------------------------
void EventHandlerClass::worker(Connect *r)
{
    if (r->operation == SEND_ENTITY)
    {
        if (r->source_entity == FROM_FILE)
        {
            int wr = send_part_file(r);
            if (wr < 0)
            {
                if (wr != ERR_TRY_AGAIN)
                {
                    r->err = -1;
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                    end_resp(r);
                }
            }
            else if (wr == 0)
            {
                end_resp(r);
            }
            else // (wr > 0)
                r->sock_timer = 0;
        }
        else if (r->source_entity == MULTIPART_ENTITY)
        {
            if (r->multipart.status == SEND_HEADERS)
            {
                int wr = send_headers(r);
                if (wr > 0)
                {
                    r->send_bytes += wr;
                    if (r->headers.size_remain() == 0)
                        r->multipart.status = SEND_PART;
                }
            }
            else if (r->multipart.status == SEND_PART)
            {
                int wr = send_part_file(r);
                if (wr < 0)
                {
                    if (wr != ERR_TRY_AGAIN)
                    {
                        r->err = wr;
                        r->req_hd.iReferer = MAX_HEADERS - 1;
                        r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                        end_resp(r);
                    }
                }
                else if (wr == 0)
                {
                    r->sock_timer = 0;
                    set_part(r);
                }
                else
                    r->sock_timer = 0;
            }
            else if (r->multipart.status == SEND_END)
            {
                int wr = send_headers(r);
                if (wr > 0)
                {
                    r->send_bytes += wr;
                    if (r->headers.size_remain() == 0)
                    {
                        end_resp(r);
                    }
                }
            }
        }
        else if (r->source_entity == FROM_DATA_BUFFER)
        {
            int wr = send_html(r);
            if (wr < 0)
            {
                if (wr != ERR_TRY_AGAIN)
                {
                    r->err = -1;
                    r->req_hd.iReferer = MAX_HEADERS - 1;
                    r->reqHdValue[r->req_hd.iReferer] = "Connection reset by peer";
                    end_resp(r);
                }
            }
            else if (wr == 0)
            {
                end_resp(r);
            }
            else
                r->sock_timer = 0;
        }
    }
    else if (r->operation == SEND_RESP_HEADERS)
    {
        int wr = send_headers(r);
        if (wr > 0)
        {
            if (r->headers.size_remain() == 0)
            {
                if (r->reqMethod == M_HEAD)
                {
                    end_resp(r);
                }
                else
                {
                    if (r->source_entity == FROM_DATA_BUFFER)
                    {
                        if (r->html.size_remain() == 0)
                        {
                            end_resp(r);
                        }
                        else
                            r->operation = SEND_ENTITY;
                    }
                    else if (r->source_entity == FROM_FILE)
                    {
                        r->operation = SEND_ENTITY;
                    }
                    else if (r->source_entity == MULTIPART_ENTITY)
                    {
                        r->operation = SEND_ENTITY;
                        set_part(r);
                    }
                }
            }
        }
    }
    else if (r->operation == READ_REQUEST)
    {
        int ret = read_request_headers(r);
        if (ret < 0)
        {
            if (ret != ERR_TRY_AGAIN)
            {
                r->err = ret;
                end_resp(r);
            }
        }
        else if (ret > 0)
        {
            num_request++;
            set_response(r);
        }
        else
        {
            r->timeout = conf->Timeout;
            r->sock_timer = 0;
        }
    }
    else if (r->operation == SSL_ACCEPT)
    {
        int ret = SSL_accept(r->tls.ssl);
        if (ret < 1)
        {
            r->tls.err = SSL_get_error(r->tls.ssl, ret);
            if (r->tls.err == SSL_ERROR_WANT_READ)
            {
                //print_err(r, "<%s:%d> SSL_accept()=%d: %s\n", __func__, __LINE__, ret, ssl_strerror(r->tls.err));
                r->io_direct = FROM_CLIENT;
            }
            else if (r->tls.err == SSL_ERROR_WANT_WRITE)
            {
                print_err(r, "<%s:%d> SSL_accept()=%d: %s\n", __func__, __LINE__, ret, ssl_strerror(r->tls.err));
                r->io_direct = TO_CLIENT;
            }
            else
            {
                print_err(r, "<%s:%d> Error SSL_accept(): %s\n", __func__, __LINE__, ssl_strerror(r->tls.err));
                close_con(r);
            }
        }
        else
        {
            r->operation = READ_REQUEST;
            r->io_direct = FROM_CLIENT;
            r->sock_timer = 0;
        }
    }
    else if (r->operation == SSL_SHUTDOWN)
    {
        char buf[256];
        int err = SSL_read(r->tls.ssl, buf, sizeof(buf));
        if (err <= 0)
        {
            r->tls.err = SSL_get_error(r->tls.ssl, err);
            //print_err(r, "<%s:%d> SSL_SHUTDOWN: Error SSL_read(): %s\n", __func__, __LINE__, ssl_strerror(r->tls.err));
            if (r->tls.err == SSL_ERROR_WANT_READ)
            {
                r->io_direct = FROM_CLIENT;
            }
            else if (r->tls.err == SSL_ERROR_WANT_WRITE)
            {
                r->io_direct = TO_CLIENT;
            }
            else
            {
                close_con(r);
            }
        }
        else
        {
            print_err(r, "<%s:%d> SSL_SHUTDOWN: SSL_read()=%d\n", __func__, __LINE__, err);
            r->sock_timer = 0;
        }
    }
    else
    {
        print_err(r, "<%s:%d> ? operation=%s\n", __func__, __LINE__, get_str_operation(r->operation));
        r->err = -1;
        end_resp(r);
    }
}
//----------------------------------------------------------------------
int EventHandlerClass::set_pollfd_array(Connect *r, int *i)
{
    if (r->io_direct == FROM_CLIENT)
    {
        if (r->operation != READ_REQUEST)
            r->timeout = conf->Timeout;
        poll_fd[*i].fd = r->clientSocket;
        poll_fd[*i].events = POLLIN;
    }
    else if (r->io_direct == TO_CLIENT)
    {
        r->timeout = conf->Timeout;
        poll_fd[*i].fd = r->clientSocket;
        poll_fd[*i].events = POLLOUT;
    }
    else if (r->io_direct == FROM_CGI)
    {
        switch (r->cgi.cgi_type)
        {
            case CGI:
            case PHPCGI:
                poll_fd[*i].fd = r->cgi.from_script;
                break;
            case PHPFPM:
            case FASTCGI:
            case SCGI:
                poll_fd[*i].fd = r->cgi.fd;
                break;
            case NO_CGI:
                print_err(r, "<%s:%d> Error: NO_CGI ?\n", __func__, __LINE__);
                return -1;
        }
        poll_fd[*i].events = POLLIN;
        r->timeout = conf->TimeoutCGI;
    }
    else if (r->io_direct == TO_CGI)
    {
        switch (r->cgi.cgi_type)
        {
            case CGI:
            case PHPCGI:
                poll_fd[*i].fd = r->cgi.to_script;
                break;
            case PHPFPM:
            case FASTCGI:
            case SCGI:
                poll_fd[*i].fd = r->cgi.fd;
                break;
            case NO_CGI:
                print_err(r, "<%s:%d> Error: NO_CGI ?\n", __func__, __LINE__);
                return -1;
        }
        poll_fd[*i].events = POLLOUT;
        r->timeout = conf->TimeoutCGI;
    }
    else
    {
        print_err(r, "<%s:%d> Error: io_direct=%d\n", __func__, __LINE__, r->io_direct);
        return -1;
    }

    (*i)++;

    return 0;
}
//----------------------------------------------------------------------
int EventHandlerClass::send_part_file(Connect *req)
{
    int rd, wr, len;
    errno = 0;

    if (req->respContentLength == 0)
        return 0;
#if defined(SEND_FILE_) && (defined(LINUX_) || defined(FREEBSD_))
    if (conf->SendFile)
    {
        if (req->respContentLength >= size_buf)
            len = size_buf;
        else
            len = req->respContentLength;
    #if defined(LINUX_)
        wr = sendfile(req->clientSocket, req->fd, &req->offset, len);
        if (wr == -1)
        {
            //print_err(req, "<%s:%d> Error sendfile(): %s\n", __func__, __LINE__, strerror(errno));
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            print_err(req, "<%s:%d> Error sendfile(): %s\n", __func__, __LINE__, strerror(errno));
            return wr;
        }
    #elif defined(FREEBSD_)
        off_t wr_bytes;
        int ret = sendfile(req->fd, req->clientSocket, req->offset, len, NULL, &wr_bytes, 0);
        if (ret == -1)
        {
            if (errno == EAGAIN)
            {
                if (wr_bytes == 0)
                    return ERR_TRY_AGAIN;
                req->offset += wr_bytes;
                wr = wr_bytes;
            }
            else
            {
                print_err(req, "<%s:%d> Error sendfile(): %s\n", __func__, __LINE__, strerror(errno));
                return -1;
            }
        }
        else if (ret == 0)
        {
            req->offset += wr_bytes;
            wr = wr_bytes;
        }
        else
        {
            print_err(req, "<%s:%d> Error sendfile()=%d, wr_bytes=%ld\n", __func__, __LINE__, ret, wr_bytes);
            return -1;
        }
    #endif
    }
    else
#endif
    {
        if (req->respContentLength >= size_buf)
            len = size_buf;
        else
            len = req->respContentLength;

        rd = read(req->fd, snd_buf, len);
        if (rd <= 0)
        {
            if (rd == -1)
                print_err(req, "<%s:%d> Error read(): %s\n", __func__, __LINE__, strerror(errno));
            return rd;
        }

        wr = write_to_client(req, snd_buf, rd);
        if (wr < 0)
        {
            if (wr == ERR_TRY_AGAIN)
            {
                lseek(req->fd, -rd, SEEK_CUR);
                return ERR_TRY_AGAIN;
            }

            return wr;
        }
        else if (rd != wr)
            lseek(req->fd, wr - rd, SEEK_CUR);
    }

    req->send_bytes += wr;
    req->respContentLength -= wr;
    if (req->respContentLength == 0)
        wr = 0;

    return wr;
}
//======================================================================
void event_handler(int n_thr)
{
    event_handler_cl[n_thr].init(n_thr);
printf(" +++++ worker thread %d run +++++\n", n_thr);
    while (1)
    {
        if (event_handler_cl[n_thr].wait_conn())
            break;

        event_handler_cl[n_thr].cgi_add_work_list();
        event_handler_cl[n_thr].add_work_list();
        event_handler_cl[n_thr].set_poll();
        if (event_handler_cl[n_thr].poll_worker() < 0)
            break;
    }

    print_err("<%s:%d> ***** exit thread %d *****\n", __func__, __LINE__, n_thr);
}
//======================================================================
void push_pollin_list(Connect *r)
{
    event_handler_cl[r->numThr].push_pollin_list(r);
}
//======================================================================
void push_cgi(Connect *r)
{
    event_handler_cl[r->numThr].push_cgi(r);
}
//======================================================================
void push_send_file(Connect *r)
{
    event_handler_cl[r->numThr].push_send_file(r);
}
//======================================================================
void push_send_multipart(Connect *r)
{
    event_handler_cl[r->numThr].push_send_multipart(r);
}
//======================================================================
void push_send_html(Connect *r)
{
    event_handler_cl[r->numThr].push_send_html(r);
}
//======================================================================
void push_ssl_shutdown(Connect *r)
{
    event_handler_cl[r->numThr].push_ssl_shutdown(r);
}
//======================================================================
int event_handler_cl_new()
{
    event_handler_cl = new(nothrow) EventHandlerClass [conf->NumWorkThreads];
    if (!event_handler_cl)
    {
        print_err("<%s:%d> Error create array EventHandlerClass: %s\n", __func__, __LINE__, strerror(errno));
        return -1;
    }

    return 0;
}
//======================================================================
void event_handler_cl_delete()
{
    if (event_handler_cl)
        delete [] event_handler_cl;
}
//======================================================================
void close_work_threads()
{
    for (int i = 0; i < conf->NumWorkThreads; ++i)
    {
        event_handler_cl[i].close_event_handler();
    }
}
