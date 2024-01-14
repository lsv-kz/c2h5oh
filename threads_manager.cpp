#include "main.h"
#include <sys/select.h>

using namespace std;
//======================================================================
static mutex mtx_conn;
static condition_variable cond_close_conn;
static int num_conn;
//======================================================================
void start_conn()
{
mtx_conn.lock();
    ++num_conn;
mtx_conn.unlock();
}
//======================================================================
void wait_close_all_conn()
{
unique_lock<mutex> lk(mtx_conn);
    while (num_conn > 0)
    {
        cond_close_conn.wait(lk);
    }
}
//======================================================================
void is_maxconn()
{
unique_lock<mutex> lk(mtx_conn);
    while (num_conn >= conf->MaxAcceptConnections)
    {
        cond_close_conn.wait(lk);
    }
}
//======================================================================
void close_connect(Connect *req)
{
    if ((req->Protocol == HTTPS) && (req->tls.ssl))
    {
        SSL_free(req->tls.ssl);
    }

    shutdown(req->clientSocket, SHUT_RDWR);
    close(req->clientSocket);
    int ret = req->numThr;
    delete req;
    conn_decrement(ret);

mtx_conn.lock();
    --num_conn;
mtx_conn.unlock();
    cond_close_conn.notify_all();
}
//======================================================================
void end_response(Connect *r)
{
    if ((r->connKeepAlive == 0) || r->err < 0)
    { // ----- Close connect -----
        if (r->err <= -RS101) // err < -100
        {
            r->respStatus = -r->err;
            r->err = 0;
            r->hdrs = "";
            if (send_message(r, NULL) == 1)
                return;
        }

        if ((r->operation != SSL_ACCEPT) && 
            (r->operation != READ_REQUEST))
        {
            print_log(r);
        }
        
        if ((r->Protocol == HTTPS) && (r->tls.ssl))
        {
    #ifdef TCP_CORK_
            if (conf->TcpCork == 'y')
            {
            #if defined(LINUX_)
                int optval = 0;
                setsockopt(r->clientSocket, SOL_TCP, TCP_CORK, &optval, sizeof(optval));
            #elif defined(FREEBSD_)
                int optval = 0;
                setsockopt(r->clientSocket, IPPROTO_TCP, TCP_NOPUSH, &optval, sizeof(optval));
            #endif
            }
    #endif
            if ((r->tls.err != SSL_ERROR_SSL) && 
                (r->tls.err != SSL_ERROR_SYSCALL))
            {
                int ret = SSL_shutdown(r->tls.ssl);
                if (ret == -1)
                {
                    r->tls.err = SSL_get_error(r->tls.ssl, ret);
                    print_err(r, "<%s:%d> Error SSL_shutdown()=%d, err=%s\n", __func__, __LINE__, ret, ssl_strerror(r->tls.err));
                    if (r->tls.err == SSL_ERROR_ZERO_RETURN)
                    {
                        close_connect(r);
                        return;
                    }
                    else if (r->tls.err == SSL_ERROR_WANT_READ)
                    {
                        r->io_status = WAIT;
                        r->io_direct = FROM_CLIENT;
                        push_ssl_shutdown(r);
                        return;
                    }
                    else if (r->tls.err == SSL_ERROR_WANT_WRITE)
                    {
                        r->io_status = WAIT;
                        r->io_direct = TO_CLIENT;
                        push_ssl_shutdown(r);
                        return;
                    }
                }
                else if (ret == 0)
                {
                    r->io_status = WORK;
                    push_ssl_shutdown(r);
                    return;
                }
            }
            else
            {
                print_err(r, "<%s:%d> tls.err: %s\n", __func__, __LINE__, ssl_strerror(r->tls.err));
            }
        }

        close_connect(r);
    }
    else
    { // ----- KeepAlive -----
    #ifdef TCP_CORK_
        if (conf->TcpCork == 'y')
        {
        #if defined(LINUX_)
            int optval = 0;
            setsockopt(r->clientSocket, SOL_TCP, TCP_CORK, &optval, sizeof(optval));
        #elif defined(FREEBSD_)
            int optval = 0;
            setsockopt(r->clientSocket, IPPROTO_TCP, TCP_NOPUSH, &optval, sizeof(optval));
        #endif
        }
    #endif
        print_log(r);
        r->init();
        r->timeout = conf->TimeoutKeepAlive;
        ++r->numReq;
        r->operation = READ_REQUEST;
        push_pollin_list(r);
    }
}
//======================================================================
unsigned long allConn = 0;
unsigned long get_all_request();
Connect *create_req();
int event_handler_cl_new();
void event_handler_cl_delete();
void close_parse_req_threads();
void list_init();
//======================================================================
void manager(int sockServer)
{
    num_conn = 0;
    list_init();
    //------------------------------------------------------------------
    if (chdir(conf->DocumentRoot.c_str()))
    {
        print_err("<%s:%d> Error chdir(%s): %s\n", __func__, __LINE__, conf->DocumentRoot.c_str(), strerror(errno));
        exit(EXIT_FAILURE);
    }
    //------------------------------------------------------------------
    if (event_handler_cl_new())
    {
        exit(1);
    }
    //------------------------------------------------------------------
    int n = 0;
    while (n < conf->NumParseReqThreads)
    {
        thread t;
        try
        {
            t = thread(parse_request_thread);
            t.detach();
        }
        catch (...)
        {
            print_err("<%s:%d> Error create thread: errno=%d\n", __func__, __LINE__, errno);
            exit(errno);
        }

        ++n;
    }
    //------------------------------------------------------------------
    printf(" +++++ num threads=%u, pid=%u, uid=%u, gid=%u +++++\n",
                                n, getpid(), getuid(), getgid());
    //------------------------------------------------------------------
    thread *work_thr = new(nothrow) thread [conf->NumWorkThreads];
    if (!work_thr)
    {
        print_err("<%s:%d> Error create array thread: %s\n", __func__, __LINE__, strerror(errno));
        exit(errno);
    }

    for (int i = 0; i < conf->NumWorkThreads; ++i)
    {
        try
        {
            work_thr[i] = thread(event_handler, i);
        }
        catch (...)
        {
            print_err("<%s:%d> Error create thread(event_handler): errno=%d\n", __func__, __LINE__, errno);
            exit(errno);
        }
    }
    //------------------------------------------------------------------
    int run = 1;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockServer, &readfds);

    while (run)
    {
        struct sockaddr_storage clientAddr;
        socklen_t addrSize = sizeof(struct sockaddr_storage);

        is_maxconn();

        FD_SET(sockServer, &readfds);
        int ret_sel = select(sockServer + 1, &readfds, NULL, NULL, NULL);
        if (ret_sel <= 0)
        {
            print_err("<%s:%d> Error select()=%d: %s\n", __func__, __LINE__, ret_sel, strerror(errno));
            break;
        }

        if (!FD_ISSET(sockServer, &readfds))
            break;
        int clientSocket = accept(sockServer, (struct sockaddr *)&clientAddr, &addrSize);
        if (clientSocket == -1)
        {
            print_err("<%s:%d>  Error accept(): %s\n", __func__, __LINE__, strerror(errno));
            if ((errno == EINTR) || (errno == EMFILE))
                continue;
            break;
        }

        Connect *req;
        req = create_req();
        if (!req)
        {
            shutdown(clientSocket, SHUT_RDWR);
            close(clientSocket);
            continue;
        }

        int opt = 1;
        ioctl(clientSocket, FIONBIO, &opt);

        req->init();
        req->Time = time(NULL);
        req->numThr = get_light_thread_number();
        if (req->numThr < 0)
        {
            print_err("<%s:%d> Error get_light_thread_number()\n", __func__, __LINE__);
            shutdown(clientSocket, SHUT_RDWR);
            close(clientSocket);
            delete req;
            continue;
        }

        req->numConn = ++allConn;
        req->numReq = 1;
        req->Protocol = conf->Protocol;
        req->serverSocket = sockServer;
        req->clientSocket = clientSocket;
        req->timeout = conf->Timeout;

        int err;
        if ((err = getnameinfo((struct sockaddr *)&clientAddr,
                addrSize,
                req->remoteAddr,
                sizeof(req->remoteAddr),
                req->remotePort,
                sizeof(req->remotePort),
                NI_NUMERICHOST | NI_NUMERICSERV)))
        {
            print_err(req, "<%s:%d> Error getnameinfo()=%d: %s\n", __func__, __LINE__, err, gai_strerror(err));
            req->remoteAddr[0] = 0;
        }
        
        if (req->Protocol == HTTPS)
        {
            req->tls.err = 0;
            req->tls.ssl = SSL_new(conf->ctx);
            if (!req->tls.ssl)
            {
                print_err(req, "<%s:%d> Error SSL_new()\n", __func__, __LINE__);
                shutdown(clientSocket, SHUT_RDWR);
                close(clientSocket);
                delete req;
                break;
            }

            int ret = SSL_set_fd(req->tls.ssl, req->clientSocket);
            if (ret == 0)
            {
                req->tls.err = SSL_get_error(req->tls.ssl, ret);
                print_err(req, "<%s:%d> Error SSL_set_fd(): %s\n", __func__, __LINE__, ssl_strerror(req->tls.err));
                SSL_free(req->tls.ssl);
                shutdown(clientSocket, SHUT_RDWR);
                close(clientSocket);
                delete req;
                continue;
            }

            req->operation = SSL_ACCEPT;
        }
        else
        {
            req->operation = READ_REQUEST;
        }

        start_conn();
        push_pollin_list(req);
    }

    close_work_threads();
    for (int i = 0; i < conf->NumWorkThreads; ++i)
    {
        work_thr[i].join();
    }

    if (work_thr)
        delete [] work_thr;
    event_handler_cl_delete();

    print_err("<%s:%d> all_conn=%lu, all_req=%lu; open_conn=%d\n",
                    __func__, __LINE__, allConn, get_all_request(), num_conn);
    close_parse_req_threads();

    usleep(100000);
}
//======================================================================
Connect *create_req(void)
{
    Connect *req = new(nothrow) Connect;
    if (!req)
        print_err("<%s:%d> Error malloc(): %s\n", __func__, __LINE__, strerror(errno));
    return req;
}
