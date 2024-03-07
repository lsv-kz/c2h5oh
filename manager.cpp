#include "main.h"

using namespace std;
//======================================================================
static mutex mtx_conn;
static condition_variable cond_close_conn;

static int num_conn, close_server;
static int *conn_count;
//======================================================================
int get_light_thread_number()
{
    int n_thr = 0, n_conn;
mtx_conn.lock();
    if (conf->BalancedWorkThreads == 'y')
    {
        n_conn = conn_count[0];
        for (int i = 1; i < conf->NumWorkThreads; ++i)
        {
            if (n_conn > conn_count[i])
            {
                n_thr = i;
                n_conn = conn_count[i];
            }
        }

        if (conn_count[n_thr] >= conf->MaxConnectionPerThr)
        {
            print_err("<%s:%d> !!!!!\n", __func__, __LINE__);
            n_thr = -1;
        }
    }
    else
    {
        n_thr = -1;
        for (int i = 0; i < conf->NumWorkThreads; ++i)
        {
            if (conn_count[i] < conf->MaxConnectionPerThr)
            {
                n_thr = i;
                break;
            }
        }
    }

mtx_conn.unlock();
    return n_thr;
}
//======================================================================
void start_conn(int n)
{
mtx_conn.lock();
    conn_count[n]++;
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
int is_maxconn()
{
unique_lock<mutex> lk(mtx_conn);
    while ((num_conn >= conf->MaxAcceptConnections) && (!close_server))
    {
        cond_close_conn.wait(lk);
    }

    return close_server;
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
    int n = req->numThr;
    delete req;

mtx_conn.lock();
    conn_count[n]--;
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
            //#elif defined(FREEBSD_)
            #else
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
        //#elif defined(FREEBSD_)
        #else
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
unsigned long get_all_request();
Connect *create_req();
int event_handler_cl_new();
void event_handler_cl_delete();
void close_threads_manager();
void threads_manager();
int get_max_thr();
//======================================================================
void manager(int sockServer)
{
    unsigned long allConn = 0;
    num_conn = close_server = 0;
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
    
    conn_count = new(nothrow) int [conf->NumWorkThreads];
    if (!conn_count)
    {
        print_err("<%s:%d> Error create array conn_count: %s\n", __func__, __LINE__, strerror(errno));
        event_handler_cl_delete();
        exit(1);
    }

    memset(conn_count, 0, sizeof(int) * conf->NumWorkThreads);
    //------------------------------------------------------------------
    thread thr;
    try
    {
        thr = thread(threads_manager);
    }
    catch (...)
    {
        print_err("<%s:%d> Error create thread: errno=%d\n", __func__, __LINE__, errno);
        exit(errno);
    }
    //------------------------------------------------------------------
    printf(" +++++ pid=%u, uid=%u, gid=%u +++++\n",
                                getpid(), getuid(), getgid());
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

        if (is_maxconn())
            break;

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
            if ((errno == EINTR) || (errno == EMFILE) || (errno == ENFILE))
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
/*
        int opt = 10000000;  
        int optlen = sizeof(opt);
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (void *)&opt, optlen);
*/
        int flags = 1;
        if (ioctl(clientSocket, FIONBIO, &flags) == -1)
        {
            print_err("<%s:%d> Error ioctl(FIONBIO, 1): %s\n", __func__, __LINE__, strerror(errno));
            break;
        }

        if (ioctl(clientSocket, FIOCLEX) == -1)
        {
            print_err("<%s:%d> Error ioctl(FIOCLEX): %s\n", __func__, __LINE__, strerror(errno));
            break;
        }
/*
        flags = fcntl(clientSocket, F_GETFD);
        if (flags == -1)
        {
            print_err("<%s:%d> Error fcntl(F_GETFD): %s\n", __func__, __LINE__, strerror(errno));
            break;
        }

        flags |= FD_CLOEXEC;
        if (fcntl(clientSocket, F_SETFD, flags) == -1)
        {
            print_err("<%s:%d> Error fcntl(F_SETFD, FD_CLOEXEC): %s\n", __func__, __LINE__, strerror(errno));
            break;
        }
*/
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

        start_conn(req->numThr);
        push_pollin_list(req);
    }

    close_work_threads();
    for (int i = 0; i < conf->NumWorkThreads; ++i)
    {
        work_thr[i].join();
    }

    delete [] work_thr;
    event_handler_cl_delete();
    delete [] conn_count;

    print_err("<%s:%d> all_conn=%lu, all_req=%lu; open_conn=%d, max_thr=%d\n",
                    __func__, __LINE__, allConn, get_all_request(), num_conn, get_max_thr());
    close_threads_manager();
    thr.join();

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
//======================================================================
void server_stop()
{
    {
    lock_guard<mutex> lk(mtx_conn);
        close_server = 1;
    }

    cond_close_conn.notify_all();
}
