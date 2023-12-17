#include "main.h"
#include <sys/select.h>

using namespace std;

int fcgi_in_ = 0, fcgi_out_ = 0;
//======================================================================
static mutex mtx_conn;
static condition_variable cond_close_conn;
static int num_conn = 0;
//======================================================================
RequestManager::RequestManager()
{
    list_start = list_end = NULL;
    all_req = stop_manager = 0;
}
//----------------------------------------------------------------------
RequestManager::~RequestManager() {}
//----------------------------------------------------------------------
void RequestManager::push_resp_list(Connect *req)
{
mtx_list.lock();
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
mtx_list.unlock();
    cond_list.notify_one();
}
//----------------------------------------------------------------------
Connect *RequestManager::pop_resp_list()
{
unique_lock<mutex> lk(mtx_list);
    while ((list_start == NULL) && !stop_manager)
    {
        cond_list.wait(lk);
    }
    if (stop_manager)
        return NULL;

    Connect *req = list_start;
    if (list_start->next)
    {
        list_start->next->prev = NULL;
        list_start = list_start->next;
    }
    else
        list_start = list_end = NULL;

    return req;
}
//----------------------------------------------------------------------
void RequestManager::close_manager()
{
    stop_manager = 1;
    cond_list.notify_all();
}
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
static RequestManager *ReqMan;
//======================================================================
void push_resp_list(Connect *r)
{
    ReqMan->push_resp_list(r);
}
//----------------------------------------------------------------------
Connect *pop_resp_list()
{
    return ReqMan->pop_resp_list();
}
//======================================================================
unsigned long allConn = 0;
void print_num_conn();
//======================================================================
static void signal_handler_child(int sig)
{
    if (sig == SIGINT)
    {
        print_err("<%s:%d> ### SIGINT ### all_conn=%u, open_conn=%d, all_req=%d\n", 
                    __func__, __LINE__, allConn, num_conn, ReqMan->get_all_request());
        print_num_conn();
    }
    else if (sig == SIGTERM)
    {
        print_err("<%s:%d> ####### SIGTERM #######\n", __func__, __LINE__);
        exit(0);
    }
    else if (sig == SIGSEGV)
    {
        print_err("<%s:%d> ### SIGSEGV ###\n", __func__, __LINE__);
        exit(1);
    }
    else if (sig == SIGUSR1)
    {
        print_err("<%s:%d> ### SIGUSR1 ###\n", __func__, __LINE__);
    }
    else if (sig == SIGUSR2)
    {
        print_err("<%s:%d> ### SIGUSR2 ###\n", __func__, __LINE__);
    }
    else
        print_err("<%s:%d> sig=%d\n", __func__, __LINE__, sig);
}
//======================================================================
Connect *create_req(void);
int event_handler_cl_new();
void event_handler_cl_delete();
//======================================================================
void manager(int sockServer)
{
    ReqMan = new(nothrow) RequestManager;
    if (!ReqMan)
    {
        print_err("<%s:%d> *********** Exit child ***********\n", __func__, __LINE__);
        close_logs();
        exit(1);
    }

    //------------------------------------------------------------------
    if (signal(SIGINT, signal_handler_child) == SIG_ERR)
    {
        print_err("<%s:%d> Error signal(SIGINT): %s\n", __func__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (signal(SIGSEGV, signal_handler_child) == SIG_ERR)
    {
        print_err("<%s:%d> Error signal(SIGSEGV): %s\n", __func__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (signal(SIGTERM, signal_handler_child) == SIG_ERR)
    {
        print_err("<%s:%d> Error signal(SIGTERM): %s\n", __func__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (signal(SIGUSR1, signal_handler_child) == SIG_ERR)
    {
        print_err("<%s:%d> Error signal(SIGUSR1): %s\n", __func__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (signal(SIGUSR2, signal_handler_child) == SIG_ERR)
    {
        print_err("<%s:%d> Error signal(SIGUSR2): %s\n", __func__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
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
    unsigned int n = 0;
    while (n < conf->NumResponseThreads)
    {
        thread resp_thr;
        try
        {
            resp_thr = thread(response1);
            resp_thr.detach();
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

    for (unsigned int i = 0; i < conf->NumWorkThreads; ++i)
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
    for (unsigned int i = 0; i < conf->NumWorkThreads; ++i)
    {
        work_thr[i].join();
    }
    
    if (work_thr)
        delete [] work_thr;
    event_handler_cl_delete();
    //wait_close_all_conn();
    close(sockServer);

    print_err("<%s:%d> all_conn=%u, all_req=%u; open_conn=%d\n",
                    __func__, __LINE__, allConn, ReqMan->get_all_request(), num_conn);

    ReqMan->close_manager();

    delete ReqMan;
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