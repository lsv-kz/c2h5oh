#include "main.h"

using namespace std;

static int sockServer = -1;
int Connect::serverSocket;

int read_conf_file(const char *path_conf);
int create_server_socket(const Config *c);
int get_size_sock_buf(int domain, int optname, int type, int protocol);
void free_fcgi_list();
int set_uid();
void manager(int);

static int main_proc();

static string pidFile;
const char *nameConfifFile = "/c2h5oh.conf";
static string confPath;
static string cwd;

static int startServer = 0, restartServer = 1;
//======================================================================
static void signal_handler(int signo)
{
    if (signo == SIGINT)
    {
        print_err("<main> ####### SIGINT #######\n");
        if (sockServer > 0)
        {
            shutdown(sockServer, SHUT_RDWR);
            close(sockServer);
            sockServer = -1;
        }
        restartServer = 0;
    }
    else if (signo == SIGSEGV)
    {
        print_err("<main> ####### SIGSEGV #######\n");
        exit(1);
    }
    else if (signo == SIGUSR1)
    {
        fprintf(stderr, "<%s> ####### SIGUSR1 #######\n", __func__);
        restartServer = 1;
        if (sockServer > 0)
        {
            shutdown(sockServer, SHUT_RDWR);
            close(sockServer);
            sockServer = -1;
        }
    }
    else if (signo == SIGUSR2)
    {
        fprintf(stderr, "<%s> ####### SIGUSR2 #######\n", __func__);
        restartServer = 0;
        if (sockServer > 0)
        {
            shutdown(sockServer, SHUT_RDWR);
            close(sockServer);
            sockServer = -1;
        }
    }
    else
        fprintf(stderr, "<%s:%d> ? signo=%d (%s)\n", __func__, __LINE__, signo, strsignal(signo));
}
//======================================================================
void print_help(const char *name)
{
    fprintf(stderr, "Usage: %s [-h] [-p] [-c configfile] [-s signal]\n"
                    "Options:\n"
                    "   -h                           : help\n"
                    "   -p                           : print parameters\n"
                    "   -c [directory of configfile] : default: \".\"\n"
                    "   -s signal                    : restart, close, abort\n", name);
}
//======================================================================
void print_limits()
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_NOFILE, &lim) == -1)
        cerr << " Error getrlimit(RLIMIT_NOFILE): " << strerror(errno) << "\n";
    else
        cout << " RLIMIT_NOFILE: cur=" << (long)lim.rlim_cur << ", max=" << (long)lim.rlim_max << "\n";
    cout << " hardware_concurrency(): " << thread::hardware_concurrency() << "\n\n";

    int sndbuf = get_size_sock_buf(AF_INET, SO_SNDBUF, SOCK_STREAM, 0);
    if (sndbuf < 0)
        cerr << " Error get_size_sock_buf(AF_INET, SO_SNDBUF, SOCK_STREAM, 0): " << strerror(-sndbuf) << "\n";
    else
        cout << " AF_INET: SO_SNDBUF=" << sndbuf << "\n";

    sndbuf = get_size_sock_buf(AF_INET, SO_RCVBUF, SOCK_STREAM, 0);
    if (sndbuf < 0)
        cerr << " Error get_size_sock_buf(AF_INET, SO_RCVBUF, SOCK_STREAM, 0): " << strerror(-sndbuf) << "\n\n";
    else
        cout << " AF_INET: SO_RCVBUF=" << sndbuf << "\n\n";
}
//======================================================================
void print_config()
{
    print_limits();

    cout << "   Protocol               : " << ((conf->Protocol == HTTPS) ? "https" : "http")
         << "\n   ServerSoftware         : " << conf->ServerSoftware.c_str()
         << "\n\n   ServerAddr             : " << conf->ServerAddr.c_str()
         << "\n   ServerPort             : " << conf->ServerPort.c_str()
         << "\n\n   ListenBacklog          : " << conf->ListenBacklog
         << "\n   TcpCork                : " << conf->TcpCork
         << "\n   TcpNoDelay             : " << conf->TcpNoDelay
         << "\n\n   SendFile               : " << conf->SendFile
         << "\n   SndBufSize             : " << conf->SndBufSize
         << "\n\n   NumCpuCores            : " << thread::hardware_concurrency()
         << "\n   BalancedWorkThreads    : " << conf->BalancedWorkThreads
         << "\n   MaxAcceptConnections   : " << conf->MaxAcceptConnections
         << "\n   MaxConnectionPerThr    : " << conf->MaxConnectionPerThr
         << "\n   MaxWorkConnPerThr      : " << conf->MaxWorkConnPerThr
         << "\n   NumWorkThreads         : " << conf->NumWorkThreads
         << "\n   NumParseReqThreads     : " << conf->NumParseReqThreads
         << "\n\n   MaxRequestsPerClient   : " << conf->MaxRequestsPerClient
         << "\n   MaxCgiProc             : " << conf->MaxCgiProc
         << "\n   TimeoutKeepAlive       : " << conf->TimeoutKeepAlive
         << "\n   Timeout                : " << conf->Timeout
         << "\n   TimeoutCGI             : " << conf->TimeoutCGI
         << "\n   TimeoutPoll            : " << conf->TimeoutPoll
         << "\n\n   MaxRanges              : " << conf->MaxRanges
         << "\n\n   ClientMaxBodySize      : " << conf->ClientMaxBodySize
         << "\n\n   ShowMediaFiles         : " << conf->ShowMediaFiles
         << "\n\n   index_html             : " << conf->index_html
         << "\n   index_php              : " << conf->index_php
         << "\n   index_pl               : " << conf->index_pl
         << "\n   index_fcgi             : " << conf->index_fcgi
         << "\n\n   DocumentRoot           : " << conf->DocumentRoot.c_str()
         << "\n   ScriptPath             : " << conf->ScriptPath.c_str()
         << "\n   LogPath                : " << conf->LogPath.c_str()
         << "\n\n   UsePHP                 : " << conf->UsePHP.c_str()
         << "\n   PathPHP                : " << conf->PathPHP.c_str()
         << "\n\n   User                   : " << conf->user.c_str()
         << "\n   Group                  : " << conf->group.c_str()
         << "\n";

    cout << "   ------------- FastCGI/SCGI -------------\n";
    fcgi_list_addr *i = conf->fcgi_list;
    for (; i; i = i->next)
    {
        cout << "   [" << i->script_name.c_str() << " : " << i->addr.c_str() << "] - " << get_cgi_type(i->type) << "\n";
    }
}
//======================================================================
int get_cwd(string& s)
{
    size_t size = 1024;
    for (int i = 0; i < 5; ++i)
    {
        char *p = new(nothrow) char [size];
        if (!p)
        {
            fprintf(stderr, "<%s:%d> Error malloc(): %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
        
        if (getcwd(p, size))
        {
            s = p;
            delete [] p;
            break;
        }
        
        if (errno == ERANGE)
        {
            delete [] p;
            size *= 2;
        }
        else
        {
            delete [] p;
            return -1;
        }
    }
    
    return 0;
}
//======================================================================
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    if (get_cwd(cwd))
    {
        return 1;
    }

    if (argc == 1)
    {
        confPath = ".";
        confPath += nameConfifFile;
    }
    else
    {
        int c, arg_print = 0;
        char *sig = NULL;
        while ((c = getopt(argc, argv, "c:s:h:p")) != -1)
        {
            switch (c)
            {
                case 'c':
                    confPath = optarg;
                    confPath += nameConfifFile;
                    break;
                case 's':
                    sig = optarg;
                    break;
                case 'h':
                    print_help(argv[0]);
                    return 0;
                case 'p':
                    arg_print = 1;
                    break;
                default:
                    print_help(argv[0]);
                    return 0;
            }
        }

        if (!confPath.size())
        {
            confPath = ".";
            confPath += nameConfifFile;
        }

        if (arg_print)
        {
            if (read_conf_file(confPath.c_str()))
                return 1;
            print_config();
            return 0;
        }

        if (sig)
        {
            int sig_send;
            if (!strcmp(sig, "restart"))
                sig_send = SIGUSR1;
            else if (!strcmp(sig, "close"))
                sig_send = SIGUSR2;
            else if (!strcmp(sig, "abort"))
                sig_send = SIGTERM;
            else
            {
                fprintf(stderr, "<%d> ? option -s: %s\n", __LINE__, sig);
                print_help(argv[0]);
                return 1;
            }

            if (read_conf_file(confPath.c_str()))
                return 1;
            pidFile = conf->PidFilePath + "/pid.txt";
            FILE *fpid = fopen(pidFile.c_str(), "r");
            if (!fpid)
            {
                fprintf(stderr, "<%s:%d> Error open PidFile(%s): %s\n", __func__, __LINE__, pidFile.c_str(), strerror(errno));
                return 1;
            }

            pid_t pid;
            fscanf(fpid, "%u", &pid);
            fclose(fpid);

            if (kill(pid, sig_send))
            {
                fprintf(stderr, "<%s:%d> Error kill(pid=%u, %s): %s\n", __func__, __LINE__, pid, strsignal(sig_send), strerror(errno));
                return 1;
            }

            return 0;
        }
    }

    while (restartServer)
    {
        restartServer = 0;

        if (read_conf_file(confPath.c_str()))
            return 1;

        set_uid();
        //--------------------------------------------------------------
        sockServer = create_server_socket(conf);
        if (sockServer == -1)
        {
            fprintf(stderr, "<%s:%d> Error: create_server_socket(%s:%s)\n", __func__, __LINE__,
                        conf->ServerAddr.c_str(), conf->ServerPort.c_str());
            break;
        }

        Connect::serverSocket = sockServer;
        //--------------------------------------------------------------
        if (startServer == 0)
        {
            startServer = 1;
            pidFile = conf->PidFilePath + "/pid.txt";
            FILE *fpid = fopen(pidFile.c_str(), "w");
            if (!fpid)
            {
                fprintf(stderr, "<%s:%d> Error open PidFile(%s): %s\n", __func__, __LINE__, pidFile.c_str(), strerror(errno));
                return 1;
            }

            fprintf(fpid, "%u\n", getpid());
            fclose(fpid);
            //----------------------------------------------------------
            if (signal(SIGINT, signal_handler) == SIG_ERR)
            {
                fprintf(stderr, "<%s:%d> Error signal(SIGINT): %s\n", __func__, __LINE__, strerror(errno));
                break;
            }

            if (signal(SIGSEGV, signal_handler) == SIG_ERR)
            {
                fprintf(stderr, "<%s:%d> Error signal(SIGSEGV): %s\n", __func__, __LINE__, strerror(errno));
                break;
            } 

            if (signal(SIGUSR1, signal_handler) == SIG_ERR)
            {
                fprintf(stderr, "<%s:%d> Error signal(SIGUSR1): %s\n", __func__, __LINE__, strerror(errno));
                break;
            }

            if (signal(SIGUSR2, signal_handler) == SIG_ERR)
            {
                fprintf(stderr, "<%s:%d> Error signal(SIGUSR2): %s\n", __func__, __LINE__, strerror(errno));
                break;
            }
        }
        //--------------------------------------------------------------
        create_logfiles(conf->LogPath);
        //--------------------------------------------------------------
        int ret = main_proc();
        close_logs();
        if (ret)
            break;
    }

    if (startServer == 1)
        remove(pidFile.c_str());
    return 0;
}
//======================================================================
int main_proc()
{
    pid_t pid = getpid();
    //------------------------------------------------------------------
    cout << "\n[" << get_time().c_str() << "] - server \"" << conf->ServerSoftware.c_str()
         << "\" run, port: " << conf->ServerPort.c_str()
         << "\n   hardware_concurrency = " << thread::hardware_concurrency() << "\n";
    if (conf->Protocol == HTTPS)
    {
        SSL  *ssl = SSL_new(conf->ctx);
        cout << "   SSL version: " << SSL_get_version(ssl) << "\n";
        SSL_free(ssl);
    }
    cerr << "   pid="  << pid << "; uid=" << getuid() << "; gid=" << getgid() << "\n";
    cout << "   pid="  << pid << "; uid=" << getuid() << "; gid=" << getgid() << "\n";
    cerr << "   NumCpuCores: " << thread::hardware_concurrency() << "\n   MaxAcceptConnections: " 
         << conf->MaxAcceptConnections << "\n   SndBufSize: " << conf->SndBufSize << "\n";
    //------------------------------------------------------------------
    for ( ; environ[0]; )
    {
        char *p, buf[512];
        if ((p = (char*)memccpy(buf, environ[0], '=', strlen(environ[0]))))
        {
            *(p - 1) = 0;
            unsetenv(buf);
        }
    }
    //------------------------------------------------------------------
    manager(sockServer);
    close_logs();

    if (sockServer > 0)
    {
        shutdown(sockServer, SHUT_RDWR);
        close(sockServer);
        sockServer = -1;
    }

    if (conf->Protocol == HTTPS)
    {
        SSL_CTX_free(conf->ctx);
        cleanup_openssl();
    }

    if (restartServer == 0)
        fprintf(stderr, "<%s> ***** Close *****\n", __func__);
    else
    {
        fprintf(stderr, "<%s> ***** Reload *****\n\n", __func__);
        if (chdir(cwd.c_str()))
        {
            fprintf(stderr, "<%s:%d> Error chdir(%s): %s\n", __func__, __LINE__, cwd.c_str(), strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
