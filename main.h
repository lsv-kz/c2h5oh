#ifndef SERVER_H_
#define SERVER_H_
#define _FILE_OFFSET_BITS 64

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <climits>
#include <iomanip>
#include <vector>

#include <mutex>
#include <thread>
#include <condition_variable>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <sys/resource.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/un.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "string__.h"
#include "ranges.h"

//#define    LINUX_
//#define    FREEBSD_
#define    SEND_FILE_
#define    TCP_CORK_

const int  MAX_PATH = 2048;
const int  MAX_NAME = 256;
const int  SIZE_BUF_REQUEST = 8192;
const int  CGI_BUF_SIZE = 16384;
const int  MAX_HEADERS = 25;
const int  ERR_TRY_AGAIN = -1000;
const int  LIMIT_WORK_THREADS = 16;
const int  LIMIT_PARSE_REQ_THREADS = 128;
const char boundary[] = "---------a9b5r7a4c0a2d5a1b8r3a";

enum {
    RS101 = 101,
    RS200 = 200,RS204 = 204,RS206 = 206,
    RS301 = 301, RS302,
    RS400 = 400,RS401,RS402,RS403,RS404,RS405,RS406,RS407,
    RS408,RS411 = 411,RS413 = 413,RS414,RS415,RS416,RS417,RS418,RS429 = 429,
    RS500 = 500,RS501,RS502,RS503,RS504,RS505
};
enum {
    M_GET = 1, M_HEAD, M_POST, M_OPTIONS, M_PUT,
    M_PATCH, M_DELETE, M_TRACE, M_CONNECT
};
enum { HTTP09 = 1, HTTP10, HTTP11, HTTP2 };

enum PROTOCOL {HTTP = 1, HTTPS};
enum MODE_SEND { NO_CHUNK, CHUNK, CHUNK_END };
enum SOURCE_ENTITY { NO_ENTITY, FROM_FILE, FROM_DATA_BUFFER, MULTIPART_ENTITY, };
enum OPERATION_TYPE { SSL_ACCEPT = 1, READ_REQUEST, RESPONSE_PREPARE, SEND_RESP_HEADERS, SEND_ENTITY, DYN_PAGE, SSL_SHUTDOWN, CLOSE_CONNECT, };
enum MULTIPART { SEND_HEADERS = 1, SEND_PART, SEND_END };
enum IO_STATUS { WAIT = 1, WORK };
enum DIRECT { FROM_CGI = 1, TO_CGI, FROM_CLIENT, TO_CLIENT };

enum CGI_TYPE { NO_CGI, CGI, PHPCGI, PHPFPM, FASTCGI, SCGI, };
enum FCGI_OPERATION { FASTCGI_BEGIN, FASTCGI_PARAMS, FASTCGI_STDIN, FASTCGI_STDOUT, };
enum CGI_OPERATION { CGI_STDIN, CGI_READ_HTTP_HEADERS, CGI_SEND_HTTP_HEADERS, CGI_SEND_ENTITY };
enum SCGI_OPERATION { SCGI_PARAMS, SCGI_STDIN, SCGI_READ_HTTP_HEADERS, SCGI_SEND_HTTP_HEADERS, SCGI_SEND_ENTITY };
union OPERATION { CGI_OPERATION cgi; FCGI_OPERATION fcgi; SCGI_OPERATION scgi;};
//----------------------------------------------------------------------
typedef struct fcgi_list_addr
{
    std::string script_name;
    std::string addr;
    CGI_TYPE type;
    struct fcgi_list_addr *next;
} fcgi_list_addr;

struct Param
{
    std::string name;
    std::string val;
};
//----------------------------------------------------------------------
class Config
{
    Config(const Config&){}
    Config& operator=(const Config&);

public:
    SSL_CTX *ctx;
    PROTOCOL Protocol;
    
    std::string ServerSoftware;

    std::string ServerAddr;
    std::string ServerPort;

    std::string DocumentRoot;
    std::string ScriptPath;
    std::string LogPath;
    std::string PidFilePath;

    std::string UsePHP;
    std::string PathPHP;

    int ListenBacklog;
    char TcpCork;
    char TcpNoDelay;

    char LingerOn;
    int LingerTime;

    char SendFile;
    int SndBufSize;

    char BalancedWorkThreads;

    int MaxAcceptConnections;

    int MaxConnectionPerThr;

    int NumWorkThreads;

    int MaxParseReqThreads;
    int MinParseReqThreads;

    int MaxCgiProc;

    int MaxRanges;
    long int ClientMaxBodySize;

    int MaxRequestsPerClient;
    int TimeoutKeepAlive;
    int Timeout;
    int TimeoutCGI;
    int TimeoutPoll;

    char AutoIndex;
    char index_html;
    char index_php;
    char index_pl;
    char index_fcgi;

    char ShowMediaFiles;

    std::string user;
    std::string group;

    uid_t server_uid;
    gid_t server_gid;

    fcgi_list_addr *fcgi_list;
    //------------------------------------------------------------------
    Config()
    {
        fcgi_list = NULL;
    }

    ~Config()
    {
        free_fcgi_list();
        //std::cout << __func__ << " ******* " << getpid() << " *******\n";
    }

    void free_fcgi_list()
    {
        fcgi_list_addr *t;
        while (fcgi_list)
        {
            t = fcgi_list;
            fcgi_list = fcgi_list->next;
            if (t)
                delete t;
        }
    }
};
//----------------------------------------------------------------------
extern const Config* const conf;
//======================================================================
class Connect
{
    Connect(const Connect&){}
    Connect& operator=(const Connect&);
public:
    Connect(){}
    Connect *prev;
    Connect *next;

    static int serverSocket;

    PROTOCOL Protocol;

    int numThr;
    unsigned long numConn, numReq;
    int    clientSocket;
    int    err;
    time_t sock_timer;
    int    timeout;

    OPERATION_TYPE operation;
    IO_STATUS io_status;
    DIRECT io_direct;

    struct
    {
        SSL *ssl;
        int err;
    } tls;

    char remoteAddr[NI_MAXHOST];
    char remotePort[NI_MAXSERV];

    struct
    {
        char buf[SIZE_BUF_REQUEST];
        int  len;
    } req;

    char *p_newline;
    char *tail;
    int  lenTail;

    char decodeUri[SIZE_BUF_REQUEST];
    unsigned int lenDecodeUri;

    char *uri;
    unsigned int uriLen;
    //------------------------------------------------------------------
    const char *sReqParam;
    char *sRange;

    int reqMethod;
    int httpProt;
    int connKeepAlive;

    struct
    {
        int iConnection;
        int iHost;
        int iUserAgent;
        int iReferer;
        int iUpgrade;
        int iReqContentType;
        int iReqContentLength;
        int iAcceptEncoding;
        int iRange;
        int iIfRange;
        long long reqContentLength;
    } req_hd;

    int  countReqHeaders;
    char *reqHdName[MAX_HEADERS + 1];
    const char *reqHdValue[MAX_HEADERS + 1];
    //--------------------------------------
    struct
    {
        String s;
        const char *p;
        int len;
    } resp_headers;

    String hdrs;

    struct
    {
        String s;
        const char *p;
        int len;
    } html;

    struct
    {
        String scriptName;
        CGI_TYPE cgi_type;
        OPERATION op;
        int  size_buf = CGI_BUF_SIZE;
        char buf[CGI_BUF_SIZE + 16];
        int len_buf;
        int len_post;
        char *p;

        pid_t pid;
        int to_script;
        int from_script;
        //-------------------------
        const std::string *script_path;
        int fd;

        bool http_hdrs_read;
        bool http_hdrs_send;
        bool entity_tail;

        int i_param;
        int size_par;
        std::vector <Param> vPar;

        unsigned char fcgi_type;
        int dataLen;
        int paddingLen;
        char header[8];
        int len_buf_hd;
    } cgi;

    Ranges rg;
    struct
    {
        MULTIPART status;
        Range *rg;
        String hdr;
    } multipart;

    SOURCE_ENTITY source_entity;
    MODE_SEND mode_send;

    time_t Time;
    int respStatus;
    int numPart;
    long long respContentLength;
    const char *respContentType;
    long long fileSize;
    int fd;
    off_t offset;
    long long send_bytes;

    void init();
};
//----------------------------------------------------------------------
class EventHandlerClass
{
    std::mutex mtx_thr, mtx_cgi;
    std::condition_variable cond_thr;

    int num_thr;
    int num_wait, num_work;
    int cgi_work;
    int close_thr;
    unsigned long num_request;

    struct pollfd *poll_fd;
    char *snd_buf;
    int size_buf;

    Connect *work_list_start;
    Connect *work_list_end;

    Connect *wait_list_start;
    Connect *wait_list_end;

    Connect *cgi_wait_list_start;
    Connect *cgi_wait_list_end;

    int send_part_file(Connect *r);
    void del_from_list(Connect *r);

    void worker(Connect *r);
    int send_html(Connect *r);
    void set_part(Connect *r);
    int send_headers(Connect *r);
    void choose_worker(Connect *r);
    int set_pollfd_array(Connect *r, int *i);

    void kill_chld(Connect *r);
    int cgi_fork(Connect *r, int* serv_cgi, int* cgi_serv);
    int cgi_create_proc(Connect *r);
    void cgi_worker(Connect* r);
    int cgi_err(Connect *r);
    void cgi_set_status_readheaders(Connect *r);
    int cgi_set_size_chunk(Connect *r);
    int cgi_stdin(Connect *r);
    int cgi_stdout(Connect *r);
    int cgi_find_empty_line(Connect *r);
    int cgi_read_http_headers(Connect *r);

    void fcgi_set_header(Connect* r, unsigned char type);
    void get_info_from_header(Connect* r, const char* p);
    void fcgi_set_param(Connect *r);
    int fcgi_create_connect(Connect *r);
    int fcgi_create_params(Connect *req);
    int fcgi_stdin(Connect *r);
    int fcgi_stdout(Connect *r);
    int fcgi_read_http_headers(Connect *r);
    int write_to_fcgi(Connect* r);
    int fcgi_read_header(Connect* r);
    void fcgi_worker(Connect* r);
    int fcgi_err(Connect *r);
    int read_padding(Connect *r);
    void read_data_from_buf(Connect *r);

    int scgi_set_size_data(Connect* r);
    int scgi_create_connect(Connect *r);
    int scgi_create_params(Connect *r);
    int scgi_set_param(Connect *r);
    void scgi_worker(Connect* r);
    int scgi_err(Connect *r);

public:

    EventHandlerClass();
    ~EventHandlerClass();

    void init(int n);
    int wait_conn();
    void add_work_list();
    void set_poll();
    void cgi_add_work_list();
    int poll_worker();

    void push_cgi(Connect *r);
    void add_wait_list(Connect *r);
    void push_send_file(Connect *r);
    void push_pollin_list(Connect *r);
    void push_send_multipart(Connect *r);
    void push_send_html(Connect *r);
    void push_ssl_shutdown(Connect *r);
    void close_event_handler();
    long get_num_req();
};
//----------------------------------------------------------------------
extern char **environ;
//----------------------------------------------------------------------
void parse_request_thread();
int prepare_response(Connect *r);
int options(Connect *r);
int index_dir(Connect *r, std::string& path);
//----------------------------------------------------------------------
int create_fcgi_socket(Connect *r, const char *host);
int read_from_client(Connect *r, char *buf, int len);
int write_to_client(Connect *r, const char *buf, int len);
int read_request_headers(Connect* r);
//----------------------------------------------------------------------
int encode(const char *s_in, char *s_out, int len_out);
int encode(const char *s_in, String& s_out);
int decode(const char *s_in, int len_in, char *s_out, int len);
//----------------------------------------------------------------------
int send_message(Connect *r, const char *msg);
int create_response_headers(Connect *r);
//----------------------------------------------------------------------
std::string get_time();
std::string get_time(time_t t);
std::string log_time();
std::string log_time(time_t t);

const char *strstr_case(const char * s1, const char *s2);
int strlcmp_case(const char *s1, const char *s2, int len);

int get_int_method(const char *s);
const char *get_str_method(int i);

int get_int_http_prot(const char *s);
const char *get_str_http_prot(int i);

const char *get_str_operation(OPERATION_TYPE n);
const char *get_cgi_operation(CGI_OPERATION n);
const char *get_fcgi_operation(FCGI_OPERATION n);
const char *get_scgi_operation(SCGI_OPERATION n);
const char *get_cgi_type(CGI_TYPE n);
const char *get_cgi_dir(DIRECT n);

int clean_path(char *path, int len);
const char *content_type(const char *s);

const char *base_name(const char *path);
int parse_startline_request(Connect *r, char *s);
int parse_headers(Connect *r);
int find_empty_line(Connect *r);
//----------------------------------------------------------------------
void create_logfiles(const std::string &);
void close_logs();
void print_err(const char *format, ...);
void print_err(Connect *r, const char *format, ...);
void print_log(Connect *r);
//----------------------------------------------------------------------
void push_resp_list(Connect *r);
void end_response(Connect *r);
void close_connect(Connect *r);
//----------------------------------------------------------------------
void push_cgi(Connect *r);
void push_pollin_list(Connect *r);
void push_send_file(Connect *r);
void push_send_multipart(Connect *r);
void push_send_html(Connect *r);
void push_ssl_shutdown(Connect *r);
void event_handler(int);
void close_work_threads();
//----------------------------------------------------------------------
int set_max_fd(int max_open_fd);
//----------------------------------------------------------------------
void init_openssl();
void cleanup_openssl();
SSL_CTX *create_context();
int configure_context(SSL_CTX *ctx);
SSL_CTX *Init_SSL();
const char *ssl_strerror(int err);
int ssl_read(Connect *r, char *buf, int len);
int ssl_write(Connect *r, const char *buf, int len);

#endif
