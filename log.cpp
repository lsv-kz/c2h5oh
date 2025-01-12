#include "main.h"

using namespace std;

static int flog = STDOUT_FILENO, flog_err = STDERR_FILENO;
static mutex mtxLog;
static unsigned int num_log_records = 0, num_logerr_records = 0;
//======================================================================
void create_logfile(const string& log_dir)
{
    char buf[256];
    struct tm tm1;
    time_t t1;

    time(&t1);
    tm1 = *localtime(&t1);
    strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &tm1);

    String fileName;
    fileName << log_dir << '/' << buf << '-' << conf->ServerSoftware << ".log";

    flog = open(fileName.c_str(), O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (flog == -1)
    {
        fprintf(stderr, "  Error create log_err: %s\n", fileName.c_str());
        exit(1);
    }
}
//======================================================================
void create_error_logfile(const string& log_dir)
{
    char buf[256];
    struct tm tm1;
    time_t t1;

    time(&t1);
    tm1 = *localtime(&t1);
    strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &tm1);

    String fileName;
    fileName << log_dir << "/error_" << buf << '_' << conf->ServerSoftware << ".log";

    flog_err = open(fileName.c_str(), O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (flog_err == -1)
    {
        fprintf(stderr, "  Error create log_err: %s\n", fileName.c_str());
        exit(1);
    }

    dup2(flog_err, STDERR_FILENO);
}
//======================================================================
void close_logs()
{
    close(flog);
    close(flog_err);
}
//======================================================================
void print_err(const char *format, ...)
{
    va_list ap;
    char buf[300];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    String ss(256);
    ss << "[" << log_time() << "] - " << buf;
mtxLog.lock();
    write(flog_err, ss.c_str(), ss.size());
    num_logerr_records++;
    if (num_logerr_records > 100000)
    {
        close(flog_err);
        create_error_logfile(conf->LogPath);
        num_logerr_records = 0;
    }
mtxLog.unlock();
}
//======================================================================
void print_err(Connect *req, const char *format, ...)
{
    va_list ap;
    char buf[300];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    String ss(256);
    ss << "[" << log_time() << "] - [" << req->numConn << "/" << req->numReq << "] " << buf;

mtxLog.lock();
    write(flog_err, ss.c_str(), ss.size());
    num_logerr_records++;
    if (num_logerr_records > 100000)
    {
        close(flog_err);
        create_error_logfile(conf->LogPath);
        num_logerr_records = 0;
    }
mtxLog.unlock();
}
//======================================================================
void print_log(Connect *req)
{
    String ss(320);
    if (req->reqMethod <= 0)
    {
        ss  << req->numConn << "/" << req->numReq << " - " << req->remoteAddr << ":" << req->remotePort
            << " - [" << log_time() << "] - \"-\" "
            << req->respStatus << " " << req->send_bytes
            << " \"" << ((req->req_hd.iReferer >= 0) ? req->reqHdValue[req->req_hd.iReferer] : "-") << "\" \"-\"\n";
    }
    else
    {
        ss  << req->numConn << "/" << req->numReq << " - " << req->remoteAddr << ":" << req->remotePort
            << " - [" << log_time(req->Time) << "] - \"" << get_str_method(req->reqMethod) << " "
            //<< req->decodeUri << ((req->sReqParam) ? "?" : "") << ((req->sReqParam) ? req->sReqParam : "") << " "
            << req->uri << " "
            << get_str_http_prot(req->httpProt) << "\" "
            << req->respStatus << " " << req->send_bytes << " "
            << "\"" << ((req->req_hd.iReferer >= 0) ? req->reqHdValue[req->req_hd.iReferer] : "-") << "\" "
            << "\"" << ((req->req_hd.iUserAgent >= 0) ? req->reqHdValue[req->req_hd.iUserAgent] : "-") << "\"\n";
    }
mtxLog.lock();
    write(flog, ss.c_str(), ss.size());
    num_log_records++;
    if (num_log_records > 100000) // 100000 ~ 9,5 Mb
    {
        close(flog);
        create_logfile(conf->LogPath);
        num_log_records = 0;
    }
mtxLog.unlock();
}
//======================================================================
void create_logfiles(const string& log_dir)
{
    create_logfile(log_dir);
    create_error_logfile(log_dir);
}
