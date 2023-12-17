#include "main.h"

using namespace std;
//======================================================================
void init_openssl()
{
    //SSL_library_init();
    //OpenSSL_add_ssl_algorithms();
    ////OpenSSL_add_all_algorithms();
    //SSL_load_error_strings();
    //ERR_load_crypto_strings();
}
//======================================================================
void cleanup_openssl()
{
    EVP_cleanup();
}
//======================================================================
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    method = TLS_server_method();
    return SSL_CTX_new(method);
}
//======================================================================
int configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_file(ctx, "cert/cert.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "<%s:%d> SSL_CTX_use_certificate_file failed\n", __func__, __LINE__);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/key.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "<%s:%d> SSL_CTX_use_PrivateKey_file failed\n", __func__, __LINE__);
        return 0;
    }
/*
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "<%s:%d> SSL_CTX_check_private_key failed\n", __func__, __LINE__);
        return 0;
    }
*/
    return 1;
}
//======================================================================
SSL_CTX *Init_SSL(void)
{
    SSL_CTX *ctx;
    init_openssl();
    ctx = create_context();
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!configure_context(ctx))
    {
        fprintf(stderr, "Error configure_context()\n");
        exit(EXIT_FAILURE);
    }
    else
        return ctx;
}
//======================================================================
const char *ssl_strerror(int err)
{
    switch (err)
    {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
    }
    
    return "?";
}
//======================================================================
int ssl_read(Connect *req, char *buf, int len)// return: ERR_TRY_AGAIN | -1 | 0 | [num read bytes]
{
    int ret = SSL_read(req->tls.ssl, buf, len);
    if (ret <= 0)
    {
        req->tls.err = SSL_get_error(req->tls.ssl, ret);
        if (req->tls.err == SSL_ERROR_ZERO_RETURN)
        {
            //print_err(req, "<%s:%d> Error SSL_read(): SSL_ERROR_ZERO_RETURN\n", __func__, __LINE__);
            return 0;
        }
        else if (req->tls.err == SSL_ERROR_WANT_READ)
        {
            req->tls.err = 0;
            return ERR_TRY_AGAIN;
        }
        else if (req->tls.err == SSL_ERROR_WANT_WRITE)
        {
            print_err(req, "<%s:%d> ??? Error SSL_read(): SSL_ERROR_WANT_WRITE\n", __func__, __LINE__);
            req->tls.err = 0;
            return ERR_TRY_AGAIN;
        }
        else
        {
            print_err(req, "<%s:%d> Error SSL_read()=%d: %s\n", __func__, __LINE__, ret, ssl_strerror(req->tls.err));
            return -1;
        }
    }
    else
        return ret;
}
//======================================================================
int ssl_write(Connect *req, const char *buf, int len)// return: ERR_TRY_AGAIN | -1 | [num read bytes]
{
    int ret = SSL_write(req->tls.ssl, buf, len);
    if (ret <= 0)
    {
        req->tls.err = SSL_get_error(req->tls.ssl, ret);
        if (req->tls.err == SSL_ERROR_WANT_WRITE)
        {
            req->tls.err = 0;
            return ERR_TRY_AGAIN;
        }
        else if (req->tls.err == SSL_ERROR_WANT_READ)
        {
            print_err(req, "<%s:%d> ??? Error SSL_write(): SSL_ERROR_WANT_READ\n", __func__, __LINE__);
            req->tls.err = 0;
            return ERR_TRY_AGAIN;
        }
        print_err(req, "<%s:%d> Error SSL_write()=%d: %s, errno=%d\n", __func__, __LINE__, ret, ssl_strerror(req->tls.err), errno);
        return -1;
    }
    else
        return ret;
}
