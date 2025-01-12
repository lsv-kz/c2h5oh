#include "main.h"

//======================================================================
int create_server_socket(const Config *conf)
{
    int sockfd, n;
    const int sock_opt = 1;
    struct addrinfo  hints, *result, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((n = getaddrinfo(conf->ServerAddr.c_str(), conf->ServerPort.c_str(), &hints, &result)) != 0)
    {
        fprintf(stderr, "Error getaddrinfo(%s:%s): %s\n", conf->ServerAddr.c_str(), conf->ServerPort.c_str(), gai_strerror(n));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));

        if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sockfd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
    {
        fprintf(stderr, "Error: failed to bind\n");
        return -1;
    }

    if (conf->TcpNoDelay == 'y')
    {
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&sock_opt, sizeof(sock_opt)); // SOL_TCP
    }

    int flags = fcntl(sockfd, F_GETFL);
    if (flags == -1)
    {
        fprintf(stderr, "Error fcntl(, F_GETFL, ): %s\n", strerror(errno));
    }
    else
    {
        flags |= O_NONBLOCK;
        if (fcntl(sockfd, F_SETFL, flags) == -1)
        {
            fprintf(stderr, "Error fcntl(, F_SETFL, ): %s\n", strerror(errno));
        }
    }

    flags = fcntl(sockfd, F_GETFD);
    if (flags == -1)
    {
        print_err("<%s:%d> Error fcntl(F_GETFD): %s\n", __func__, __LINE__, strerror(errno));
        close(sockfd);
        return -1;
    }

    flags |= FD_CLOEXEC;
    if (fcntl(sockfd, F_SETFD, flags) == -1)
    {
        print_err("<%s:%d> Error fcntl(F_SETFD, FD_CLOEXEC): %s\n", __func__, __LINE__, strerror(errno));
        close(sockfd);
        return -1;
    }

    struct linger l;
    if (conf->LingerOn == 'y')
        l.l_onoff = 1;
    else
        l.l_onoff = 0;
    l.l_linger = conf->LingerTime;
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)))
    {
        print_err("<%s:%d> Error setsockopt(SO_LINGER): %s\n", __func__, __LINE__, strerror(errno));
    }

    if (listen(sockfd, conf->ListenBacklog) == -1)
    {
        fprintf(stderr, "Error listen(): %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}
//======================================================================
int create_fcgi_socket(Connect *r, const char *host)
{
    int sockfd, n;
    char addr[256];
    char port[16];

    if (!host)
        return -1;
    n = sscanf(host, "%[^:]:%s", addr, port);
    if (n == 2) //==== AF_INET ====
    {
        struct sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof(sock_addr));

        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd == -1)
        {
            print_err(r, "<%s:%d> Error socket(): %s\n", __func__, __LINE__, strerror(errno));
            return -RS500;
        }

        const int sock_opt = 1;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&sock_opt, sizeof(sock_opt)))
        {
            print_err(r, "<%s:%d> Error setsockopt(TCP_NODELAY): %s\n", __func__, __LINE__, strerror(errno));
            close(sockfd);
            return -RS500;
        }

        sock_addr.sin_port = htons(atoi(port));
        sock_addr.sin_family = AF_INET;
        if (inet_aton(addr, &(sock_addr.sin_addr)) == 0)
//      if (inet_pton(AF_INET, addr, &(sock_addr.sin_addr)) < 1)
        {
            print_err(r, "<%s:%d> Error inet_pton(%s): %s\n", __func__, __LINE__, addr, strerror(errno));
            close(sockfd);
            return -RS500;
        }

        int flags = fcntl(sockfd, F_GETFL);
        if (flags == -1)
        {
            print_err(r, "<%s:%d> Error fcntl(, F_GETFL, ): %s\n", __func__, __LINE__, strerror(errno));
            return -RS500;
        }
        else
        {
            flags |= O_NONBLOCK;
            if (fcntl(sockfd, F_SETFL, flags) == -1)
            {
                print_err(r, "<%s:%d> Error fcntl(, F_SETFL, ): %s\n", __func__, __LINE__, strerror(errno));
                return -RS500;
            }
        }

        if (connect(sockfd, (struct sockaddr *)(&sock_addr), sizeof(sock_addr)) != 0)
        {
            if (errno != EINPROGRESS)
            {
                print_err(r, "<%s:%d> Error connect(%s): %s\n", __func__, __LINE__, host, strerror(errno));
                close(sockfd);
                return -RS502;
            }
            else
                r->io_status = WAIT;
        }
        else
            r->io_status = WORK;
    }
    else //==== PF_UNIX ====
    {
        struct sockaddr_un sock_addr;
        sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sockfd == -1)
        {
            print_err(r, "<%s:%d> Error socket(): %s\n", __func__, __LINE__, strerror(errno));
            return -RS500;
        }

        sock_addr.sun_family = AF_UNIX;
        snprintf(sock_addr.sun_path, sizeof(sock_addr.sun_path), "%s", host);

        int flags = fcntl(sockfd, F_GETFL);
        if (flags == -1)
        {
            print_err(r, "<%s:%d> Error fcntl(, F_GETFL, ): %s\n", __func__, __LINE__, strerror(errno));
            return -RS500;
        }
        else
        {
            flags |= O_NONBLOCK;
            if (fcntl(sockfd, F_SETFL, flags) == -1)
            {
                print_err(r, "<%s:%d> Error fcntl(, F_SETFL, ): %s\n", __func__, __LINE__, strerror(errno));
                return -RS500;
            }
        }

        if (connect(sockfd, (struct sockaddr *) &sock_addr, SUN_LEN(&sock_addr)) == -1)
        {
            if (errno != EINPROGRESS)
            {
                print_err(r, "<%s:%d> Error connect(%s): %s\n", __func__, __LINE__, host, strerror(errno));
                close(sockfd);
                return -RS502;
            }
            else
                r->io_status = WAIT;
        }
        else
            r->io_status = WORK;
    }

    int flags = fcntl(sockfd, F_GETFD);
    if (flags == -1)
    {
        print_err("<%s:%d> Error fcntl(F_GETFD): %s\n", __func__, __LINE__, strerror(errno));
        close(sockfd);
        return -RS500;
    }

    flags |= FD_CLOEXEC;
    if (fcntl(sockfd, F_SETFD, flags) == -1)
    {
        print_err("<%s:%d> Error fcntl(F_SETFD, FD_CLOEXEC): %s\n", __func__, __LINE__, strerror(errno));
        close(sockfd);
        return -RS500;
    }

    return sockfd;
}
//======================================================================
int get_size_sock_buf(int domain, int optname, int type, int protocol)
{
    int sock = socket(domain, type, protocol);
    if (sock < 0)
    {
        fprintf(stderr, "<%s:%d> Error socketpair(): %s\n", __func__, __LINE__, strerror(errno));
        return -errno;
    }

    int sndbuf;
    socklen_t optlen = sizeof(sndbuf);
    if (getsockopt(sock, SOL_SOCKET, optname, &sndbuf, &optlen) < 0)
    {
        fprintf(stderr, "<%s:%d> Error getsockopt(SO_SNDBUF): %s\n", __func__, __LINE__, strerror(errno));
        close(sock);
        return -errno;
    }

    close(sock);
    return sndbuf;
}
//======================================================================
int write_to_client(Connect *req, const char *buf, int len)
{
    if (req->Protocol == HTTPS)
    {
        return ssl_write(req, buf, len);
    }
    else
    {
        int ret = send(req->clientSocket, buf, len, 0);
        if (ret == -1)
        {
            print_err(req, "<%s:%d> Error send(): %s\n", __func__, __LINE__, strerror(errno));
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            else 
                return -1;
        }
        else
            return  ret;
    }
}
//======================================================================
int read_from_client(Connect *req, char *buf, int len)
{
    if (req->Protocol == HTTPS)
    {
        return ssl_read(req, buf, len);
    }
    else
    {
        int ret = recv(req->clientSocket, buf, len, 0);
        if (ret == -1)
        {
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            else
            {
                print_err(req, "<%s:%d> Error recv(): %s\n", __func__, __LINE__, strerror(errno));
                return -1;
            }
        }
        else
            return  ret;
    }
}
//======================================================================
int read_request_headers(Connect *req)
{
    int num_read = SIZE_BUF_REQUEST - req->req.len - 1;
    if (num_read <= 0)
    {
        print_err(req, "<%s:%d> Error 414: %d\n", __func__, __LINE__, req->req.len);
        return -RS414;
    }
    int n = read_from_client(req, req->req.buf + req->req.len, num_read);
    if (n < 0)
    {
        if (n == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        print_err(req, "<%s:%d> Error read_from_client()=%d\n", __func__, __LINE__, n);
        return -1;
    }
    else if (n == 0)
        return -1;

    req->lenTail += n;
    req->req.len += n;
    req->req.buf[req->req.len] = 0;

    n = find_empty_line(req);
    if (n == 1) // empty line found
        return req->req.len;
    else if (n < 0) // error
        return n;

    return 0;
}
