// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sys/socket.h"
#include "sys/poll.h"
#include "netdb.h"
#include "errno.h"
#include <unistd.h>
#include <string.h>

int u_socket (int domain, int type, int protocol)
{
    errno = 0;
    return socket(domain, type, protocol);
}

int u_bind (int fd, const struct sockaddr *addr, socklen_t len)
{
    errno = 0;
    return bind(fd, addr, len);
}

int u_listen (int fd, int n)
{
    errno = 0;
    return listen(fd, n);
}

int u_accept (int fd, struct sockaddr *addr, socklen_t addrlen_in, socklen_t *addrlen_out)
{
    int ret = -1;
    errno = 0;

    if ((ret = accept(fd, addr, &addrlen_in)) != -1) {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int u_connect (int fd, const struct sockaddr *addr, socklen_t len)
{
    errno = 0;
    return connect(fd, addr, len);
}

ssize_t u_send (int fd, const void *buf, size_t n, int flags)
{
    errno = 0;
    return send(fd, buf, n, flags); 
}

ssize_t u_sendto (int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
{
    errno = 0;
    return sendto(fd, buf, n, flags, addr, addr_len);
}

ssize_t u_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    errno = 0;
    return sendmsg(sockfd, msg, flags);
}

ssize_t u_recv (int fd, void *buf, size_t n, int flags)
{
    errno = 0;
    return recv(fd, buf, n, flags);
}

ssize_t u_recvfrom (int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t addrlen_in, socklen_t *addrlen_out)
{
    ssize_t ret = -1;
    errno = 0;

    if ((ret = recvfrom(fd, buf, n, flags, addr, &addrlen_in)) != -1) {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

ssize_t u_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    errno = 0;
    return recvmsg(sockfd, msg, flags);
}

int u_getsockopt (int fd, int level, int optname, void *optval, socklen_t optlen_in, socklen_t *optlen_out)
{
    int ret = -1;
    errno = 0;

    if ((ret = getsockopt(fd, level, optname, optval, &optlen_in)) != -1)
    {
        if (optlen_out)
            *optlen_out = optlen_in;
    }

    return ret;
}

int u_setsockopt (int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    errno = 0;
    return setsockopt(fd, level, optname, optval, optlen);
}

int u_select (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    errno = 0;
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

int u_poll (struct pollfd *fds, nfds_t nfds, int timeout)
{
    errno = 0;
    return poll(fds, nfds, timeout);
}

int u_socketpair(int domain, int type, int protocol, int retfd[2])
{
    errno = 0;
    return socketpair(domain, type, protocol, retfd);
}

int u_shutdown(int sockfd, int how)
{
    errno = 0;
    return shutdown(sockfd, how);
}

int u_getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    errno = 0;
    return getaddrinfo(node, service, hints, res);
}

void u_freeaddrinfo(struct addrinfo *res)
{
    errno = 0;
    return freeaddrinfo(res);
}

int u_getnameinfo(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    errno = 0;
    return getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

char *u_gai_strerror(int errcode)
{
    errno = 0;
    return (char *)gai_strerror(errcode);
}

