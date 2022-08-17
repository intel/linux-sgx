// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_stdc_ex_t.h"
#include "errno.h"
#include "string.h"
#include "stdio.h"
#include "netinet/in.h"
#include "sys/uio.h"
#include "netdb.h"
#include "sys/socket.h"
#include "sys/bits/sigset.h"
#include "sgx_trts.h"
#include "se_trace.h"

int socket (int domain, int type, int protocol)
{
    int ret = -1;

    errno = 0;

    if (u_socket(&ret, domain, type, protocol) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int bind (int fd, const struct sockaddr *addr, socklen_t len)
{
    int ret = -1;

    errno = 0;

    if (u_bind(&ret, fd, addr, len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int listen (int fd, int n)
{
    int ret = -1;

    errno = 0;

    if (u_listen(&ret, fd, n) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int accept (int fd, struct sockaddr *addr, socklen_t *addr_len)
{
    int ret = -1;
    socklen_t addrlen_in = 0;

    errno = 0;

    if ((addr && !addr_len) || (addr_len && !addr)) {
        SE_TRACE_ERROR("[stdc_ex] accept - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if (addr && addr_len) {
        addrlen_in = *addr_len;
    }

    if (u_accept(&ret, fd, addr, addrlen_in, addr_len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int connect (int fd, const struct sockaddr *addr, socklen_t len)
{
    int ret = -1;

    errno = 0;

    if (u_connect(&ret, fd, addr, len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t send (int fd, const void *buf, size_t n, int flags)
{
    ssize_t ret = -1;

    errno = 0;

    if((n && !buf) || n > INT64_MAX) {
        SE_TRACE_ERROR("[stdc_ex] send - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if (u_send(&ret, fd, buf, n, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    if (ret > (ssize_t)n) {
        SE_TRACE_ERROR("[stdc_ex] send - return value should be no more than n\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t sendto (int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
{
    ssize_t ret = -1;

    errno = -1;

    if ((n && !buf) || n > INT64_MAX) {
        SE_TRACE_ERROR("[stdc_ex] sendto - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if (u_sendto(&ret, fd, buf, n, flags, addr, addr_len) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    if (ret > (ssize_t)n) {
        SE_TRACE_ERROR("[stdc_ex] sendto - return value should be no more than n\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    ssize_t ret = -1;

    errno = 0;

    if (!sockfd || !msg || (msg->msg_iovlen && !msg->msg_iov))
    { 
        SE_TRACE_ERROR("[stdc_ex] sendmsg - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if(!sgx_is_outside_enclave(msg, sizeof(struct msghdr))
      || !sgx_is_outside_enclave(msg->msg_name, msg->msg_namelen)
      || !sgx_is_outside_enclave(msg->msg_control, msg->msg_controllen))
    {
        SE_TRACE_ERROR("[stdc_ex] sendmsg - parameter msg should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(msg->msg_iov)
    {
        for(size_t i = 0; i < msg->msg_iovlen; i++)
	{
            if(!sgx_is_outside_enclave(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len))
            {
                SE_TRACE_ERROR("[stdc_ex] sendmsg - parameter msg should be outside enclave\n");
                errno = EINVAL;
	        return -1;
            }
	}
    }
 
    if (u_sendmsg(&ret, sockfd, msg, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t recv (int fd, void *buf, size_t n, int flags)
{
    ssize_t ret = -1;

    errno = 0;

    if ((n && !buf) || n > INT64_MAX) {
        SE_TRACE_ERROR("[stdc_ex] recv - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if (u_recv(&ret, fd, buf, n, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    if (ret > (ssize_t)n) {
        SE_TRACE_ERROR("[stdc_ex] recv - return value should be no more than n\n");
        errno = EINVAL;
        return -1;
    }

    return ret;

}

ssize_t recvfrom (int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
{
    ssize_t ret = -1;
    socklen_t addrlen_in = 0;
    socklen_t addrlen_out =0;

    errno = 0;

    if ((n && !buf) || n > INT64_MAX) {
        SE_TRACE_ERROR("[stdc_ex] recvfrom - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if (addr && addr_len)
        addrlen_in = *addr_len;

    if (u_recvfrom(&ret, fd, buf, n, flags, addr, addrlen_in, &addrlen_out) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    if (addr && addr_len) {
        if (addrlen_out > sizeof(struct sockaddr_storage)) {
            SE_TRACE_ERROR("[stdc_ex] recvfrom - returned addrlen is too small\n");
            errno = EINVAL;
            return -1;
        }

        // The returned value can stil exceed the supplied one, which indicates a address trunction.
        *addr_len = addrlen_out;
    }

    if (ret > (ssize_t)n) {
        SE_TRACE_ERROR("[stdc_ex] recvfrom - return value should be no more than n\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t ret = -1;

    errno = 0;

    if (!sockfd || !msg || (msg->msg_iovlen && !msg->msg_iov))
    { 
        SE_TRACE_ERROR("[stdc_ex] recvmsg - invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    if(!sgx_is_outside_enclave(msg, sizeof(struct msghdr))
      || !sgx_is_outside_enclave(msg->msg_name, msg->msg_namelen)
      || !sgx_is_outside_enclave(msg->msg_control, msg->msg_controllen))
    {
        SE_TRACE_ERROR("[stdc_ex] recvmsg - parameter msg should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(msg->msg_iov)
    {
        for(size_t i = 0; i < msg->msg_iovlen; i++)
	{
            if(!sgx_is_outside_enclave(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len))
            {
                SE_TRACE_ERROR("[stdc_ex] recvmsg - parameter msg should be outside enclave\n");
                errno = EINVAL;
	        return -1;
            }
	}
    }
    if (u_recvmsg(&ret, sockfd, msg, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int getsockopt (int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    int ret = -1;

    socklen_t optlen_in = 0;
    socklen_t optlen_out = 0;

    errno = 0;

    if (!optval || !optlen)
    {
        SE_TRACE_ERROR("[stdc_ex] getsockopt invalid parameter\n");
        errno = EINVAL;
        return -1;
    }

    optlen_in = *optlen;

    if (u_getsockopt(&ret, fd, level, optname, optval, optlen_in, &optlen_out) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    /*
     * The POSIX specification for getsockopt states that if the size of optval
     * is greater than the input optlen, then the value stored in the object
     * pointed to by the optval argument shall be silently truncated.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockopt.html
     * for more detail.
     */
    if (optlen_out > optlen_in)
        optlen_out = optlen_in;

    *optlen = optlen_out;

    return ret;
}

int setsockopt (int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    int ret = -1;

    errno = 0;

    if (!optval || !optlen)
    {
        errno = EINVAL;
        return -1;
    }

    if (u_setsockopt(&ret, fd, level, optname, optval, optlen) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int select (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    int ret = -1;

    errno = 0;

    if (u_select (&ret, nfds, readfds, writefds, exceptfds, timeout) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}


int poll (struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret = -1;

    errno = 0;

    if (u_poll (&ret, fds, nfds, timeout)) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *ts, const sigset_t *sigmask)
{
    int ret = -1;
    int timeout = -1;

    errno = 0;

    if (sigmask != NULL)
    {
        SE_TRACE_ERROR("[stdc_ex] ppoll sigmask must be NULL\n");
        errno = EINVAL;
        return -1;
    }

    if (ts)
    {
        int64_t mul;
        int64_t div;
        int64_t sum;

        if(__builtin_mul_overflow(ts->tv_sec, 1000, &mul))
        {
            SE_TRACE_ERROR("[stdc_ex] ppoll unexpected error\n");
            errno = EINVAL;
            goto done;
        }

        div = ts->tv_nsec / 1000000;

        if(__builtin_add_overflow(mul, div, &sum))
        {
            SE_TRACE_ERROR("[stdc_ex] ppoll unexpected error\n");
            errno = EINVAL;
            goto done;
        }

        timeout = (int)sum;
    }

    ret = poll(fds, nfds, timeout);
done:
    return ret;
}

int getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    int ret = -1;

    errno = 0;

    if (!addrlen)
    {
        SE_TRACE_ERROR("[stdc_ex] getsockyyname invalid parameter\n");
        errno = EINVAL;
        return -1;
    }
    if (u_getsockname (&ret, sockfd, addr, *addrlen, addrlen) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int ret = -1;

    errno = 0;

    if (!addrlen)
    {
        SE_TRACE_ERROR("[stdc_ex] getpeername invalid parameter\n");
        errno = EINVAL;
        return -1;
    }
    if (u_getpeername (&ret, sockfd, addr, *addrlen, addrlen) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int socketpair(int domain, int type, int protocol, int retfd[2])
{
    int ret = -1;

    errno = 0;

    if (u_socketpair(&ret, domain, type, protocol, retfd) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int shutdown(int sockfd, int how)
{
    int ret = -1;

    errno = 0;

    if (u_shutdown (&ret, sockfd, how) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    int ret = 0;

    errno = 0;

    if(hints && (hints->ai_addrlen || hints->ai_addr || hints->ai_canonname || hints->ai_next))
    {
        SE_TRACE_ERROR("[stdc_ex] getaddrinfo invalid parameter\n");
        errno = EINVAL;
        return EAI_SYSTEM;
    }
    if(u_getaddrinfo(&ret, node, service, hints, res) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return EAI_SYSTEM;
    }
    for (struct addrinfo *rp = *res; rp != NULL; rp = rp->ai_next)
    {
        if(!sgx_is_outside_enclave(rp, sizeof(*rp)))
        {
            SE_TRACE_ERROR("[stdc_ex] getaddrinfo output parameter res should be outside enclave\n");
            errno = EINVAL;
            return EAI_SYSTEM;
        }
    }
    return ret;
}

void freeaddrinfo(struct addrinfo *res)
{
    errno = 0;

    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next)
    {
        if(!sgx_is_outside_enclave(rp, sizeof(*rp)))
        {
            SE_TRACE_ERROR("[stdc_ex] freeaddrinfo input parameter res should be outside enclave\n");
            errno = EINVAL;
            return;
        }
    }
    if(u_freeaddrinfo(res) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }
    return;
}

int getnameinfo(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    int ret = 0;

    errno = 0;

    if(u_getnameinfo(&ret, sa, salen, host, hostlen, serv, servlen, flags) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return EAI_SYSTEM;
    }

    return ret;
}

const char *gai_strerror(int errcode)
{
    errno = 0;
    char *ret = NULL;
    if(u_gai_strerror(&ret, errcode) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return NULL;
    }
    if(!sgx_is_outside_enclave(ret, strlen(ret)+1))
    {
        SE_TRACE_ERROR("[stdc_ex] gai_strerror return value should be outside enclave\n");
        errno = EINVAL;
        return NULL;
    }
    return (const char*)ret;
}

static inline uint16_t __bswap_16(uint16_t __x)
{
    return (uint16_t)((__x<<8) | (__x>>8));
}

static inline uint32_t __bswap_32(uint32_t __x)
{
    return (__x>>24) | (__x>>8&0xff00) | (__x<<8&0xff0000) | (__x<<24);
}

#define bswap_16(x) __bswap_16(x)
#define bswap_32(x) __bswap_32(x)

uint32_t htonl(uint32_t n)
{
    union { int i; char c; } u = { 1 };
    return u.c ? bswap_32(n) : n;
}

uint16_t htons(uint16_t n)
{
    union { int i; char c; } u = { 1 };
    return u.c ? bswap_16(n) : n;
}

uint32_t ntohl(uint32_t n)
{
    union { int i; char c; } u = { 1 };
    return u.c ? bswap_32(n) : n;
}

uint16_t ntohs(uint16_t n)
{
    union { int i; char c; } u = { 1 };
    return u.c ? bswap_16(n) : n;
}

char *inet_ntoa(struct in_addr in)
{
    static char buf[16];
    unsigned char *a = (unsigned char *)&in;
    snprintf(buf, sizeof buf, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
    return buf;
}


