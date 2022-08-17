// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_EPOLL_H_
#define _SYS_EPOLL_H_

#include <bits/types.h>
#include <sys/bits/sigset.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

enum EPOLL_EVENTS
{
    EPOLLIN = 0x001,
    EPOLLPRI = 0x002,
    EPOLLOUT = 0x004,
    EPOLLRDNORM = 0x040,
    EPOLLRDBAND = 0x080,
    EPOLLWRNORM = 0x100,
    EPOLLWRBAND = 0x200,
    EPOLLMSG = 0x400,
    EPOLLERR = 0x008,
    EPOLLHUP = 0x010,
    EPOLLRDHUP = 0x2000,
    EPOLLEXCLUSIVE = 1u << 28,
    EPOLLWAKEUP = 1u << 29,
    EPOLLONESHOT = 1u << 30,
    EPOLLET = 1u << 31
};

typedef union _epoll_data_t
{
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

#pragma pack(push, 1)
struct epoll_event
{
    uint32_t events;
    epoll_data_t data;
};
#pragma pack(pop)

int epoll_create(int size);

int epoll_create1(int flags);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event);

int epoll_wait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout);
/*
 * epoll_pwait
 * sigmask - must be NULL, epoll_pwait behaves same as epoll_wait
 */
int epoll_pwait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout,
    const sigset_t* sigmask);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EPOLL_H_ */
