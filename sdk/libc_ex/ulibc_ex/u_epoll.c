// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define true 1
#define false 0
#define bool _Bool

#define MAX_EPOLLS 64
#define WAKEFD_MAGIC 0x8700666859244b71

typedef struct _epoll
{
    int epfd;
    int wakefds[2];
} epoll_t;

static epoll_t _epolls[MAX_EPOLLS];
static size_t _num_epolls;
static pthread_spinlock_t _epolls_lock;
static pthread_once_t _epolls_once = PTHREAD_ONCE_INIT;

static void _init_epolls_lock(void)
{
    pthread_spin_init(&_epolls_lock, PTHREAD_PROCESS_PRIVATE);
}

int u_epoll_create1(int flags)
{
    int ret = -1;
    int epfd = -1;
    int wakefds[2] = {-1, -1};
    errno = 0;

    pthread_once(&_epolls_once, _init_epolls_lock);

    if ((epfd = epoll_create1(flags)) == -1)
        goto done;

    if (pipe(wakefds) == -1)
        goto done;

    /* Watch for events on the wake file descriptor. */
    {
        struct epoll_event event;

        memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        event.data.u64 = WAKEFD_MAGIC;

        if ((epoll_ctl(epfd, EPOLL_CTL_ADD, wakefds[0], &event)) == -1)
            goto done;
    }

    /* Inject entry for this epoll into the epolls array. */
    {
        pthread_spin_lock(&_epolls_lock);

        if (_num_epolls == MAX_EPOLLS)
        {
            errno = ENOMEM;
            pthread_spin_unlock(&_epolls_lock);
            goto done;
        }

        _epolls[_num_epolls].epfd = epfd;
        _epolls[_num_epolls].wakefds[0] = wakefds[0];
        _epolls[_num_epolls].wakefds[1] = wakefds[1];
        _num_epolls++;

        pthread_spin_unlock(&_epolls_lock);
    }

    ret = epfd;
    epfd = -1;
    wakefds[0] = -1;
    wakefds[1] = -1;

done:

    if (epfd != -1)
        close(epfd);

    if (wakefds[0] != -1)
        close(wakefds[0]);

    if (wakefds[1] != -1)
        close(wakefds[1]);

    return ret;
}

int u_epoll_wait(
    int epfd,
    struct epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    int ret = -1;
    int nfds;
    bool found_wake_event = false;

    pthread_once(&_epolls_once, _init_epolls_lock);

    errno = 0;

    nfds = epoll_wait(
        (int)epfd, (struct epoll_event*)events, (int)maxevents, timeout);

    if (nfds < 0)
        goto done;

    /* Remove the dummy event for the wakefd. */
    for (int i = 0; i < nfds; i++)
    {
        if (events[i].data.u64 == WAKEFD_MAGIC)
        {
            events[i] = events[nfds - 1];
            nfds--;
            found_wake_event = true;
            break;
        }
    }

    /* Read the word that u_epoll_wake() wrote. */
    if (found_wake_event)
    {
        int fd = -1;
        uint64_t c;

        /* Find the read descriptor for the wakefds[] pipe. */
        {
            pthread_spin_lock(&_epolls_lock);

            for (size_t i = 0; i < _num_epolls; i++)
            {
                if (_epolls[i].epfd == epfd)
                {
                    fd = _epolls[i].wakefds[0];
                    break;
                }
            }

            pthread_spin_unlock(&_epolls_lock);
        }

        if (fd == -1)
        {
            errno = EINVAL;
            goto done;
        }

        if (read(fd, &c, sizeof(c)) != sizeof(c) || c != WAKEFD_MAGIC)
        {
            goto done;
        }

        /* Treat as an interrupt if no other descriptors are read. */
        if (nfds == 0)
        {
            errno = EINTR;
            goto done;
        }
    }

    ret = nfds;

done:

    return ret;
}

int u_epoll_ctl(
    int epfd,
    int op,
    int fd,
    struct epoll_event* event)
{
    errno = 0;

    return epoll_ctl((int)epfd, op, (int)fd, (struct epoll_event*)event);
}

int u_epoll_close(int epfd)
{
    int fd0 = -1;
    int fd1 = -1;
    errno = 0;

    pthread_once(&_epolls_once, _init_epolls_lock);

    /* Close both ends of the wakefd pipe and remove the epoll_t struct. */
    {
        pthread_spin_lock(&_epolls_lock);

        for (size_t i = 0; i < _num_epolls; i++)
        {
            if (_epolls[i].epfd == epfd)
            {
                fd0 = _epolls[i].wakefds[0];
                fd1 = _epolls[i].wakefds[1];
                _epolls[i] = _epolls[_num_epolls - 1];
                _num_epolls--;
                break;
            }
        }

        pthread_spin_unlock(&_epolls_lock);
    }

    if (fd0 != -1)
        close(fd0);

    if (fd1 != -1)
        close(fd1);

    return close((int)epfd);
}

