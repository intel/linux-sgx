#ifndef	_POLL_H_
#define	_POLL_H_

#include "sys/bits/sigset.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008
#define POLLHUP    0x010
#define POLLNVAL   0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#ifndef POLLWRNORM
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200
#endif
#ifndef POLLMSG
#define POLLMSG    0x400
#define POLLRDHUP  0x2000
#endif

typedef unsigned long nfds_t;

struct pollfd {
    int fd;
    short events;
    short revents;
};

// Poll the file descriptors described by the NFDS structures starting at
// FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
// an event to occur; if TIMEOUT is -1, block until an event occurs.
// Returns the number of file descriptors with events, zero if timed out,
// or -1 for errors.
int poll (struct pollfd *fds, nfds_t nfds, int timeout);
// sigmask must be NULL, ppoll behaves same as poll
int ppoll(struct pollfd *fds, nfds_t nfds,
               const struct timespec *tmo_p, const sigset_t *sigmask);

#ifdef __cplusplus
}
#endif

#endif
