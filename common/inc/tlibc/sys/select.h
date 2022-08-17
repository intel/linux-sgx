#ifndef _SYS_SELECT_H_
#define _SYS_SELECT_H_

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FD_SETSIZE 1024

typedef unsigned long fd_mask;

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

#define FD_ZERO(s) do { int __i; unsigned long *__b=(s)->fds_bits; for(__i=sizeof (fd_set)/sizeof (long); __i; __i--) *__b++=0; } while(0)
#define FD_SET(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] |= (1UL<<((d)%(8*sizeof(long)))))
#define FD_CLR(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] &= ~(1UL<<((d)%(8*sizeof(long)))))
#define FD_ISSET(d, s) !!((s)->fds_bits[(d)/(8*sizeof(long))] & (1UL<<((d)%(8*sizeof(long)))))

// Check the first NFDS descriptors each in READFDS (if not NULL) for read
// readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
// (if not NULL) for exceptional conditions.  If TIMEOUT is not NULL, time out
// after waiting the interval specified therein.
// Returns the number of ready descriptors, or -1 for errors.
int select (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		    struct timeval *timeout);

#define NFDBITS (8*(int)sizeof(long))

#ifdef __cplusplus
}
#endif
#endif
