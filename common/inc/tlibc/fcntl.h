// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _FCNTL_H_
#define _FCNTL_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

#ifndef __pid_t_defined
typedef int pid_t;
# define __pid_t_defined
#endif

struct flock
{
    short l_type;
    short l_whence;
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
};

#define flock64 flock

struct f_owner_ex
{
    int type;
    pid_t pid;
};

#ifdef __cplusplus
extern "C" {
#endif

// For posix fcntl() and `l_type' field of a `struct flock'
# define F_RDLCK                0       // Read lock.
# define F_WRLCK                1       // Write lock.
# define F_UNLCK                2       // Remove lock.

#define O_RDONLY        000000000
#define O_WRONLY        000000001
#define O_RDWR          000000002
#define O_CREAT         000000100
#define O_EXCL          000000200
#define O_NOCTTY        000000400
#define O_TRUNC         000001000
#define O_APPEND        000002000
#define O_NONBLOCK      000004000
#define O_DSYNC         000010000
#define O_SYNC          004010000
#define O_RSYNC         004010000
#define O_DIRECTORY     000200000
#define O_NOFOLLOW      000400000
#define O_CLOEXEC       002000000
#define O_ASYNC         000020000
#define O_DIRECT        000040000
#define O_LARGEFILE     000000000
#define O_NOATIME       001000000
#define O_PATH          010000000
#define O_TMPFILE       020200000
#define O_NDELAY        O_NONBLOCK

#define F_DUPFD          0
#define F_GETFD          1
#define F_SETFD          2
#define F_GETFL          3
#define F_SETFL          4
#define F_GETLK          5
#define F_SETLK          6
#define F_SETLKW         7
#define F_SETOWN         8
#define F_GETOWN         9
#define F_SETSIG        10
#define F_GETSIG        11
#define F_GETLK64       F_GETLK
#define F_SETLK64       F_SETLK
#define F_SETLKW64      F_SETLKW
#define F_SETOWN_EX     15
#define F_GETOWN_EX     16
#define F_GETOWNER_UIDS 17
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200

int open(const char* pathname, int flags, mode_t mode);

int openat(int dirfd, const char* pathname, int flags, mode_t mode);

int fcntl(int fd, int cmd, ...);

int open64(const char* pathname, int flags, mode_t mode);

int openat64(int dirfd, const char* pathname, int flags, mode_t mode);

int fcntl64(int fd, int cmd, ...);

#ifdef __cplusplus
}
#endif

#endif /* _FCNTL_H_ */
