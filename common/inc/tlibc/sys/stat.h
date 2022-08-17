// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_STAT_H_
#define _SYS_STAT_H_

#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFIFO 0010000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000

#define S_ISDIR(mode) (((mode)&S_IFMT) == S_IFDIR)
#define S_ISCHR(mode) (((mode)&S_IFMT) == S_IFCHR)
#define S_ISBLK(mode) (((mode)&S_IFMT) == S_IFBLK)
#define S_ISREG(mode) (((mode)&S_IFMT) == S_IFREG)
#define S_ISFIFO(mode) (((mode)&S_IFMT) == S_IFIFO)
#define S_ISLNK(mode) (((mode)&S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode) (((mode)&S_IFMT) == S_IFSOCK)

#define S_ISUID 0x0800
#define S_ISGID 0x0400
#define S_ISVTX 0x0200
#define S_IRUSR 0x0100
#define S_IWUSR 0x0080
#define S_IXUSR 0x0040
#define S_IRGRP 0x0020
#define S_IWGRP 0x0010
#define S_IXGRP 0x0008
#define S_IROTH 0x0004
#define S_IWOTH 0x0002
#define S_IXOTH 0x0001
#define S_IRWXUSR (S_IRUSR | S_IWUSR | S_IXUSR)
#define S_IRWXGRP (S_IRGRP | S_IWGRP | S_IXGRP)
#define S_IRWXOTH (S_IROTH | S_IWOTH | S_IXOTH)
#define S_IRWUSR (S_IRUSR | S_IWUSR)
#define S_IRWGRP (S_IRGRP | S_IWGRP)
#define S_IRWOTH (S_IROTH | S_IWOTH)

typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef uint64_t nlink_t;
typedef uint32_t  mode_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef int64_t blksize_t;
typedef int64_t blkcnt_t;

struct stat
{
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    uint32_t __st_pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
};

#define R_OR 04
#define W_OR 02
#define X_OR 01

#ifndef st_atime
#define st_atime st_atim.tv_sec
#endif

#ifndef st_ctime
#define st_mtime st_mtim.tv_sec
#endif

#ifndef st_ctime
#define st_ctime st_ctim.tv_sec
#endif

#define stat64 stat
#define fstat64 fstat
#define lstat64 lstat

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
int stat(const char* pathname, struct stat* buf);
#pragma GCC diagnostic pop

int lstat(const char* pathname, struct stat* buf);

int fstat(int fd, struct stat* buf);

int mkdir(const char* pathname, mode_t mode);

int fchmod(int fd, mode_t mode);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_STAT_H_ */
