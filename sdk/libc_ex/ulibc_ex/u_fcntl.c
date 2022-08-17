// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>

struct _stat_t
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
    int64_t st_blksize;
    int64_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
};

static void _stat_copy(const struct stat* st, struct _stat_t* buf)
{
    // Make sure unset members are zero.
    *buf = (struct _stat_t){0};

    buf->st_dev = st->st_dev;
    buf->st_ino = st->st_ino;
    buf->st_nlink = st->st_nlink;
    buf->st_mode = st->st_mode;
    buf->st_uid = st->st_uid;
    buf->st_gid = st->st_gid;
    buf->st_rdev = st->st_rdev;
    buf->st_size = st->st_size;
    buf->st_blksize = (int64_t)st->st_blksize;
    buf->st_blocks = (int64_t)st->st_blocks;
    buf->st_atim.tv_sec = st->st_atim.tv_sec;
    buf->st_atim.tv_nsec = st->st_atim.tv_nsec;
    buf->st_mtim.tv_sec = st->st_mtim.tv_sec;
    buf->st_mtim.tv_nsec = st->st_mtim.tv_nsec;
    buf->st_ctim.tv_sec = st->st_ctim.tv_sec;
    buf->st_ctim.tv_nsec = st->st_ctim.tv_nsec;
}

int u_fcntl (int fd, int cmd, int arg, uint64_t argsize, void* argout)
{
    errno = 0;
    (void)argsize;

    if (!argout)
    {
        return fcntl(fd, cmd, arg);
    }
    else
    {
        return fcntl(fd, cmd, argout);
    }
}

int u_open(const char* pathname, int flags, mode_t mode)
{
    errno = 0;

    return open(pathname, flags, mode);
}

int u_openat(int dirfd, const char* pathname, int flags, mode_t mode)
{
    errno = 0;

    return openat(dirfd, pathname, flags, mode);
}

int u_stat(const char *pathname, struct _stat_t *statbuf)
{
    int ret = -1;
    struct stat st;

    errno = 0;

    if (!statbuf)
        goto done;

    if ((ret = stat(pathname, &st)) == -1)
        goto done;

    _stat_copy(&st, statbuf);

done:
    return ret;
}

int u_lstat(const char *pathname, struct _stat_t *statbuf)
{
    int ret = -1;
    struct stat st;

    errno = 0;

    if (!statbuf)
        goto done;

    if ((ret = lstat(pathname, &st)) == -1)
        goto done;

    _stat_copy(&st, statbuf);

done:
    return ret;
}

int u_fstat(int fd, struct _stat_t *statbuf)
{
    int ret = -1;
    struct stat st;

    errno = 0;

    if (!statbuf)
        goto done;

    if ((ret = fstat(fd, &st)) == -1)
        goto done;

    _stat_copy(&st, statbuf);

done:
    return ret;
}

int u_fchmod(int fd, mode_t mode)
{
    errno = 0;

    return fchmod(fd, mode);
}

int u_mkdir(const char *pathname, mode_t mode)
{
    errno = 0;

    return mkdir(pathname, mode);
}

