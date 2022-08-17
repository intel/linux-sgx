/*	$OpenBSD: unistd.h,v 1.62 2008/06/25 14:58:54 millert Exp $ */
/*	$NetBSD: unistd.h,v 1.26.4.1 1996/05/28 02:31:51 mrg Exp $	*/

/*-
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)unistd.h	5.13 (Berkeley) 6/17/91
 */

#ifndef _UNISTD_H_
#define	_UNISTD_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* access() mode flags. */
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1

/* lseek() whence parameters. */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define NGROUP_MAX 256

__BEGIN_DECLS

int getpagesize(void);

void * _TLIBC_CDECL_ sbrk(intptr_t);

int access(const char* pathname, int mode);

ssize_t read(int fd, void* buf, size_t count);

ssize_t write(int fd, const void* buf, size_t count);

int fchown(int fd, unsigned int uid, unsigned int gid);

off_t lseek(int fd, off_t offset, int whence);

ssize_t pread(int fd, void* buf, size_t count, off_t offset);

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset);

int truncate(const char* path, off_t length);

int ftruncate(int fd, off_t length);

int link(const char* oldpath, const char* newpath);

int unlink(const char* pathname);

int rmdir(const char* pathname);

/*
 * getcwd
 * return value - inside enclave. If buf is NULL, the memory needs to free when it's not needed
 */
char* getcwd(char* buf, size_t size);

int chdir(const char* path);

int close(int fd);

int gethostname(char* name, size_t len);

int getdomainname(char* name, size_t len);

unsigned int sleep(unsigned int seconds);

int nanosleep(struct timespec* req, struct timespec* rem);
int clock_nanosleep(
    clockid_t clockid,
    int flag,
    struct timespec* req,
    struct timespec* rem);

int fsync(int fd);
int fdatasync(int fd);

int dup(int fd);

int dup2(int fd, int newfd);

pid_t getpid(void);

pid_t getppid(void);

pid_t getpgrp(void);

uid_t getuid(void);

uid_t geteuid(void);

gid_t getgid(void);

gid_t getegid(void);

pid_t getpgid(pid_t pid);

int getgroups(int size, gid_t list[]);

long fpathconf(int fd, int name);

long pathconf(const char *path, int name);

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);

long sysconf(int name);

off_t lseek64(int fd, off_t offset, int whence);

ssize_t pread64(int fd, void* buf, size_t count, off_t offset);

ssize_t pwrite64(int fd, const void* buf, size_t count, off_t offset);

int ftruncate64(int fd, off_t length);


/*
 * Deprecated Non-C99. 
 */
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execl, const char *, const char *, ...);
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execlp, const char *, const char *, ...);
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execle, const char *, const char *, ...);
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execv, const char *, char * const *);
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execve, const char *, char * const *, char * const *);
_TLIBC_DEPRECATED_FUNCTION_(int _TLIBC_CDECL_, execvp, const char *, char * const *);

//_TLIBC_DEPRECATED_FUNCTION_(pid_t _TLIBC_CDECL_, fork, void); /* no pid_t */

__END_DECLS

#endif /* !_UNISTD_H_ */
