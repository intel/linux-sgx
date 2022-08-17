// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _DIRENT_H_
#define _DIRENT_H_

#include <bits/dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

/* struct dirent d_type values. */
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

typedef struct _DIR DIR;

/* 
 * opendir
 * Return value - outside enclave 
 * */
DIR* opendir(const char* pathname);

/* 
 * readdir
 * dir - [IN] outside enclave
 * return value - outside enclave 
 * */
struct dirent* readdir(DIR* dir);

/*
 * rewinddir
 * dir - [IN] outside enclave
 */
void rewinddir(DIR* dir);

/*
 * closedir
 * dir - [IN] outside enclave
 */
int closedir(DIR* dir);

int getdents64(unsigned int fd, struct dirent* dirp, unsigned int count);

/*
 * telldir
 * dir - [IN] outside enclave
 */
long telldir(DIR *dir);

/*
 * seekdir
 * dir - [IN] outside enclave
 */
void seekdir(DIR *dir, long loc);

/*
 * readdir64 
 * dir - [IN] outside enclave
 * return value - outside enclave
 */
struct dirent* readdir64(DIR* dir);

#ifdef __cplusplus
}
#endif


#endif /* _DIRENT_H_ */
