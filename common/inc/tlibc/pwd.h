// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _PWD_H_
#define _PWD_H_

#include "sys/cdefs.h"

struct passwd {
   char *pw_name;
   char *pw_passwd;
   uid_t pw_uid;
   gid_t pw_gid;
   char *pw_gecos;
   char *pw_dir;
   char *pw_shell;
};

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * getpwuid
 * return value - outside enclave
 */
struct passwd *getpwuid(uid_t uid);

/* 
 * getpwuid_r
 * pwd - [OUT] outside enclave, omalloc to allocate the buffer before the call to getgrgid_r
 * buf - [OUT] outside enclave, omalloc to allocate the buffer before the call to getgrgid_r
 * result - [OUT] inside enclave, *result is outside enclave
 */
int getpwuid_r(uid_t uid, struct passwd *pwd,
               char *buf, size_t buflen, struct passwd **result);

#ifdef __cplusplus
}
#endif


#endif /* _PWD_H */
