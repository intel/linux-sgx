// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _GRP_H_
#define _GRP_H_

#include "sys/cdefs.h"

struct group {
   char *gr_name;
   char *gr_passwd;
   gid_t gr_gid;
   char **gr_mem;
};

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * getgrgid_r
 * grp - [OUT] outside enclave, omalloc to allocate the buffer before the call to getgrgid_r
 * buf - [OUT] outside enclave, omalloc to allocate the buffer before the call to getgrgid_r
 * result - [OUT] inside enclave, *result is outside enclave
 */
int getgrgid_r(gid_t gid, struct group *grp,
               char *buf, size_t buflen, struct group **result);

#ifdef __cplusplus
}
#endif


#endif /* _GRP_H */
