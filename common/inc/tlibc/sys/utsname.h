// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_UTSNAME_H_
#define _SYS_UTSNAME_H_

// _UTSNAME_FIELD_SIZE == 65
struct utsname
{
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};
 
#ifdef __cplusplus
extern "C" {
#endif

int uname(struct utsname* buf);

#ifdef __cplusplus
}
#endif


#endif /* _SYS_UTSNAME_H_ */
