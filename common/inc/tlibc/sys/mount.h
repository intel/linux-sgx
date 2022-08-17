// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_MOUNT_H_
#define _SYS_MOUNT_H_

#ifdef __cplusplus
extern "C" {
#endif

int mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data);

int umount(const char* target);

int umount2(const char* target, int flags);

#ifdef __cplusplus
}
#endif


#endif /* _SYS_MOUNT_H_ */
