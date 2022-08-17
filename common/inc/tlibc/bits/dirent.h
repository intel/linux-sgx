// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _BITS_DIRENT_H_
#define _BITS_DIRENT_H_

#include <sys/types.h>

struct dirent
{
    uint64_t d_ino;
    off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[256];
};

#endif
