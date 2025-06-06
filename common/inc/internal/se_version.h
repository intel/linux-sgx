/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifndef _SE_VERSION_H_
#define _SE_VERSION_H_

#define STRFILEVER    "2.26.100.0"
#define SGX_MAJOR_VERSION       2
#define SGX_MINOR_VERSION       26
#define SGX_REVISION_VERSION    100
#define MAKE_VERSION_UINT(major,minor,rev)  (((uint64_t)major)<<32 | ((uint64_t)minor) << 16 | rev)
#define VERSION_UINT        MAKE_VERSION_UINT(SGX_MAJOR_VERSION, SGX_MINOR_VERSION, SGX_REVISION_VERSION)

#define COPYRIGHT      "Copyright (C) 2025 Intel Corporation"

#define UAE_SERVICE_VERSION       "2.3.225.0"
#define URTS_VERSION              "2.0.109.0"
#define ENCLAVE_COMMON_VERSION    "1.2.109.0"
#define LAUNCH_VERSION            "1.0.127.0"
#define EPID_VERSION              "1.0.127.0"
#define QUOTE_EX_VERSION          "1.1.127.0"

#define PCE_VERSION               "1.25.100.1"
#define LE_VERSION                "1.25.100.1"
#define QE_VERSION                "1.25.100.1"
#define PVE_VERSION               "1.25.100.1"

#endif
