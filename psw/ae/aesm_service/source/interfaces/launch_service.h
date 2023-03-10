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

#ifndef LAUNCH_SERVICE_EXPORT_H
#define LAUNCH_SERVICE_EXPORT_H
#include "service.h"
#include "stdint.h"
#include "aesm_error.h"
#include "sgx_error.h"
#include "sgx_urts.h"
#include "arch.h"

struct ILaunchService : virtual public IService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 2};
    virtual ~ILaunchService() = default;

    virtual aesm_error_t get_launch_token(
        const uint8_t *mrenclave, uint32_t mrenclave_size,
        const uint8_t *public_key, uint32_t public_key_size,
        const uint8_t *se_attributes, uint32_t se_attributes_size,
        uint8_t *lictoken, uint32_t lictoken_size) = 0;
    virtual sgx_status_t get_launch_token(
        const enclave_css_t *signature,
        const sgx_attributes_t *attribute,
        sgx_launch_token_t *launch_token) = 0;
    virtual aesm_error_t white_list_register(
        const uint8_t *white_list_cert,
        uint32_t white_list_cert_size) = 0;
    virtual aesm_error_t get_white_list(
        uint8_t *white_list_cert, uint32_t buf_size) = 0;
    virtual aesm_error_t get_white_list_size(
        uint32_t *white_list_cert_size) = 0;
};

#endif /* LAUNCH_SERVICE_EXPORT_H */
