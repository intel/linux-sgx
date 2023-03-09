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

#ifndef NETWORK_SERVICE_EXPORT_H
#define NETWORK_SERVICE_EXPORT_H
#include "service.h"
#include "stdint.h"
#include "aeerror.h"
#include "aesm_error.h"


typedef enum _network_protocol_type_t
{
	HTTP = 0,
	HTTPS,
} network_protocol_type_t;

typedef enum _http_methods_t
{
	GET = 0,
	POST,
} http_methods_t;

struct INetworkService : virtual public IService
{
    // The value should be the same as the major version in manifest.json
    enum {VERSION = 2};
    virtual ~INetworkService() = default;

    virtual ae_error_t aesm_send_recv_msg(
        const char *url,
        const uint8_t *msg,
        uint32_t msg_size,
        uint8_t* &resp_msg,
        uint32_t& resp_size,
        http_methods_t type,
        bool is_ocsp) = 0;

    virtual void aesm_free_response_msg(
        uint8_t *resp) = 0;
        
    virtual ae_error_t aesm_send_recv_msg_encoding(
        const char *url,
        const uint8_t *msg,
        uint32_t msg_size,
        uint8_t* &resp,
        uint32_t& resp_size) = 0;
};

#endif /* NETWORK_SERVICE_EXPORT_H */
