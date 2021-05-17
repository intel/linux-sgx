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


#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sgx_enclave_common.h"
#include "sgx_enclave_ss.h"
#include "sgx_enclave_blob.h"

#define SGX_PAGE_SIZE 0x1000

#define SGX_FLAGS_INITTED        0x0000000000000001ULL
#define SGX_FLAGS_DEBUG          0x0000000000000002ULL
#define SGX_FLAGS_MODE64BIT      0x0000000000000004ULL
#define SGX_FLAGS_PROVISION_KEY  0x0000000000000010ULL
#define SGX_FLAGS_EINITTOKEN_KEY 0x0000000000000020ULL

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 96
#define SGX_SECS_RESERVED4_SIZE 3836

/*SECS data structure*/
typedef struct _secs_t
{
    uint64_t size;
    uint64_t base;
    uint32_t ssaframesize;
    uint32_t miscselect;
    uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
    uint64_t attributes;
    uint64_t xfrm;
    uint32_t mrenclave[8];
    uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
    uint32_t mrsigner[8];
    uint8_t reserved3[SGX_SECS_RESERVED3_SIZE];
    uint16_t isvprodid;
    uint16_t isvsvn;
    uint8_t reserved4[SGX_SECS_RESERVED4_SIZE];
} secs_t;

extern "C" void sgx_get_token(void *req, void *entry);

static bool create_enclave(secs_t *secs)
{
    assert(secs != NULL);

    for (secs->size = SGX_PAGE_SIZE; secs->size < sgx_enclave_blob_length; )
        secs->size <<= 1;

    enclave_create_sgx_t create_ioc = {0};
    memcpy(create_ioc.secs, secs, SECS_SIZE);

    uint32_t enclave_error = ENCLAVE_ERROR_SUCCESS;
    void *enclave_base = enclave_create(NULL, (size_t)secs->size, sgx_enclave_blob_length, ENCLAVE_TYPE_SGX1, &create_ioc, sizeof(create_ioc), &enclave_error);

    if (enclave_error)
    {
        printf("create enclave error! error code - %#x\n", enclave_error);
        return false;
    }

    secs->base = (uint64_t)enclave_base;

    return true;
}

static bool add_enclave_page(secs_t *secs)
{
    assert(secs != NULL);

    uint32_t enclave_error = ENCLAVE_ERROR_SUCCESS;

    // load the TCS page
    enclave_load_data((void *)(secs->base), SGX_PAGE_SIZE, (void *)((uint64_t)sgx_enclave_blob), ENCLAVE_PAGE_THREAD_CONTROL | ENCLAVE_PAGE_READ | ENCLAVE_PAGE_WRITE, &enclave_error);

   if (enclave_error)
    {
        printf("add TCS page error! error code - %#x\n", enclave_error);
        return false;
    }

    // load the regular pages
    enclave_load_data((void *)(secs->base + SGX_PAGE_SIZE), sgx_enclave_blob_length - SGX_PAGE_SIZE, (void *)((uint64_t)sgx_enclave_blob + SGX_PAGE_SIZE), ENCLAVE_PAGE_READ | ENCLAVE_PAGE_WRITE | ENCLAVE_PAGE_EXECUTE, &enclave_error);

    if (enclave_error)
    {
        printf("add regular page error! error code - %#x\n", enclave_error);
        return false;
    }

    return true;
}

static bool init_enclave(secs_t *secs)
{
    assert(secs != NULL);

    enclave_init_sgx_t init_ioc = {0};
    memcpy(init_ioc.sigstruct, sgx_enclave_ss, SIGSTRUCT_SIZE);

    uint32_t enclave_error = ENCLAVE_ERROR_SUCCESS;
    enclave_initialize((void *)secs->base, &init_ioc, sizeof(init_ioc), &enclave_error);

    if (enclave_error)
    {
        printf("init enclave error! error code - %#x\n", enclave_error);
        return false;
    }

    return true;
}

static bool destroy_enclave(secs_t *secs)
{
    assert(secs != NULL);

    uint32_t enclave_error = ENCLAVE_ERROR_SUCCESS;
    enclave_delete((void*)secs->base, &enclave_error);

    if (enclave_error)
    {
        printf("destroy enclave error! error code - %#x\n", enclave_error);
        return false;
    }

    return true;
}

int main(void)
{
    secs_t secs;
    memset(&secs, 0, sizeof(secs));

    secs.ssaframesize = 1;
    secs.attributes = SGX_FLAGS_MODE64BIT | SGX_FLAGS_DEBUG;
    secs.xfrm = 3;

    if (false == create_enclave(&secs))
        return 1;

    if (false == add_enclave_page(&secs))
        return 1;

    if (false == init_enclave(&secs))
        return 1;

    // enclave is ready to use.
    sgx_get_token(NULL, (void *)secs.base);

    if (false == destroy_enclave(&secs))
        return 1;

    printf("Success!\n");

    return 0;
}
