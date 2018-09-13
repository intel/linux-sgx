/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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


#include "sgx_error.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"
#include "se_types.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include "urts_com.h"

static bool inline _check_ex_params_(const uint32_t ex_features, const void* ex_features_p[32])
{
    //update last feature index if it fails here
    se_static_assert(_SGX_LAST_EX_FEATURE_IDX_ == SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX);
    
    uint32_t i;

    if (ex_features_p != NULL)
    {
        for (i = 0; i <= _SGX_LAST_EX_FEATURE_IDX_; i++)
        {
            if (((ex_features & (1<<i)) == 0) && (ex_features_p[i] != NULL))
                return false;
        }

        for (i = _SGX_LAST_EX_FEATURE_IDX_ + 1; i < MAX_EX_FEATURES_COUNT; i++)
        {
            if (ex_features_p[i] != NULL)
                return false;
        }
    }
    
    return ((ex_features | _SGX_EX_FEATURES_MASK_) == _SGX_EX_FEATURES_MASK_);
}

extern "C" sgx_status_t __sgx_create_enclave_ex(const char *file_name, 
                                                const int debug, 
                                                sgx_launch_token_t *launch_token, 
                                                int *launch_token_updated, 
                                                sgx_enclave_id_t *enclave_id, 
                                                sgx_misc_attribute_t *misc_attr,
                                                const uint32_t ex_features,
                                                const void* ex_features_p[32])
{
    sgx_status_t ret = SGX_SUCCESS;

    //Only true or false is valid
    if(TRUE != debug &&  FALSE != debug)
        return SGX_ERROR_INVALID_PARAMETER;

    if (!_check_ex_params_(ex_features, ex_features_p))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    int fd = open(file_name, O_RDONLY);
    if(-1 == fd)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open the enclave file, error = %d\n", errno);
        return SGX_ERROR_ENCLAVE_FILE_ACCESS;
    }
    se_file_t file = {NULL, 0, false};
    char resolved_path[PATH_MAX];
    file.name = realpath(file_name, resolved_path);
    file.name_len = (uint32_t)strlen(resolved_path);

    ret = _create_enclave_ex(!!debug, fd, file, NULL, launch_token, launch_token_updated, enclave_id, misc_attr, ex_features, ex_features_p);
    if(SGX_SUCCESS != ret && misc_attr)
    {
        sgx_misc_attribute_t plat_cap;
        memset(&plat_cap, 0, sizeof(plat_cap));
        get_enclave_creator()->get_plat_cap(&plat_cap);
        memcpy_s(misc_attr, sizeof(sgx_misc_attribute_t), &plat_cap, sizeof(sgx_misc_attribute_t));
    }

    close(fd);

    return ret;
}

extern "C" sgx_status_t sgx_create_enclave(const char *file_name, 
                                           const int debug, 
                                           sgx_launch_token_t *launch_token, 
                                           int *launch_token_updated, 
                                           sgx_enclave_id_t *enclave_id, 
                                           sgx_misc_attribute_t *misc_attr) 
{
    return __sgx_create_enclave_ex(file_name, debug, launch_token, launch_token_updated, enclave_id, misc_attr, 0, NULL);
}


extern "C"  sgx_status_t sgx_create_enclave_ex(const char *file_name,
                                               const int debug,
                                               sgx_launch_token_t *launch_token,
                                               int *launch_token_updated,
                                               sgx_enclave_id_t *enclave_id,
                                               sgx_misc_attribute_t *misc_attr,
                                               const uint32_t ex_features,
                                               const void* ex_features_p[32])
{

    return __sgx_create_enclave_ex(file_name, debug, launch_token,
        launch_token_updated, enclave_id, misc_attr, ex_features, ex_features_p);
}


extern "C" sgx_status_t
sgx_create_encrypted_enclave(
    const char *file_name,
    const int debug,
    sgx_launch_token_t *launch_token,
    int *launch_token_updated,
    sgx_enclave_id_t *enclave_id,
    sgx_misc_attribute_t *misc_attr,
    uint8_t* sealed_key)
{
    uint32_t ex_features = SGX_CREATE_ENCLAVE_EX_PCL;
    const void* ex_features_p[32] = { 0 };
    ex_features_p[SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX] = (void*)sealed_key;

    return __sgx_create_enclave_ex(file_name, debug, launch_token,
        launch_token_updated, enclave_id, misc_attr, ex_features, ex_features_p);
}
