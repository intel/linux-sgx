/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
#include "se_types.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "file.h"
#include "se_wrapper.h"
#include "se_map.h"
#include "edmm_utility.h"
#include "uae_service_internal.h"


extern sgx_status_t _create_enclave(const bool debug, se_file_handle_t pfile, se_file_t& file, le_prd_css_file_t *prd_css_file, sgx_launch_token_t *launch, int *launch_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr);

extern func_get_launch_token_t get_launch_token_func;

extern "C" void init_get_launch_token(const func_get_launch_token_t func)
{
    get_launch_token_func = func;
}


extern "C" sgx_status_t sgx_create_le(const char* file_name, const char* prd_css_file_name, const int debug, sgx_launch_token_t *launch_token, int *launch_token_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr, int *production_loaded)
{
    sgx_status_t ret = SGX_SUCCESS;

    //Only true or false is valid
    if(TRUE != debug &&  FALSE != debug)
        return SGX_ERROR_INVALID_PARAMETER;

    int fd = open(file_name, O_RDONLY);
    if(-1 == fd)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open the enclave file, error = %d\n", errno);
        return SGX_ERROR_ENCLAVE_FILE_ACCESS;
    }
    se_file_t file = {NULL, 0, false};
    char resolved_path[PATH_MAX] = {0};
    file.name = realpath(file_name, resolved_path);
    file.name_len = (uint32_t)strlen(resolved_path);

    char css_real_path[PATH_MAX] = {0};

    le_prd_css_file_t prd_css_file = {NULL, false};
    prd_css_file.prd_css_name = realpath(prd_css_file_name, css_real_path);

    ret = _create_enclave(!!debug, fd, file, &prd_css_file, launch_token, launch_token_updated, enclave_id, misc_attr);
    close(fd);
    if(ret == SGX_SUCCESS && production_loaded != NULL)
    {
        *production_loaded = prd_css_file.is_used ? 1: 0;
    }

    return ret;
}

extern "C" bool is_launch_token_required()
{
    //noly out of tree driver need to get launch token
    return is_out_of_tree_driver();
}


#include "binparser.h"
#ifndef PARSER
#include "elfparser.h"
#define PARSER ElfParser
#endif

static bool get_metadata_internal(BinParser *parser, metadata_t **metadata)
{
    if (parser == NULL || metadata == NULL)
        return false;
    uint64_t meta_rva = parser->get_metadata_offset();
    const uint8_t *base_addr = parser->get_start_addr();
    uint64_t urts_version = META_DATA_MAKE_VERSION(MAJOR_VERSION,MINOR_VERSION);
    metadata_t *target_metadata = NULL;

    //assume AE only contains one metadata
    *metadata = GET_PTR(metadata_t, base_addr, meta_rva);

    if(metadata == NULL)
    {
        return false;
    }
    if((*metadata)->magic_num != METADATA_MAGIC)
    {
        return false;
    }
    if(0 == (*metadata)->size)
    {
        SE_TRACE(SE_TRACE_ERROR, "ERROR: metadata's size can't be zero.\n");
        return false;
    }
    //check metadata version
    if(MAJOR_VERSION_OF_METADATA(urts_version) >=
       MAJOR_VERSION_OF_METADATA((*metadata)->version))
    {
        if(target_metadata == NULL ||
           target_metadata->version < (*metadata)->version)
        {
            target_metadata = *metadata;
        }
    }
    if(target_metadata == NULL )
    {
        return false;
    }
    else
    {
        *metadata = target_metadata;
    }
    return true;
}

extern "C" bool get_metadata(const char* enclave_file, metadata_t *metadata)
{
    map_handle_t* mh = NULL;
    metadata_t *p_metadata;

    off_t file_size = 0;
    int fd = open(enclave_file, O_RDONLY);
    if(-1 == fd)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open the enclave file, error = %d\n", errno);
        return false;
    }


    mh = map_file(fd, &file_size);
    if (!mh)
    {
        close(fd);
        return false;
    }

    PARSER parser(const_cast<uint8_t *>(mh->base_addr), (uint64_t)(file_size));
    if(SGX_SUCCESS != parser.run_parser())
    {
        unmap_file(mh);
        close(fd);
        return false;
    }

    if(true != get_metadata_internal(&parser, &p_metadata))
    {
        unmap_file(mh);
        close(fd);
        return false;
    }
    memcpy(metadata, p_metadata, sizeof(metadata_t));
    unmap_file(mh);
    close(fd);
    return true;
}
