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

#include "sgx_tprotected_fs.h"
#include "sgx_tprotected_fs_t.h"
#include "protected_fs_file.h"

#include <sgx_utils.h>
//#include <sgx_trts.h>

#include <errno.h>

// this function returns 0 only if the specified file existed and it was actually deleted
// before we do that, we try to see if the file contained a monotonic counter, and if it did, we delete it from the system
int32_t protected_fs_file::remove(const char* filename)
{
	sgx_status_t status;
	int32_t result32 = 0;
	
	// do the actual file removal
	status = u_sgxprotectedfs_remove(&result32, filename);
	if (status != SGX_SUCCESS) 
	{
		errno = status;
		return 1;
	}

	if (result32 != 0)
	{
		if (result32 == -1) // no external errno value
			errno = EPERM;
		else
			errno = result32;

		return 1;
	}

	return 0;
}


int64_t protected_fs_file::tell()
{
	int64_t result;

	sgx_thread_mutex_lock(&mutex);

	if (file_status != SGX_FILE_STATUS_OK)
	{
		errno = EPERM;
		last_error = SGX_ERROR_FILE_BAD_STATUS;
		sgx_thread_mutex_unlock(&mutex);
		return -1;
	}

	result = offset;

	sgx_thread_mutex_unlock(&mutex);

	return result;
}


// we don't support sparse files, fseek beyond the current file size will fail
int protected_fs_file::seek(int64_t new_offset, int origin)
{
	sgx_thread_mutex_lock(&mutex);

	if (file_status != SGX_FILE_STATUS_OK)
	{
		last_error = SGX_ERROR_FILE_BAD_STATUS;
		sgx_thread_mutex_unlock(&mutex);
		return -1;
	}

	int result = -1;

	switch (origin)
	{
	case SEEK_SET:
		if (new_offset >= 0 && new_offset <= encrypted_part_plain.size)
		{
			offset = new_offset;
			result = 0;
		}
		break;

	case SEEK_CUR:
		if ((offset + new_offset) >= 0 && (offset + new_offset) <= encrypted_part_plain.size)
		{
			offset += new_offset;
			result = 0;
		}
		break;

	case SEEK_END:
		if (new_offset <= 0 && new_offset >= (0 - encrypted_part_plain.size))
		{
			offset = encrypted_part_plain.size + new_offset;
			result = 0;
		}
		break;

	default: 
		break;
	}

	if (result == 0)
		end_of_file = false;
	else
		last_error = EINVAL;

	sgx_thread_mutex_unlock(&mutex);

	return result;
}


uint32_t protected_fs_file::get_error()
{
	uint32_t result = SGX_SUCCESS;

	sgx_thread_mutex_lock(&mutex);

	if (last_error != SGX_SUCCESS)
		result = last_error;
	else if (file_status != SGX_FILE_STATUS_OK)
		result = SGX_ERROR_FILE_BAD_STATUS;

	sgx_thread_mutex_unlock(&mutex);

	return result;
}


bool protected_fs_file::get_eof()
{
	return end_of_file;
}


void protected_fs_file::clear_error()
{
	sgx_thread_mutex_lock(&mutex);

	if (file_status == SGX_FILE_STATUS_NOT_INITIALIZED ||
		file_status == SGX_FILE_STATUS_CLOSED ||
		file_status == SGX_FILE_STATUS_WRITE_TO_DISK_FAILED ||
		file_status == SGX_FILE_STATUS_CRYPTO_ERROR ||
		file_status == SGX_FILE_STATUS_CORRUPTED ||
		file_status == SGX_FILE_STATUS_MEMORY_CORRUPTED) // can't fix these...
	{
		sgx_thread_mutex_unlock(&mutex);
		return;
	}

	if (file_status == SGX_FILE_STATUS_FLUSH_ERROR)
	{
		if (internal_flush() == true)
			file_status = SGX_FILE_STATUS_OK;
	}
	
	if (file_status == SGX_FILE_STATUS_OK)
	{
		last_error = SGX_SUCCESS;
		end_of_file = false;
	}
	sgx_thread_mutex_unlock(&mutex);
}


// clears the cache with all the plain data that was in it
// doesn't clear the meta-data and first node, which are part of the 'main' structure
int32_t protected_fs_file::clear_cache()
{
	sgx_thread_mutex_lock(&mutex);

	if (file_status != SGX_FILE_STATUS_OK)
	{
		sgx_thread_mutex_unlock(&mutex);
		clear_error(); // attempt to fix the file, will also flush it
		sgx_thread_mutex_lock(&mutex);
	}
	else // file_status == SGX_FILE_STATUS_OK
	{
		internal_flush();
	}

	if (file_status != SGX_FILE_STATUS_OK) // clearing the cache might lead to losing un-saved data
	{
		sgx_thread_mutex_unlock(&mutex);
		return 1;
	}

	while (cache.size() > 0)
	{
		void* data = cache.get_last();

		assert(data != NULL);
		assert(((file_data_node_t*)data)->need_writing == false); // need_writing is in the same offset in both node types
		// for production - 
		if (data == NULL || ((file_data_node_t*)data)->need_writing == true)
		{
			sgx_thread_mutex_unlock(&mutex);
			return 1;
		}
		
		cache.remove_last();

		// before deleting the memory, need to scrub the plain secrets
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			file_data_node_t* file_data_node = (file_data_node_t*)data;
			memset_s(&file_data_node->plain, sizeof(data_node_t), 0, sizeof(data_node_t));
			delete file_data_node;
		}
		else
		{
			file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
			memset_s(&file_mht_node->plain, sizeof(mht_node_t), 0, sizeof(mht_node_t));
			delete file_mht_node;
		}
	}

	sgx_thread_mutex_unlock(&mutex);

	return 0;
}
