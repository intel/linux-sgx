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

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <errno.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "sgx_tprotected_fs_u.h"
#include "../sgx_tprotected_fs/protected_fs_nodes.h"
#include <uprotected_fs.h>


#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "[sgx_uprotected_fs.h:%d] " fmt, __LINE__, ##args)
#else
#define DEBUG_PRINT(...)
#endif


int8_t u_sgxprotectedfs_check_if_file_exists(const char* filename)
{
	struct stat stat_st;
	
	memset(&stat_st, 0, sizeof(struct stat));

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		return -EINVAL;
	}
	
	return (stat(filename, &stat_st) == 0); 
}


uint8_t* u_sgxprotectedfs_exclusive_file_map(const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	void* f_addr = NULL;
	int64_t f_size = 0;
	int result = 0;
	int fd = -1;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	struct stat stat_st;

	memset(&stat_st, 0, sizeof(struct stat));

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		*error_code = EINVAL;
		return NULL;
	}

	// open the file with OS API so we can 'lock' the file and get exclusive access to it
	fd = open(filename,	O_CREAT | (read_only ? O_RDONLY : O_RDWR) | O_LARGEFILE, mode); // create the file if it doesn't exists, read-only/read-write
	if (fd == -1)
	{
		DEBUG_PRINT("open returned -1, errno %d\n", errno);
		*error_code = errno;
		return NULL;
	}

	// this lock is advisory only and programs with high priviliges can ignore it
	// it is set to help the user avoid mistakes, but it won't prevent intensional DOS attack from priviliged user
	result = flock(fd, (read_only ? LOCK_SH : LOCK_EX) | LOCK_NB); // NB - non blocking
	if (result != 0)
	{
		DEBUG_PRINT("flock returned %d, errno %d\n", result, errno);
		*error_code = errno;
		result = close(fd);
		assert(result == 0);
		return NULL;
	}

	result = fstat(fd, &stat_st);
	if (result != 0)
	{
		DEBUG_PRINT("fstat returned %d, errno %d\n", result, errno);
		*error_code = errno;
		flock(fd, LOCK_UN);
		result = close(fd);
		assert(result == 0);
		return NULL;
	}

	f_size = stat_st.st_size;
	if (f_size == 0) // in case of new file, append size of node_size
	{
		result = ftruncate(fd, NODE_SIZE);
		if (result != 0)
		{
			DEBUG_PRINT("ftruncate returned %d, errno %d\n", result, errno);
			*error_code = errno;
			flock(fd, LOCK_UN);
			result = close(fd);
			assert(result == 0);
			return NULL;
		}

		f_size = NODE_SIZE;
	}

	f_addr = mmap(NULL, f_size, PROT_READ | (read_only ? 0 : PROT_WRITE), MAP_SHARED, fd, 0);
	if (f_addr == MAP_FAILED)
	{
		DEBUG_PRINT("mmap returned MAP_FAILED, errno %d\n", errno);
		flock(fd, LOCK_UN);
		result = close(fd);
		assert(result == 0);
		return NULL;
	}

	result = close(fd);
	if (result != 0)
	{
		DEBUG_PRINT("close returned %d, errno: %d\n", result, errno);
		munmap(f_addr, f_size);
		flock(fd, LOCK_UN);
		return NULL;
	}

	if (file_size != NULL)
		*file_size = stat_st.st_size; // file_size=0 to indicate new file, althrough actural size is NODE_SIZE

	return (uint8_t*)f_addr;
}


int32_t u_sgxprotectedfs_file_remap(const char* filename, uint8_t** file_addr, int64_t old_size, int64_t new_size)
{
	void* f_new_addr = NULL;
	int result = 0;

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		return -1;
	}

	if (file_addr == NULL || *file_addr == NULL)
	{
		DEBUG_PRINT("file address is NULL\n");
		return -1;
	}

	if (new_size == old_size)
	{
		DEBUG_PRINT("file size not changed\n");
		return -1;
	}

	result = truncate(filename, new_size);
	if (result != 0)
	{
		int err = errno;
		DEBUG_PRINT("truncate returned %d, errno %d\n", result, err);
		return err ? err : -1;
	}

	f_new_addr = mremap(*file_addr, old_size, new_size, MREMAP_MAYMOVE);
	if (f_new_addr == MAP_FAILED)
	{
		int err = errno;
		DEBUG_PRINT("mremap returned MAP_FAILED, errno %d\n", err);
		return err ? err : -1;
	}

	*file_addr = (uint8_t*)f_new_addr;

	return 0;
}


int32_t u_sgxprotectedfs_file_unmap(uint8_t* file_addr, int64_t file_size)
{
	int result = 0;

	if (file_addr == NULL)
	{
		DEBUG_PRINT("file address is NULL\n");
		return -1;
	}

	if ((result = munmap(file_addr, file_size)) != 0)
	{
		int err = errno;
		DEBUG_PRINT("munmap returned %d, errno: %d\n", result, err);
		return err ? err : -1;
	}

	return 0;
}


int32_t u_sgxprotectedfs_remove(const char* filename)
{
	int result;

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		return -1;
	}

	if ((result = remove(filename)) != 0)
	{// this function is called from the destructor which is called when calling fclose, if there were no writes, there is no recovery file...we don't want endless prints...
		//DEBUG_PRINT("remove returned %d\n", result);
		if (errno != 0)
			return errno;
		return -1;
	}
	
	return 0;
}

#define MILISECONDS_SLEEP_FOPEN 10
#define MAX_FOPEN_RETRIES       10
uint8_t u_sgxprotectedfs_fwrite_recovery_file(uint8_t* fileaddress, const char* filename, uint64_t* recovery_list, uint64_t length)
{
	FILE* f = NULL;
	size_t count = 0;
	int result = 0;

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("recovery filename is NULL or empty\n");
		return 1;
	}

	for (int i = 0; i < MAX_FOPEN_RETRIES; i++)
	{
		f = fopen(filename, "wb");
		if (f != NULL)
			break;
		usleep(MILISECONDS_SLEEP_FOPEN);
	}

	if (f == NULL)
	{
		DEBUG_PRINT("fopen (%s) returned NULL\n", filename);
		return 1;
	}

	for (uint64_t i = 0; i < length; i++)
	{
		// write physical_node_number of recovery_node
		if ((count = fwrite(recovery_list + i, 1, sizeof(uint64_t), f)) != sizeof(uint64_t))
		{
			DEBUG_PRINT("fwrite returned %ld instead of %ld\n", count, sizeof(uint64_t));
			result = fclose(f);
			assert(result == 0);
			result = remove(filename);
			assert(result == 0);
			return 1;
		}
		// write node_data of the recovery_node
		if ((count = fwrite(fileaddress + recovery_list[i] * NODE_SIZE, 1, NODE_SIZE, f)) != NODE_SIZE)
		{
			DEBUG_PRINT("fwrite returned %ld instead of %d\n", count, NODE_SIZE);
			result = fclose(f);
			assert(result == 0);
			result = remove(filename);
			assert(result == 0);
			return 1;
		}
	}

	if ((result = fclose(f)) != 0)
	{
		DEBUG_PRINT("fclose returned %d\n", result);
		return 1;
	}

	return 0;
}


int32_t u_sgxprotectedfs_do_file_recovery(const char* filename, const char* recovery_filename)
{
	FILE* recovery_file = NULL;
	FILE* source_file = NULL;
	int32_t ret = -1;
	uint32_t nodes_count = 0;
	uint32_t recovery_node_size = (uint32_t)(sizeof(uint64_t)) + NODE_SIZE; // node offset + data
	uint64_t file_size = 0;
	int err = 0;
	int result = 0;
	size_t count = 0;
	uint8_t* recovery_node = NULL;
	uint32_t i = 0;

	do 
	{
		if (filename == NULL || strnlen(filename, 1) == 0)
		{
			DEBUG_PRINT("filename is NULL or empty\n");
			return (int32_t)NULL;
		}

		if (recovery_filename == NULL || strnlen(recovery_filename, 1) == 0)
		{
			DEBUG_PRINT("recovery filename is NULL or empty\n");
			return (int32_t)NULL;
		}
	
		recovery_file = fopen(recovery_filename, "rb");
		if (recovery_file == NULL)
		{
			DEBUG_PRINT("fopen of recovery file returned NULL - no recovery file exists\n");
			ret = -1;
			break;
		}

		if ((result = fseeko(recovery_file, 0, SEEK_END)) != 0)
		{
			DEBUG_PRINT("fseeko returned %d\n", result);
			if (errno != 0)
				ret = errno;
			break;
		}

		file_size = ftello(recovery_file);
	
		if ((result = fseeko(recovery_file, 0, SEEK_SET)) != 0)
		{
			DEBUG_PRINT("fseeko returned %d\n", result);
			if (errno != 0)
				ret = errno;
			break;
		}

		if (file_size % recovery_node_size != 0)
		{
			// corrupted recovery file
			DEBUG_PRINT("recovery file size is not the right size [%lu]\n", file_size);
			ret = ENOTSUP;
			break;
		}

		nodes_count = (uint32_t)(file_size / recovery_node_size);

		recovery_node = (uint8_t*)malloc(recovery_node_size);
		if (recovery_node == NULL)
		{
			DEBUG_PRINT("malloc failed\n");
			ret = ENOMEM;
			break;
		}

		source_file = fopen(filename, "r+b");
		if (source_file == NULL)
		{
			DEBUG_PRINT("fopen returned NULL\n");
			ret = -1;
			break;
		}

		for (i = 0 ; i < nodes_count ; i++)
		{
			if ((count = fread(recovery_node, recovery_node_size, 1, recovery_file)) != 1)
			{
				DEBUG_PRINT("fread returned %ld [!= 1]\n", count);
				err = ferror(recovery_file);
				if (err != 0)
					ret = err;
				else if (errno != 0) 
					ret = errno;
				break;
			}

			// seek the regular file to the required offset
			if ((result = fseeko(source_file, (*((uint64_t*)recovery_node)) * NODE_SIZE, SEEK_SET)) != 0)
			{
				DEBUG_PRINT("fseeko returned %d\n", result);
				if (errno != 0)
					ret = errno;
				break;
			}

			// write down the original data from the recovery file
			if ((count = fwrite(&recovery_node[sizeof(uint64_t)], NODE_SIZE, 1, source_file)) != 1)
			{
				DEBUG_PRINT("fwrite returned %ld [!= 1]\n", count);
				err = ferror(source_file);
				if (err != 0)
					ret = err;
				else if (errno != 0) 
					ret = errno;
				break;
			}
		}

		if (i != nodes_count) // the 'for' loop exited with error
			break;

		if ((result = fflush(source_file)) != 0)
		{
			DEBUG_PRINT("fflush returned %d\n", result);
			ret = result;
			break;
		}

		ret = 0;

	} while(0);

	if (recovery_node != NULL)
		free(recovery_node);

	if (source_file != NULL)
	{
		result = fclose(source_file);
		assert(result == 0);
	}

	if (recovery_file != NULL)
	{
		result = fclose(recovery_file);
		assert(result == 0);
	}

	if (ret == 0)
	{
		result = remove(recovery_filename);
		assert(result == 0);
	}
	
	return ret;
}
