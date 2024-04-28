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

#include <vector>
#include <pthread.h>
#include "sgx_tprotected_fs.h"
#include "sgx_tprotected_fs_t.h"
#include "protected_fs_file.h"
#include <tprotected_fs.h>


#include <sgx_trts.h>

bool protected_fs_file::flush()
{
	bool result = false;

	int32_t result32 = sgx_thread_mutex_lock(&mutex);
	if (result32 != 0)
	{
		last_error = result32;
		file_status = SGX_FILE_STATUS_MEMORY_CORRUPTED;
		return false;
	}

	if (file_status != SGX_FILE_STATUS_OK)
	{
		last_error = SGX_ERROR_FILE_BAD_STATUS;
		sgx_thread_mutex_unlock(&mutex);
		return false;
	}
	
	result = internal_flush();
	if (result == false)
	{
		assert(file_status != SGX_FILE_STATUS_OK);
		if (file_status == SGX_FILE_STATUS_OK)
			file_status = SGX_FILE_STATUS_FLUSH_ERROR; // for release set this anyway
	}

	sgx_thread_mutex_unlock(&mutex);

	return result;
}


bool protected_fs_file::internal_flush()
{
	if (need_writing == false) // no changes at all
		return true;

	if (encrypted_part_plain.size > MD_USER_DATA_SIZE && root_mht.need_writing == true) // otherwise it's just one write - the meta-data node
	{
		if (_RECOVERY_HOOK_(0) || write_recovery_file() != true)
		{
			file_status = SGX_FILE_STATUS_FLUSH_ERROR;
			return false;
		}

		if (_RECOVERY_HOOK_(1) || set_update_flag() != true)
		{
			file_status = SGX_FILE_STATUS_FLUSH_ERROR;
			return false;
		}

		if (_RECOVERY_HOOK_(2) || update_all_data_and_mht_nodes() != true)
		{
			file_status = SGX_FILE_STATUS_WRITE_TO_DISK_FAILED;
			return false;
		}
	}

	if (_RECOVERY_HOOK_(3) || update_meta_data_node() != true)
	{
		file_status = SGX_FILE_STATUS_WRITE_TO_DISK_FAILED;
		return false;
	}

	need_writing = false;

/* this is causing problems when we delete and create the file rapidly
   we will just leave the file, and re-write it every time
   u_sgxprotectedfs_fwrite_recovery_file opens it with 'w' so it is truncated
	if (encrypted_part_plain.size > MD_USER_DATA_SIZE)
	{
		erase_recovery_file();
	}
*/

	return true;
}


bool protected_fs_file::write_recovery_file()
{
	sgx_status_t status;
	uint8_t result = 0;
	std::vector<uint64_t> vec;

	void* data = NULL;

	for (data = cache.get_first() ; data != NULL ; data = cache.get_next())
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			file_data_node_t* file_data_node = (file_data_node_t*)data;
			if (file_data_node->need_writing == false || file_data_node->new_node == true)
				continue;

			vec.push_back(file_data_node->physical_node_number);
		}
		else
		{
			file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
			assert(file_mht_node->type == FILE_MHT_NODE_TYPE);
			if (file_mht_node->need_writing == false || file_mht_node->new_node == true)
				continue;

			vec.push_back(file_mht_node->physical_node_number);
		}
	}

	if (root_mht.need_writing == true && root_mht.new_node == false)
		vec.push_back(root_mht.physical_node_number);

	vec.push_back(meta_data_node_number);

	status = u_sgxprotectedfs_fwrite_recovery_file(&result, file_addr, recovery_filename, (uint64_t*)&vec[0], vec.size());
	if (status != SGX_SUCCESS || result != 0)
	{
		last_error = status != SGX_SUCCESS ? status : SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE;
		return false;
	}

	return true;
}


bool protected_fs_file::set_update_flag()
{
	if (file_addr == NULL || real_file_size < NODE_SIZE)
	{
		last_error = EIO;
		return false;
	}

	file_meta_data.plain_part.update_flag = 1;
	memcpy(file_addr, &file_meta_data, NODE_SIZE);
	file_meta_data.plain_part.update_flag = 0; // turn it off in memory. at the end of the flush, when we'll write the meta-data to disk, this flag will also be cleared there.

	return true;
}


// sort function, we need the mht nodes sorted before we start to update their gmac's
bool mht_order(const file_mht_node_t* first, const file_mht_node_t* second)
{// higher (lower tree level) node number first
	return first->mht_node_number > second->mht_node_number;
}


// 1. encrypt the changed data
// 2. set the IV+GMAC in the parent MHT
// [3. set the need_writing flag for all the parents]
void* update_data_nodes(void* thread_input)
{
	thread_input_t* input = (thread_input_t*)thread_input;
	uint8_t* addr = input->addr;
	uint8_t* empty_iv = input->empty_iv;
	thread_queue_t* que_elm;
	file_data_node_t* data_node;
	file_mht_node_t* mht_node;
	uint8_t temp_node[NODE_SIZE] = { 0 };
	gcm_crypto_data_t* gcm_crypto_data;
	uint8_t* file_data_node_addr;
	sgx_status_t status;

	while (true)
	{
		if (input->queue->empty())
		{
			memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
			return NULL;
		}
		que_elm = input->queue->front();
		input->queue->pop();

		data_node = (file_data_node_t*)que_elm->node;
		gcm_crypto_data = &data_node->parent->plain.data_nodes_crypto[data_node->data_node_number % ATTACHED_DATA_NODES_COUNT];
		file_data_node_addr = addr + NODE_SIZE * data_node->physical_node_number;

		// encrypt the data, this also saves the gmac of the operation in the mht crypto node
		status = sgx_rijndael128GCM_encrypt(&que_elm->key, data_node->plain.data, NODE_SIZE, temp_node,
											empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &gcm_crypto_data->gmac);
		if (status != SGX_SUCCESS)
		{
			input->error = status;
			memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE); // clear temp encrypted data in memory
			memset_s(que_elm->key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t)); // clear key in memory
			delete que_elm;
			return data_node;
		}

		memcpy(file_data_node_addr, temp_node, NODE_SIZE);
		memcpy(gcm_crypto_data->key, que_elm->key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this encryption
		memset_s(que_elm->key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t)); // clear key in memory
		delete que_elm;

		data_node->need_writing = false;
		data_node->new_node = false;

		mht_node = data_node->parent;
		// this loop should do nothing, add it here just to be safe
		while (mht_node->mht_node_number != 0)
		{
			assert(mht_node->need_writing == true);
			mht_node->need_writing = true; // just in case, for release
			mht_node = mht_node->parent;
		}
	}
}


bool protected_fs_file::multi_thread_update_data_nodes()
{
	uint64_t max_tnum = parallel_flush_level - 1;
	pthread_t threads[max_tnum];
	thread_input_t thread_inputs[max_tnum];
	uint32_t tnum = 0;
	int32_t result32;
	std::queue<thread_queue_t*> queue[max_tnum];
	thread_queue_t* queue_element;
	file_data_node_t* data_node;
	uint64_t node_cnt = 0;

	// should not happen, for safety purpose
	assert(last_error == 0);
	if (last_error)
		return false;

	// generate all the encryption keys in advance; save each key and data node
	for (void* node = cache.get_first(); node != NULL; node = cache.get_next())
	{
		data_node = (file_data_node_t*)node;
		if (data_node->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			if (data_node->need_writing == true)
			{
				if (derive_random_node_key(data_node->physical_node_number) == false)
					break;
				try {
					queue_element = new thread_queue_t;
				}
				catch (std::bad_alloc& e) {
					(void)e; // remove warning
					last_error = ENOMEM;
					break;
				}
				queue_element->node = node;
				memcpy(queue_element->key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key to local for parallel computing
				queue[node_cnt++ % max_tnum].push(queue_element);
			}
		}
	}

	// if error occurs in key generation or create queue element
	if (last_error != 0)
	{
		for (uint32_t i = 0; i < max_tnum; i++)
		{
			while (!queue[i].empty())
			{
				memset_s(queue[i].front()->key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t)); // clear key in memory
				delete queue[i].front();
				queue[i].pop();
			}
		}
		return false;
	}

	// start threads and record number of threads created
	for (tnum = 0; tnum < max_tnum && tnum < node_cnt; tnum++)
	{
		thread_inputs[tnum] = {0, file_addr, empty_iv, &queue[tnum]};
		result32 = pthread_create(&threads[tnum], NULL, &update_data_nodes, &thread_inputs[tnum]);
		if (result32 != 0)
		{
			last_error = (result32 == EAGAIN) ? SGX_ERROR_OUT_OF_TCS : result32;
			break;
		}
	}

	// wait threads to complete; if error occurs, only record the last thread error
	for (uint32_t i = 0; i < tnum; i++)
	{
		void* res;
		result32 = pthread_join(threads[i], &res);
		if (last_error == 0 && (result32 != 0 || res != NULL))
			last_error = (result32 != 0) ? result32 : thread_inputs[i].error;
	}

	// in case of error, queue may not be cleared
	for (uint32_t i = 0; i < tnum; i++)
	{
		while (!queue[i].empty())
		{
			memset_s(queue[i].front()->key, sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t)); // clear key in memory
			delete queue[i].front();
			queue[i].pop();
		}
	}

	if (last_error != 0)
		return false;

	return true;
}


bool protected_fs_file::single_thread_update_data_nodes()
{
	gcm_crypto_data_t* gcm_crypto_data;
	uint8_t* file_data_node_addr;
	file_data_node_t* data_node;
	file_mht_node_t* mht_node;
	uint8_t temp_node[NODE_SIZE] = { 0 };
	sgx_status_t status;
	void* data = cache.get_first();

	// 1. encrypt the changed data
	// 2. set the IV+GMAC in the parent MHT
	// [3. set the need_writing flag for all the parents]
	while (data != NULL)
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			data_node = (file_data_node_t*)data;

			if (data_node->need_writing == true)
			{
				if (derive_random_node_key(data_node->physical_node_number) == false)
				{
					memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
					return false;
				}

				gcm_crypto_data = &data_node->parent->plain.data_nodes_crypto[data_node->data_node_number % ATTACHED_DATA_NODES_COUNT];
				file_data_node_addr = file_addr + NODE_SIZE * data_node->physical_node_number;

				// encrypt the data, this also saves the gmac of the operation in the mht crypto node
				status = sgx_rijndael128GCM_encrypt(&cur_key, data_node->plain.data, NODE_SIZE, temp_node,
													empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &gcm_crypto_data->gmac);
				if (status != SGX_SUCCESS)
				{
					memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
					last_error = status;
					return false;
				}

				memcpy(file_data_node_addr, temp_node, NODE_SIZE);
				memcpy(gcm_crypto_data->key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this encryption

				data_node->need_writing = false;
				data_node->new_node = false;

				mht_node = data_node->parent;
				// this loop should do nothing, add it here just to be safe
				while (mht_node->mht_node_number != 0)
				{
					assert(mht_node->need_writing == true);
					mht_node->need_writing = true; // just in case, for release
					mht_node = mht_node->parent;
				}
			}
		}
		data = cache.get_next();
	}

	memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
	return true;
}


bool protected_fs_file::update_all_data_and_mht_nodes()
{
	std::list<file_mht_node_t*> mht_list;
	std::list<file_mht_node_t*>::iterator mht_list_it;
	file_mht_node_t* file_mht_node;
	uint8_t temp_node[NODE_SIZE] = { 0 };
	int32_t result32 = -1;
	sgx_status_t status;
	uint64_t max_node_number = 0;
	void* data = cache.get_first();

	// find the max physical node number and remap
	while (data != NULL)
	{
		if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) // type is in the same offset in both node types
		{
			file_data_node_t* data_node = (file_data_node_t*)data;
			if (data_node->need_writing == true)
				max_node_number = (max_node_number > data_node->physical_node_number) ? max_node_number : data_node->physical_node_number;
		}
		data = cache.get_next();
	}
	if ((uint64_t)real_file_size < NODE_SIZE * (max_node_number + 1))
	{
		status = u_sgxprotectedfs_file_remap(&result32, file_name, &file_addr, real_file_size, NODE_SIZE * (max_node_number + 1));
		if (status != SGX_SUCCESS || result32 != 0)
		{
			last_error = (status != SGX_SUCCESS) ? status :
					     (result32 != -1) ? result32 : EIO;
			return false;
		}
		real_file_size = NODE_SIZE * (max_node_number + 1);
	}

	if (parallel_flush_level <= 1)
	{
		if (single_thread_update_data_nodes() == false)
			return false;
	}
	else
	{
		if (multi_thread_update_data_nodes() == false)
			return false;
	}

	// add all the mht nodes that needs writing to a list
	data = cache.get_first();
	while (data != NULL)
	{
		if (((file_mht_node_t*)data)->type == FILE_MHT_NODE_TYPE) // type is in the same offset in both node types
		{
			file_mht_node = (file_mht_node_t*)data;

			if (file_mht_node->need_writing == true)
				mht_list.push_front(file_mht_node);
		}

		data = cache.get_next();
	}

	// sort the list from the last node to the first (bottom layers first)
	mht_list.sort(mht_order);

	// update the gmacs in the parents
	while ((mht_list_it = mht_list.begin()) != mht_list.end())
	{
		file_mht_node = *mht_list_it;

		gcm_crypto_data_t* gcm_crypto_data = &file_mht_node->parent->plain.mht_nodes_crypto[(file_mht_node->mht_node_number - 1) % CHILD_MHT_NODES_COUNT];
		uint8_t* file_mht_node_addr = file_addr + NODE_SIZE * file_mht_node->physical_node_number;

		if (derive_random_node_key(file_mht_node->physical_node_number) == false)
		{
			mht_list.clear();
			memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
			return false;
		}

		status = sgx_rijndael128GCM_encrypt(&cur_key, (const uint8_t*)&file_mht_node->plain, NODE_SIZE, temp_node,
											empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &gcm_crypto_data->gmac);
		if (status != SGX_SUCCESS)
		{
			mht_list.clear();
			memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
			last_error = status;
			return false;
		}

		memcpy(file_mht_node_addr, temp_node, NODE_SIZE);
		memcpy(gcm_crypto_data->key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this gmac

		file_mht_node->need_writing = false;
		file_mht_node->new_node = false;

		mht_list.pop_front();
	}

	// update mht root gmac in the meta data node
	if (derive_random_node_key(root_mht.physical_node_number) == false)
	{
		memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
		return false;
	}

	status = sgx_rijndael128GCM_encrypt(&cur_key, (const uint8_t*)&root_mht.plain, NODE_SIZE, temp_node,
										empty_iv, SGX_AESGCM_IV_SIZE, NULL, 0, &encrypted_part_plain.mht_gmac);
	if (status != SGX_SUCCESS)
	{
		memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
		last_error = status;
		return false;
	}

	memcpy(file_addr + NODE_SIZE, temp_node, NODE_SIZE);
	memcpy(&encrypted_part_plain.mht_key, cur_key, sizeof(sgx_aes_gcm_128bit_key_t)); // save the key used for this gmac

	root_mht.need_writing = false;
	root_mht.new_node = false;

	memset_s(temp_node, NODE_SIZE, 0, NODE_SIZE);
	return true;
}


bool protected_fs_file::update_meta_data_node()
{
	sgx_status_t status;
	
	// randomize a new key, saves the key _id_ in the meta data plain part
	if (generate_random_meta_data_key() != true)
	{
		// last error already set
		return false;
	}
		
	// encrypt meta data encrypted part, also updates the gmac in the meta data plain part
	status = sgx_rijndael128GCM_encrypt(&cur_key, 
										(const uint8_t*)&encrypted_part_plain, sizeof(meta_data_encrypted_t), (uint8_t*)&file_meta_data.encrypted_part, 
										empty_iv, SGX_AESGCM_IV_SIZE, 
										NULL, 0, 
										&file_meta_data.plain_part.meta_data_gmac);
	if (status != SGX_SUCCESS)
	{
		last_error = status;
		return false;
	}

	memcpy(file_addr, &file_meta_data, NODE_SIZE);

	return true;
}


void protected_fs_file::erase_recovery_file()
{
	sgx_status_t status;
	int32_t result32;

	if (recovery_filename[0] == '\0') // not initialized yet
		return;

	status = u_sgxprotectedfs_remove(&result32, recovery_filename);
	(void)status; // don't care if it succeeded or failed...just remove the warning
}


int32_t protected_fs_file::set_parallel_flush_level(uint32_t max_threads_number)
{
	if (max_threads_number == 0)
		return 1;

	parallel_flush_level = max_threads_number;
	return 0;
}
