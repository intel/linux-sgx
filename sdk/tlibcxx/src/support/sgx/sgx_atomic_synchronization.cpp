/**
*   Copyright (C) 2011-2016 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <sgx_spinlock.h>
#include <atomic>

namespace {
    struct sgx_spinlock_array {
        static const size_t array_size = 97;
        sgx_spinlock_t array[array_size];

        sgx_spinlock_array() {
            for (size_t i = 0; i < array_size; i++) {
                array[i] = SGX_SPINLOCK_INITIALIZER;
            }
        }

        void lock(const std::sgx_lock_id_t& address) {
            uint32_t hash_value = hash(address) % array_size;
            sgx_spin_lock(&(array[hash_value]));
        }

        void unlock(const std::sgx_lock_id_t& address) {
            uint32_t hash_value = hash(address) % array_size;
            sgx_spin_unlock(&(array[hash_value]));
        }

    private:
        // Implementation from:
        // https://en.wikipedia.org/wiki/Jenkins_hash_function , based on
        // http://www.burtleburtle.net/bob/hash/doobs.html
        // License is public domain (it is ok)
        uint32_t hash(const std::sgx_lock_id_t & _key)
        {
            size_t key = static_cast<size_t> (_key);

            uint32_t hash_val, i;
            for (hash_val = i = 0; i < sizeof(size_t); ++i)
            {
                hash_val += (uint32_t)key & 0xFFu;
                key >>= 8;
                hash_val += (hash_val << 10);
                hash_val ^= (hash_val >> 6);
            }
            hash_val += (hash_val << 3);
            hash_val ^= (hash_val >> 11);
            hash_val += (hash_val << 15);
            return hash_val;
        }
    };
}

sgx_spinlock_array array;

void std::__libcpp_internal_sgx_lock(const sgx_lock_id_t & lock_id) {
    array.lock(lock_id);
}

void std::__libcpp_internal_sgx_unlock(const sgx_lock_id_t & lock_id) {
    array.unlock(lock_id);
}
