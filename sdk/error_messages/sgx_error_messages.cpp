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

#include "sgx_error_messages.h"

const char *sgx_create_enclave_err_msg(sgx_status_t err)
{
    switch (err) {
      case SGX_SUCCESS:
        return "The enclave was loaded and initialized successfully.";
        break;
      case SGX_ERROR_INVALID_ENCLAVE:
        return "The enclave file is corrupted.";
        break;
      case SGX_ERROR_INVALID_PARAMETER:
        return "The ‘enclave_id’, ‘updated’ or ‘token’ parameter is NULL.";
        break;
      case SGX_ERROR_OUT_OF_MEMORY:
        return "Not enough memory available to complete sgx_create_enclave().";
        break;
      case SGX_ERROR_ENCLAVE_FILE_ACCESS:
        return "The enclave file can’t be opened. It may be caused by enclave file not being found or no privilege to access the enclave file.";
        break;
      case SGX_ERROR_INVALID_METADATA:
        return "The metadata embedded within the enclave image is corrupt or missing.";
        break;
      case SGX_ERROR_INVALID_VERSION:
        return "The enclave metadata version (created by the signing tool) and the untrusted library version (uRTS) do not match.";
        break;
      case SGX_ERROR_INVALID_SIGNATURE:
        return "The signature for the enclave is not valid.";
        break;
      case SGX_ERROR_OUT_OF_EPC:
        return "The protected memory has run out. For example, a user is creating too many enclaves, the enclave requires too much memory, or we cannot load one of the Architecture Enclaves needed to complete this operation.";
        break;
      case SGX_ERROR_NO_DEVICE:
        return "The Intel SGX device is not valid. This may be caused by the Intel SGX driver not being installed or the Intel SGX driver being disabled.";
        break;
      case SGX_ERROR_MEMORY_MAP_CONFLICT:
        return "During enclave creation, there is a race condition for mapping memory between the loader and another thread. The loader may fail to map virtual address. If this errorcode is encountered, create the enclave again.";
        break;
      case SGX_ERROR_DEVICE_BUSY:
        return "The Intel SGX driver or low level system is busy when creating the enclave. If this error code is encountered, we suggest creating the enclave again.";
        break;
      case SGX_ERROR_MODE_INCOMPATIBLE:
        return "The target enclave mode is incompatible with the mode of the current RTS. For example, a 64-bit application tries to load a 32-bit enclave or a simulation uRTS tries to load a hardware enclave.";
        break;
      case SGX_ERROR_SERVICE_UNAVAILABLE:
        return "sgx_create_enclave() needs the AE service to get a launch token. If the service is not available, the enclave may not be launched.";
        break;
      case SGX_ERROR_SERVICE_TIMEOUT:
        return "The request to the AE service timed out.";
        break;
      case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
        return "The request requires some special attributes for the enclave, but is not privileged.";
        break;
      case SGX_ERROR_NDEBUG_ENCLAVE:
        return "The enclave is signed as a product enclave and cannot be created as a debuggable enclave.";
        break;
      case SGX_ERROR_UNDEFINED_SYMBOL:
        return "The enclave contains an undefined symbol. The signing tool should typically report this type of error when the enclave is built.";
        break;
      case SGX_ERROR_INVALID_MISC:
        return "The MiscSelct/MiscMask settings are not correct.";
        break;
      case SGX_ERROR_PCL_ENCRYPTED:
        return "PCL is not set in the input parameters, sgx_create_enclave is called, but the enclave is encrypted. PCL is set in the input parameters, while the enclave is not encrypted.";
        break;
      default:
        return "Unexpected error is detected.";
    }
}