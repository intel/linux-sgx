/**
*   Copyright(C) 2011-2016 Intel Corporation All Rights Reserved.
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

#pragma once

#ifndef _SGX_CAPABLE_H_
#define _SGX_CAPABLE_H_

#include "sgx_error.h"
#include "sgx_defs.h"

#if defined(_MSC_VER)
#include <Windows.h>
#endif

typedef enum _sgx_device_status_t {
    SGX_ENABLED,
    SGX_DISABLED_REBOOT_REQUIRED, /* A reboot is required to finish enabling SGX */
    SGX_DISABLED_LEGACY_OS, /* SGX is disabled and a Software Control Interface is not available to enable it */
    SGX_DISABLED, /* SGX is not enabled on this platform. More details are unavailable. */
    SGX_DISABLED_SCI_AVAILABLE, /* SGX is disabled, but a Software Control Interface is available to enable it */
    SGX_DISABLED_MANUAL_ENABLE, /* SGX is disabled, but can be enabled manually in the BIOS setup */
    SGX_DISABLED_HYPERV_ENABLED, /* Detected an unsupported version of Windows* 10 with Hyper-V enabled */
    SGX_DISABLED_UNSUPPORTED_CPU, /* SGX is not supported by this CPU */
} sgx_device_status_t;

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Function to check if the client platform is SGX enabled.
 *
 * @param sgx_capable[out] The SGX capable status of the client platform.
 *          1 - Platform is SGX enabled or the Software Control Interface is available to configure SGX
 *          0 - SGX not available
 * @return If the function succeeds, return SGX_SUCCESS, any other value indicates an error.
 */
sgx_status_t sgx_is_capable(int* sgx_capable);

/*
 * Function used to enable SGX device through EFI.
 *
 * @param sgx_device_status[out] The status of SGX device.
 * @return If the function succeeds, return SGX_SUCCESS, any other value indicates an error.
 */
sgx_status_t sgx_cap_enable_device(sgx_device_status_t* sgx_device_status);

/*
* Function used to query SGX device status.
*
* @param sgx_device_status[out] The status of SGX device. 
* @return If the function succeeds, return SGX_SUCCESS, any other value indicates an error.
*/
sgx_status_t SGXAPI sgx_cap_get_status(sgx_device_status_t* sgx_device_status);


/*
* Function used to query the version of PSW installed.
*
* @param version_string[out] The version of PSW installed on the system, in string format.
* @param version_string_len[in out] When version_string is not NULL, version_string_len is
*           interpreted to be the length of version_string. If version_string_len is
*           smaller than the buffer length needed, or if a NULL pointer is passed
*           in version_string, version_string_len returns the number of characters
*           required to hold the version string.
*
* @return If the function succeeds, return SGX_SUCCESS and the length of the string in
*         version_string_len (not including NULL). SGX_ERROR_OUT_OF_MEMORY is returned if
*         the buffer is too small or NULL, and the length required is in version_string_len.
*         SGX_ERROR_SERVICE_UNAVAILABLE indicates the PSW is not installed. Any other value
*         indicates an error.
*/
#if defined(_MSC_VER)
#ifdef UNICODE
#define sgx_cap_get_psw_version_string sgx_cap_get_psw_version_stringw
#else
#define sgx_cap_get_psw_version_string sgx_cap_get_psw_version_stringa
#endif
sgx_status_t SGXAPI sgx_cap_get_psw_version_stringw(LPWSTR version_string, DWORD *version_string_len);
sgx_status_t SGXAPI sgx_cap_get_psw_version_stringa(LPSTR version_string, DWORD *version_string_len);
#endif

#ifdef  __cplusplus
}
#endif

#endif

