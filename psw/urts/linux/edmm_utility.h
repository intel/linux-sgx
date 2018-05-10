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


#ifndef _EDMM_UTILITY_H_
#define _EDMM_UTILITY_H_

#ifdef __cplusplus
extern "C" {
#endif

/* open_se_device()
 * Parameters:
 *      hdevice [out] - The device handle as returned from the open_se_device API.
 *      in_kernel_driver [out] - Indicate it is in-kernel driver or not.
 * Return Value:
 *      true - The function succeeds.
 *      false - The function fails.
*/
bool open_se_device(int *hdevice, bool *in_kernel_driver);

/* close_se_device()
 * Parameters:
 *      hdevice [in out] - The device handle will be set to -1 if it is closed successfully.
 * Return Value:
 *      true - The function succeeds.
 *      false - The function fails.
*/
bool close_se_device(int *hdevice);

/* is_cpu_support_edmm()
 * Parameters:
 *      None.
 * Return Value:
 *      true - CPU supports EDMM.
 *      false - CPU does not support EDMM.
*/
bool is_cpu_support_edmm();

/* is_driver_support_edmm()
 * Parameters:
 *      hdevice [in] - The device handle used to communicate with driver.
 * Return Value:
 *      true - Driver supports EDMM.
 *      false - Driver does not support EDMM.
*/
bool is_driver_support_edmm(int hdevice);

/* is_support_edmm()
 * Parameters:
 *      None.
 * Return Value:
 *      true - CPU/driver/uRTS supports EDMM.
 *      false - Either of CPU/driver/uRTS does not support EDMM.
*/
bool is_support_edmm();

#ifdef __cplusplus
}
#endif

#endif //_EDMM_UTILITY_H_
