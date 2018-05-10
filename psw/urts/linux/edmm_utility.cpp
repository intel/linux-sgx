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


#include "edmm_utility.h"
#include "se_trace.h"
#include "isgx_user.h"
#include "cpuid.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>

#define SGX_URTS_CMD "strings /usr/lib/libsgx_urts.so 2> /dev/null | grep SGX_URTS_VERSION_2"
#define SGX_CPUID    0x12

/* is_urts_support_edmm()
 * Parameters:
 *      None.
 * Return Value:
 *      true - uRTS supports EDMM.
 *      false - uRTS does not support EDMM.
*/
static bool is_urts_support_edmm()
{
    FILE* pipe = popen(SGX_URTS_CMD, "r");
    if (NULL == pipe)
    {
        SE_TRACE(SE_TRACE_WARNING, "Failed to open pipe.\n");
        return false;
    }

    char line[1024];
    if (NULL == fgets(line, sizeof(line), pipe))
        return false;

    if (-1 == pclose(pipe))
    {
        SE_TRACE(SE_TRACE_WARNING, "Failed to close pipe.\n");
    }

    return true;
}

/* open_se_device()
 * Parameters:
 *      hdevice [out] - The device handle as returned from the open_se_device API.
 *      in_kernel_driver [out] - Indicate it is in-kernel driver or not.
 * Return Value:
 *      true - The function succeeds.
 *      false - The function fails.
*/
extern "C" bool open_se_device(int *hdevice, bool *in_kernel_driver)
{
    if (NULL == hdevice)
        return false;

    int hdev = open("/dev/isgx", O_RDWR);
    if (-1 == hdev)
    {
        hdev = open("/dev/sgx", O_RDWR);
        if (-1 == hdev)
        {
            SE_TRACE(SE_TRACE_WARNING, "Failed to open Intel SGX device.\n");
            return false;
        }

        if (NULL != in_kernel_driver)
            *in_kernel_driver = true;
    }

    *hdevice = hdev;

    return true;
}

/* close_se_device()
 * Parameters:
 *      hdevice [in out] - The device handle will be set to -1 if it is closed successfully.
 * Return Value:
 *      true - The function succeeds.
 *      false - The function fails.
*/
extern "C" bool close_se_device(int *hdevice)
{
    if (NULL == hdevice)
        return false;

    if (-1 != *hdevice && 0 != close(*hdevice))
    {
        SE_TRACE(SE_TRACE_WARNING, "Failed to close Intel SGX device.\n");
        return false;
    }

    *hdevice = -1;

    return true;
}

/* is_cpu_support_edmm()
 * Parameters:
 *      None.
 * Return Value:
 *      true - CPU supports EDMM.
 *      false - CPU does not support EDMM.
*/
extern "C" bool is_cpu_support_edmm()
{
    int a[4] = {0,0,0,0};

    //Check CPU EDMM capability by CPUID
    __cpuid(a, 0);
    if (a[0] < SGX_CPUID)
        return false;

    __cpuidex(a, SGX_CPUID, 0);
    if (!(a[0] & 1))
        return false;

    return ((a[0] & 2) != 0);
}

/* is_driver_support_edmm()
 * Parameters:
 *      hdevice [in] - The device handle used to communicate with driver.
 * Return Value:
 *      true - Driver supports EDMM.
 *      false - Driver does not support EDMM.
*/
extern "C" bool is_driver_support_edmm(int hdevice)
{
    if (-1 == hdevice)
        return false;

    sgx_modification_param param;
    param.flags = 0;
    param.range.start_addr = 0;
    param.range.nr_pages = 0;

    int ret = ioctl(hdevice, SGX_IOC_ENCLAVE_EMODPR, &param);
    if ((-1 == ret) && (errno == ENOTTY))
        return false;

    return true;
}

/* is_support_edmm()
 * Parameters:
 *      None.
 * Return Value:
 *      true - CPU/driver/uRTS supports EDMM.
 *      false - Either of CPU/driver/uRTS does not support EDMM.
*/
extern "C" bool is_support_edmm()
{
    if (false == is_cpu_support_edmm())
        return false;

    int hdevice = -1;
    if (false == open_se_device(&hdevice, NULL))
        return false;

    if (false == is_driver_support_edmm(hdevice))
    {
        close_se_device(&hdevice);
        return false;
    }

    close_se_device(&hdevice);

    if (false == is_urts_support_edmm())
        return false;

    return true;
}
