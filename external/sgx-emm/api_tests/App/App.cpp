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
#include <assert.h>

#include <thread>
#include <vector>
#include <atomic>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "../tcs.h"
using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int test_tcs();

static atomic<int> counter_failures;

#include <stdlib.h>//rand
void driver(int sid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    do{
        usleep(rand()%11);
        ret = ecall_test_sgx_mm(global_eid, &retval, sid);
        if (ret == SGX_SUCCESS){
            printf("test_sgx_mm returned %d\n", retval);
            counter_failures += retval;
        }else if (ret == SGX_ERROR_OUT_OF_TCS){
            printf("!!! enclave out of TCS, retrying...\n");
            continue;
        }else
        {
            abort();
        }
        //test_tcs does its own retry
        counter_failures += test_tcs();
        return;
    }while(true);
}


int test_unsafe()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_test_sgx_mm_unsafe(global_eid, &retval);
    if (ret == SGX_SUCCESS){
        if(retval)
            printf("!!! test_sgx_mm_unsafe returned %d\n", retval);
        else
            printf("*** unsafe tests passed\n");
        return retval;
    }else
    abort();
}


typedef struct ms_ecall_check_context_t {
    int ms_retval;
    size_t ms_tcs;
} ms_ecall_check_context_t;

extern "C" {
#include "sgx.h"
}
vdso_sgx_enter_enclave_t vdso_sgx_enter_enclave;

#define EENTER 2

int ecall_check_context_manual(int* retval, size_t tcs)
{
    ms_ecall_check_context_t ms;
    ms.ms_tcs = tcs;
    ms.ms_retval= -1;
    struct sgx_enclave_run run;
    memset(&run, 0, sizeof(run));
    run.tcs = (__u64)tcs;
/********
    !NOTE: hardcoded ecall number. Needs update if edl changes
*******/
    int ret = vdso_sgx_enter_enclave((unsigned long)3, (unsigned long)(&ms), 0, EENTER,
            0, 0, &run);
    if (ret == 0) *retval = ms.ms_retval;
    return ret;
}
#include <sys/auxv.h>
#include <elf.h>
void* get_vdso_sym(const char* vdso_func_name)
{
    char* dynstr = 0;
    void *ret = NULL;

    uint8_t* vdso_addr = (uint8_t*)getauxval(AT_SYSINFO_EHDR);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)vdso_addr;
    Elf64_Shdr* section_header = (Elf64_Shdr*)(vdso_addr + elf_header->e_shoff);

    for (int i = 0; i < elf_header->e_shnum; i++) {
        auto& s = section_header[i];
        auto& ss_ = section_header[elf_header->e_shstrndx];
        auto name = (char*)(vdso_addr + ss_.sh_offset + s.sh_name);
        if (strcmp(name, ".dynstr") == 0) {
            dynstr = (char*)(vdso_addr + s.sh_offset);
            break;
        }
    }

    for (int i = 0; i < elf_header->e_shnum; i++) {
        auto& s = section_header[i];
        auto& ss_ = section_header[elf_header->e_shstrndx];
        auto name = (char*)(vdso_addr + ss_.sh_offset + s.sh_name);
        if (strcmp(name, ".dynsym") == 0) {
            for (unsigned int si = 0; si < (s.sh_size/s.sh_entsize); si++) {
                auto &sym = ((Elf64_Sym*)(vdso_addr + s.sh_offset))[si];
                auto vdname = dynstr + sym.st_name;
                if (strcmp(vdname, vdso_func_name) == 0) {
                    ret = (vdso_addr + sym.st_value);
                    break;
                }
            }
            if (ret) break;
        }
    }
    return ret;
}

#define fastcall __attribute__((regparm(3),noinline,visibility("default")))
//this function is used to notify GDB scripts
//GDB is supposed to have a breakpoint on urts_add_tcs to receive debug interupt
//once the breakpoint has been hit, GDB extracts the address of tcs and sets DBGOPTIN for the tcs
extern "C" void fastcall urts_add_tcs(tcs_t * const tcs)
{
    (void)(tcs);
}

int test_tcs()
{
    if(vdso_sgx_enter_enclave == NULL)
        return 0; //skip this test
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    size_t tcs = 0;

    do {
        usleep(rand()%11);
        ret = ecall_alloc_context(global_eid, &tcs);
        if (ret == SGX_SUCCESS){
            if (tcs > 1) {
                printf("*** test_alloc_context returned 0X%LX\n", tcs);
                break;
            } else {
                printf("!!! alloc context failed\n");
                return 1;
            }
        }else if (ret == SGX_ERROR_OUT_OF_TCS){
            continue;
        }else
            abort();
    } while (true);

    urts_add_tcs((tcs_t*)tcs);//turn on sgx-gdb
    int retval = 0;
    int r = ecall_check_context_manual(&retval, tcs);

    if (r == 0){
        if (retval) {
            printf("!!! check tcs returned %d\n", retval);
            return 1;
        }
        else
            printf("*** check tcs passed\n");
    }else
        abort();

    do {
        usleep(rand()%11);
        ret = ecall_dealloc_context(global_eid, &retval, tcs);
        if (ret == SGX_SUCCESS) {
            if(retval) {
                printf("!!! test_deaalloc_context returned %d\n", retval);
                return 1;
            }
            else{
                printf("*** dealloc context pass\n");
                return 0;
            }
        } else if (ret == SGX_ERROR_OUT_OF_TCS){
            continue;
        }else
            abort();
    } while (true);
    return 0;
}

/* ecall_thread_functions:
 *   Invokes thread functions including mutex, condition variable, etc.
 */
int test_sgx_mm_functions(int num_threads)
{
    vector<thread*> threads;
    for (int i=0; i< num_threads; i++)
        threads.push_back(new thread(driver, i));

    for (int i=0; i< num_threads; i++)
    {
        threads[i]->join();
        delete threads[i];
    }

    if(counter_failures)
    {
        printf("!!! Fail in %d threads\n", static_cast<int>(counter_failures));
    }else
        printf("*** All threads ran successfully.\n");
    return counter_failures;
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    vdso_sgx_enter_enclave = (vdso_sgx_enter_enclave_t)get_vdso_sym("__vdso_sgx_enter_enclave");
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Failed initialize enclave.\n");
        return -1;
    }
    //srand (time(NULL));
    srand ((3141596/1618)*271828);
    int ret = 0;

    //50 threads for 100 iterations passed when this is checked in
    ret += test_sgx_mm_functions(50);
    ret += test_unsafe();

    sgx_destroy_enclave(global_eid);
    if (!ret)
        printf("*** All tests pass.\n");
    else
        printf("!!! %d test(s) failed.\n", ret);

    return ret;
}

