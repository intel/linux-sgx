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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <errno.h>
#include "../../include/sgx_mm.h"
#define SGX_PAGE_SIZE 4096
#include "sgx_thread.h"
#include <vector>
#include "../tcs.h"
using namespace std;
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[4096*2] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

#define LOG(fmt, ...)   do {                                                    \
    printf("[%s %s:%d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
}while(0)


#define EXPECT_EQ(a, b) \
    do { \
        if ((a) != (b)){ \
            LOG( #a " expected:" #b " got: %lu\n", (uint64_t)(a)); \
            return 1; \
        }\
    } while(0);

#define EXPECT_NEQ(a, b) \
    do { \
        if ((a) == (b)) {\
            LOG( #a " not expected: " #b "\n" ); \
            return 1; \
        }\
    } while(0);

const size_t ALLOC_SIZE = 0x2000;
vector<void*> allocated_blocks;
sgx_thread_mutex_t mutex = SGX_THREAD_MUTEX_INITIALIZER;

int test_sgx_mm_alloc_dealloc()
{
    int ret = sgx_mm_dealloc(0, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);
    // we should be able to alloc, commit, uncommit
    // in multiple threads without interference
    void* addr = 0;
    ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);
    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    return 0;
}

int test_sgx_mm_alloc_commit_uncommit()
{
    int ret = sgx_mm_dealloc(0, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);
    // we should be able to alloc, commit, uncommit
    // in multiple threads without interference
    void* addr = 0;
    ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    void* addr1 = NULL;
    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW | SGX_EMA_FIXED, NULL, NULL, &addr1);

    EXPECT_EQ(ret, EEXIST);
    EXPECT_EQ(addr1, NULL);
    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);
    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0); //we do nothing if it's already uncommitted

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    //no longer use these areas, ready to be
    // released by any thread
    sgx_thread_mutex_lock(&mutex);
    allocated_blocks.push_back(addr);
    sgx_thread_mutex_unlock(&mutex);
    return 0;
}
/*
 * Only release areas previously stored
 * by other threads as ready to be released
 */
int test_sgx_mm_dealloc()
{
    int res = 0;
    sgx_thread_mutex_lock(&mutex);
    auto it = allocated_blocks.begin();
    while ( it!=allocated_blocks.end()){
        int ret =  sgx_mm_dealloc(*it, ALLOC_SIZE);
        if(ret){
            res ++;
            LOG("!!! failed dealloc, errno = %d\n", ret);
            it++;
        }else
            it = allocated_blocks.erase(it);
    }
    sgx_thread_mutex_unlock(&mutex);
    return res;
}

int test_sgx_mm_alloc_dealloc_unsafe1()
{
// allocation, deallocation
    int ret = sgx_mm_dealloc(0, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);

    void* addr = 0;
    ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    void* addr1 = NULL;
    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW|SGX_EMA_FIXED, NULL, NULL, &addr1);

    EXPECT_EQ(ret, EEXIST);
    EXPECT_EQ(addr1, NULL);

    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0); //we do nothing if it's already uncommitted

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);

    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL); // error if it's already deallocated

    void* addr2 = NULL;
    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_ON_DEMAND|SGX_EMA_FIXED, NULL, NULL, &addr2);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(addr2, addr);//mm should realloc to the given addr

    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_ON_DEMAND|SGX_EMA_FIXED, NULL, NULL, &addr2);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(addr, addr2);

    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_ON_DEMAND, NULL, NULL, &addr2);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, addr2);

    uint8_t *data= (uint8_t*)addr2;
    data[0]=0xFF;
    data[ALLOC_SIZE-1]=0xFF;

    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_dealloc(addr2, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    return 0;
}

typedef struct _pfdata
{
    sgx_pfinfo pf;
    union {
        int access; // access that triggers PF, R/W/X
        int magic;
    };
    void* addr_expected;
} pf_data_t;

int permissions_handler(const sgx_pfinfo *pfinfo, void *private_data)
{
    pf_data_t* pd = (pf_data_t *) private_data;
    memcpy(private_data, pfinfo, sizeof(*pfinfo));
    void* addr = (void*) pd->pf.maddr;
    if(pd->pf.pfec.rw == 1 && pd->access == SGX_EMA_PROT_WRITE){
        sgx_mm_modify_permissions(addr, SGX_PAGE_SIZE, SGX_EMA_PROT_WRITE | SGX_EMA_PROT_READ);
    }else if (pd->pf.pfec.rw == 0 && (pd->access & SGX_EMA_PROT_READ )){//R or RX
        sgx_mm_modify_permissions(addr, SGX_PAGE_SIZE, pd->access);
    }else
        abort();
    return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
}

int commit_data_handler(const sgx_pfinfo *pfinfo, void *private_data)
{
    pf_data_t* pd = (pf_data_t *) private_data;
    memcpy(private_data, pfinfo, sizeof(*pfinfo));
    void* addr = (void*) pd->pf.maddr;

    if (pd->access == SGX_EMA_PROT_WRITE
                && pd->pf.pfec.rw == 1
                && addr == pd->addr_expected)
    {
        int ret = sgx_mm_modify_permissions(addr, SGX_PAGE_SIZE, SGX_EMA_PROT_WRITE | SGX_EMA_PROT_READ);
        if(ret) abort();
        return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
    }

    if (addr == pd->addr_expected)
    {
        void* data = 0;
        int ret = sgx_mm_alloc(NULL, SGX_PAGE_SIZE, SGX_EMA_COMMIT_NOW,
                                    NULL, NULL, &data);
        if(ret) abort();
        assert(data!=0);
        memset(data, pd->magic, SGX_PAGE_SIZE);
        ret = sgx_mm_commit_data(addr, SGX_PAGE_SIZE, (uint8_t*)data,
                                            SGX_EMA_PROT_READ);
        if(ret) abort();
        ret = sgx_mm_dealloc((void*)data, SGX_PAGE_SIZE);
        if(ret) abort();
        return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
    }else
        return SGX_MM_EXCEPTION_CONTINUE_SEARCH;
}

int test_sgx_mm_permissions()
{

    void* addr = 0;
    pf_data_t pd;
    memset((void*) &pd, 0, sizeof(pd));
    int ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, &permissions_handler, &pd, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    uint8_t* data = (uint8_t*)addr;
    uint8_t d0 = data[0];
    EXPECT_EQ(d0, 0);
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //Read suceess without PF
    data[0] = 0xFF;
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //WRITE suceess without PF

    // permissions reduction
    ret = sgx_mm_modify_permissions(addr, ALLOC_SIZE/2, SGX_EMA_PROT_READ);
    EXPECT_EQ(ret, 0);

    pd.access = SGX_EMA_PROT_READ;
    d0 = data[0];
    EXPECT_EQ(d0, 0xFF);
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //Read suceess without PF

    pd.access = SGX_EMA_PROT_WRITE;
    data[ALLOC_SIZE-1] = 0xFF;
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //WRITE suceess without PF

    pd.access = SGX_EMA_PROT_WRITE;
    data[0] = 0xFF;
    EXPECT_NEQ (pd.pf.pfec.errcd, 0); //WRITE suceess with PF
    EXPECT_EQ (pd.pf.pfec.rw, 1); //WRITE indicated in PFEC

    memset((void*) &pd, 0, sizeof(pd));
    pd.access = SGX_EMA_PROT_READ|SGX_EMA_PROT_EXEC;

    //no longer used, ready to be released by any thread
    //we could dealloc here but to make it more interesting...
    sgx_thread_mutex_lock(&mutex);
    allocated_blocks.push_back(addr);
    sgx_thread_mutex_unlock(&mutex);

    return 0;
}


int test_sgx_mm_permissions_dealloc()
{
    void* addr = 0;
    pf_data_t pd;
    memset((void*) &pd, 0, sizeof(pd));
    int ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, &permissions_handler, &pd, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    uint8_t* data = (uint8_t*)addr;
    uint8_t d0 = data[0];
    EXPECT_EQ(d0, 0);
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //Read suceess without PF
    data[0] = 0xFF;
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //WRITE suceess without PF

    // permissions reduction
    ret = sgx_mm_modify_permissions(addr, ALLOC_SIZE/2, SGX_EMA_PROT_READ);
    EXPECT_EQ(ret, 0);

    pd.access = SGX_EMA_PROT_READ;
    d0 = data[0];
    EXPECT_EQ(d0, 0xFF);
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //Read suceess without PF

    pd.access = SGX_EMA_PROT_WRITE;
    data[ALLOC_SIZE-1] = 0xFF;
    EXPECT_EQ (pd.pf.pfec.errcd, 0); //WRITE suceess without PF

    pd.access = SGX_EMA_PROT_WRITE;
    data[0] = 0xFF;
    EXPECT_NEQ (pd.pf.pfec.errcd, 0); //WRITE suceess with PF
    EXPECT_EQ (pd.pf.pfec.rw, 1); //WRITE indicated in PFEC

    memset((void*) &pd, 0, sizeof(pd));
    pd.access = SGX_EMA_PROT_READ|SGX_EMA_PROT_EXEC;


    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ (pd.pf.pfec.errcd, 0); // no PF

    return 0;
}

int test_sgx_mm_commit_data()
{
    void* addr = 0;
    const int MAGIC = 0x55UL;
    pf_data_t pd;
    memset((void*) &pd, 0, sizeof(pd));
    int ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
                                SGX_EMA_COMMIT_ON_DEMAND,
                                &commit_data_handler,
                                &pd, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    pd.addr_expected = addr;
    pd.magic = MAGIC;

    uint8_t* data = (uint8_t*)addr;
    for (int i =0; i<SGX_PAGE_SIZE; i++)
    {
        EXPECT_EQ(data[i], MAGIC);
    }
    EXPECT_NEQ (pd.pf.pfec.errcd, 0); //READ suceess with PF
    EXPECT_EQ (pd.pf.pfec.rw, 0); //READ indicated in PFEC


    pd.access = SGX_EMA_PROT_WRITE;
    data[0] = 0xFF;
    EXPECT_NEQ (pd.pf.pfec.errcd, 0); //WRITE suceess with PF
    EXPECT_EQ (pd.pf.pfec.rw, 1); //WRITE indicated in PFEC


    //direct call commit_data on the second page
    void* ptr = addr + SGX_PAGE_SIZE;
    ret = sgx_mm_commit_data(ptr, SGX_PAGE_SIZE,
                                        data, SGX_EMA_PROT_READ);
    EXPECT_EQ (ret, 0);

    ret = memcmp(ptr, addr, SGX_PAGE_SIZE);
    EXPECT_EQ (ret, 0);

    void* pages13[13];
    memset(pages13, 0, 13*sizeof(void*));

    ret = sgx_mm_alloc(NULL, 13*SGX_PAGE_SIZE,
                                SGX_EMA_RESERVE,
                                NULL,
                                NULL, &(pages13[0]));
    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(pages13[0], NULL);
    // -------------
    ret = sgx_mm_alloc(pages13[0] + SGX_PAGE_SIZE, SGX_PAGE_SIZE,
                        SGX_EMA_COMMIT_ON_DEMAND | SGX_EMA_FIXED,
                                NULL,
                                NULL, &(pages13[1]));
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pages13[1], pages13[0] + SGX_PAGE_SIZE);

    // -x-----------
    ret = sgx_mm_commit_data(pages13[0], SGX_PAGE_SIZE,
                                data, SGX_EMA_PROT_READ);

    EXPECT_EQ(ret, EACCES);

    // -x-----------
    ret = sgx_mm_commit_data(pages13[1], SGX_PAGE_SIZE,
                                data, SGX_EMA_PROT_READ);

    EXPECT_EQ(ret, 0);
    ret = memcmp(data, pages13[1], SGX_PAGE_SIZE);
    EXPECT_EQ (ret, 0);

    // -d-----------
    ret = sgx_mm_commit_data(pages13[1], SGX_PAGE_SIZE,
                                data, SGX_EMA_PROT_READ);

    EXPECT_EQ(ret, EACCES);

    // -d-----------
    ret = sgx_mm_alloc(pages13[0], 4*SGX_PAGE_SIZE,
                        SGX_EMA_COMMIT_ON_DEMAND | SGX_EMA_FIXED,
                                NULL,
                                NULL, &(pages13[0]));

    EXPECT_EQ(ret, EEXIST);

    // -d-----------
    ret = sgx_mm_alloc(pages13[0], SGX_PAGE_SIZE,
                        SGX_EMA_COMMIT_ON_DEMAND | SGX_EMA_FIXED,
                                NULL,
                                NULL, &(pages13[0]));
    // xd-----------
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_commit_data(pages13[0], SGX_PAGE_SIZE,
                                data, SGX_EMA_PROT_READ);

    // dd-----------
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_alloc(pages13[0]+2*SGX_PAGE_SIZE, 2*SGX_PAGE_SIZE,
                        SGX_EMA_COMMIT_ON_DEMAND | SGX_EMA_FIXED,
                                NULL,
                                NULL, &(pages13[2]));
    // ddxx---------
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pages13[2], pages13[0] + 2*SGX_PAGE_SIZE);

    ret = sgx_mm_commit_data(pages13[2], 2*SGX_PAGE_SIZE,
                                data, SGX_EMA_PROT_READ);

    // dddd---------
    EXPECT_EQ(ret, 0);
    ret = memcmp(data, pages13[2], 2*SGX_PAGE_SIZE);
    EXPECT_EQ (ret, 0);
    int i = 7;
    for(; i < 11; i++){
        ret = sgx_mm_alloc(pages13[0] + i*SGX_PAGE_SIZE, SGX_PAGE_SIZE,
                        SGX_EMA_COMMIT_ON_DEMAND,
                        NULL, NULL,
                        &pages13[i]);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(pages13[i], (pages13[0] + i*SGX_PAGE_SIZE));
    }
    // dddd---xxxx--

    EXPECT_EQ(pages13[7], pages13[0] + 7*SGX_PAGE_SIZE);
    EXPECT_EQ(pages13[10], pages13[0] + 10*SGX_PAGE_SIZE);

    ret = sgx_mm_commit_data(pages13[7], 4*SGX_PAGE_SIZE,
                                (uint8_t*)(pages13[0]), SGX_EMA_PROT_READ);

    // dddd---dddd--
    EXPECT_EQ(ret, 0);
    ret = memcmp(pages13[7], pages13[0], 4*SGX_PAGE_SIZE);
    EXPECT_EQ (ret, 0);

    const unsigned char code[] = {
        0x55,                       //    push   %rbp
        0x48, 0x89, 0xe5,           //    mov    %rsp,%rbp
        0x48, 0x89, 0x7d, 0xf8,     //    mov    %rdi,-0x8(%rbp)
                                    // return 0;
        0xb8, 0x0, 0x0, 0x0, 0x0,   //    mov    $0x0,%eax
        0x5d,                       //    pop    %rbp
        0xc3                        //    retq
        };
    ret = sgx_mm_modify_permissions (pages13[0], SGX_PAGE_SIZE, SGX_EMA_PROT_READ_WRITE);
    EXPECT_EQ(ret, 0);

    memcpy(pages13[0], (void*)code, sizeof(code));
    i = 12;
    ret = sgx_mm_alloc(pages13[0] + i*SGX_PAGE_SIZE, SGX_PAGE_SIZE,
                    SGX_EMA_COMMIT_ON_DEMAND,
                    NULL, NULL,
                    &pages13[i]);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(pages13[i], (pages13[0] + i*SGX_PAGE_SIZE));

    // dddd---ddddx-
    sgx_mm_commit_data(pages13[i], SGX_PAGE_SIZE, (uint8_t*)pages13[0], SGX_EMA_PROT_READ_EXEC);
    EXPECT_EQ(ret, 0);

    ret = (*(int(*)()) pages13[i]) ();
    EXPECT_EQ(ret, 0);

    // dddd---ddddc-
    ret = sgx_mm_dealloc(pages13[0], 13*SGX_PAGE_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_dealloc(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);
    return 0;
}


// Thread-safe tests in separate threads
// TODO:
// - alloc big buf on stack to trigger expansion
// - alloc ondemand in handler with a nested hanndler
// - do setjmp at allocation and long jmp in handler?
// - random addrss allocation and deallocation
//
int ecall_test_sgx_mm(int sid)
{
    int failures = test_sgx_mm_alloc_dealloc();
    failures += test_sgx_mm_alloc_commit_uncommit();

    failures += test_sgx_mm_permissions();
    failures += test_sgx_mm_permissions_dealloc();
    failures += test_sgx_mm_commit_data();
    failures += test_sgx_mm_dealloc();
    if(failures)
        LOG("!!! %d fail(s) in thread %d\n",  failures, sid);
    return failures;
}

int test_sgx_mm_alloc_dealloc_unsafe2()
{
    int ret = sgx_mm_dealloc(0, ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);

    void* addr = 0;
    ret = sgx_mm_alloc(NULL, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    void* addr1 = NULL;
    ret = sgx_mm_alloc(addr, ALLOC_SIZE,
            SGX_EMA_COMMIT_NOW|SGX_EMA_FIXED, NULL, NULL, &addr1);

    EXPECT_EQ(ret, EEXIST);
    EXPECT_EQ(addr1, NULL);

    ret = sgx_mm_uncommit(addr, 2*ALLOC_SIZE);
    EXPECT_EQ(ret, EINVAL);

    ret = sgx_mm_uncommit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0); //we do nothing if it's already uncommitted

    ret = sgx_mm_commit(addr, ALLOC_SIZE);
    EXPECT_EQ(ret, 0);

    ret = sgx_mm_dealloc(addr, 2*ALLOC_SIZE);
    EXPECT_EQ(ret, 0);//OK to dealloc if not allocated or already deallocated
    const size_t max_size = 0x90000000;//configured as max reserved memory
    ret = sgx_mm_alloc(NULL, max_size*2,
            SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    EXPECT_EQ(ret, ENOMEM);
    return 0;
}

//Called from single thread
int ecall_test_sgx_mm_unsafe()
{
    int failures = 0;
    failures += test_sgx_mm_alloc_dealloc_unsafe1();
    failures += test_sgx_mm_alloc_dealloc_unsafe2();
    return failures;
}


typedef void (*entry_t)(void);
extern entry_t  enclave_entry;
extern uint8_t  __ImageBase;
size_t ecall_alloc_context()
{
     // Intel SDK thread context memory layout
    // 16 guard page | (5)  stack | 16 guard page | 1 TCS | 2 SSA | 16 guard page | 1  TLS
    size_t N = 16 * 3 + 5 + 1 + 2 + 1;
    void* addr = NULL;
    int ret = sgx_mm_alloc(NULL, N*SGX_PAGE_SIZE,
            SGX_EMA_RESERVE, NULL, NULL, &addr);
    EXPECT_EQ(ret, 0);
    EXPECT_NEQ(addr, NULL);

    void* tmp = NULL;
    void* stack =  (void*)((size_t)addr + 16*SGX_PAGE_SIZE);
    ret = sgx_mm_alloc(stack, 5*SGX_PAGE_SIZE,
            SGX_EMA_COMMIT_NOW | SGX_EMA_FIXED, NULL, NULL, &tmp);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tmp, stack);

    void* ptcs = (void*)((size_t)addr + 37*SGX_PAGE_SIZE);
    ret = sgx_mm_alloc(ptcs, SGX_PAGE_SIZE,
            SGX_EMA_COMMIT_NOW | SGX_EMA_FIXED, NULL, NULL, &tmp);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tmp, ptcs);

    void* ssa = (void*)((size_t)ptcs + SGX_PAGE_SIZE);
    ret = sgx_mm_alloc(ssa, 2*SGX_PAGE_SIZE,
            SGX_EMA_COMMIT_NOW | SGX_EMA_FIXED, NULL, NULL, &tmp);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tmp, ssa);

    void* tls = (void*)((size_t)ssa + 18*SGX_PAGE_SIZE);
    ret = sgx_mm_alloc(tls, SGX_PAGE_SIZE,
            SGX_EMA_COMMIT_NOW | SGX_EMA_FIXED, NULL, NULL, &tmp);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(tmp, tls);

    size_t enclave_base = (size_t)(&__ImageBase);//from Makefile
    tcs_t* tcs = (tcs_t*)ptcs;
    tcs->oentry = (size_t)(&enclave_entry) - enclave_base;
    tcs->cssa = 0;
    tcs->nssa = 2;
    tcs->ofs_limit = tcs->ogs_limit = (uint32_t)-1;
    tcs->ossa = (size_t) ssa - enclave_base;
    tcs->ofs_base = (size_t)tls - enclave_base;
    tcs->ogs_base = (size_t)tls - enclave_base;

    ret =sgx_mm_modify_type(ptcs, SGX_PAGE_SIZE, SGX_EMA_PAGE_TYPE_TCS);

    EXPECT_EQ(ret, 0);
    return (size_t) ptcs;
}

int ecall_check_context(size_t tcs)
{
    return 0;
}

int ecall_dealloc_context(size_t tcs)
{
    size_t base = tcs - 37*SGX_PAGE_SIZE;
    size_t size = (16 * 3 + 5 + 1 + 2 + 1) * SGX_PAGE_SIZE;

    int ret = sgx_mm_dealloc ((void*)base, size);

    EXPECT_EQ(ret, 0);

    return 0;
}
