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


/**
 * File: trts_veh.cpp
 * Description: 
 *     This file implements the support of custom exception handling. 
 */

#include "sgx_trts_exception.h"
#include <stdlib.h>
#include <string.h>
#include "sgx_trts.h"
#include "xsave.h"
#include "arch.h"
#include "sgx_spinlock.h"
#include "thread_data.h"
#include "global_data.h"
#include "trts_internal.h"
#include "trts_mitigation.h"
#include "trts_inst.h"
#include "util.h"
#include "trts_util.h"
#include "trts_shared_constants.h"
#include "se_cdefs.h"
#include "emm_private.h"
#include "sgx_mm_rt_abstraction.h"
#include "sgx_trts_aex.h"
#include "ctd.h"

#include "se_memcpy.h"
typedef struct _handler_node_t
{
    uintptr_t callback;
    struct _handler_node_t   *next;
} handler_node_t;

static handler_node_t *g_first_node = NULL;
static sgx_spinlock_t g_handler_lock = SGX_SPINLOCK_INITIALIZER;

static uintptr_t g_veh_cookie = 0;
sgx_mm_pfhandler_t g_mm_pfhandler = NULL;
#define ENC_VEH_POINTER(x)  (uintptr_t)(x) ^ g_veh_cookie
#define DEC_VEH_POINTER(x)  (sgx_exception_handler_t)((x) ^ g_veh_cookie)
extern int g_aexnotify_supported;
extern "C" sgx_status_t sgx_apply_mitigations(const sgx_exception_info_t *);

extern uint16_t aex_notify_c3_cache[2048];
extern uint8_t *__ct_mitigation_ret;


// sgx_register_exception_handler()
//      register a custom exception handler
// Parameter
//      is_first_handler - the order in which the handler should be called.
// if the parameter is nonzero, the handler is the first handler to be called.
// if the parameter is zero, the handler is the last handler to be called.
//      exception_handler - a pointer to the handler to be called.
// Return Value
//      handler - success
void *sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler)
{
    // initialize g_veh_cookie for the first time sgx_register_exception_handler is called.
    if(unlikely(g_veh_cookie == 0))
    {
        uintptr_t rand = 0;
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
            {
                return NULL;
            }
        } while(rand == 0);

        sgx_spin_lock(&g_handler_lock);
        if(g_veh_cookie == 0)
        {
            g_veh_cookie = rand;
        }
        sgx_spin_unlock(&g_handler_lock);
    }
    if(!sgx_is_within_enclave((const void*)exception_handler, 0))
    {
        return NULL;
    }
    handler_node_t *node = (handler_node_t *)malloc(sizeof(handler_node_t));
    if(!node)
    {
        return NULL;
    }
    node->callback = ENC_VEH_POINTER(exception_handler);

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if((g_first_node == NULL) || is_first_handler)
    {
        node->next = g_first_node;
        g_first_node = node;
    }
    else
    {
        handler_node_t *tmp = g_first_node;
        while(tmp->next != NULL)
        {
            tmp = tmp->next;
        }
        node->next = NULL;
        tmp->next = node;
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    return node;
}
// sgx_unregister_exception_handler()
//      unregister a custom exception handler.
// Parameter
//      handler - a handler to the custom exception handler previously 
// registered using the sgx_register_exception_handler function.
// Return Value
//      none zero - success
//              0 - fail
int sgx_unregister_exception_handler(void *handler)
{
    if(!handler)
    {
        return 0;
    }

    int status = 0;

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if(g_first_node)
    {
        handler_node_t *node = g_first_node;
        if(node == handler)
        {
            g_first_node = node->next;
            status = 1;
        }
        else
        {
            while(node->next != NULL)
            {
                if(node->next == handler)
                {
                    node->next = node->next->next;
                    status = 1;
                    break;
                }
                node = node->next;
            }
        }
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    if(status) free(handler);
    return status;
}

// continue_execution(sgx_exception_info_t *info):
// try to restore the thread context saved in info to current execution context.
extern "C" __attribute__((regparm(1))) void continue_execution(sgx_exception_info_t *info);
extern "C" void restore_xregs(uint8_t *buf);

#ifndef SE_SIM
extern "C" __attribute__((regparm(1))) void second_phase(sgx_exception_info_t *info, 
    void *new_sp, void *second_phase_handler_addr);

extern "C" void constant_time_apply_sgxstep_mitigation_and_continue_execution(sgx_exception_info_t *info,
        uintptr_t ssa_aexnotify_addr, uintptr_t stack_tickle_pages, uintptr_t code_tickle_page, uintptr_t data_tickle_address, uintptr_t c3_byte_address);

// constant time select based on given condition
static inline uint64_t cselect64(uint64_t pred, const uint64_t expected, uint64_t old_val, uint64_t new_val)
{
    __asm__("cmp %3, %1\n\t"
            "cmove %2, %0"
            : "+rm"(new_val)
            : "rm"(pred), "rm"(old_val), "ri"(expected));
    return new_val;
}

// apply the constant time mitigation handler
static void apply_constant_time_sgxstep_mitigation_and_continue_execution(sgx_exception_info_t *info)
{
    thread_data_t *thread_data = get_thread_data();
    int ct_result;
    uint64_t data_address;
    uintptr_t code_tickle_page, c3_byte_address, stack_tickle_pages, data_tickle_address,
              stack_base_page = ((thread_data->stack_base_addr & ~0xFFF) == 0) ?
                  (thread_data->stack_base_addr) - 0x1000 :
                  (thread_data->stack_base_addr & ~0xFFF),
              stack_limit_page = thread_data->stack_limit_addr & ~0xFFF;
    int data_tickle_address_is_within_enclave;

    // Determine which stack pages can be tickled
    if (((uintptr_t)info & ~0xFFF) == stack_base_page) {
        if (stack_base_page == stack_limit_page) {
            // The stack is only a single page, so we tickle that page
            stack_tickle_pages = stack_base_page;
        } else {
            // The current stack page is the base page, but there are more
            // pages so we tickle the next one as well.
            stack_tickle_pages = stack_base_page | 1;
        }
    } else {
        // If the current stack page is not the base page, then it's generally
        // better to also tickle the previous page. For example, the mitigation
        // code and the interrupted code may have separate but adjacent stack
        // pages (in this case, the interrupted code's stack frame must be on
        // the page with a higher address).
        stack_tickle_pages = (((uintptr_t)info & ~0xFFF) + 0x1000) | 1;
    }

    // Look up the code page in the c3 cache
    code_tickle_page = info->cpu_context.REG(ip) & ~0xFFF;
    c3_byte_address = code_tickle_page + *(aex_notify_c3_cache + ((code_tickle_page >> 12) & 0x07FF));
    if (*(uint8_t *)c3_byte_address != 0xc3) {
        uint8_t *i = (uint8_t *)code_tickle_page, *e = i + 4096;
        for (; i != e && *i != 0xc3; ++i) {}
        if (i == e) { // code_tickle_page does not contain a c3 byte
            c3_byte_address = (uintptr_t)&__ct_mitigation_ret;
        } else {
            c3_byte_address = (uintptr_t)i;
            *(aex_notify_c3_cache + ((code_tickle_page >> 12) & 0x07FF)) =
                (uint16_t)(c3_byte_address & 0xFFF);
        }
    }

    ct_result = ct_decode(&info->cpu_context, &data_address);

    data_tickle_address = stack_tickle_pages & ~0x1;
    data_tickle_address = cselect64(ct_result, 1, data_address, data_tickle_address);
    data_tickle_address = cselect64(ct_result, 2, data_address, data_tickle_address);
    data_tickle_address_is_within_enclave =
		sgx_is_within_enclave((void*) data_tickle_address, sizeof(uint8_t));

    /*
     * Ensure the tickle page dereferenced by the mitigation lies _inside_ the enclave.
     *
     * NOTE:
     *  - Unguarded user memory accesses can leak through MMIO stale data.
     *  - User memory accesses are detectable and single-steppable anyway.
     *  - Below non-cst time check can only ever be false when the next enclave
     *    instruction will dereference user memory (trivially known to attacker).
     */
    data_tickle_address = data_tickle_address_is_within_enclave ?
                          data_tickle_address : stack_tickle_pages & ~0x1;

    code_tickle_page = cselect64(ct_result, 2, code_tickle_page | 0x1, code_tickle_page);
    code_tickle_page = cselect64(data_tickle_address_is_within_enclave, 1, code_tickle_page, code_tickle_page & ~0x1);

    // Pop an entropy byte from the entropy cache
    if (--thread_data->aex_notify_entropy_remaining < 0) {
        if (0 == do_rdrand(&thread_data->aex_notify_entropy_cache))
        {
            thread_data->exception_flag = -1;
            abort();
        }
        thread_data->aex_notify_entropy_remaining = 31;
    }
    code_tickle_page |= (thread_data->aex_notify_entropy_cache & 1) << 4;
    thread_data->aex_notify_entropy_cache >>= 1;

    // There are three additional "implicit" parameters to this function:
    // 1. The low-order bit of `stack_tickle_pages` is 1 if a second stack
    //    page should be tickled (specifically, the stack page immediately
    //    below the page specified in the upper bits)
    // 2. Bit 0 of `code_tickle_page` is 1 if `data_tickle_address`
    //    is writable, and therefore should be tested for write permissions
    //    by the mitigation
    // 3. Bit 4 of `code_tickle_page` is 1 if the cycle delay
    //    should be added to the mitigation
    constant_time_apply_sgxstep_mitigation_and_continue_execution(
                    info, thread_data->first_ssa_gpr + offsetof(ssa_gpr_t, aex_notify),
                    stack_tickle_pages, code_tickle_page,
                    data_tickle_address, c3_byte_address);
}
#endif

//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    int status = EXCEPTION_CONTINUE_SEARCH;
    handler_node_t *node = NULL;
    thread_data_t *thread_data = get_thread_data();
    size_t size = 0;
    uintptr_t *nhead = NULL;
    uintptr_t *ntmp = NULL;
    uintptr_t xsp = 0;
    uint8_t *xsave_in_ssa = (uint8_t*)ROUND_TO_PAGE(thread_data->first_ssa_gpr) - ROUND_TO_PAGE(get_xsave_size() + sizeof(ssa_gpr_t));

    // AEX Notify allows this handler to handle interrupts
    if (info == NULL) {
        goto failed_end;
    }

    memcpy_s(info->xsave_area, info->xsave_size, xsave_in_ssa, info->xsave_size);

    if (info->exception_valid == 0) {
        goto exception_handling_end;
    }

    if (thread_data->exception_flag < 0)
        goto failed_end;
    thread_data->exception_flag++;

    if(info->exception_vector == SGX_EXCEPTION_VECTOR_PF &&
        (g_mm_pfhandler != NULL))
    {
        thread_data->exception_flag--;
        sgx_pfinfo* pfinfo = (sgx_pfinfo*)(&info->exinfo);
        if(SGX_MM_EXCEPTION_CONTINUE_EXECUTION == g_mm_pfhandler(pfinfo))
        {
            //instruction triggering the exception will be executed again.
           goto exception_handling_end;
        }
        //restore old flag, and fall thru
        thread_data->exception_flag++;
    }
    // read lock
    sgx_spin_lock(&g_handler_lock);

    node = g_first_node;
    while(node != NULL)
    {
        size += sizeof(uintptr_t);
        node = node->next;
    }

    // There's no exception handler registered
    if (size == 0)
    {
        sgx_spin_unlock(&g_handler_lock);

        //exception cannot be handled
        thread_data->exception_flag = -1;

        goto exception_handling_end;
    }
    // The customer handler may never return, use alloca instead of malloc
    if ((nhead = (uintptr_t *)alloca(size)) == NULL)
    {
        sgx_spin_unlock(&g_handler_lock);
        goto failed_end;
    }
    ntmp = nhead;
    node = g_first_node;
    while(node != NULL)
    {
        *ntmp = node->callback;
        ntmp++;
        node = node->next;
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);

    // decrease the nested exception count before the customer
    // handler execution, becasue the handler may never return
    thread_data->exception_flag--;

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    while(size > 0)
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
        status = handler(info);
        if(EXCEPTION_CONTINUE_EXECUTION == status)
        {
            break;
        }
        ntmp++;
        size -= sizeof(sgx_exception_handler_t);
    }

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    if (!is_valid_sp(xsp))
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION != status)
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    }

exception_handling_end:
#ifndef SE_SIM
    //instruction triggering the exception will be executed again.
    if(info->do_aex_mitigation == 1)
    {
        // apply customized mitigation handlers
        // Note that we don't enable AEX-notify for customized mitigation handler
        sgx_apply_mitigations(info);
        restore_xregs(info->xsave_area);
        apply_constant_time_sgxstep_mitigation_and_continue_execution(info);
    }
    else
#endif
    {
        //instruction triggering the exception will be executed again.
        restore_xregs(info->xsave_area);
        continue_execution(info);
    }
failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    abort();    // throw abortion
}

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    int ret = -1;

    if ((start_addr == NULL) || (page_count == 0))
        return -1;

    ret = mm_commit(start_addr, page_count << SE_PAGE_SHIFT);
    return ret;
}

extern "C" const char Lereport_inst;
extern "C" const char Leverifyreport2_inst;

// trts_handle_exception(void *tcs)
//      the entry point for the exceptoin handling
// Parameter
//      the pointer of TCS
// Return Value
//      none zero - success
extern "C" sgx_status_t trts_handle_exception(void *tcs)
{
    thread_data_t *thread_data = get_thread_data();
    ssa_gpr_t *ssa_gpr = NULL;
    sgx_exception_info_t *info = NULL;
    uintptr_t sp_u, sp, *new_sp = NULL;
    size_t size = 0;
    bool is_exception_handled = false;

    if ((thread_data == NULL) || (tcs == NULL)) goto default_handler;
    if (check_static_stack_canary(tcs) != 0)
        goto default_handler;
 
    if(get_enclave_state() != ENCLAVE_INIT_DONE)
    {
        goto default_handler;
    }
    
    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1) {
        goto default_handler;
    }
 
    if ((TD2TCS(thread_data) != tcs) 
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - ROUND_TO_PAGE(get_xsave_size() + sizeof(ssa_gpr_t))) != (uintptr_t)tcs) {
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);

    // The unstrusted RSP should never point inside the enclave
    sp_u = ssa_gpr->REG(sp_u);
    if (!sgx_is_outside_enclave((void *)sp_u, sizeof(sp_u)))
    {
        set_enclave_state(ENCLAVE_CRASHED);
        return SGX_ERROR_STACK_OVERRUN;
    }

    // The untrusted and trusted RSPs cannot be the same, unless
    // an exception happened before the enclave setup the trusted stack
    sp = ssa_gpr->REG(sp);
    if (sp_u == sp)
    {
        set_enclave_state(ENCLAVE_CRASHED);
        return SGX_ERROR_STACK_OVERRUN;
    }

    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    {
        set_enclave_state(ENCLAVE_CRASHED);
        return SGX_ERROR_STACK_OVERRUN;
    }

    size = 0;
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;

    // Add space for reserved slot for GPRs that will be used by mitigation
    // assembly code RIP, RAX, RBX, RCX, RDX, RBP, RSI, RDI Saved flags, 1st
    // D/QWORD of red zone, &SSA[0].GPRSGX.AEXNOTIFY, stack_tickle_pages,
    // code_tickle_page, data_tickle_page, c3_byte_address
    size += RSVD_SIZE_OF_MITIGATION_STACK_AREA;

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    size += thread_data->xsave_size;
    sp -= size;
    sp = sp & ~0x3F;

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    {
        set_enclave_state(ENCLAVE_CRASHED);
        return SGX_ERROR_STACK_OVERRUN;
    }

    info = (sgx_exception_info_t *)sp;
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    sp -= size;
    if(!is_stack_addr((void *)sp, size))
    {
        set_enclave_state(ENCLAVE_CRASHED);
        return SGX_ERROR_STACK_OVERRUN;
    }

    /* try to allocate memory dynamically */
    if((size_t)sp < thread_data->stack_commit_addr)
    {
        int ret = -1;
        size_t page_aligned_delta = 0;
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
        if ((thread_data->stack_commit_addr > page_aligned_delta)
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta),
                                        (page_aligned_delta >> SE_PAGE_SHIFT));
        }
        if (ret == 0)
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
            is_exception_handled = true; // The exception has been handled in the 1st phase exception handler
            goto handler_end;
        }
        else
        {
            set_enclave_state(ENCLAVE_CRASHED);
            return SGX_ERROR_STACK_OVERRUN;
        }
    }

    if (size_t(&Lereport_inst) == ssa_gpr->REG(ip) && SE_EREPORT == ssa_gpr->REG(ax))
    {
        // Handle the exception raised by EREPORT instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
        ssa_gpr->REG(flags) |= 1;  // Set CF to indicate error condition, see implementation of do_report()
        is_exception_handled = true; // The exception has been handled in the 1st phase exception handler.
        goto handler_end;
    }
    if (size_t(&Leverifyreport2_inst) == ssa_gpr->REG(ip) && SE_EVERIFYREPORT2 == ssa_gpr->REG(ax))
    {
        // Handle the exception raised by everifyreport2 instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
        ssa_gpr->REG(flags) |= 64;  // Set ZF to indicate error condition, see implementation of do_everifyreport2()
        ssa_gpr->REG(ax) = EVERIFYREPORT2_INVALID_LEAF;
        is_exception_handled = true; // The exception has been handled in the 1st phase exception handler.
        goto handler_end;
    }

    if(g_aexnotify_supported == 0 && ssa_gpr->exit_info.valid != 1)
    {
        // exception handlers are not allowed to call in a non-exception state
        // add aexnotify check here to skip the case of interrupts
        goto default_handler;
    }
handler_end:
    // initialize the info with SSA[0]
    info->exception_valid = is_exception_handled ? 0 : ssa_gpr->exit_info.valid;
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;
    info->xsave_size = thread_data->xsave_size;

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    info->cpu_context.r9  = ssa_gpr->r9;
    info->cpu_context.r10 = ssa_gpr->r10;
    info->cpu_context.r11 = ssa_gpr->r11;
    info->cpu_context.r12 = ssa_gpr->r12;
    info->cpu_context.r13 = ssa_gpr->r13;
    info->cpu_context.r14 = ssa_gpr->r14;
    info->cpu_context.r15 = ssa_gpr->r15;
#endif
    if ((info->exception_vector == SGX_EXCEPTION_VECTOR_PF)
            || (info->exception_vector == SGX_EXCEPTION_VECTOR_GP))
    {
        misc_exinfo_t* exinfo =
            (misc_exinfo_t*)((uint64_t)ssa_gpr - (uint64_t)MISC_BYTE_SIZE);
        info->exinfo.faulting_address = exinfo->maddr;
        info->exinfo.error_code = exinfo->errcd;
    }
    new_sp = (uintptr_t *)sp;
    if(!(g_aexnotify_supported || is_exception_handled == true))
    {
        // Two cases that we don't need to run below code:
        //  1. AEXNotify is enabled
        //  2. stack expansion or EREPORT exception. We have handled it 
        //  in the first phase and we should not change anything in the ssa_gpr
        //
        ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
        ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
        ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
        ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    }
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
#ifndef SE_SIM
    if(g_aexnotify_supported)
    {
        info->do_aex_mitigation = get_ssa_aexnotify();
        void *first_ssa_xsave = reinterpret_cast<void *>(thread_data->first_ssa_xsave);
        restore_xregs((uint8_t*)first_ssa_xsave);
        // With AEX Notify, we don't need to do a return here (phase-1 handler). 
        // Instead, we jump to internal_handle_exception (phase-2 handler).
        // We should not make a function call either, because ideally the return at 
        // the end of phase-2 handler should directly return to the interrupted enclave code.
        // Disable aexnotify before EDCSSA
        if(info->do_aex_mitigation == 1)
        {
            sgx_set_ssa_aexnotify(0);
        }
        second_phase(info, new_sp, (void *)internal_handle_exception);
    }
    else
#endif
    {
        return SGX_SUCCESS;
    }
 
default_handler:
    set_enclave_state(ENCLAVE_CRASHED);
    return SGX_ERROR_ENCLAVE_CRASHED;
}
