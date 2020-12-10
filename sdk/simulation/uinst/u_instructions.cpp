/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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


// u_instructions.cpp -- It simulates Enclave instructions.
#include <string.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "arch.h"
#include "util.h"
#include "se_memory.h"
#include "se_memcpy.h"
#include "se_trace.h"
#include "enclave.h"
#include "td_mngr.h"
#include "thread_data.h"

#include "lowlib.h"
#include "sgxsim.h"
#include "enclave_mngr.h"
#include "u_instructions.h"

#include "crypto_wrapper.h"

static uintptr_t _EINIT(secs_t* secs, enclave_css_t* css, token_t* launch);
static uintptr_t _ECREATE (page_info_t* pi);
static uintptr_t _EADD (page_info_t* pi, void* epc_lin_addr);
static uintptr_t _EREMOVE(const void* epc_lin_addr);
extern "C" void* get_td_addr(void);

////////////////////////////////////////////////////////////////////////
#define __GP__() exit(EXIT_FAILURE)

#define GP() do {                                                       \
        SE_TRACE(SE_TRACE_DEBUG, "#GP on %s, line: %d\n", __FILE__, __LINE__); \
        __GP__();                                                       \
    } while (0)

#define GP_ON(cond) if (cond) GP()

#define GP_ON_EENTER GP_ON

#define mcp_same_size(dst_ptr, src_ptr, size) memcpy_s(dst_ptr, size, src_ptr, size)

static void xsave_regs(char *addr, uint64_t bits)
{
    if(bits == 3)
    {
        asm volatile("fxsave %0" : : "m" (*addr));
    }
    else
    {
        uint32_t high = (uint32_t)(bits >> 32);
        uint32_t low = (uint32_t)(bits & 0xFFFFFFFF);
        asm volatile("xsave %0" : : "m" (*addr), "a" (low), "d" (high));
    }
}
static void xrstor_regs(char *addr, uint64_t bits)
{
    if(bits == 3)
    {
        asm volatile("fxrstor %0" : : "m" (*addr));
    }
    else
    {
        uint32_t high = (uint32_t)(bits >> 32);
        uint32_t low = (uint32_t)(bits & 0xFFFFFFFF);
        asm volatile("xrstor %0" : : "m" (*addr), "a" (low), "d" (high));
    }
}

static struct sigaction g_old_sigact[_NSIG];
void call_old_handler(int signum, void* siginfo, void *priv)
{
    SE_TRACE(SE_TRACE_DEBUG, "call urts handler\n");
    if(SIG_DFL == g_old_sigact[signum].sa_handler)
    {
        signal(signum, SIG_DFL);
        raise(signum);
    }
    //if there is old signal handler, we need transfer the signal to the old signal handler;
    else
    {
        if(!(g_old_sigact[signum].sa_flags & SA_NODEFER))
            sigaddset(&g_old_sigact[signum].sa_mask, signum);

        sigset_t cur_set;
        pthread_sigmask(SIG_SETMASK, &g_old_sigact[signum].sa_mask, &cur_set);
   
        if(g_old_sigact[signum].sa_flags & SA_SIGINFO)
        {

            g_old_sigact[signum].sa_sigaction(signum, (siginfo_t*)siginfo, priv);
        }
        else
        {
            g_old_sigact[signum].sa_handler(signum);
        }

        pthread_sigmask(SIG_SETMASK, &cur_set, NULL);

        if(g_old_sigact[signum].sa_flags & SA_RESETHAND)
            g_old_sigact[signum].sa_handler = SIG_DFL;
    }
}
void sig_handler_sim(int signum, siginfo_t* siginfo, void *priv)  __attribute__((optimize(0)));
void sig_handler_sim(int signum, siginfo_t* siginfo, void *priv)
{
    SE_TRACE(SE_TRACE_DEBUG, "SIM signal handler is triggered\n");
    GP_ON(signum != SIGFPE && signum != SIGSEGV);
    
    thread_data_t *thread_data = (thread_data_t*)get_td_addr();
    if (thread_data != NULL) 
    {
        // first SSA can be used to get tcs, even cssa > 0.
        ssa_gpr_t *p_ssa_gpr = (ssa_gpr_t*)thread_data->first_ssa_gpr;
        size_t xbp = p_ssa_gpr -> REG(bp_u);
        tcs_t *tcs = GET_TCS_PTR(xbp);
        if(tcs != NULL)
        {
            CEnclaveMngr *mngr = CEnclaveMngr::get_instance();
            assert(mngr != NULL);

            CEnclaveSim* ce = mngr->get_enclave(tcs);
            if (ce != NULL && ce->is_tcs_page(tcs))
            {
                ucontext_t* context = reinterpret_cast<ucontext_t *>(priv);
                size_t xip = context->uc_mcontext.gregs[REG_RIP];
                secs_t *secs = ce->get_secs();
                if (secs && (xip >= (size_t)secs->base) && (xip < (size_t)secs->base + secs->size))
	        {
                    tcs_sim_t *tcs_sim = reinterpret_cast<tcs_sim_t *>(tcs->reserved);
                    GP_ON(tcs_sim->tcs_state != TCS_STATE_ACTIVE);
                    tcs_sim->tcs_state = TCS_STATE_INACTIVE;
                    GP_ON(tcs->cssa >= tcs->nssa);
                    p_ssa_gpr = (ssa_gpr_t*)((size_t)p_ssa_gpr + tcs->cssa * secs->ssa_frame_size * SE_PAGE_SIZE);
                    p_ssa_gpr->REG(ax) = context->uc_mcontext.gregs[REG_RAX];
                    p_ssa_gpr->REG(cx) = context->uc_mcontext.gregs[REG_RCX];
                    p_ssa_gpr->REG(dx) = context->uc_mcontext.gregs[REG_RDX];
                    p_ssa_gpr->REG(bx) = context->uc_mcontext.gregs[REG_RBX];
                    p_ssa_gpr->REG(sp) = context->uc_mcontext.gregs[REG_RSP];
                    p_ssa_gpr->REG(bp) = context->uc_mcontext.gregs[REG_RBP];
                    p_ssa_gpr->REG(si) = context->uc_mcontext.gregs[REG_RSI];
                    p_ssa_gpr->REG(di) = context->uc_mcontext.gregs[REG_RDI];
                    p_ssa_gpr->REG(ip) = context->uc_mcontext.gregs[REG_RIP];
                    p_ssa_gpr->r8  = context->uc_mcontext.gregs[REG_R8];
                    p_ssa_gpr->r9  = context->uc_mcontext.gregs[REG_R9];
                    p_ssa_gpr->r10 = context->uc_mcontext.gregs[REG_R10];
                    p_ssa_gpr->r11 = context->uc_mcontext.gregs[REG_R11];
                    p_ssa_gpr->r12 = context->uc_mcontext.gregs[REG_R12];
                    p_ssa_gpr->r13 = context->uc_mcontext.gregs[REG_R13];
                    p_ssa_gpr->r14 = context->uc_mcontext.gregs[REG_R14];
                    p_ssa_gpr->r15 = context->uc_mcontext.gregs[REG_R15];
                    p_ssa_gpr->rflags = context->uc_flags;

	            xsave_regs((char*)((size_t)p_ssa_gpr + sizeof(ssa_gpr_t) - secs->ssa_frame_size * SE_PAGE_SIZE), secs->attributes.xfrm);
		    // not sure if they are the same, copy context->__fpregs_mem to SSA again
		    memcpy((uint8_t*)((size_t)p_ssa_gpr + sizeof(ssa_gpr_t) - secs->ssa_frame_size * SE_PAGE_SIZE), &context->__fpregs_mem, sizeof(context->__fpregs_mem));
                    context->uc_mcontext.gregs[REG_RAX] = SE_ERESUME;
                    context->uc_mcontext.gregs[REG_RBX] = (size_t)tcs;
                    context->uc_mcontext.gregs[REG_RIP] = tcs_sim->saved_aep;
                    context->uc_mcontext.gregs[REG_RBP] = p_ssa_gpr->REG(bp_u);
                    context->uc_mcontext.gregs[REG_RSP] = p_ssa_gpr->REG(sp_u);
                    if(signum == SIGSEGV)
		    {
                        p_ssa_gpr->exit_info.valid = 1;
                        p_ssa_gpr->exit_info.exit_type = 6; //SW
                        p_ssa_gpr->exit_info.vector = 14;   //#PF
			struct misc_t {
                            void *   maddr;
			    uint32_t errcd;
			    uint32_t reserved;
			};
		        struct misc_t *misc = (misc_t*)((size_t)p_ssa_gpr - 16);
			misc->maddr = siginfo->si_addr;
			misc->errcd = siginfo->si_errno; 
		    }
		    else if(signum == SIGFPE)
		    {
                        p_ssa_gpr->exit_info.valid = 1;
                        p_ssa_gpr->exit_info.exit_type = 6; //SW
                        p_ssa_gpr->exit_info.vector = 0;   //#DE
		    }
		    else
		    {
                        p_ssa_gpr->exit_info.valid = 0;
		    }
                    tcs->cssa +=1;
		    // copy stack to untrusted stack
		    uintptr_t rsp_t = 0;
		    uintptr_t rbp_t = 0;
		    asm volatile("mov %%rsp, %0":"=m"(rsp_t));
		    size_t stack_size = p_ssa_gpr->REG(sp) - rsp_t;
		    uintptr_t rsp_u = ((p_ssa_gpr->REG(sp_u) - stack_size) >> 4) << 4;
		    memcpy((void*)rsp_u, (void*)rsp_t, stack_size);
		    uintptr_t *p_t = (uintptr_t *)rsp_t;
		    uintptr_t *p_u = (uintptr_t *)rsp_u;
		    for (size_t i = 0; i < stack_size / sizeof(uintptr_t); i++ )
		    {
                        if(*p_t - rsp_t <= stack_size)
			{
				*p_u = *p_t - rsp_t + rsp_u;
			}
			p_t++;
			p_u++;
		    }
		    asm volatile("mov %%rbp, %0":"=m"(rbp_t));
		    if (rbp_t -rsp_t <= stack_size)
                    {
                        uintptr_t rbp_u = rbp_t - rsp_t + rsp_u;
		        asm volatile("mov %0, %%rbp"::"r"(rbp_u));
		    }

                    ucontext_t *context_u = (ucontext_t *)((uintptr_t)priv - rsp_t + rsp_u);
		    siginfo_t *siginfo_u = (siginfo_t *)((uintptr_t)siginfo - rsp_t + rsp_u);
                    switch_stack(signum, (void*)siginfo_u, (void*)context_u, rsp_u);
		    return;
	        }
	    }
        }
    }
    call_old_handler(signum, siginfo, priv);
}

void reg_sig_handler_sim()
{
    int ret = 0;
    struct sigaction sig_act;

    memset(&sig_act, 0, sizeof(sig_act));
    sig_act.sa_sigaction = sig_handler_sim;
    sig_act.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
    sigemptyset(&sig_act.sa_mask);
    if(sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask))
    {
        SE_TRACE(SE_TRACE_WARNING, "%s\n", strerror(errno));
    }
    else
    {
        sigdelset(&sig_act.sa_mask, SIGSEGV);
        sigdelset(&sig_act.sa_mask, SIGFPE);
    }

    ret = sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]);
    if (0 != ret) abort();
    ret = sigaction(SIGFPE, &sig_act, &g_old_sigact[SIGFPE]);
    if (0 != ret) abort();
}

uintptr_t _EINIT(secs_t* secs, enclave_css_t *css, token_t *launch)
{
    CEnclaveMngr *mngr = CEnclaveMngr::get_instance();
    assert(mngr != NULL);

    CEnclaveSim* ce = mngr->get_enclave(secs);
    GP_ON(ce == NULL);

    GP_ON((ce->get_secs()->attributes.flags & SGX_FLAGS_INITTED) != 0);

    // Fill MREnclave, MRSigner, ISVPRODID, ISVSVN
    secs_t* this_secs = ce->get_secs();
    if (css != NULL) {
        // Check signature
        if ((css->body.attribute_mask.xfrm & this_secs->attributes.xfrm)
            != (css->body.attribute_mask.xfrm & css->body.attributes.xfrm))
        {
            SE_TRACE(SE_TRACE_DEBUG,
                "SECS attributes.xfrm does NOT match signature attributes.xfrm\n");
            return SGX_ERROR_INVALID_ATTRIBUTE;
        }

        if ((css->body.attribute_mask.flags & this_secs->attributes.flags)
            != (css->body.attribute_mask.flags & css->body.attributes.flags))
        {
            SE_TRACE(SE_TRACE_DEBUG,
                "SECS attributes.flag does NOT match signature attributes.flag\n");
            return SGX_ERROR_INVALID_ATTRIBUTE;
        }

        reg_sig_handler_sim();

        mcp_same_size(&this_secs->mr_enclave, &css->body.enclave_hash, sizeof(sgx_measurement_t));
        this_secs->isv_prod_id = css->body.isv_prod_id;
        this_secs->isv_svn = css->body.isv_svn;
        
        uint8_t signer[SGX_HASH_SIZE] = {0};
        unsigned int signer_len = SGX_HASH_SIZE;
        sgx_status_t ret = sgx_EVP_Digest(EVP_sha256(), css->key.modulus, SE_KEY_SIZE, signer, &signer_len);
        if(ret != SGX_SUCCESS)
        {
            if(ret != SGX_ERROR_OUT_OF_MEMORY)
                ret = SGX_ERROR_UNEXPECTED;
            return ret;
        }
        assert(signer_len == SGX_HASH_SIZE);

        mcp_same_size(&this_secs->mr_signer, signer, SGX_HASH_SIZE);
    }

    // Check launch token
    if (launch != NULL && launch->body.valid) {
        if (memcmp(&launch->body.attributes, &this_secs->attributes, sizeof(sgx_attributes_t)))
        {
            SE_TRACE(SE_TRACE_DEBUG,
                "SECS attributes does NOT match launch token attribuets\n");
            return SGX_ERROR_INVALID_ATTRIBUTE;
        }
    }

    // Mark it initialized
    this_secs->attributes.flags |= SGX_FLAGS_INITTED;

    return SGX_SUCCESS;
}

static inline bool is_power_of_two(size_t n)
{
    return (n != 0) && (!(n & (n - 1)));
}

// Returns the pointer to the Enclave instance on success.
uintptr_t _ECREATE(page_info_t* pi)
{
    secs_t* secs = reinterpret_cast<secs_t*>(pi->src_page);

    // Enclave size must be at least 2 pages and a power of 2.
    GP_ON(!is_power_of_two((size_t)secs->size));
    GP_ON(secs->size < (SE_PAGE_SIZE << 1));

    CEnclaveSim* ce = new CEnclaveSim(secs);
    void*   addr;

    // `ce' is not checked against NULL, since it is not
    // allocated with new(std::no_throw).
    addr = se_virtual_alloc(NULL, (size_t)secs->size, MEM_COMMIT);
    if (addr == NULL) {
        delete ce;
        return 0;
    }

    // Mark all the memory inaccessible.
    se_virtual_protect(addr, (size_t)secs->size, SGX_PROT_NONE);
    ce->get_secs()->base = addr;

    CEnclaveMngr::get_instance()->add(ce);
    return reinterpret_cast<uintptr_t>(ce);
}

uintptr_t _EADD(page_info_t* pi, void *epc_lin_addr)
{
    void     *src_page = pi->src_page;
    CEnclaveMngr *mngr = CEnclaveMngr::get_instance();
    CEnclaveSim    *ce = mngr->get_enclave(pi->lin_addr);

    if (ce == NULL) {
        SE_TRACE(SE_TRACE_DEBUG, "failed to get enclave instance\n");
        return SGX_ERROR_UNEXPECTED;
    }

    GP_ON(!IS_PAGE_ALIGNED(epc_lin_addr));
    GP_ON((ce->get_secs()->attributes.flags & SGX_FLAGS_INITTED) != 0);

    // Make the page writable before doing memcpy()
    se_virtual_protect(epc_lin_addr, SE_PAGE_SIZE, SI_FLAGS_RW);

    mcp_same_size(epc_lin_addr, src_page, SE_PAGE_SIZE);

    se_virtual_protect(epc_lin_addr, SE_PAGE_SIZE, (uint32_t)pi->sec_info->flags);

    GP_ON(!ce->add_page(pi->lin_addr, pi->sec_info->flags));
    return SGX_SUCCESS;
}

uintptr_t _EREMOVE(const void *epc_lin_addr)
{
    CEnclaveMngr *mngr = CEnclaveMngr::get_instance();
    CEnclaveSim *ce = mngr->get_enclave(epc_lin_addr);

    GP_ON(!ce);
    GP_ON(!IS_PAGE_ALIGNED(epc_lin_addr));

    return ce->remove_page(epc_lin_addr) ? 0 : -1;
}

////////////////////////////////////////////////////////////////////////

// Master entry functions

// The call to load_regs assumes the existence of a frame pointer.
LOAD_REGS_ATTRIBUTES
void _SE3(uintptr_t xax, uintptr_t xbx,
          uintptr_t xcx, uintptr_t xdx,
          uintptr_t xsi, uintptr_t xdi)
{
    UNUSED(xdx);

    switch (xax)
    {
    case SE_EENTER:
        uintptr_t     xip;
        void        * enclave_base_addr;
        se_pt_regs_t* p_pt_regs;
        tcs_t*        tcs;
        tcs_sim_t*    tcs_sim;
        ssa_gpr_t*    p_ssa_gpr;
        secs_t*       secs;
        CEnclaveMngr* mngr;
        CEnclaveSim*    ce;

        // xbx contains the address of a TCS
        tcs = reinterpret_cast<tcs_t*>(xbx);

        // Is TCS pointer page-aligned?
        GP_ON_EENTER(!IS_PAGE_ALIGNED(tcs));

        mngr = CEnclaveMngr::get_instance();
        assert(mngr != NULL);

        // Is it really a TCS?
        ce = mngr->get_enclave(tcs);
        GP_ON_EENTER(ce == NULL);
        GP_ON_EENTER(!ce->is_tcs_page(tcs));

        // Check the EntryReason
        tcs_sim = reinterpret_cast<tcs_sim_t *>(tcs->reserved);
        GP_ON_EENTER(tcs_sim->tcs_state != TCS_STATE_INACTIVE);
        GP_ON_EENTER(tcs->cssa >= tcs->nssa);

        secs = ce->get_secs();
        enclave_base_addr = secs->base;

        p_ssa_gpr = reinterpret_cast<ssa_gpr_t*>(reinterpret_cast<uintptr_t>(enclave_base_addr) + static_cast<size_t>(tcs->ossa)
                + secs->ssa_frame_size * SE_PAGE_SIZE
                - sizeof(ssa_gpr_t));

        tcs_sim->saved_aep = xcx;

        p_pt_regs = reinterpret_cast<se_pt_regs_t*>(get_bp());
        p_ssa_gpr->REG(bp_u) = p_pt_regs->xbp;

        p_ssa_gpr->REG(sp_u) = reinterpret_cast<uintptr_t>(p_pt_regs + 1);
        xcx = p_pt_regs->xip;

        xip = reinterpret_cast<uintptr_t>(enclave_base_addr);
        GP_ON_EENTER(xip == 0);

        //set the _tls_array to point to the self_addr of TLS section inside the enclave
        GP_ON_EENTER(td_mngr_set_td(enclave_base_addr, tcs) == false);
 
        // Destination depends on STATE
        xip += (uintptr_t)tcs->oentry;
        tcs_sim->tcs_state = TCS_STATE_ACTIVE;

        // Link the TCS to the thread
        GP_ON_EENTER((secs->attributes.flags & SGX_FLAGS_INITTED) == 0);

        // Replace the return address on the stack with the enclave entry,
        // so that when we return from this function, we'll enter the enclave.
        enclu_regs_t regs;
        regs.xax = tcs->cssa;
        regs.xbx = reinterpret_cast<uintptr_t>(tcs);
        regs.xcx = xcx;
        regs.xdx = 0;
        regs.xsi = xsi;
        regs.xdi = xdi;
        regs.xbp = p_ssa_gpr->REG(bp_u);
        regs.xsp = p_ssa_gpr->REG(sp_u);
        regs.xip = xip;

        load_regs(&regs);

        // Returning from this function enters the enclave
        return;
    case SE_ERESUME:
        SE_TRACE(SE_TRACE_DEBUG, "ERESUME instruction\n");
        // xbx contains the address of a TCS
        tcs = reinterpret_cast<tcs_t*>(xbx);
        // Is TCS pointer page-aligned?
        GP_ON_EENTER(!IS_PAGE_ALIGNED(tcs));

        mngr = CEnclaveMngr::get_instance();
        assert(mngr != NULL);

        ce = mngr->get_enclave(tcs);
        ce = mngr->get_enclave(tcs);
        GP_ON_EENTER(ce == NULL);
        GP_ON_EENTER(!ce->is_tcs_page(tcs));

        // Check the EntryReason
        tcs_sim = reinterpret_cast<tcs_sim_t *>(tcs->reserved);
        GP_ON_EENTER(tcs_sim->tcs_state != TCS_STATE_INACTIVE);
        tcs_sim->tcs_state = TCS_STATE_ACTIVE;
        tcs->cssa -=1;

        secs = ce->get_secs();
        enclave_base_addr = secs->base;

        p_ssa_gpr = reinterpret_cast<ssa_gpr_t*>(reinterpret_cast<uintptr_t>(enclave_base_addr) + static_cast<size_t>(tcs->ossa)
                + (tcs->cssa+1) * secs->ssa_frame_size * SE_PAGE_SIZE
                - sizeof(ssa_gpr_t));

        xrstor_regs((char*)((size_t)p_ssa_gpr + sizeof(ssa_gpr_t) - secs->ssa_frame_size * SE_PAGE_SIZE), secs->attributes.xfrm);
        regs.xax = p_ssa_gpr->REG(ax);
        regs.xbx = p_ssa_gpr->REG(bx);
        regs.xdx = p_ssa_gpr->REG(dx);
        regs.xcx = p_ssa_gpr->REG(cx);
        regs.xdi = p_ssa_gpr->REG(di);
        regs.xsi = p_ssa_gpr->REG(si);
        regs.xsp = p_ssa_gpr->REG(sp);
        regs.xbp = p_ssa_gpr->REG(bp);
        regs.xip = p_ssa_gpr->REG(ip);

        load_regs(&regs);
        return;

    default:
        // There's only 1 ring 3 instruction outside the enclave: EENTER.
        GP();
    }
}

uintptr_t _SE0(uintptr_t xax, uintptr_t xbx,
               uintptr_t xcx, uintptr_t xdx,
               uintptr_t xsi, uintptr_t xdi)
{
    UNUSED(xsi), UNUSED(xdi);

    switch (xax)
    {
    case SE_ECREATE:
        return _ECREATE(reinterpret_cast<page_info_t*>(xbx));

    case SE_EADD:
        return _EADD(reinterpret_cast<page_info_t*>(xbx),
                     reinterpret_cast<void*>(xcx));

    case SE_EINIT:
        return _EINIT(reinterpret_cast<secs_t*>(xbx),
                      reinterpret_cast<enclave_css_t *>(xcx),
                      reinterpret_cast<token_t *>(xdx));

    case SE_EREMOVE:
        return _EREMOVE(reinterpret_cast<void*>(xcx));

    default:
        GP();
    }

    return 0;
}

