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

/*
 * Description:
 *     The file provides `enclave_entry' function to switch code between
 * trusted and untrusted envronment.
 */

    .file "trts_pic.S"

#include "trts_pic.h"

    /* .text */
    .section .nipx,"ax",@progbits

DECLARE_LOCAL_FUNC get_enclave_base
    lea_pic __ImageBase, %xax
    ret
END_FUNC

DECLARE_LOCAL_FUNC get_enclave_state
    lea_pic g_enclave_state, %xcx
    xor     %xax, %xax
    movl    (%xcx), %eax
    ret
END_FUNC

DECLARE_LOCAL_FUNC set_enclave_state
    lea_pic g_enclave_state, %xax
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %edi
#endif
    movl    %edi, (%xax)
    ret
END_FUNC

DECLARE_LOCAL_FUNC lock_enclave
    lea_pic g_enclave_state, %xdx
    xor     %xax, %xax
    mov     $ENCLAVE_INIT_NOT_STARTED, %eax
    xor     %xcx, %xcx
    mov     $ENCLAVE_INIT_IN_PROGRESS, %ecx     /* if (g_global_data.enclave_state == ENCLAVE_INIT_NOT_STARTED) */
    lock cmpxchgl %ecx, (%xdx)                  /*   g_global_data.enclave_state == ENCLAVE_INIT_IN_PROGRESS */
    ret                                         /* xax: the initial value of enclave state */
END_FUNC

/*
 * ---------------------------------------------------------------------
 * Function: thread_data_t* get_thread_data(void);
 *
 *     Get the address of thread_data
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_thread_data
    READ_TD_DATA self_addr
    ret
END_FUNC

/*
 * ---------------------------------------------------------------------
 * Function: sys_word_t get_stack_guard(void);
 *
 *     Get the value of stack_guard
 * ---------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC get_stack_guard
    READ_TD_DATA stack_guard
    ret
END_FUNC

/*
 * ---------------------------------------------------------------------
 * Function: enclave_entry
 *      The entry point of the enclave.
 *
 * Registers:
 *      XAX - TCS.CSSA
 *      XBX - the address of a TCS
 *      XCX - the address of the instruction following the EENTER
 *      XDI - the reason of entering the enclave
 *      XSI - the pointer to the marshalling structure
 */
DECLARE_GLOBAL_FUNC enclave_entry
/*
 * ----------------------------------------------------------------------
 * Dispatch code according to CSSA and the reason of EENTER
 *      eax >   0 - exception handler
 *      edi >=  0 - ecall
 *      edi == -1 - do_init_enclave
 *      edi == -2 - oret
 * Registers
 *      No need to use any register during the dispatch
 * ----------------------------------------------------------------------
 */

    /* Clear unused general registers */
    xor     %xdx, %xdx
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    cld                         /* DF = 0 */
#if defined(LINUX64)
    xor     %r8, %r8
    xor     %r9, %r9
    xor     %r10, %r10
    xor     %r11, %r11
    xor     %r12, %r12
    xor     %r13, %r13
    xor     %r14, %r14
    xor     %r15, %r15
#endif

    /* switch to trusted stack */
    cmp     $0, %xax
    jne     .Ldo_handler                /* handle exception state */
    /* xor     %xdx, %xdx                  xdx is cssa, make sure it is 0 */
    READ_TD_DATA last_sp
    cmp     $0, %xax
    jne .Lswitch_stack
    GET_STACK_BASE  %xbx                /* if last_sp == 0, set sp to stack base */
    sub     $STATIC_STACK_SIZE, %xax    /* give space for static stack */
.Lswitch_stack:
    xchg    %xsp, %xax
    push    %xcx
    push    %xbp

    .cfi_def_cfa_offset   2 * SE_WORDSIZE
    .cfi_offset           xbp, -2 * SE_WORDSIZE
    mov     %xsp, %xbp
    .cfi_def_cfa_register xbp

    CLEAN_XFLAGS


    /* Save the registers */
    sub     $(6*SE_WORDSIZE), %xsp
    mov     %xax, -1*SE_WORDSIZE(%xbp)  /* xsp_u */
    mov     %xdx, -3*SE_WORDSIZE(%xbp)  /* cssa */
    mov     %xbx, -4*SE_WORDSIZE(%xbp)  /* TCS */
    mov     %xsi, -5*SE_WORDSIZE(%xbp)  /* XSI */
    mov     %xdi, -6*SE_WORDSIZE(%xbp)  /* XDI */

    /* clean extended feature registers */
    sub     $(4*SE_WORDSIZE), %xsp

    lea_pic SYNTHETIC_STATE, %xdi
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    lfence
    add     $(4*SE_WORDSIZE), %xsp

    /* switch to C code */
#ifdef LINUX64
    mov     -6*SE_WORDSIZE(%xbp), %xdi  /* index */
    mov     -5*SE_WORDSIZE(%xbp), %xsi  /* ms */
    mov     -4*SE_WORDSIZE(%xbp), %xdx  /* TCS */
    mov     -3*SE_WORDSIZE(%xbp), %xcx  /* cssa */
#endif
    call    enter_enclave
    mov     %xax, %xbx

.Lexit_enclave:
/* clean extended feature registers */
    lea_pic SYNTHETIC_STATE, %xdi
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    lfence

#ifndef SE_SIM
    mov     -3*SE_WORDSIZE(%xbp), %xax  /* cssa */
    cmp      $0, %xax
    jne     .Lrestore_untrust_stack

    READ_TD_DATA self_addr          /* xax: td */
    cmp     $0, %xax                /* check if td is initialized */
    je      .Lrestore_untrust_stack
    mov     first_ssa_gpr(%xax), %xdx
    movb    aex_notify(%xdx), %cl
    cmpb    $0, %cl
    je     .Lrestore_untrust_stack
    /*
     * clear aexnotify bit to disable aexnotify temporarily and
     * set td.aex_notify_flag to indicate aexnotify is enabled
     * before EEXIT
     */
    movb    $0, aex_notify(%xdx)
    movl    $0x1, aex_notify_flag(%xax)
#endif
.Lrestore_untrust_stack:
/* set xdi and xsi */
    mov     $OCMD_ERET, %xdi
    mov     %xbx, %xsi

/* restore stack */
    mov     -1*SE_WORDSIZE(%xbp), %xdx  /* xdx: xsp_u  */
    mov     %xbp, %xsp
    pop     %xbp                        /* xbp_u */
    pop     %xbx                        /* ret_u */
    mov     %xdx, %xsp                  /* xsp_u */

.Lclear_and_exit_enclave:
    /* Clear all GPRs, except xax, xbx, xdi and xsi */
    xor     %xcx, %xcx
    xor     %xdx, %xdx
#if defined(LINUX64)
    xor     %r8, %r8
    xor     %r9, %r9
    xor     %r10, %r10
    xor     %r11, %r11
    xor     %r12, %r12
    xor     %r13, %r13
    xor     %r14, %r14
    xor     %r15, %r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    cld                         /* DF = 0 */

    /* EEXIT */
    mov     $SE_EEXIT, %xax     /* EEXIT leaf */
    ENCLU

    /* Should not come here */
    ud2

.Ldo_handler:
    mov     %xax, %xdx          /* XDX: cssa */
    GET_STACK_BASE %xbx         /* XAX: static stack, set sp to stack base */
    jmp     .Lswitch_stack

    /* Should not come here */
    ud2

END_FUNC

/*
 * -------------------------------------------------------------------------
 *  sgx_status_t do_ocall(unsigned int index, void *ms);
 *
 *  Function: do_ocall
 *        The entry point of the enclave
 *  Parameters:
 *        func_addr - target function address
 *        ms - marshalling structure
 *
 *  Stack: (same as do_oret)
 *        bottom of stack ->
 *                            -----------------
 *                           | ECALL/OCALL     |
 *    previous TD.last_sp -> |   frames        |
 *                            -----------------
 *                           |   ECALL frame   |
 *                           | do_ocall param 2| 3
 *                           | do_ocall param 1| 2
 *                           |do_ocall ret_addr| 1
 *                           |     xbp         | 0 + xbp
 *                           |     ....        |
 *                           |   xsave buffer  |
 *                           |     ....        |
 *                           |  xsave pointer  | 19
 *                           |   ocall_depth   | 18
 *                           |   reserved      | 17
 *                           |   reserved      | 16
 *                           |   reserved      | 15
 *                           |     rbx         | 14
 *                           |     rsi         | 13
 *                           |     rdi         | 12
 *                           |     rbp         | 11
 *                           |     r12         | 10
 *                           |     r13         | 9
 *                           |     r14         | 8
 *                           |     r15         | 7
 *                           | prev TD.last_sp | 6
 *                           |  ocall_index    | 5
 *                           |   OCALL FLAG    | 4
 *                           |    shadow       | 3
 *                           |    shadow       | 2
 *                           |    shadow       | 1
 *             TD.last_sp -> |    shadow       | 0 + xsp
 *                            -----------------
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC do_ocall

/*
 * 8 for GPR, 1 for TD.last_sp, 1 for ocall_index
 * 1 for OCALL_FLAG, 4 for shadow space.
 * Stack Pointer is 16-byte aligned under x86_64.
 */
    push    %xbp
    mov     %xsp, %xbp

/* save parameters in stack */
#ifdef LINUX64
    mov     %xdi, 2*SE_WORDSIZE(%xbp)
    mov     %xsi, 3*SE_WORDSIZE(%xbp)
#endif

/* save and clean extended feature registers */
    READ_TD_DATA xsave_size
    sub     %xax, %xsp                 /* allocate buffer to save xregs */
    mov     $0x3f, %xax
    not     %xax
    and     %xax, %xsp                 /* xsave requires 64 byte aligned */
    mov     %xsp, %xcx                 # xsave pointer

    sub     $(20*SE_WORDSIZE), %xsp    /* 20 slots for GPRs and other info */
    mov     %xcx, SE_WORDSIZE*19(%xsp) /* addr for xsave */
/* save non-volatile registers, except xsp */
    mov     %xbx, SE_WORDSIZE*14(%xsp)
    mov     %xsi, SE_WORDSIZE*13(%xsp)
    mov     %xdi, SE_WORDSIZE*12(%xsp)
    mov     %xbp, SE_WORDSIZE*11(%xsp)

#ifdef LINUX64
    mov     %r12, SE_WORDSIZE*10(%rsp)
    mov     %r13, SE_WORDSIZE* 9(%rsp)
    mov     %r14, SE_WORDSIZE* 8(%rsp)
    mov     %r15, SE_WORDSIZE* 7(%rsp)
#endif

/* save and clean extended feature registers */
    mov     SE_WORDSIZE*19(%xsp), %xdi /* xsave pointer */
    READ_TD_DATA xsave_size
    mov     %xax, %xcx
    shr     $2, %xcx                   /* xsave size in dword */
    xor     %xax, %xax
    cld
    rep stos %eax, %es:(%xdi)

    mov     SE_WORDSIZE*19(%xsp), %xdi # xsave pointer
    mov     %xdi, (%xsp)
    call    save_xregs
    lea_pic SYNTHETIC_STATE, %xdi
    mov     %xdi, (%xsp)
    call    restore_xregs
    lfence

    /* set xdi and xsi using the input parameters */
#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi
    mov     SE_WORDSIZE*13(%xsp), %xsi
#else
    mov     SE_WORDSIZE*2(%ebp), %edi
    mov     SE_WORDSIZE*3(%ebp), %esi
#endif

    /* save ocall index to the stack */
    mov     $OCALL_FLAG, %xax
    mov     %xax, SE_WORDSIZE*4(%xsp)   /* save OCALL_FLAG */
    mov     %xdi, SE_WORDSIZE*5(%xsp)   /* save ocall_index */

    /*
     * save the inside stack context
     *     push TD.last_sp
     *     set TD.last_sp = xsp
     */
    READ_TD_DATA self_addr
    mov     %xax, %xbx

    /* call update_ocall_lastsp */
#ifdef LINUX32
    mov     %xsp, (%xsp)
#else
    mov     %xsp, %xdi
#endif

    call    update_ocall_lastsp         /* xax: td.last_sp */

#ifdef LINUX64
    mov     SE_WORDSIZE*12(%xsp), %xdi   /* restore xdi */
    mov     SE_WORDSIZE*13(%xsp), %xsi   /* restore xdi */
#endif
    /* restore outside stack context */
    mov     first_ssa_gpr(%xbx), %xdx
#ifndef SE_SIM
    movb    aex_notify(%xdx), %cl
    cmpb    $0, %cl
    je     .Lrestore_outside_stack

    /*
     * clear aexnotify to disable aexnotify temporarily and
     * set td.aex_notify_flag to indicate aexnotify is enabled
     * before EEXIT
     */
    movb    $0, aex_notify(%xdx)
    movl    $0x1, aex_notify_flag(%xbx)
#endif
.Lrestore_outside_stack:
    mov     ssa_bp_u(%xdx), %xbp
    mov     ssa_sp_u(%xdx), %xsp
    /*
     * set EEXIT registers
     * return address can be read from the ECALL frame:
     *       TD.last_sp ->
     *                     -------------
     *                    | ret_addr    |
     *                    | xbp_u       |
     *                    | xsp_u       |
     *                    | ...         |
     */
    mov     -1*SE_WORDSIZE(%xax), %xbx  /* return address */
    mov     $SE_EEXIT, %xax             /* EEXIT leaf */

    /* Clear all GPRs, except xax, xbx, xdi, and xsi*/
    xor     %xcx, %xcx
    xor     %xdx, %xdx
#ifdef LINUX64
    xor     %r8,  %r8
    xor     %r9,  %r9
    xor     %r10, %r10
    xor     %r11, %r11
    xor     %r12, %r12
    xor     %r13, %r13
    xor     %r14, %r14
    xor     %r15, %r15
#endif

    /* Set status flags to pre-defined values */
    add     %xdx, %xdx          /* OF = SF = AF = CF = 0; ZF = PF = 1 */
    cld                         /* DF = 0 */

    ENCLU
END_FUNC

/*
 * ------------------------------------------------------------------
 * this function is the wrapper of do_ocall, which is used to
 * stick ocall bridge and proxy frame together
 * ------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC __morestack
    push %xbp
    .cfi_def_cfa_offset     2*SE_WORDSIZE
    .cfi_offset             xbp,-2*SE_WORDSIZE
    mov %xsp, %xbp
    .cfi_def_cfa_register   xbp
    sub $(4*SE_WORDSIZE), %xsp
#ifdef LINUX32
    /* save the 2 parameters */
    mov (2*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (0*SE_WORDSIZE)(%xsp)
    mov (3*SE_WORDSIZE)(%xbp), %xax
    mov %xax, (1*SE_WORDSIZE)(%xsp)
#endif
    call        do_ocall
    leave
    ret
END_FUNC

DECLARE_GLOBAL_FUNC asm_oret
    mov     %xsp, %xbx
#ifdef LINUX64
    mov     %xdi, SE_WORDSIZE(%xsp)
    mov     %xsi, 2*SE_WORDSIZE(%xsp)
#endif
    mov     SE_WORDSIZE(%xbx), %xsp    /* restore thread_data.last_sp */

/* restore extended feature registers */
    mov     19*SE_WORDSIZE(%xsp), %xdi
#ifdef LINUX32
    mov     %xdi, (%xsp)
#endif
    call    restore_xregs
    lfence

/* memset_s */
    xor     %xax, %xax
    mov     11*SE_WORDSIZE(%xsp), %xcx
    sub     %xdi, %xcx
    sub     $SE_WORDSIZE, %xcx
    shr     $2, %xcx
    cld
    rep stos %eax,%es:(%xdi)

    mov     2*SE_WORDSIZE(%xbx), %xax  /* ocall return value */

#ifdef LINUX64
    mov     7*SE_WORDSIZE(%xsp), %r15
    mov     8*SE_WORDSIZE(%xsp), %r14
    mov     9*SE_WORDSIZE(%xsp), %r13
    mov    10*SE_WORDSIZE(%xsp), %r12
#endif

    mov    11*SE_WORDSIZE(%xsp), %xbp
    mov    12*SE_WORDSIZE(%xsp), %xdi
    mov    13*SE_WORDSIZE(%xsp), %xsi
    mov    14*SE_WORDSIZE(%xsp), %xbx

    mov     %xbp, %xsp
    pop     %xbp

    ret
    /* should not come here */
    ud2
END_FUNC

/*
 * ------------------------------------------------------------------------
 * extern "C" int do_egetkey(key_request_t *key_request, key_128bit_t *key)
 * return value:
 *	0 - success
 *	none-zeor - EGETKEY error code
 * EGETKEY: rbx - the address of KEYREQUEST structure
 *	   rcx - the address where the key is outputted
 * ------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC do_egetkey
    SE_PROLOG
    mov  $SE_EGETKEY, %xax      /* EGETKEY leaf */
    ENCLU
#ifdef SE_SIM
    cmp  $SGX_SUCCESS, %xax     /* In simulation mode, ZF flag will not be set */
    jnz	 .Legetkey_done         /* because the stack clean operation will always clean ZF flag */
#else
    jz   .Legetkey_done         /* if EGETKEY error, ZF flag is set and error code is set to xax */
#endif
    xor  %xax, %xax
.Legetkey_done:
    SE_EPILOG
END_FUNC


/*
 * -------------------------------------------------------------------------
 * extern "C" int do_ereport(sgx_target_info_t *target_info, sgx_report_data_t *report_data, sgx_report_t *report);
 * EREPORT: rbx - the address of TARGETINFO;
 *          rcx - the address of REPORTDATA;
 *          rdx - the address where REPORT is outputted
 * return value:
 *          zero: success
 *          non-zero: failure
 * -------------------------------------------------------------------------
 */
.global Lereport_inst
DECLARE_LOCAL_FUNC do_ereport
    SE_PROLOG
    mov       $SE_EREPORT, %xax  /* EREPORT leaf */
    clc
Lereport_inst:
    ENCLU
    setc      %al
    SE_EPILOG
END_FUNC

.global Leverifyreport2_inst
DECLARE_LOCAL_FUNC do_everifyreport2
    SE_PROLOG
    mov       $SE_EVERIFYREPORT2, %xax  /* EVERIFYREPORT2 leaf */
Leverifyreport2_inst:
    ENCLU
    jz   .Leverifyreport2_done  /* if EVERIFYREPORT2 error, ZF flag is set and error code is set to xax */
    xor  %xax, %xax
.Leverifyreport2_done:
    SE_EPILOG
END_FUNC

DECLARE_GLOBAL_FUNC do_eaccept
    SE_PROLOG
    mov     $SE_EACCEPT, %eax
    ENCLU
    cmp  $SGX_SUCCESS, %eax
    jnz	 abort
    SE_EPILOG
END_FUNC

DECLARE_GLOBAL_FUNC do_eacceptcopy
    SE_PROLOG
    mov     $SE_EACCEPTCOPY, %eax
    ENCLU
    cmp  $SGX_SUCCESS, %eax
    jnz  abort
    SE_EPILOG
END_FUNC

DECLARE_GLOBAL_FUNC do_emodpe
    SE_PROLOG
    mov     $SE_EMODPE, %eax
    ENCLU
    SE_EPILOG
END_FUNC

#define _RDRAND_RETRY_TIMES 10
/*
 * -------------------------------------
 * extern "C" uint32_t do_rdrand(uint32_t *rand);
 * return value:
 *	non-zero: rdrand succeeded
 *	zero: rdrand failed
 * -------------------------------------
 */
DECLARE_LOCAL_FUNC do_rdrand
    mov $_RDRAND_RETRY_TIMES, %ecx
.Lrdrand_retry:
    .byte 0x0F, 0xC7, 0xF0	    /* rdrand %eax */
    jc	.Lrdrand_return
    dec	%ecx
    jnz 	.Lrdrand_retry
    xor 	%xax, %xax
    ret
.Lrdrand_return:
#ifdef LINUX32
    mov     SE_WORDSIZE(%esp), %ecx
#else
    mov     %rdi, %rcx
#endif
    movl    %eax, (%xcx)
    mov     $1, %xax
    ret
END_FUNC

/*
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC abort
    lea_pic g_enclave_state, %xax
    movl    $ENCLAVE_CRASHED, (%xax)
    ud2
END_FUNC

/*
 * -------------------------------------------------------------------------
 * extern "C" __attribute__((regparm(1))) void continue_execution(sgx_exception_info_t *info);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC continue_execution
#ifdef LINUX32
    mov     %xax, %xcx
#else
    mov     %xdi, %xcx
#endif
    mov     SE_WORDSIZE*0(%xcx), %xax
    push    %xax                       /* push xax */
    mov     SE_WORDSIZE*1(%xcx), %xax
    push    %xax                       /* push xcx */
    mov     SE_WORDSIZE*4(%xcx), %xax  /* xax: xsp */
/* x86_64 requires a 128-bytes red zone. We need to allocate buffer to avoid touching the red zone. */
    sub     $(SE_WORDSIZE + RED_ZONE_SIZE), %xax   /* allocate buffer to skip red zone and save xip */

/* restore registers except xax, xcx, xsp */
    mov     SE_WORDSIZE*2(%xcx), %xdx
    mov     SE_WORDSIZE*3(%xcx), %xbx
    mov     SE_WORDSIZE*5(%xcx), %xbp
    mov     SE_WORDSIZE*6(%xcx), %xsi
    mov     SE_WORDSIZE*7(%xcx), %xdi
#ifdef LINUX64
    mov     SE_WORDSIZE*8(%xcx), %r8
    mov     SE_WORDSIZE*9(%xcx), %r9
    mov     SE_WORDSIZE*10(%xcx), %r10
    mov     SE_WORDSIZE*11(%xcx), %r11
    mov     SE_WORDSIZE*12(%xcx), %r12
    mov     SE_WORDSIZE*13(%xcx), %r13
    mov     SE_WORDSIZE*14(%xcx), %r14
    mov     SE_WORDSIZE*15(%xcx), %r15
    push    SE_WORDSIZE*16(%xcx)
    popf    /* make sure the following instructions do not affect flags */
#else
    push    SE_WORDSIZE*8(%xcx)
    popf
#endif

#ifdef LINUX64
    mov     SE_WORDSIZE*17(%xcx), %xcx
#else
    mov     SE_WORDSIZE*9(%xcx), %xcx  /* xcx: xip */
#endif

/* do not setup the new stack until info is not needed any more
 * otherwise, info will be overwritten
 */
    mov     %xcx, (%xax)               /* save xip to the new stack */
    pop     %xcx                       /* restore xcx */
    pop     %xsp                       /* xsp: xax */
    xchg    %xax, %xsp

    ret     $(RED_ZONE_SIZE)           /* pop xip and red zone (if any) */
END_FUNC

/* 
 * -------------------------------------------------------------------------
 * extern "C" __attribute__((regparm(1))) void second_phase(sgx_exception_info_t *info, 
 *   void *new_sp, void *second_phase_handler_addr);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC second_phase
    movq    %xsi, %xsp
    mov     $SE_EDECCSSA, %xax
    enclu                               /* DECCSSA */
    jmp     *%xdx
END_FUNC
    
