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

// Generates code that consumes `n` cycles by repeatedly moving from register
// `r` to itself.
.macro CYCLE_DELAY n r
    lea (\r), \r
.if \n-1
CYCLE_DELAY "(\n-1)" \r
.endif
.endm

    .data
    .align 0x1000   /* 4KB */
.globl aex_notify_c3_cache
aex_notify_c3_cache:
    .space 0x1000 /* 4KB */

/*
 * Description:
 *     The file provides mitigations for SGX-Step
 */

    .file "trts_mitigation.S"

#include "trts_pic.h"
#include "../trts_mitigation.h"

    /* .text */
    .section .nipx,"ax",@progbits

/*
 * -------------------------------------------------------------------------
 *  extern "C"
 *  void constant_time_apply_sgxstep_mitigation_and_continue_execution(
 *      sgx_exception_info_t *info,
 *      uintptr_t ssa_aexnotify_addr,
 *      uintptr_t stack_tickle_pages,
 *      uintptr_t code_tickle_page,
 *      uintptr_t data_tickle_address,
 *      uintptr_t c3_byte_address);
 *
 *  Function: constant_time_apply_sgxstep_mitigation_and_continue_execution
 *      Mitigate SGX-Step and return to the point at which the most recent
 *      interrupt/exception occurred.
 *  Parameters:
 *      -  info: pointer to the SGX exception info for the most recent
 *         interrupt/exception
 *      -  ssa_aexnotify_addr: address of the SSA[0].GPRSGX.AEXNOTIFY byte
 *      -  stack_tickle_pages: Base address of stack page(s) to tickle
 *      -  code_tickle_page: Base address of code page to tickle
 *      -  data_tickle_address: address of data memory to tickle
 *      -  c3_byte_address: Address of a c3 byte in code_tickle_page
 *      There are three additional "implicit" parameters to this function:
 *      1. The low-order bit of `stack_tickle_pages` is 1 if a second stack
 *         page should be tickled (specifically, the stack page immediately
 *         below the page specified in the upper bits)
 *      2. Bit 0 of `code_tickle_page` is 1 if `data_tickle_address`
 *         is writable, and therefore should be tested for write permissions
 *         by the mitigation
 *      3. Bit 4 of `code_tickle_page` is 1 if the cycle delay
 *         should be added to the mitigation
 *
 *  Stack:
 *        bottom of stack ->  ---------------------------
 *                           | Lower frame(s)            |
 *                            ---------------------------
 * rsp of main flow    ---+  | Stack frame of the "main  |
 *         ==             |  | flow" function that was   |
 * rsp @mitigation_begin  -> | interrupted               |<--+-(irq mitigation)
 *                            ---------------------------    |
 *                           |      ...                  |<--+-(irq c3)
 *                           |  red zone (128 bytes)     |   |
 *                           |      ...                  |   |
 *                         +- ---------------------------    |
 *                       +-|-|  rsvd main-flow RIP       |-1 |
 *                       | | |  rsvd main-flow RAX       |-2 |
 *                       | | |  rsvd main-flow RCX       |-3 |
 * (main-flow regs that  | | |  rsvd main-flow RDX       |-4 |
 *  will be reset in     | | |  rsvd main-flow RBX       |-5 |
 *  ct_restore_state)    | | |  rsvd main-flow RBP       |-6 |
 *                       | | |  rsvd main-flow RSI       |-7 |
 *                       | | |  rsvd main-flow RDI       |-8 |
 *                       +-|-|  rsvd main-flow -8(rsp)   |-9 |
 * (this whole rsvd area   |  ---------------------------    |
 *  is persistent and will | |      ...                  |   |
 *  not be touched by      | |   padding for alignment   |   |
 *  stage-1/2 handlers)    +-|      ...                  |   |
 *                        +-- ---------------------------    |
 *                        |  |  exception_type           |   |
 *                        |  |  exception_vec            |   |
 *                        |  |  pre-irq RIP              |17 |
 *                        |  |  pre-irq RFLAGS           |16 |
 *                        |  |  pre-irq R15              |15 |
 * (pre-irq CPU state     |  |  pre-irq R14              |14 |
 *  prepared by stage-1   |  |  pre-irq R13              |13 |
 *  handler in            |  |  pre-irq R12              |12 |
 *  trts_handle_exception)|  |  pre-irq R11              |11 |
 *                        |  |  pre-irq R10              |10 |
 *                        |  |  pre-irq R9               |9  |
 *                        |  |  pre-irq R8               |8  |
 *                        |  |  pre-irq RDI              |7  |
 *                        |  |  pre-irq RSI              |6  |
 *                        |  |  pre-irq RBP              |5  |
 *                        |  |  pre-irq RSP              |4--+
 *                        |  |  pre-irq RBX              |3
 *                        |  |  pre-irq RDX              |2
 *                        |  |  pre-irq RCX              |1
 * rdi @entry             -> |  pre-irq RAX              |0
 *                        +-- ---------------------------|
 * rsp @second_phase      -> |  pre-irq RIP (for dbg)    |
 *                            ---------------------------|
 *                           | Stack frame of stage-2    |
 *                           | internal_handle_exception |
 * rsp @entry             -> |      ...                  |
 *                            ---------------------------
 * -------------------------------------------------------------------------
 */

#define RSVD_BOTTOM                   (-RED_ZONE_SIZE-0*SE_WORDSIZE)
#define RSVD_RIP_OFFSET               (-RED_ZONE_SIZE-1*SE_WORDSIZE)
#define RSVD_RAX_OFFSET               (-RED_ZONE_SIZE-2*SE_WORDSIZE)
#define RSVD_RCX_OFFSET               (-RED_ZONE_SIZE-3*SE_WORDSIZE)
#define RSVD_RDX_OFFSET               (-RED_ZONE_SIZE-4*SE_WORDSIZE)
#define RSVD_RBX_OFFSET               (-RED_ZONE_SIZE-5*SE_WORDSIZE)
#define RSVD_RBP_OFFSET               (-RED_ZONE_SIZE-6*SE_WORDSIZE)
#define RSVD_RSI_OFFSET               (-RED_ZONE_SIZE-7*SE_WORDSIZE)
#define RSVD_RDI_OFFSET               (-RED_ZONE_SIZE-8*SE_WORDSIZE)
#define RSVD_REDZONE_WORD_OFFSET      (-RED_ZONE_SIZE-9*SE_WORDSIZE)
#define RSVD_TOP                      (-RED_ZONE_SIZE-9*SE_WORDSIZE)

#if RSVD_SIZE_OF_MITIGATION_STACK_AREA != (RSVD_BOTTOM-RSVD_TOP)
#error "Malformed reserved mitigation stack area"
#endif

#define INFO_RAX_OFFSET               (0*SE_WORDSIZE)
#define INFO_RCX_OFFSET               (1*SE_WORDSIZE)
#define INFO_RDX_OFFSET               (2*SE_WORDSIZE)
#define INFO_RBX_OFFSET               (3*SE_WORDSIZE)
#define INFO_RSP_OFFSET               (4*SE_WORDSIZE)
#define INFO_RBP_OFFSET               (5*SE_WORDSIZE)
#define INFO_RSI_OFFSET               (6*SE_WORDSIZE)
#define INFO_RDI_OFFSET               (7*SE_WORDSIZE)
#define INFO_R8_OFFSET                (8*SE_WORDSIZE)
#define INFO_R9_OFFSET                (9*SE_WORDSIZE)
#define INFO_R10_OFFSET               (10*SE_WORDSIZE)
#define INFO_R11_OFFSET               (11*SE_WORDSIZE)
#define INFO_R12_OFFSET               (12*SE_WORDSIZE)
#define INFO_R13_OFFSET               (13*SE_WORDSIZE)
#define INFO_R14_OFFSET               (14*SE_WORDSIZE)
#define INFO_R15_OFFSET               (15*SE_WORDSIZE)
#define INFO_FLAGS_OFFSET             (16*SE_WORDSIZE)
#define INFO_RIP_OFFSET               (17*SE_WORDSIZE)

# Returns the enclave application resumption point if the AEX occurred within
# the mitigation or at __ct_mitigation_ret. If the AEX occurred during the
# mitigation at a RET instruction within the enclave application called by
# .ct_check_execute, then cselect_mitigation_rip() will return the address of
# that RET. Thus, the returned RIP will always point within the originally
# interrupted enclave application page.
DECLARE_LOCAL_FUNC cselect_mitigation_rip
# rdi: info
    mov     INFO_RIP_OFFSET(%rdi), %rax  # rax: pre-irq rip
    mov     INFO_RSP_OFFSET(%rdi), %rcx  # rcx: pre-irq rsp
    lea_pic __ct_mitigation_ret, %rsi
    cmp     %rsi, %rax
    lea     8(%rcx), %rsi

    # set rcx = IRQ in __ct_mitigation_ret ? original main-flow rsp : pre-irq rsp
    cmove   %rsi, %rcx

    lea_pic __ct_mitigation_ret, %rdx
    sub     %rax, %rdx

    # set CF=1 (B) if IRQ in mitigation (including __ct_mitigation_ret)
    cmp     $(.ct_aexnotify_end - .ct_mitigation_begin), %rdx

    # set rax = irq in mitigation ? original main-flow rip : pre-irq rip
    cmovb   RSVD_RIP_OFFSET(%rcx), %rax

    ret
END_FUNC

# If interrupt happened during execution of the atomic mitigation stub
# (including any C3 calls from ct_check_execute), restore clobbered
# enclave application registers from the persistent reserved area on the
# stack into the info struct parameter.
DECLARE_LOCAL_FUNC cselect_mitigation_regs
# rdi: info
# rsi: saved_rip
# rdx: c3_byte_address
    mov     INFO_RIP_OFFSET(%rdi), %rax
    mov     INFO_RSP_OFFSET(%rdi), %rcx

    # Set r8b=1 if saved_rip=c3_byte_address
    cmp     %rsi, %rdx
    sete    %r8b

    # Set r9b=1 if info->rip=__ct_mitigation_ret
    lea_pic __ct_mitigation_ret, %rdx
    cmp     %rax, %rdx
    sete    %r9b

    # Set r10b=1 if *info->rsp=.ct_check_execute_post
    lea_pic .ct_check_execute_post, %rdx
    cmp     (%rcx), %rdx
    sete    %r10b

    # Set r8b=1 if (*info->rsp=.ct_check_execute_post)
    # and ((saved_rip=c3_byte_address) or (info->rip=__ct_mitigation_ret))
    or      %r9b, %r8b
    and     %r10b, %r8b

    # Pop the return address if r8b=1
    lea     8(%rcx), %rdx
    cmovnz  %rdx, %rcx
    mov     %rcx, INFO_RSP_OFFSET(%rdi)

    # Set r9b=1 if the mitigation was interrupted, but not at a RET
    lea_pic .ct_mitigation_end, %rdx
    sub     %rax, %rdx
    cmp     $(.ct_mitigation_end - .ct_mitigation_begin + 1), %rdx
    setb    %r9b

    # If the mitigation was interrupted, restore clobbered registers from the
    # reserved area on the stack.
    or      %r9b, %r8b
    mov     INFO_RIP_OFFSET(%rdi), %rax
    cmovnz  RSVD_RIP_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RIP_OFFSET(%rcx)
    mov     %rax, INFO_RIP_OFFSET(%rdi)
    mov     INFO_RAX_OFFSET(%rdi), %rax
    cmovnz  RSVD_RAX_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RAX_OFFSET(%rcx)
    mov     %rax, INFO_RAX_OFFSET(%rdi)
    mov     INFO_RCX_OFFSET(%rdi), %rax
    cmovnz  RSVD_RCX_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RCX_OFFSET(%rcx)
    mov     %rax, INFO_RCX_OFFSET(%rdi)
    mov     INFO_RDX_OFFSET(%rdi), %rax
    cmovnz  RSVD_RDX_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RDX_OFFSET(%rcx)
    mov     %rax, INFO_RDX_OFFSET(%rdi)
    mov     INFO_RBX_OFFSET(%rdi), %rax
    cmovnz  RSVD_RBX_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RBX_OFFSET(%rcx)
    mov     %rax, INFO_RBX_OFFSET(%rdi)
    mov     INFO_RBP_OFFSET(%rdi), %rax
    cmovnz  RSVD_RBP_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RBP_OFFSET(%rcx)
    mov     %rax, INFO_RBP_OFFSET(%rdi)
    mov     INFO_RSI_OFFSET(%rdi), %rax
    cmovnz  RSVD_RSI_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RSI_OFFSET(%rcx)
    mov     %rax, INFO_RSI_OFFSET(%rdi)
    mov     INFO_RDI_OFFSET(%rdi), %rax
    cmovnz  RSVD_RDI_OFFSET(%rcx), %rax
    mov     %rax, RSVD_RDI_OFFSET(%rcx)
    mov     %rax, INFO_RDI_OFFSET(%rdi)

    # If the mitigation was interrupted, restore the first q/dword of the red
    #  zone from the reserved area; otherwise save it to the reserved area
    mov     -SE_WORDSIZE(%rcx), %rax
    cmovnz  RSVD_REDZONE_WORD_OFFSET(%rcx), %rax
    mov     %rax, RSVD_REDZONE_WORD_OFFSET(%rcx)
    ret
END_FUNC

DECLARE_LOCAL_FUNC constant_time_apply_sgxstep_mitigation_and_continue_execution
# rdi: info
# rsi: address of the AEX-Notify-enabling byte
# rdx: stack_tickle_pages
# rcx: code_tickle_page
# r8:  data_tickle_address
# r9:  c3_byte_address
    mov     %r8, %rbx
    mov     %r9, %rbp
    mov     INFO_R8_OFFSET(%rdi), %r8
    mov     INFO_R9_OFFSET(%rdi), %r9
    mov     INFO_R10_OFFSET(%rdi), %r10
    mov     INFO_R11_OFFSET(%rdi), %r11
    mov     INFO_R12_OFFSET(%rdi), %r12
    mov     INFO_R13_OFFSET(%rdi), %r13
    mov     INFO_R14_OFFSET(%rdi), %r14
    mov     INFO_R15_OFFSET(%rdi), %r15


/* NOTE: moving rsp upwards as a scratchpad register discards any data at lower
 * addresses (i.e., these may be overwritten by nested exception handlers), but
 * the stage-1 handler will always safeguard a 128-byte red zone under the
 * interrupted stack pointer. Thus, the code below is safe:
 * INFO_FLAGS_OFFSET-INFO_RSP_OFFSET = 12*8 = 96 < 128-byte ABI red zone.
 */
    lea     INFO_FLAGS_OFFSET(%rdi), %rsp
    popf
    mov     INFO_RSP_OFFSET(%rdi), %rsp  /* rsp: pre-irq rsp */
    mov     %rdx, %rdi

# NOTHING AFTER THIS POINT CAN MODIFY EFLAGS/RFLAGS

################################################################################
# BEGIN MITIGATION CODE
################################################################################

# rdi: stack_tickle_pages
# rsi: address of the AEX-Notify-enabling byte
# rdx: unused (will be clobbered)
# rcx: code_tickle_page
# rax: unused (will be clobbered)
# rbx: data_tickle_address
# rbp: c3_byte_address

#define MITIGATION_CODE_ALIGNMENT 0x200
.align MITIGATION_CODE_ALIGNMENT

# Enable AEX Notify
.ct_enable_aexnotify:
    movb    $1, (%rsi)

.ct_mitigation_begin:
    mov     RSVD_REDZONE_WORD_OFFSET(%rsp), %rsi
    lfence

# Set up the stack tickles
    movzx   %dil, %edx # Bit 0 in %rdi indicates whether a second stack page can be tickled
    mov     $0, %dil
    mov     $12, %eax
    shlx    %rax, %rdx, %rdx
    lea     (%rdi,%rdx), %rdx

.ct_check_write:
    mov     %rcx, %rax
    mov     $63, %ecx
    shlx    %rcx, %rax, %rcx # Bit 0 in %rax indicates whether data_tickle_address can be written
    jrcxz   .ct_clear_low_bits_of_rbx
    lea     -1(%rax), %rax   # Clear bit 0 in %rax
    movb    (%rbx), %cl
    movb    %cl, (%rbx)      # Will fault if the data page is not writable

.ct_clear_low_bits_of_rbx:
    movl    $12, %ecx
    shrx    %rcx, %rbx, %rbx
    shlx    %rcx, %rbx, %rbx

.ct_check_execute:
    call    *%rbp

.ct_check_execute_post:
    mov     RSVD_RBP_OFFSET(%rsp), %rbp
    mov     %rsi, -SE_WORDSIZE(%rsp) # restore the first q/dword of the red zone

# Load all working set cache lines and warm the TLB entries
    mov     $0x1000, %ecx
.align 0x10
.ct_warm_caches_and_tlbs:
    lea     -0x40(%ecx), %ecx
    mov     (%rax, %rcx), %esi # code page tickle
    mov     (%rdi, %rcx), %esi # stack page 1 tickle
    mov     (%rdx, %rcx), %esi # stack page 2 tickle
    mov     (%rbx, %rcx), %esi # data tickle
    jrcxz   .ct_restore_state
    jmp     .ct_warm_caches_and_tlbs # loops 64 times

.ct_restore_state:
    movzx   %al, %ecx # Bit 4 of %al indicates whether cycles should be added
    mov     RSVD_RDI_OFFSET(%rsp), %rdi
    mov     RSVD_RSI_OFFSET(%rsp), %rsi
    mov     RSVD_RBX_OFFSET(%rsp), %rbx
    mov     RSVD_RDX_OFFSET(%rsp), %rdx
    mov     RSVD_RAX_OFFSET(%rsp), %rax

# Inject random cycle noise
    jrcxz  .ct_restore_rcx
    CYCLE_DELAY 20, %rsp

.ct_restore_rcx:
    mov     RSVD_RCX_OFFSET(%rsp), %rcx
.ct_mitigation_end:
    jmp     *RSVD_RIP_OFFSET(%rsp)

.global __ct_mitigation_ret
__ct_mitigation_ret:
    ret
END_FUNC

.ct_aexnotify_end:

.sect   _to_be_discarded, "e", @nobits
.space MITIGATION_CODE_ALIGNMENT - (.ct_aexnotify_end - .ct_enable_aexnotify)
.previous
