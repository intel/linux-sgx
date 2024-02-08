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
 *                       | | |  rsvd main-flow FLAGS     |-9 |
 *                       +-|-|  rsvd main-flow -8(rsp)   |-10|
 *                       +-|-|  &SSA[0].AEXNOTIFY (rsi)  |-11|
 * (copy of parameters   | | |  ptr stack tickle  (rdx)  |-12|
 *  passed @entry)       | | |  ptr code tickle   (rcx)  |-13|
 *                       | | |  ptr data tickle   (r8)   |-14|
 *                       +-|-|  ptr c3 byte       (r9)   |-15|
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
#define RSVD_FLAGS_OFFSET             (-RED_ZONE_SIZE-9*SE_WORDSIZE)
#define RSVD_REDZONE_WORD_OFFSET      (-RED_ZONE_SIZE-10*SE_WORDSIZE)
#define RSVD_AEXNOTIFY_ADDRESS_OFFSET (-RED_ZONE_SIZE-11*SE_WORDSIZE)
#define RSVD_STACK_TICKLE_OFFSET      (-RED_ZONE_SIZE-12*SE_WORDSIZE)
#define RSVD_CODE_TICKLE_OFFSET       (-RED_ZONE_SIZE-13*SE_WORDSIZE)
#define RSVD_DATA_TICKLE_OFFSET       (-RED_ZONE_SIZE-14*SE_WORDSIZE)
#define RSVD_C3_ADDRESS_OFFSET        (-RED_ZONE_SIZE-15*SE_WORDSIZE)
#define RSVD_TOP                      (-RED_ZONE_SIZE-15*SE_WORDSIZE)

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

DECLARE_LOCAL_FUNC constant_time_apply_sgxstep_mitigation_and_continue_execution
/* Note: moving rsp upwards as a scratchpad register discards any data at lower
 * addresses (i.e., these may be overwritten by nested exception handlers, but
 * the stage-1 handler will always safeguard a red zone + rsvd area under the
 * interrupted stack pointer). */
    mov     INFO_RSP_OFFSET(%rdi), %rsp  /* rsp: pre-irq rsp */
    mov     INFO_RIP_OFFSET(%rdi), %rax  /* rax: pre-irq rip */
    mov     %rax, %r10

/* Check whether the last AEX occurred during the mitigation */
    cmpb    $0xc3, (%rax)             # ZF=1 if interrupted c3 (ret)
    cmovz   (%rsp), %rax              # rax: irq c3? caller rip : pre-irq rip
    mov     %rsp, %rbp
    lea     SE_WORDSIZE(%rsp), %rbx
    cmovz   %rbx, %rbp                # rbp: irq c3? post-ret rsp : pre-irq rsp

    lea_pic __ct_mitigation_end, %rbx
    sub     %rax, %rbx
    cmp     $(__ct_mitigation_end - __ct_mitigation_begin + 1), %rbx
// CMP will set CF=1 (B) if the mitigation was interrupted, CF=0 (NB) otherwise
    cmovb   %rbp, %rsp               # rsp: original main flow rsp
    mov     %rsp, INFO_RSP_OFFSET(%rdi)

// If the mitigation was interrupted, restore the interrupted IP from the
// reserved area
    cmovb   RSVD_RIP_OFFSET(%rsp), %r10
    mov     %r10, RSVD_RIP_OFFSET(%rsp)

// Copy RFLAGS onto the reserved stack area
    mov     INFO_FLAGS_OFFSET(%rdi), %rax
    mov     %rax, RSVD_FLAGS_OFFSET(%rsp)

// If the mitigation was interrupted, restore the first q/dword of the red
// zone from the reserved area; otherwise save it to the reserved area
    mov     -SE_WORDSIZE(%rsp), %rax
    cmovb   RSVD_REDZONE_WORD_OFFSET(%rsp), %rax
    mov     %rax, RSVD_REDZONE_WORD_OFFSET(%rsp)

// Save &SSA[0].GPRSGX.AEXNOTIFY to the reserved area
    mov     %rsi, RSVD_AEXNOTIFY_ADDRESS_OFFSET(%rsp)

// If the mitigation was interrupted, restore tickle parameters from the
// reserved area.
    cmovb   RSVD_STACK_TICKLE_OFFSET(%rsp), %rdx
    cmovb   RSVD_CODE_TICKLE_OFFSET(%rsp), %rcx
    cmovb   RSVD_DATA_TICKLE_OFFSET(%rsp), %r8
    cmovb   RSVD_C3_ADDRESS_OFFSET(%rsp), %r9
    mov     %rdx, RSVD_STACK_TICKLE_OFFSET(%rsp)
    mov     %rcx, RSVD_CODE_TICKLE_OFFSET(%rsp)
    mov     %r8,  RSVD_DATA_TICKLE_OFFSET(%rsp)
    mov     %r9,  RSVD_C3_ADDRESS_OFFSET(%rsp)

// If the mitigation was not interrupted (the interrupt occured in the main flow)
// then restore the registers from *info
    mov     INFO_R8_OFFSET(%rdi), %r8
    mov     INFO_R9_OFFSET(%rdi), %r9
    mov     INFO_R10_OFFSET(%rdi), %r10
    mov     INFO_R11_OFFSET(%rdi), %r11
    mov     INFO_R12_OFFSET(%rdi), %r12
    mov     INFO_R13_OFFSET(%rdi), %r13
    mov     INFO_R14_OFFSET(%rdi), %r14
    mov     INFO_R15_OFFSET(%rdi), %r15
    mov     INFO_RAX_OFFSET(%rdi), %rax
    mov     INFO_RCX_OFFSET(%rdi), %rcx
    mov     INFO_RDX_OFFSET(%rdi), %rdx
    mov     INFO_RBX_OFFSET(%rdi), %rbx
    mov     INFO_RBP_OFFSET(%rdi), %rbp
    mov     INFO_RSI_OFFSET(%rdi), %rsi
    mov     INFO_RDI_OFFSET(%rdi), %rdi

// If the mitigation was interrupted, restore registers from the reserved area
// on the stack.
    cmovb   RSVD_RAX_OFFSET(%rsp), %rax
    cmovb   RSVD_RCX_OFFSET(%rsp), %rcx
    cmovb   RSVD_RDX_OFFSET(%rsp), %rdx
    cmovb   RSVD_RBX_OFFSET(%rsp), %rbx
    cmovb   RSVD_RBP_OFFSET(%rsp), %rbp
    cmovb   RSVD_RSI_OFFSET(%rsp), %rsi
    cmovb   RSVD_RDI_OFFSET(%rsp), %rdi

    mov     %rax, RSVD_RAX_OFFSET(%rsp)
    mov     %rcx, RSVD_RCX_OFFSET(%rsp)
    mov     %rdx, RSVD_RDX_OFFSET(%rsp)
    mov     %rbx, RSVD_RBX_OFFSET(%rsp)
    mov     %rbp, RSVD_RBP_OFFSET(%rsp)
    mov     %rsi, RSVD_RSI_OFFSET(%rsp)
    mov     %rdi, RSVD_RDI_OFFSET(%rsp)

# Restore tickle addresses
    mov     RSVD_STACK_TICKLE_OFFSET(%rsp), %rbp
    mov     RSVD_CODE_TICKLE_OFFSET(%rsp), %rsi
    mov     RSVD_DATA_TICKLE_OFFSET(%rsp), %rdx
    mov     RSVD_C3_ADDRESS_OFFSET(%rsp), %rdi

# Set up the stack tickles
    shrb    $1, %bpl # Bit 0 in %rbp indicates whether a second stack page can be tickled
    mov     %rbp, %rbx
    jnc     .restore_flags
    sub     $0x1000, %rbx

.restore_flags:
    lea     RSVD_FLAGS_OFFSET(%rsp), %rax
    xchg    %rax, %rsp
    popf
    xchg    %rax, %rsp

# NOTHING AFTER THIS POINT CAN MODIFY EFLAGS/RFLAGS

################################################################################
# BEGIN MITIGATION CODE
################################################################################

#define MITIGATION_CODE_ALIGNMENT 0x200
.align MITIGATION_CODE_ALIGNMENT

# Enable AEX Notify
.ct_enable_aexnotify:
    mov     RSVD_AEXNOTIFY_ADDRESS_OFFSET(%rsp), %rax
    movb    $1, (%rax)

    .global __ct_mitigation_begin
__ct_mitigation_begin:
    lfence

.ct_check_write:
    movl    $63, %ecx
    shlx    %rcx, %rsi, %rcx # Bit 0 in %rsi indicates whether data_tickle_address can be written
    jrcxz   .ct_clear_low_bits_of_rdx
    lea     -1(%rsi), %rsi   # Clear bit 0 in %rsi
    movb    (%rdx), %al
    movb    %al, (%rdx)      # Will fault if the data page is not writable

.ct_clear_low_bits_of_rdx:
    movl    $12, %ecx
    shrx    %rcx, %rdx, %rdx
    shlx    %rcx, %rdx, %rdx

.ct_check_execute:
    call    *%rdi

# Load all working set cache lines and warm the TLB entries
    mov     $0x1000, %ecx
.align 0x10
.ct_warm_caches_and_tlbs:
    lea     -0x40(%ecx), %ecx
    mov     (%rsi, %rcx), %eax
    mov     (%rbp, %rcx), %eax
    mov     (%rbx, %rcx), %eax
    mov     (%rdx, %rcx), %eax
    jrcxz   .ct_restore_state
    jmp     .ct_warm_caches_and_tlbs # loops 64 times

.ct_restore_state:
    movzx   %sil, %ecx # Bit 4 of %sil indicates whether cycles should be added
    mov     RSVD_REDZONE_WORD_OFFSET(%rsp), %rdi
    mov     %rdi, -SE_WORDSIZE(%rsp) # restore the first q/dword of the red zone
    mov     RSVD_RDI_OFFSET(%rsp), %rdi
    mov     RSVD_RSI_OFFSET(%rsp), %rsi
    mov     RSVD_RBP_OFFSET(%rsp), %rbp
    mov     RSVD_RBX_OFFSET(%rsp), %rbx
    mov     RSVD_RDX_OFFSET(%rsp), %rdx
    mov     RSVD_RAX_OFFSET(%rsp), %rax

# Inject random cycle noise
    jrcxz  .ct_restore_rcx
    CYCLE_DELAY 20, %rsp

.ct_restore_rcx:
    mov     RSVD_RCX_OFFSET(%rsp), %rcx
__ct_mitigation_end:
    jmp     *RSVD_RIP_OFFSET(%rsp)

.global __ct_mitigation_ret
__ct_mitigation_ret:
    ret
    .cfi_endproc

.ct_aexnotify_end:

.sect   _to_be_discarded, "e", @nobits
.space MITIGATION_CODE_ALIGNMENT - (.ct_aexnotify_end - .ct_enable_aexnotify)
.previous
