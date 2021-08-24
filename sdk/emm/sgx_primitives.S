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
 */


#define SE_EACCEPT    5
#define SE_EMODPE     6
#define SE_EACCEPTCOPY   7

.macro ENCLU
.byte 0x0f, 0x01, 0xd7
.endm

.macro SE_PROLOG
    .cfi_startproc

    push    %rbx
    push    %rcx
    push    %rdx
    movq    %rdi, %rbx
    movq    %rsi, %rcx

.endm


.macro SE_EPILOG
    pop     %rdx
    pop     %rcx
    pop     %rbx

    ret
    .cfi_endproc
.endm


.macro DECLARE_GLOBAL_FUNC name
    .globl \name
    .type \name, @function
\name:
.endm


DECLARE_GLOBAL_FUNC do_eaccept
    SE_PROLOG
    mov     $SE_EACCEPT, %eax
    ENCLU
    SE_EPILOG

DECLARE_GLOBAL_FUNC do_eacceptcopy
    SE_PROLOG
    mov     $SE_EACCEPTCOPY, %eax
    ENCLU
    SE_EPILOG

DECLARE_GLOBAL_FUNC do_emodpe
    SE_PROLOG
    mov     $SE_EMODPE, %eax
    ENCLU
    SE_EPILOG

