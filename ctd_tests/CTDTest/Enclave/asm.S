.data
.align 0x1000
.global test_data
.byte 0
.byte 0
.byte 0
test_data:  # 3-byte offset within the page
.word 0
.word 0

.align 0x1000
.text
.global asm_test
asm_test:
mov $0, %rax
mov $1, %rcx
mov $3, %rbx
mov $8, %r8
mov $9, %r9
mov $10, %r10
mov $11, %r11
mov $12, %r12
mov $13, %r13
mov $14, %r14
mov $15, %r15
mov %rax, (8*0)(%rdi)
mov %rcx, (8*1)(%rdi)
mov %rdx, (8*2)(%rdi)
mov %rbx, (8*3)(%rdi)
mov %rsp, (8*4)(%rdi)
mov %rbp, (8*5)(%rdi)
mov %rsi, (8*6)(%rdi)
mov %rdi, (8*7)(%rdi)
mov %r8, (8*8)(%rdi)
mov %r9, (8*9)(%rdi)
mov %r10, (8*10)(%rdi)
mov %r11, (8*11)(%rdi)
mov %r12, (8*12)(%rdi)
mov %r13, (8*13)(%rdi)
mov %r14, (8*14)(%rdi)
mov %r15, (8*15)(%rdi)
pushfq
popq (8*16)(%rdi)
lea -8(%rsp), %rsp
popq (8*18)(%rdi)
ud2               # Trigger a #UD exception
mov %eax, (%rdx)  # <- The enclave ud_handler moves RIP to point here
mov %rax, (8*0)(%rsi)
mov %rcx, (8*1)(%rsi)
mov %rdx, (8*2)(%rsi)
mov %rbx, (8*3)(%rsi)
mov %rsp, (8*4)(%rsi)
mov %rbp, (8*5)(%rsi)
mov %rsi, (8*6)(%rsi)
mov %rdi, (8*7)(%rsi)
mov %r8, (8*8)(%rsi)
mov %r9, (8*9)(%rsi)
mov %r10, (8*10)(%rsi)
mov %r11, (8*11)(%rsi)
mov %r12, (8*12)(%rsi)
mov %r13, (8*13)(%rsi)
mov %r14, (8*14)(%rsi)
mov %r15, (8*15)(%rsi)
lea -8(%rsp), %rsp
popq (8*18)(%rsi)
pushfq
popq (8*16)(%rsi)

# (-128-(14*8))(%rsp) is where the data tickle address is spilled by the mitigation
mov (-128-(14*8))(%rsp), %rax
ret
