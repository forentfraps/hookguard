global syscall_wrapper

section .text

syscall_wrapper:
    push r12

    mov r11, rcx         ; r11 = syscall number
    mov r12, rdx         ; r12 = argument count
    mov r10, r8          ; r10 = pointer to arguments array

    lea r10, [r10 + 8 * rdx]
.push_args:
    sub r10, 8
    mov rax, [r10]
    push rax
    dec r12
    jz .populate_registers
    jmp .push_args
.populate_registers:
    mov r12, rdx
    push rax
    xor rax, rax
    mov r10, [rsp + 8]
    mov rdx, [rsp + 16]
    mov r8, [rsp + 24]
    mov r9, [rsp + 32]
.do_syscall:
    mov rax, r11
    syscall

.epilogue:
    lea rcx, [r12 * 8]
    pop rdx
    add rsp, rcx
    pop r12
    ret
