global call_asm 
global retry_asm 

section .data
arg_count_offset: dq 0

section .bss

save_arg_count: resb 1024 


section .text



call_asm:
; rcx contains 5 following pointers/elements:
  ; rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15 - 8 bytes each
  ; ptr to function
  ; arg count
  ; ptr to arg array: [*]usize

  mov [rcx],      rsp ; rsp
  mov [rcx + 8],  rbp
  mov [rcx + 16], rbx
  mov [rcx + 24], rsi
  mov [rcx + 32], rdi
  mov [rcx + 40], r12
  mov [rcx + 48], r13
  mov [rcx + 56], r14
  mov [rcx + 64], r15


  mov r11, [rcx + 72] ; + 72 - func ptr
  mov r10, rcx
  mov rax, [r10 + 80] ; arg_count
  mov r9, rax
  and r9, 1
  jnz .call_skip_stack_align
  mov r9, dummy_ret
  push r9

  .call_skip_stack_align:
  lea r8, [rcx + 80]
  mov rdx, rax

  .call_push_args:
  mov rcx, [r8 + rax * 8]
  push rcx
  dec rax
  jnz .call_push_args
  mov rcx, [rsp]
  mov [rsp], rdx
  mov rdx, [rsp + 8]
  mov r8, [rsp + 16]
  mov r9, [rsp + 24]
  call r11
  mov rdx, [rsp]
  lea rsp, [rsp + rdx * 8]
dummy_ret:
  ret


retry_asm:
  ; rcx contains 5 following pointers/elements:
  ; rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15 - 8 bytes each
  ; ptr to function
  ; arg count
  ; ptr to arg array: [*]usize


  ; restore preserved registers
  mov rsp, [rcx]
  mov rbp, [rcx + 8]
  mov rbx, [rcx + 16]
  mov rsi, [rcx + 24]
  mov rdi, [rcx + 32]
  mov r12, [rcx + 40]
  mov r13, [rcx + 48]
  mov r14, [rcx + 56]
  mov r15, [rcx + 64]
  
  mov r11, [rcx + 72] ; + 72 - func ptr
  mov r10, rcx
  mov rax, [r10 + 80] ; arg_count
  mov r9, rax
  and r9, 1
  jnz .retry_skip_stack_align
  mov r9, dummy_ret
  push r9
.retry_skip_stack_align:
  lea r8, [rcx + 80]
  mov rdx, rax
  .retry_push_args:
  mov rcx, [r8 + rax * 8]
  push rcx
  dec rax
  jnz .retry_push_args
  mov rcx, [rsp]
  mov [rsp], rdx
  mov rdx, [rsp + 8]
  mov r8, [rsp + 16]
  mov r9, [rsp + 24]
  call r11
  mov rdx, [rsp]
  lea rsp, [rsp + rdx * 8]
  ret


  

  
