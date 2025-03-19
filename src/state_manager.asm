global save_preserved_registers 
global load_preserved_registers 

section .text


save_preserved_registers:
  lea rax, [rsp - 8]
  mov [rcx], rax ; rsp
  mov [rcx + 8], rbp
  mov [rcx + 16], rbx
  mov [rcx + 24], rsi
  mov [rcx + 32], rdi
  mov [rcx + 40], r12
  mov [rcx + 48], r13
  mov [rcx + 56], r14
  mov [rcx + 64], r15
  ret

retry_asm:
  ; rcx contains 5 following pointers/elements:
  ; ptr to rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15
  ; ptr to function
  ; arg count
  ; ptr to arg array
  ; ptr to arg_size array

  ; restore preserved registers
  mov rax, [rcx]
  mov rsp, [rax]
  mov rbp, [rax + 8]
  mov rbx, [rax + 16]
  mov rsi, [rax + 24]
  mov rdi, [rax + 32]
  mov r12, [rax + 40]
  mov r13, [rax + 48]
  mov r14, [rax + 56]
  mov r15, [rax + 64]
  


  

  
