global save_preserved_registers 
global load_preserved_registers 

section .text


save_preserved_registers:
  lea rax, [rsp - 8]
  mov [rcx], rbx
  mov [rdx], rax
  mov [r8], rbp
  mov [r9], r15
  ret

retry_asm:
  ; rcx - ptr to rsp, rbp, r15
  ; rdx - ptr to function
  ; r8 - ptr to arg array
  ; r9 - ptr to arg_size array
  mov rsp, [rcx]
  mov rbp, [rcx + 8]
  mov r15, [rcx + 16]
  mov rax, rdx
  

  
