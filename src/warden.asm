global _MEH_warden_asm

extern MEH_warden
section .text

_MEH_warden_asm:
  lea rcx, [rsp + 0x4f0]
  lea rdx, [rsp]
  jmp MEH_warden
