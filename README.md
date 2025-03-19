# HookGuard


This is a WIP, idea is to protect process from being hooked by writing a memory controller. 


This memory controller would manage page protection and scramble ntdll, since reprotecting it presents a couple of problems. Each function call would pass through a state manager, which would allow to replay it, if the rogue hook was discovered.


In the event of discovering a crash (supposedly from a hook, which tried to execute from a reprotected page), process memory would be scanned to see any discrepancies with the source file on disk, then it would be patched and the last function called would be replayed
