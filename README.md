# HookGuard

**HookGuard** is a work-in-progress (WIP) system for Windows designed to protect a running process from malicious hooks or code tampering. It uses a specialized memory controller to manage page protections and a state manager to replay function calls if suspicious behavior is detected. Whenever an unexpected crash occurs—potentially caused by a rogue hook—HookGuard scans the process memory for discrepancies from the on-disk binary, patches any changes, and retries the last function call.

## Overview

HookGuard aims to:
1. **Manage Page Protections** – Use Windows-specific APIs (e.g., `VirtualProtect`) to lock down memory regions and detect unauthorized modifications.
2. **Replay Function Calls** – Route calls through a state manager that saves the registers and arguments, allowing them to be replayed if a crash points to a malicious patch or hook.
3. **Auto-Patch Memory** – On detecting a crash in protected code, HookGuard scans the in-memory code versus the original on disk. Any mismatches—likely injected hooks—are repaired, and the last call is retried.

### How It Works
1. **Intercepting Calls**  
   - HookGuard intercepts function calls via a state manager, storing the necessary state to replay if needed.
2. **Crash Detection**  
   - If execution fails within a protected memory region, HookGuard treats it as a possible hook or injection attempt.
3. **Memory Scanning & Patching**  
   - The memory controller scans the process address space, comparing it to the file on disk. Any differences are patched back to the original.
4. **Replay Execution**  
   - The saved call state is restored, and the function is retried once memory is corrected.

## Project Structure
While still under development, you can expect these core modules:
- **Memory Controller**  
  Manages Windows memory protection and detects unauthorized changes.
- **State Manager**  
  Zig/Assembly logic that saves and restores the CPU state for replays.
- **Discrepancy Scanner**  
  Reads memory and compares it to the on-disk binary sections, patching any changed bytes.

## Prerequisites
- **Windows x86_64** platform
- **Zig** compiler (recommended 0.10+)
- **MASM** or **NASM** for assembling `.asm` code
- Administrative privileges if modifying certain memory regions

## Building
1. Assemble the `.asm` files, for example:
   nasm -f win64 syscall_wrapper.asm -o syscall_wrapper.obj
2. Compile your Zig code and link against the object files. If using a `build.zig`, run:
   zig build
3. Check for the executable in `zig-out/bin` (or your configured output directory).

## Usage
1. **Initialize HookGuard**  
   - Load and configure the memory controller (set up page protections).
2. **Run Your Application**  
   - Function calls flow through HookGuard’s state manager, allowing replay if any crashes occur.
3. **Crash/Hook Handling**  
   - On crash, HookGuard patches altered pages and replays the last function call.

## Current Status & Roadmap
- **Status**: Still a prototype focusing on proof-of-concept. Tests are ongoing, and more robust handling of Windows-specific edge cases is planned.
- **Future Plans**:
  - Improved hooking detection
  - Enhanced exception handling using SEH or vectored exception handlers
  - Broader support for dynamically loaded modules

## Contributing
Contributions are welcome! If you have ideas or bug fixes:
1. **Fork** the repo
2. **Create** a feature branch
3. **Open** a Pull Request

## License
The code within this project is open-source unless otherwise specified. Check the repository for any specific licensing details.

---
**Disclaimer**: HookGuard directly manipulates memory protection settings and intercepts function calls; use it cautiously in testing or production. Unintended side effects may occur. Always back up critical data and use a controlled environment for safety.
