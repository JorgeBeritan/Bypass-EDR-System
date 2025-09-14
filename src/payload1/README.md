# Obfuscated and Evasive Shellcode Loader

⚠️ **Disclaimer**: This code uses techniques commonly associated with malware for **educational purposes only**. Its purpose is to help understand how modern threats work and how security systems attempt to detect them. It must **not** be used for malicious purposes.

---

## Overview

This document provides a detailed analysis of a C++ program designed to load and execute shellcode in memory, using advanced techniques to evade detection by security software such as antivirus (AV) and endpoint detection and response (EDR) systems.

The main purpose of this code is to serve as a **shellcode loader**. Its primary function is to take a payload (the shellcode), which is encrypted, decrypt it at runtime, allocate it in an executable memory region, and finally transfer execution control to it.

What makes this loader special is the stealth techniques it employs:

- **Payload Encryption**: The shellcode is not stored in plaintext but is AES-encrypted to avoid static detection in the executable file.
- **Key Obfuscation**: The AES decryption key is not stored in plaintext; it is obfuscated with a simple XOR cipher and only deobfuscated in memory.
- **Direct Syscalls**: Instead of using high-level Windows API functions like `VirtualAlloc` (commonly monitored), the code performs a direct syscall to `NtAllocateVirtualMemory`, making interception harder.
- **Dynamic Function Resolution**: Instead of using `GetProcAddress` (also monitored), the code manually parses the export table of `ntdll.dll` to retrieve function addresses.

---

## Detailed Code Analysis

### `main()`

This is the entry point and the main orchestrator of the process. Steps:

1. **Decryption**: Calls `DecryptShellcode()` to decrypt the payload (`encryptedShellcode`) in memory. If it fails, the program exits.
2. **Memory Allocation**: Uses `NtAllocateVirtualMemorySyscall` to request a memory page with read, write, and execute permissions (`PAGE_EXECUTE_READWRITE`). This is the central evasion technique for memory allocation.
3. **Shellcode Copying**: Copies the decrypted shellcode into the newly allocated memory region.
4. **Permission Hardening**: Calls `VirtualProtect` to change memory permissions from RWX to RX. This reduces suspicion, since RWX pages are a red flag for EDR.
5. **Execution**: Treats the allocated memory address as a function pointer and calls it, transferring execution to the shellcode.

---

### `DecryptShellcode()`

Handles the entire decryption process:

- **Key Deobfuscation**: Calls `XORDeobfuscate` to reverse the AES key obfuscation (`obfuscatedKey`). A static XOR key (`"\x6F\xBF..."`) is used to recover the real AES key.
- **Windows CryptoAPI Usage**: Uses functions from `wincrypt.h` for AES decryption:
  - `CryptAcquireContext`: Obtains a handle for the Windows cryptographic provider.
  - `CryptImportKey`: Imports the AES key for use.
  - `CryptSetKeyParam`: Sets parameters such as CBC mode and IV.
  - `CryptDecrypt`: Decrypts `encryptedShellcode` in-place.
- **Secure Cleanup**: The AES key is destroyed with `SecureZeroMemory`, and cryptographic handles are released to prevent recovery.

---

### `GetNativeProcAddress()`

A custom reimplementation of `GetProcAddress` to avoid detection:

- Manually parses the **Export Address Table (EAT)** of `ntdll.dll`.
- Compares exported function names with the target (`"NtAllocateVirtualMemory"`).
- Returns the function’s memory address when found.

---

### `NtAllocateVirtualMemorySyscall()`

Implements the direct syscall for memory allocation, bypassing user-land hooks:

- **Syscall ID Extraction**: Uses `GetNativeProcAddress` to retrieve the function stub of `NtAllocateVirtualMemory` from `ntdll.dll`. On Windows x64, the syscall ID is located at byte 4 of the stub.
- **Inline Assembly Injection**:
  - `mov %1, %eax`: Loads the syscall ID into `EAX`.
  - `mov %rcx, %r10`: Required by the x64 syscall calling convention.
  - `syscall`: Transfers control to kernel mode to execute the requested function.

This technique is highly effective because execution jumps directly to the kernel, bypassing potential EDR hooks.

---

## Dependencies

The code requires the following headers and libraries from the Windows SDK:

- `<windows.h>`: Core Windows API (e.g., `GetModuleHandleA`, `memcpy`, `VirtualProtect`, `SecureZeroMemory`, PE structures).
- `<wincrypt.h>`: Windows CryptoAPI for AES decryption (`CryptAcquireContext`, `CryptImportKey`, etc.). Link with `Advapi32.lib`.
- `<iostream>` and `<cstring>`: Standard C++ headers for I/O and string operations.

---

## Compilation

The build command uses **cross-compilation**, likely compiling a Windows executable from a Linux environment:

```bash
x86_64-w64-mingw32-g++ obfuscation.cpp -o obfuscation.exe -static-libgcc -static-libstdc++
## Command Breakdown

- **`x86_64-w64-mingw32-g++`**: The MinGW-w64 compiler for 64-bit Windows targets.  
- **`obfuscation.cpp`**: The source file.  
- **`-o obfuscation.exe`**: Specifies the output executable name.  
- **`-static-libgcc` & `-static-libstdc++`**: Link the GCC and C++ standard libraries statically.  

Without these flags, the program would require external DLLs (`libgcc_s_seh-1.dll`, `libstdc++-6.dll`).  
With them, the binary is fully self-contained and portable.  

---
```

## ⚠️ Final Warning

This project demonstrates **malware-like techniques** (encryption, obfuscation, syscalls, API parsing) strictly for **research and educational purposes**.  
It must **not** be used for malicious activities.  
