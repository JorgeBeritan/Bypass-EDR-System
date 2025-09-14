# Process Injection with "Process Hollowing" and "Unhooking"

⚠️ **Disclaimer**: This code is for **educational purposes only**, intended for security researchers, malware analysts, and cybersecurity professionals to understand attack and evasion techniques. Its use for malicious purposes is **illegal and inappropriate**.

---

## Overview

This document describes a C++ program that demonstrates a sophisticated code injection technique known as **Process Hollowing**, combined with an evasion technique called **DLL Unhooking**.  
The goal is to execute an arbitrary payload inside the memory space of a legitimate process, making it extremely difficult to detect.

The program performs the following key actions:

1. Starts a legitimate process (`notepad.exe`) in a suspended state.  
2. **Hollows** the process, unmapping (removing) its original code from memory.  
3. Injects a shellcode payload into the now-empty memory space of the legitimate process.  
4. Hijacks the process’s main thread, modifying its entry point to redirect execution to the injected shellcode.  
5. Resumes the process, which now runs the injected shellcode instead of its original code, but still appears as `notepad.exe` to both the OS and the user.  

To increase stealth, before performing these actions, the program **"cleans" ntdll.dll** in its own memory space to remove any hooks that security software (EDR/AV) may have placed.

---

## Detailed Code Analysis

### `main()` – The Hollowing Orchestrator

The `main` function coordinates the entire attack:

- **Initial Unhooking**: Calls `UnhookNtdll()` first to ensure subsequent native API calls are not intercepted by security software.  
- **Payload Preparation**:
  - The shellcode is a small assembly program that shows a `MessageBoxA`.  
  - The function addresses (`MessageBoxA`, `ExitThread`) and strings (title/message) are initially zeroed.  
  - The code dynamically retrieves the real addresses using `GetProcAddress` and patches them into the shellcode with `memcpy`.  
- **Victim Process Creation**: Launches `notepad.exe` with `CreateProcessA` and the `CREATE_SUSPENDED` flag.  
- **Process Information Retrieval**:
  - Calls `GetProcessBaseAddress` to find the memory base address of `notepad.exe`.  
  - Uses `GetThreadContext` to capture the register state of the suspended main thread.  
- **Hollowing (Unmapping)**:
  - Calls `NtUnmapViewOfSection` from `ntdll.dll` to remove the original executable code section of `notepad.exe`.  
- **Payload Injection**:
  - Allocates new memory inside the victim process with `VirtualAllocEx`.  
  - Writes the prepared shellcode with `WriteProcessMemory`.  
- **Thread Hijacking**:
  - Modifies the thread context with `SetThreadContext`.  
  - Changes the instruction pointer (`Rip` in x64) to point to the injected shellcode.  
- **Execution**:
  - Calls `ResumeThread`, resuming the process execution, now starting at the injected shellcode.  

---

### `UnhookNtdll()` – User-Land Hook Evasion

This function bypasses EDR hooks placed on Windows API functions inside `ntdll.dll`:

1. **Loads a Clean Copy**: Opens `ntdll.dll` directly from disk (`C:\Windows\System32\`).  
2. **Maps the Copy**: Maps this file into the current process’s memory, ensuring a clean, hook-free version.  
3. **Identifies the `.text` Section**: Locates the executable code section in both the hooked and clean versions.  
4. **Restores the Original Code**:
   - Changes memory protection of the loaded `ntdll.dll` `.text` section to writable (`PAGE_EXECUTE_READWRITE`).  
   - Copies clean bytes from the mapped copy to overwrite the hooked section.  
   - Restores original memory protections.  

After this, any subsequent native API calls (like `NtUnmapViewOfSection`) execute unmonitored by EDR.  

---

### `GetProcessBaseAddress()`

A helper function to retrieve the base address of the remote process image. Two approaches:  

- **High-Level**: Using `EnumProcessModules`.  
- **Low-Level**: Reading the **PEB (Process Environment Block)** with `NtQueryInformationProcess` and extracting the image base address from offset `+0x10`.  

---

## Dependencies

The code requires the following Windows SDK headers and libraries:

- `<windows.h>` – Core Windows API.  
- `<tlhelp32.h>` – For process/thread snapshots (not used in the final version, but common in this context).  
- `<psapi.h>` – For `EnumProcessModules`. Requires linking against `Psapi.lib`.  
- `<iostream>` – Standard C++ for console logging.  

---

## Compilation

The build command uses **cross-compilation** to produce a 64-bit Windows executable:

```bash
x86_64-w64-mingw32-g++ hollowing_unhook.cpp -o hollowing_unhook.exe -static-libgcc -static-libstdc++
## Breakdown

- **`x86_64-w64-mingw32-g++`**: The MinGW-w64 compiler for 64-bit Windows.  
- **`hollowing_unhook.cpp`**: The source file.  
- **`-o hollowing_unhook.exe`**: Specifies the output executable.  
- **`-static-libgcc -static-libstdc++`**: Statically links the GCC and C++ runtime libraries.  

Without these flags, the program requires external DLLs (`libgcc_s_seh-1.dll`, `libstdc++-6.dll`).  
With them, the final binary is fully self-contained and portable.  

---
```

## ⚠️ Final Warning

This project demonstrates **malware-like techniques** (process hollowing, unhooking, API patching, memory injection) strictly for **research and educational purposes**.  
It must **not** be used for malicious activities.  
