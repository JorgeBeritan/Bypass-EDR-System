# Payload Design 2: Process Hollowing with NTDLL Unhooking

This document describes the architecture of an advanced payload that uses the **Process Hollowing** technique combined with **API Unhooking** to stealthily execute malicious code.  

The goal is to inject and run shellcode inside the memory space of a legitimate process, evading detection mechanisms that rely on process reputation and API monitoring by Endpoint Detection and Response (EDR) solutions.

---

## 📌 Process Hollowing Architecture

**Process Hollowing** is an evasion technique where a legitimate process is created in a suspended state, its original memory image is removed, and it is replaced with a malicious payload.  

The architecture consists of three main components:

- **Loader**: The main program. Responsible for unhooking, creating the victim process, hollowing it, injecting the payload, and resuming execution.  
- **Victim Process**: A legitimate and common system process (e.g., `notepad.exe`). Chosen to mask malicious activity under the name of a trusted application.  
- **Payload (Shellcode)**: The code to be executed stealthily. In the example, it is a simple MessageBox shellcode, but in a real-world case, it could be a C2 agent, keylogger, etc.  

**General flow:**
1. **Creation**: Launches `notepad.exe` in suspended state.  
2. **Hollowing**: Uses `NtUnmapViewOfSection` to unmap the original image from memory.  
3. **Injection**: Allocates new memory in the victim process and writes the payload into it.  
4. **Execution**: Modifies the victim’s thread context so that execution resumes at the payload instead of the original entry point.  

**Advantage**: The payload executes under the cover of a trusted process, bypassing firewalls, whitelists, and shallow checks that rely only on process names.

---

## 🛡️ Unhooking + Injection Sequence

EDRs often place **hooks** in user-mode APIs (especially in **ntdll.dll**) to monitor suspicious actions. The loader neutralizes these defenses before hollowing.

### 1. **Proactive Evasion – NTDLL Unhooking**
- **Problem**: Required functions (`CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, etc.) rely on ntdll.dll, which may be hooked by EDR.  
- **Solution**: The loader loads a clean copy of `ntdll.dll` from disk (`C:\Windows\System32\ntdll.dll`) and overwrites the `.text` section of the in-memory copy with the clean bytes.  
- This effectively **removes hooks** and blinds the EDR’s user-mode monitoring within the loader’s process.  

### 2. **Suspended Victim Process Creation**
- Uses `CreateProcessA` with the `CREATE_SUSPENDED` flag.  
- Loads `notepad.exe` into memory but halts execution of its main thread before any instruction is executed.  

### 3. **Memory Hollowing**
- Retrieves the base address of `notepad.exe` in the victim’s memory space.  
- Calls `NtUnmapViewOfSection` to release that memory region, leaving an empty “hollow” space.  

### 4. **Payload Injection**
- Reserves new memory in the victim process using `VirtualAllocEx`, ideally at the original base address, with RWX permissions.  
- Copies the shellcode into the allocated memory with `WriteProcessMemory`.  

### 5. **Thread Hijacking**
- Obtains the main thread context with `GetThreadContext`.  
- Modifies the **RCX register** (which typically points to the entry point in x64 processes) to point to the payload.  
- Applies the modified context with `SetThreadContext`.  

### 6. **Payload Activation**
- Calls `ResumeThread`, resuming execution.  
- Instead of starting `notepad.exe`, the OS jumps directly into the injected payload.  

---

## ⚠️ Error Handling and Fallbacks

A robust loader must adapt to failures and anti-evasion defenses.  

### 🔹 Fallback for Base Address Retrieval
- **Primary Method**: `EnumProcessModules` (high-level API, but easy for EDR to monitor).  
- **Fallback Method**: Uses `NtQueryInformationProcess` to get the Process Environment Block (PEB) and read the base address directly from memory. This is stealthier and less likely to be blocked.  

### 🔹 Handling NtUnmapViewOfSection Failure
- If `NtUnmapViewOfSection` fails (e.g., blocked by security tools), the loader continues execution instead of aborting.  
- Allocates new memory and injects the payload anyway.  
- **Result**: Technique degrades into classic **Process Injection**. Less stealthy (two executable regions remain), but still functional.  

### 🔹 Cleanup and Safe Termination
- After each critical API call, errors are checked.  
- On irrecoverable failure, the loader calls `TerminateProcess` to clean up the victim process and exits.  
- Prevents leaving zombie or suspicious half-injected processes running.  

---

## ✅ Conclusion
This payload design combines **Process Hollowing** with **NTDLL Unhooking** to stealthily execute malicious code inside a trusted process.  

The **unhooking step** blinds EDR monitoring, while the **hollowing technique** ensures execution under the identity of a legitimate application. With built-in error handling and fallback strategies, the loader maintains reliability even in hardened environments.

