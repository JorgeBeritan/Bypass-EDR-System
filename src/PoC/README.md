# Executive Summary

The present code implements an advanced system of code injection and analysis evasion techniques in the Windows environment. This program combines multiple offensive cybersecurity techniques including code obfuscation, process injection, analysis environment detection, and dynamic API resolution. The code is designed to execute shellcode on a target system while avoiding detection by security solutions and analysis environments.

---

## 📑 Table of Contents
- [1. General Architecture](#1-general-architecture)
- [2. Dynamic API Resolution](#2-dynamic-api-resolution)
  - [2.1 APIAddresses Structure](#21-apiaddresses-structure)
  - [2.2 Obtaining Base Addresses](#22-obtaining-base-addresses)
  - [2.3 Resolution of Exported Functions](#23-resolution-of-exported-functions)
- [3. Obfuscation Mechanisms](#3-obfuscation-mechanisms)
  - [3.1 String Encryption](#31-string-encryption)
  - [3.2 Shellcode Encryption](#32-shellcode-encryption)
- [4. Shellcode](#4-shellcode)
- [5. Anti-Analysis Techniques](#5-anti-analysis-techniques)
  - [5.1 Virtual Machine Detection](#51-virtual-machine-detection)
  - [5.2 Sandbox Detection](#52-sandbox-detection)
  - [5.3 Debugger Detection](#53-debugger-detection)
  - [5.4 API Hook Detection](#54-api-hook-detection)
  - [5.5 Anti-Sandbox Delay](#55-anti-sandbox-delay)
- [6. Code Injection Techniques](#6-code-injection-techniques)
  - [6.1 Standard Process Injection](#61-standard-process-injection)
  - [6.2 Process Hollowing](#62-process-hollowing)
- [7. Main Execution Flow](#7-main-execution-flow)
- [8. Security Analysis](#8-security-analysis)
  - [8.1 Security Implications](#81-security-implications)
  - [8.2 Mitigation Techniques](#82-mitigation-techniques)
  - [8.3 Legitimate Uses](#83-legitimate-uses)
- [9. Conclusions](#9-conclusions)

---

## 1. General Architecture

The code is structured into several core components:

- **Dynamic API resolution system**: Avoids static linking of system functions.  
- **Obfuscation mechanisms**: Implements XOR encryption for strings and data.  
- **Segmented shellcode**: Malicious code divided into multiple parts.  
- **Anti-analysis system**: Detects virtual environments, sandboxes, and debuggers.  
- **Injection methods**: Implements both standard injection and Process Hollowing.  

---

## 2. Dynamic API Resolution

### 2.1 APIAddresses Structure
This structure stores function pointers from multiple system DLLs (`kernel32.dll`, `user32.dll`, `ntdll.dll`). Using function pointers instead of direct calls allows runtime dynamic resolution, thus avoiding static import tables that could be detected by antivirus solutions.

### 2.2 Obtaining Base Addresses
The `GetModuleBaseAddress` function retrieves the base address of a module without using standard APIs, by directly accessing the **PEB (Process Environment Block)**. This is less detectable than calling `GetModuleHandle`.

### 2.3 Resolution of Exported Functions
The `GetProcAddressHidden` function manually parses the **PE structure** to access the export directory and locate the desired function, avoiding the use of `GetProcAddress` which could be monitored.

---

## 3. Obfuscation Mechanisms

### 3.1 String Encryption
The code uses XOR-based string encryption, with a dedicated `EncryptedString` class and the `ENC_STR` macro for convenience.

### 3.2 Shellcode Encryption
Shellcode is also XOR-encrypted, remaining hidden in the binary and decrypted only at runtime.

---

## 4. Shellcode

The shellcode is split into **22 parts** to evade signature-based detection and then combined at runtime. It remains encrypted until just before execution.

---

## 5. Anti-Analysis Techniques

### 5.1 Virtual Machine Detection
- Checks CPU count, RAM size, and presence of virtual devices.

### 5.2 Sandbox Detection
- Monitors system uptime.  
- Searches for analysis-related processes.

### 5.3 Debugger Detection
- Implements methods such as:  
  - `IsDebuggerPresent`  
  - `CheckRemoteDebuggerPresent`  
  - Memory inspection  

### 5.4 API Hook Detection
- Inspects the first bytes of critical functions (e.g., `NtAllocateVirtualMemory`) to detect modifications.

### 5.5 Anti-Sandbox Delay
- Implements randomized execution delays (**30–60 seconds**) with mixed waiting methods.  
- Increases delay if sandboxing is suspected.  

---

## 6. Code Injection Techniques

### 6.1 Standard Process Injection
- Searches for legitimate processes (e.g., `notepad.exe`, `chrome.exe`).  
- Injects shellcode using remote memory allocation and thread creation.  

### 6.2 Process Hollowing
- Creates a legitimate process in **suspended mode**.  
- Replaces its memory with shellcode.  
- Modifies its entry point.  
- Resumes execution.  

---

## 7. Main Execution Flow

The main function:

1. Initializes APIs.  
2. Checks for analysis environments (VM, sandbox, debuggers, API hooks).  
3. Executes benign code if analysis is detected.  
4. Applies anti-sandbox delays.  
5. Combines and decrypts shellcode.  
6. Attempts **Process Hollowing**.  
   - If it fails → falls back to **standard injection**.  
   - If all fails → executes locally.  

---

## 8. Security Analysis

### 8.1 Security Implications
The code uses techniques commonly associated with **advanced malware**:

- Detection evasion through anti-analysis methods.  
- Obfuscation of strings and shellcode.  
- Code injection into other processes.  
- Dynamic API resolution.  

### 8.2 Mitigation Techniques
- **EDR solutions** to detect suspicious runtime behavior.  
- **Behavioral analysis** to spot injection patterns.  
- **Application control** to restrict unauthorized executables.  
- **System hardening** to make injection harder.  
- **Memory monitoring** for suspicious modifications.  

### 8.3 Legitimate Uses
While often associated with malware, these techniques also serve:

- Penetration testing.  
- Security research.  
- Forensic analysis.  
- Security tool development.  

---

## 9. Conclusions

This code represents a **sophisticated example of offensive cybersecurity techniques**, combining multiple methods for covert code execution and evasion. It demonstrates deep knowledge of Windows internals, including the **PEB, PE format, and process/memory management**.

For the security community, this serves as a reminder of the need for **multi-layered defenses** that focus on **behavioral detection** rather than relying solely on static signatures.

## 10. Compilation
x86_64-w64-mingw32-g++ poc.cpp -o poc.exe -static-libgcc -static-libstdc++ -lsetupapi -ladvapi32 -lole32 -loleaut32