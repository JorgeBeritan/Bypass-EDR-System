# Payload 3 Design: PowerShell Obfuscation and AMSI Evasion

This document details the design of a PowerShell-based dropper, whose main objective is to evade endpoint defenses—specifically the Antimalware Scan Interface (AMSI)—in order to download and execute a second-stage payload from a remote source.  
The effectiveness of this payload lies in its multi-layered approach, which combines robust command obfuscation with two distinct in-memory AMSI bypass techniques.

---

## PowerShell Obfuscation Strategy

Obfuscation is essential to prevent the script from being detected by signature-based security solutions that look for keywords and known malicious command patterns.

### String Concatenation
Critical commands and text strings are constructed at runtime from smaller fragments. By splitting strings like `Invoke-Expression` or URLs, static signatures searched by antivirus engines are disrupted.  
In the script, variables such as `$c`, `$u`, and `$d` are assembled this way to conceal their final purpose.

### String Encoding (Base64)
The most sensitive strings—used to interact with AMSI internals (like `AmsiUtils` and `amsiInitFailed`)—are completely hidden from the source code.  
They are stored as Base64-encoded strings and only decoded in memory at runtime. This completely frustrates static analysis looking for these indicators of compromise.

### Dynamic Execution with Operators
The final payload execution is not a direct, readable line of code. Instead, the invocation operator `&` and variable concatenation are used to build and run the final command.  
The line `& ($c -replace ' ','') ($d+'('+"'$u'"+')')` is a perfect example: it assembles the `Invoke-Expression` command and the download script from obfuscated variables and executes it in a way that is difficult to statically analyze.

---

## Implemented AMSI Bypass Techniques

AMSI is a Microsoft framework that allows applications (such as PowerShell, WScript, etc.) to integrate their defenses with the antimalware software installed on the system.  
Before PowerShell executes a block of code, it sends it to AMSI for inspection. This script implements two bypass techniques to neutralize this defense.

### Bypass 1: Forcing AMSI Failure State 🕵️‍♂️
This is a logical bypass that tricks PowerShell into believing that AMSI is not functioning properly.

- **Reflection Access**: The script uses .NET reflection to access an internal, non-public PowerShell class: `System.Management.Automation.AmsiUtils`. The strings to locate this class are obfuscated in Base64.  
- **Flag Modification**: Within this class, there is a static private field named `amsiInitFailed`. This flag, if set to `$true`, tells the PowerShell session that AMSI initialization has failed.  
- **Disabling AMSI**: The script sets `amsiInitFailed` to `$true`. As a result, the current PowerShell session stops sending any subsequent commands to AMSI for scanning, effectively disabling it for our payload.

---

### Bypass 2: In-Memory Patching of AmsiScanBuffer 🩹
This is a lower-level, more powerful and resilient method, which directly corrupts AMSI functionality in memory.

- **Importing Windows APIs**: Using `Add-Type`, the script dynamically imports Win32 API functions from `kernel32.dll`, such as `LoadLibrary`, `GetProcAddress`, and `VirtualProtect`. This enables interaction with its own process memory.  
- **Locating the Function**: It retrieves the memory address of the `AmsiScanBuffer` function inside `amsi.dll`. This is the main function applications use to request a buffer scan.  
- **Changing Memory Permissions**: It calls `VirtualProtect` to make the memory page containing `AmsiScanBuffer` writable.  
- **Overwriting Code**: The script overwrites the first bytes of `AmsiScanBuffer` with carefully selected machine code (opcodes). These instructions cause the function to immediately return an error code (`E_INVALIDARG` or `0x80070057`) without performing any scan.  
- **Effect**: Any subsequent attempt to scan content through AMSI within the current process fails instantly, providing a “free pass” to execute malicious commands.

---
