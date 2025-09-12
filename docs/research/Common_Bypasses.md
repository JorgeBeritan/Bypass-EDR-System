# EDR/AV Evasion Techniques: A Technical Deep Dive

## 1. Introduction to the Evasion Landscape
Modern Endpoint Detection and Response (EDR) platforms and Antivirus (AV) solutions operate by deploying agents on endpoints to monitor system activity. They primarily use two methods:

- **User-mode Hooking:** Intercepting function calls in loaded DLLs (e.g., kernel32.dll, ntdll.dll) to inspect arguments and behavior before they execute.  
- **Kernel-mode Telemetry:** Utilizing Event Tracing for Windows (ETW) and Kernel Callbacks to receive deep system-level events (process creation, thread creation, image loading, etc.).

The goal of evasion is to execute malicious code without triggering the defensive mechanisms of these tools. This is achieved by either going undetected (**stealth**) or disrupting the EDR's visibility (**blinding**).

---

## 2. Catalogue of Evasion Techniques

### 2.1. Direct System Calls (Syscalls)
**Concept:** The highest-level Windows API functions (e.g., `CreateProcess`) are wrappers around lower-level functions in `ntdll.dll`, which themselves contain the syscall instruction that transitions from user mode to kernel mode. EDRs hook the functions in `ntdll.dll`. Direct Syscalls bypass these hooks by writing the assembly syscall instruction directly into the current thread's memory, avoiding the hooked `ntdll` functions entirely.

**How it Works:**
1. **Identify the SSN:** Find the System Service Number (SSN) for the desired native API (e.g., `NtCreateProcess`).  
2. **Setup Registers:** Load the SSN into the EAX register and function arguments into the correct registers (RCX, RDX, R8, R10, etc.) according to the x64 calling convention.  
3. **Execute syscall:** The instruction triggers a switch to kernel mode, executing the requested function.  
4. **Return Result:** The kernel places the result back in RAX, and execution returns to user mode.  

**Tools & Implementations:**
- **Hell's Gate & Halos Gate:** Dynamically find SSNs from the Export Address Table (EAT) of `ntdll.dll` in memory, even if the EDR has tampered with the order.  
- **FreshyCalls / SysWhispers3:** Generate header files and assembly stubs for direct syscalls. They often include SSN spoofing.  

**MITRE ATT&CK:**  
- T1027 - Obfuscated Files or Information  
- T1620 - Reflective Code Loading  

---

### 2.2. Unhooking
**Concept:** If an EDR has placed hooks in user-mode DLLs, a process can "unhook" itself by loading a clean, unhooked version of the DLL from disk and overwriting the malicious, hooked `.text` section in memory.

**How it Works:**
1. Identify Hooked Module.  
2. Read Clean DLL from Disk (`\SystemRoot\System32\`).  
3. Parse PE Headers to locate the `.text` section.  
4. Overwrite Memory: Change protection, copy clean code, restore protection, flush cache.  

**Tools & Implementations:**
- Manual implementations in custom loaders.  
- **PE-sieve** to dump an unhooked process.  
- **Cobalt Strike inline-execute** supports unhooking.  

**Considerations:** Writing to executable memory can itself be detected.  

**MITRE ATT&CK:**  
- T1562.001 - Impair Defenses: Disable or Modify Tools  

---

### 2.3. Custom Loaders / Shellcode Encoders/Decoders
**Concept:** Instead of executing a plain malicious executable, attackers use a **loader** that decrypts/decodes payloads (shellcode) directly in memory.

**How it Works:**
1. **Generation:** Payload created (e.g., Cobalt Strike Beacon).  
2. **Encryption/Obfuscation:** XOR, RC4, AES, Base64.  
3. **Embedding:** Payload inside a legitimate-looking loader.  
4. **Execution:** Loader decrypts, allocates memory, executes via pointer, `CreateThread`, or injection.  

**Advanced Variants:**
- **Staged Payloads** (stager fetches main payload).  
- **API Hashing** (hide API names).  
- **AES Encryption** for stronger protection.  

**MITRE ATT&CK:**  
- T1027 - Obfuscated Files or Information  
- T1140 - Deobfuscate/Decode Files or Information  
- T1620 - Reflective Code Loading  

---

### 2.4. Abusing LOLBins & LOLScripts (Living Off the Land)
**Concept:** Use pre-installed, trusted binaries/scripts (LOLBins/LOLScripts) to blend in with normal activity.  

**Examples:**
- **Execution:**  
  - `mshta.exe` → Run `.hta` from URL  
  - `regsvr32.exe` → Execute DLL scriptlets  
  - `rundll32.exe` → Execute DLL functions  
- **Lateral Movement/C2:**  
  - `bitsadmin.exe` / `certutil.exe` → Download payloads  
  - `wmic.exe` → Remote commands  
  - `msiexec.exe` → Malicious MSI from URL  
- **Scripting:**  
  - **PowerShell** → Download/execute in memory  
  - **CScript/WScript** → Run malicious scripts  

**MITRE ATT&CK:**  
- T1218 - Signed Binary Proxy Execution  
- T1105 - Ingress Tool Transfer  
- T1059 - Command and Scripting Interpreter  

---

### 2.5. ETW Patching
**Concept:** ETW is critical for logging events. Patching `EtwEventWrite` disables logging for the process, blinding the EDR.  

**How it Works:**
- Locate `ntdll!EtwEventWrite`.  
- Overwrite with a `ret` instruction.  

**Considerations:** Highly effective but easily detected.  

**MITRE ATT&CK:**  
- T1562.006 - Impair Defenses: Disable Windows Event Logging  

---

## 3. Comparative Table of Effectiveness

| Technique        | Detection Difficulty (for EDR) | Implementation Difficulty | Primary Use Case                 | EDR Blindspot Targeted         |
|------------------|--------------------------------|---------------------------|----------------------------------|--------------------------------|
| Direct Syscalls  | High (if done well)            | High (ASM/C required)     | Executing sensitive APIs         | User-mode Hooking              |
| Unhooking        | Medium                         | Medium                    | Preparing a process for execution| User-mode Hooking              |
| Custom Loaders   | Low to Medium                  | Low to Medium             | General payload delivery         | Static Analysis, Disk Scanning |
| LOLBins          | Low (by itself)                | Low                       | Execution, Defense Evasion       | Process Whitelisting, Behavioral Heuristics |
| ETW Patching     | Very High (easily flagged)     | Medium                    | Blinding the EDR post-exploit    | Event Tracing for Windows (ETW)|
| API Hashing      | Medium                         | Medium                    | Hiding imports in loaders        | Static String Analysis         |
| PPID Spoofing    | Low                            | Low                       | Hiding process lineage           | Process Tree Analysis          |
| Blocking DLLs    | Low                            | Low                       | Preventing EDR agent loading     | EDR Functionality              |

> **Note:** The most effective malware combines multiple techniques (e.g., a loader that uses API hashing, performs unhooking, and then uses direct syscalls for process injection).

---

## 4. References to MITRE ATT&CK Framework
The MITRE ATT&CK framework is the industry-standard taxonomy for adversary tactics and techniques. Nearly all evasion methods are catalogued there.

- **Tactic: Defense Evasion**  
  - T1027 - Obfuscated Files or Information  
  - T1218 - Signed Binary Proxy Execution  
  - T1620 - Reflective Code Loading  

- **Tactic: Impair Defenses**  
  - T1562.001 - Impair Defenses: Disable or Modify Tools  
  - T1562.006 - Impair Defenses: Disable Windows Event Logging  

---

## External Resources
- **LOLBAS Project:** [https://lolbas-project.github.io/](https://lolbas-project.github.io/)  
- **ired.team:** [https://www.ired.team/](https://www.ired.team/)  
- **MITRE ATT&CK - Defense Evasion:** [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)  

---

## Disclaimer
This document is intended for educational purposes, security research, and defensive hardening only. Understanding these techniques is crucial for Blue Teams to effectively detect and mitigate threats and for Red Teams to conduct realistic adversary simulations with proper authorization.
