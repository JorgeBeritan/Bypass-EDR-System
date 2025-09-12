# Research Project on EDR Evasion Techniques

## 📌 Executive Summary
This project focuses on the **research and application of advanced techniques** to evade **Endpoint Detection and Response (EDR)** solutions.  
The goal is **educational and defensive**: to understand how attackers bypass detection in order to later **propose stronger mitigation and detection strategies**.  

Through the development of **Proofs of Concept (PoCs)**, the project explores methods such as:  
- Code obfuscation  
- Payload encryption  
- Process injection  
- API hook evasion  

The results will provide concrete recommendations for **security teams (Blue Teams)**.

---

## 🎯 Project Objectives
- Research the internal workings of EDR solutions and their detection mechanisms (signatures, behavior, and heuristics).  
- Develop custom payloads in **C/C++** and tools such as **Metasploit**, applying evasion techniques.  
- Evaluate the effectiveness of these techniques against **Windows Defender** and **CrowdStrike** in controlled lab environments.  
- Document results and propose **countermeasures and detection rules** for Blue Teams.  

---

## 🛠️ Methodology and Phases
### Week 1: Research and Fundamentals
- Study of EDR architecture.  
- Analysis of Windows API *hooking* techniques (user-land).  
- Research of common evasion techniques: **Process Hollowing**, **DLL Injection**, **shellcode encryption**, **direct syscalls**.  

### Week 2: Payload Development and Obfuscation
- Creation of shellcodes with **Metasploit / Cobalt Strike**.  
- PoC implementation in **C/C++**.  
- Application of **obfuscators (Obfuscator-LLVM)**.  

### Week 3: Lab Testing
- Setup of Windows 10/11 with Defender and CrowdStrike.  
- Execution of PoCs and systematic result logging.  
- Iteration and refinement of evasion techniques.  

### Week 4: Analysis and Final Documentation
- Identification of the most effective techniques.  
- Final report including **binaries, logs, and defensive recommendations**.  

---

## ⚗️ Proofs of Concept (PoC)

### PoC 1: Obfuscated Shellcode Execution with Direct Syscalls
**Objective:** Bypass static detection and API hooks using:  
- 🔐 **AES shellcode encryption**  
- 🔑 **XOR key obfuscation**  
- 🔍 **Dynamic API resolution**  
- ⚡ **Direct syscall invocation**  

**Execution Flow:**  
1. AES key deobfuscated in memory.  
2. Shellcode decrypted.  
3. Memory reserved with `NtAllocateVirtualMemory` via direct syscall.  
4. Payload copied and executed in memory.  

---

### PoC 2: Process Hollowing with Unhooking
**Objective:** Inject a payload into a legitimate process (e.g., `notepad.exe`) while removing EDR hooks.  

**Key Techniques:**  
- 🧹 **Unhooking ntdll.dll** (restoring the `.text` section).  
- 👻 **Process Hollowing** using `NtUnmapViewOfSection`, `WriteProcessMemory`, and thread context manipulation.  

**Execution Flow:**  
1. Hooks in `ntdll.dll` are removed.  
2. A trusted process is launched in suspended mode.  
3. Original memory unmapped and replaced with payload.  
4. Thread context redirected to injected shellcode.  
5. Process resumed, executing the payload under disguise.  

---

## 🛡️ Defensive Recommendations (Blue Team)

### Process Behavior Monitoring
- Detect processes created with **CREATE_SUSPENDED** in unusual contexts.  
- Monitor **anomalous parent-child process relationships**.  
- Alert on calls to **NtUnmapViewOfSection**.  

### Memory and API Analysis
- Identify **direct syscalls** outside legitimate modules.  
- Scan processes for **PAGE_EXECUTE_READWRITE** regions containing shellcode.  
- Verify integrity of `.text` sections in critical DLLs.  

### Detection Rules (YARA/Sigma)
- Detect suspicious API call patterns:  
  `CreateProcessA + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread`.  

---

## 📦 Deliverables
- **PoC binaries**  
- **Evasion logs** (detection/bypass results)  
- **Defensive recommendations report**  

---

## ⚠️ Disclaimer
This project is strictly for **educational and defensive research purposes**.  
**It must not be used for malicious intent.**  
The author is not responsible for any misuse of the information provided.  

---
