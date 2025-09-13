# Payload Design 1: Encrypted Shellcode with Hook Evasion

This document details the design and execution flow of a shellcode loader built to evade detection by Endpoint Detection and Response (EDR) solutions.  

The main techniques employed are **payload encryption**, **key obfuscation**, and the use of **direct syscalls** to bypass user-mode hooks.

---

## 📌 Technical Specifications of the Encrypted Shellcode

The payload is designed to remain stealthy and effective, minimizing its footprint both on disk and in memory.

- **Payload**: The shellcode is the final payload to be executed in memory. In the code, `encryptedShellcode` acts as a placeholder (dummy) for the already encrypted payload.  
- **In-Memory Format**: The shellcode is stored as an encrypted byte array (`unsigned char[]`) inside the executable’s data section, preventing visibility of its plaintext form during static file analysis.  

---

## 🔹 Key Evasion Techniques

### 1. **In-Memory Encryption**
- The shellcode stays encrypted until execution time.  
- It is only decrypted in dynamically allocated memory, never written to disk.  

### 2. **Encryption Key Obfuscation**
- The AES-256 key is not stored in plaintext.  
- Instead, it is stored in the array `obfuscatedKey`, obfuscated with a simple XOR operation.  
- The real key is reconstructed in memory right before decryption.  

### 3. **Dynamic API Resolution (IAT Hook Evasion)**
- The custom function `GetNativeProcAddress` avoids the use of `GetProcAddress`, which is commonly monitored by EDRs.  
- Instead, it manually parses the Export Address Table (EAT) of **ntdll.dll** in memory to locate native function addresses.  

### 4. **Direct Syscalls**
- For memory allocation, the loader does not call `VirtualAlloc` or the exported `NtAllocateVirtualMemory` from ntdll.dll.  
- Instead, `NtAllocateVirtualMemorySyscall` retrieves the syscall number and executes the instruction directly using inline assembly (`syscall`).  
- This completely bypasses any hooks placed by EDR in user-mode functions.  

### 5. **Memory Protection Flipping**
- After copying the decrypted shellcode into memory (initially allocated as `PAGE_EXECUTE_READWRITE`), the region is changed to `PAGE_EXECUTE_READ` via `VirtualProtect`.  
- Moving from RWX ➝ RX mimics legitimate software behavior and reduces memory scanning suspicion.  

---

## 🔹 Encryption Algorithm (AES-256)

- **Algorithm**: AES-256 (Advanced Encryption Standard) with a 256-bit (32-byte) key.  
- **Mode of Operation**: CBC (Cipher Block Chaining). Requires an initialization vector (IV). Here, an IV of zero is used for simplicity.  
- **Implementation**: Uses **Windows CryptoAPI (wincrypt.h)**, leveraging native OS cryptographic functions to avoid suspicious third-party libraries.  

### 🔑 Key Management
- The AES key (32 bytes) is obfuscated with XOR using a static 8-byte key.  
- At runtime, `XORDeobfuscate` restores the real AES key in memory.  
- After decryption, `SecureZeroMemory` wipes the key from memory, minimizing exposure.  

---

## 📊 Execution Flow Diagram

The following outlines the logical flow of the loader:

1. ▶️ **Start**: Program begins execution.  

2. 🔑 **Deobfuscate AES Key**  
   - `XORDeobfuscate` reconstructs the AES-256 key from `obfuscatedKey`.  

3. 🔓 **Decrypt Shellcode**  
   - `DecryptShellcode` uses Windows CryptoAPI with the AES key.  
   - Decrypts the contents of `encryptedShellcode` in-place.  
   - Immediately wipes the key from memory with `SecureZeroMemory`.  

4. 🆔 **Retrieve Syscall ID**  
   - `NtAllocateVirtualMemorySyscall` is called.  
   - Internally uses `GetNativeProcAddress` to find `NtAllocateVirtualMemory` inside **ntdll.dll**.  
   - Extracts the syscall ID (e.g., `0x18` on Windows 10/11).  

5. 🧠 **Allocate Executable Memory (via Syscall)**  
   - Inline assembly executes the syscall directly.  
   - A new memory region is allocated with RWX (`PAGE_EXECUTE_READWRITE`).  

6. ✍️ **Copy Shellcode**  
   - `memcpy` copies the decrypted shellcode into the RWX memory region.  

7. 🛡️ **Change Memory Protections**  
   - `VirtualProtect` flips the region from RWX ➝ RX (`PAGE_EXECUTE_READ`).  

8. 🚀 **Transfer Execution**  
   - The allocated memory pointer is cast to a function pointer.  
   - Control is transferred to the shellcode.  

9. 🏁 **End**: The shellcode is now running.  

---

## ✅ Conclusion
This payload design leverages **encryption, API evasion, syscall-level execution, and memory protection techniques** to bypass EDR detection mechanisms. By combining stealth in storage and execution with direct kernel interactions, the loader minimizes its visibility while maintaining reliable execution.

