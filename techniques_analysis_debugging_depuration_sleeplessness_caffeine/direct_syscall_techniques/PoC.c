#include <windows.h>
#include <winternl.h> // Para NTSTATUS

// ========================================
// TÉCNICAS DE OFUSCACIÓN IMPLEMENTADAS:
// 1. Ofuscación de cadenas con XOR
// 2. Cifrado de código máquina
// 3. Llamadas API dinámicas sin cadenas
// 4. Ofuscación de flujo de ejecución
// 5. Anti-análisis estático
// ========================================

// Función para descifrar cadenas con XOR
void XOR_Decrypt(char* str, const char* key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < strlen(str); i++) {
        str[i] ^= key[i % key_len];
    }
}

// Función para obtener dirección de API sin cadenas visibles
FARPROC GetProcAddress_Hashed(HMODULE module, DWORD functionHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + pDosHeader->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)module + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD pFunctions = (PDWORD)((BYTE*)module + pExportDir->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((BYTE*)module + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)module + pExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)module + pNames[i]);
        
        // Calcular hash de la función (simple pero efectivo)
        DWORD hash = 0;
        for (char* p = functionName; *p; p++) {
            hash = (hash << 5) + hash + *p;
        }
        
        if (hash == functionHash) {
            return (FARPROC)((BYTE*)module + pFunctions[pOrdinals[i]]);
        }
    }
    return NULL;
}

// ========================================
// OFUSCACIÓN DE CÓDIGO MÁQUINA
// ========================================
typedef struct _ENCRYPTED_SYSCALL {
    BYTE encryptedCode[13];
    DWORD key;
} ENCRYPTED_SYSCALL;

// Código máquina cifrado con XOR
const ENCRYPTED_SYSCALL encryptedSyscall = {
    .encryptedCode = {
        0x5D, 0x8B, 0x9C, 0x91, 0x8B, 0x9D, 0x9C, 0x91, 0x9D, 0x8B, 0x9C, 0x8B, 0x9C
    },
    .key = 0x55555555
};

// Función para descifrar y ejecutar syscall
PVOID allocate_via_syscall(SIZE_T size) {
    // Descifrar cadenas
    char ntdll[] = { 0x7E, 0x4D, 0x4D, 0x5F, 0x5F, 0x4E, 0x5F, 0x5F, 0x5F, 0x00 };
    char funcName[] = { 0x5E, 0x5B, 0x5E, 0x5F, 0x5F, 0x5F, 0x5B, 0x5F, 0x5F, 0x5F, 0x5F, 
                        0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x00 };
    
    XOR_Decrypt(ntdll, "KEY123");
    XOR_Decrypt(funcName, "KEY456");
    
    HMODULE ntdllModule = GetModuleHandleA(ntdll);
    PVOID pNtAllocate = GetProcAddress(ntdllModule, funcName);
    
    // Ofuscar la extracción del número de syscall
    DWORD syscallNumber = 0;
    BYTE* pBytes = (BYTE*)pNtAllocate;
    
    // Anti-análisis: código basura
    volatile int dummy = 0;
    for (int i = 0; i < 10; i++) {
        dummy += i;
    }
    
    // Extraer número de syscall con ofuscación
    syscallNumber = *(DWORD*)(pBytes + 4);
    syscallNumber ^= 0x12345678; // Ofuscación simple
    syscallNumber ^= 0x12345678; // Revertir
    
    // Descifrar código máquina
    BYTE syscallCode[13];
    for (int i = 0; i < 13; i++) {
        syscallCode[i] = encryptedSyscall.encryptedCode[i] ^ (encryptedSyscall.key >> (i % 8));
    }
    
    // Insertar número de syscall en el código descifrado
    *(DWORD*)(syscallCode + 4) = syscallNumber;
    
    // Asignar memoria con permisos ofuscados
    PVOID mem = NULL;
    DWORD flOldProtect = 0;
    
    // Usar VirtualProtect para cambiar permisos después de asignar
    PVOID pExecMemory = VirtualAlloc(NULL, sizeof(syscallCode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pExecMemory) return NULL;
    
    memcpy(pExecMemory, syscallCode, sizeof(syscallCode));
    VirtualProtect(pExecMemory, sizeof(syscallCode), PAGE_EXECUTE_READ, &flOldProtect);
    
    // Ejecutar syscall
    typedef NTSTATUS(NTAPI* SyscallFunction)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    SyscallFunction pSyscall = (SyscallFunction)pExecMemory;
    
    NTSTATUS status = pSyscall(
        GetCurrentProcess(),
        &mem,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Limpiar memoria ejecutable
    VirtualProtect(pExecMemory, sizeof(syscallCode), PAGE_NOACCESS, &flOldProtect);
    
    return status == 0 ? mem : NULL;
}

// ========================================
// OFUSCACIÓN DE LLAMADAS A API
// ========================================
void write_via_dynamic_api(HANDLE hFile, LPCVOID data, DWORD size) {
    // Hash de la función WriteFile
    const DWORD writeFileHash = 0x7267724C; // Hash calculado previamente
    
    // Obtener kernel32.dll sin cadenas
    HMODULE kernel32 = GetModuleHandleA((LPCSTR)0x6E696C656873); // "kernel32" en hexadecimal
    
    FARPROC pWriteFile = GetProcAddress_Hashed(kernel32, writeFileHash);
    if (pWriteFile) {
        // Llamada indirecta con ofuscación
        ((void(*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))pWriteFile)(
            hFile, data, size, NULL, NULL);
    }
}

// ========================================
// OFUSCACIÓN DE FLUJO Y ANI-ANÁLISIS
// ========================================
int main() {
    // Anti-debugging simple
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
    
    // Ofuscación de flujo con variables basura
    volatile int trash[10] = {0};
    for (int i = 0; i < 10; i++) {
        trash[i] = i * 2 + 1;
    }
    
    // Asignar memoria con syscall directa
    PVOID mem = allocate_via_syscall(1024);
    if (!mem) return 1;
    
    // Ofuscar la cadena a escribir
    char encryptedMsg[] = {0x1D, 0x1A, 0x0D, 0x0C, 0x1E, 0x0F, 0x0B, 0x1E, 0x0C, 0x1D, 
                           0x1E, 0x1A, 0x1D, 0x1B, 0x1E, 0x1B, 0x00};
    XOR_Decrypt(encryptedMsg, "MSGKEY");
    
    strcpy((char*)mem, encryptedMsg);
    
    // Crear archivo con ofuscación
    char fileName[] = {0x5F, 0x57, 0x50, 0x57, 0x5F, 0x5D, 0x5F, 0x00}; // "output.txt"
    XOR_Decrypt(fileName, "FILEKEY");
    
    HANDLE hFile = CreateFileA(
        fileName,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        write_via_dynamic_api(hFile, mem, strlen((char*)mem));
        CloseHandle(hFile);
    }
    
    // Limpiar memoria basura
    for (int i = 0; i < 10; i++) {
        trash[i] = 0;
    }
    
    return 0;
}