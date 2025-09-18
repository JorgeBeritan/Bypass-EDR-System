#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

typedef FARPROC (WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI* tLoadLibraryA)(LPCSTR);
typedef LPVOID (WINAPI* tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI* tCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI* tWaitForSingleObject)(HANDLE, DWORD);
typedef int (WINAPI* tMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

DWORD HashFunction(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = ((hash << 5) + hash) + *name++;
    }
    return hash;
}

void GetBaseDllName(PLDR_DATA_TABLE_ENTRY entry, char* output, size_t outSize) {
    wchar_t* nameBuffer = entry->FullDllName.Buffer;
    size_t nameLength = entry->FullDllName.Length / sizeof(WCHAR);
    
    wchar_t* lastSlash = NULL;
    for (size_t i = 0; i < nameLength; i++) {
        if (nameBuffer[i] == L'\\') {
            lastSlash = &nameBuffer[i];
        }
    }
    
    if (lastSlash) {
        nameBuffer = lastSlash + 1;
        nameLength = nameLength - (lastSlash - entry->FullDllName.Buffer + 1);
    }
    
    if (nameBuffer && nameLength > 0) {
        WideCharToMultiByte(CP_ACP, 0, nameBuffer, nameLength, output, outSize, NULL, NULL);
        output[nameLength < outSize ? nameLength : outSize - 1] = '\0';
    } else {
        output[0] = '\0';
    }
}

FARPROC GetFunctionAddressByPEB(const char* libName, DWORD functionHash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    
    for (PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
         list != &ldr->InMemoryOrderModuleList;
         list = list->Flink) {
        
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        char baseName[MAX_PATH];
        GetBaseDllName(entry, baseName, MAX_PATH);
        
        if (_stricmp(baseName, libName) == 0) {
            BYTE* base = (BYTE*)entry->DllBase;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
            
            IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)
                (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            
            DWORD* names = (DWORD*)(base + exports->AddressOfNames);
            WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
            DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
            
            for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                char* name = (char*)(base + names[i]);
                if (HashFunction(name) == functionHash) {
                    return (FARPROC)(base + functions[ordinals[i]]);
                }
            }
        }
    }
    return NULL;
}

int main() {
    DWORD hashGetProc = HashFunction("GetProcAddress");
    DWORD hashLoadLib = HashFunction("LoadLibraryA");
    DWORD hashVirtualAlloc = HashFunction("VirtualAlloc");
    DWORD hashCreateThread = HashFunction("CreateThread");
    DWORD hashWaitForSingleObject = HashFunction("WaitForSingleObject");
    DWORD hashMessageBoxA = HashFunction("MessageBoxA");

    tGetProcAddress pGetProc = (tGetProcAddress)GetFunctionAddressByPEB("kernel32.dll", hashGetProc);
    tLoadLibraryA pLoadLib = (tLoadLibraryA)GetFunctionAddressByPEB("kernel32.dll", hashLoadLib);
    tVirtualAlloc pVirtualAlloc = (tVirtualAlloc)GetFunctionAddressByPEB("kernel32.dll", hashVirtualAlloc);
    tCreateThread pCreateThread = (tCreateThread)GetFunctionAddressByPEB("kernel32.dll", hashCreateThread);
    tWaitForSingleObject pWaitForSingleObject = (tWaitForSingleObject)GetFunctionAddressByPEB("kernel32.dll", hashWaitForSingleObject);
    
    if (!pGetProc || !pLoadLib || !pVirtualAlloc || !pCreateThread || !pWaitForSingleObject) {
        printf("Error al resolver funciones de kernel32.dll\n");
        return 1;
    }
    
    HMODULE hUser32 = pLoadLib("user32.dll");
    if (!hUser32) {
        printf("Error al cargar user32.dll\n");
        return 1;
    }
    
    tMessageBoxA pMessageBoxA = (tMessageBoxA)pGetProc(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("Error al resolver MessageBoxA\n");
        return 1;
    }
    
    unsigned char shellcode[] = {
        0x48, 0x31, 0xC9,                                           // xor rcx, rcx          ; hWnd = NULL
        0x48, 0x8D, 0x15, 0x1A, 0x00, 0x00, 0x00,                   // lea rdx, [rip+0x1A]   ; lpText -> "Hola Mundo"
        0x4D, 0x31, 0xC0,                                           // xor r8, r8            ; lpCaption = NULL
        0x4D, 0x31, 0xC9,                                           // xor r9, r9            ; uType = 0 (MB_OK)
        0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // mov rax, 0xAAAAAAAA... ; Placeholder para la dirección
        0xFF, 0xD0,                                                 // call rax
        0xC3,                                                       // ret
        // Cadena "Hola Mundo" + NULL terminator
        'H', 'o', 'l', 'a', ' ', 'M', 'u', 'n', 'd', 'o', '\0'
    };
    
    memcpy(shellcode + 18, &pMessageBoxA, sizeof(pMessageBoxA));
    
    LPVOID execMem = pVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        printf("Error al asignar memoria ejecutable\n");
        return 1;
    }
    
    memcpy(execMem, shellcode, sizeof(shellcode));
    
    printf("Shellcode inyectado en: %p\n", execMem);
    printf("Presiona Enter para ejecutar el shellcode...");
    getchar();
    
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        printf("Error al crear el hilo\n");
        return 1;
    }
    
    pWaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    VirtualFree(execMem, 0, MEM_RELEASE);
    
    printf("Shellcode ejecutado correctamente\n");
    return 0;
}