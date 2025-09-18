#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

DWORD HashFunction(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = ((hash << 5) + hash) + *name++;
    }
    return hash;
}

FARPROC GetFunctionAddressByPEB(const char* libName, DWORD functionHash) {

    HMODULE modules[1024];
    DWORD cbNeeded;
    
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &cbNeeded)) {
        return NULL;
    }
    
    DWORD numModules = cbNeeded / sizeof(HMODULE);
    
    for (DWORD i = 0; i < numModules; i++) {
        char modulePath[MAX_PATH];
        if (GetModuleFileNameA(modules[i], modulePath, MAX_PATH)) {
            char* baseName = strrchr(modulePath, '\\');
            if (baseName) {
                baseName++;
            } else {
                baseName = modulePath;
            }
            
            if (_stricmp(baseName, libName) == 0) {
                BYTE* base = (BYTE*)modules[i];
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
                
                IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)
                    (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                
                DWORD* names = (DWORD*)(base + exports->AddressOfNames);
                WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
                DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
                
                for (DWORD j = 0; j < exports->NumberOfNames; j++) {
                    char* name = (char*)(base + names[j]);
                    if (HashFunction(name) == functionHash) {
                        return (FARPROC)(base + functions[ordinals[j]]);
                    }
                }
            }
        }
    }
    
    return NULL;
}

int main() {
    DWORD hash = HashFunction("GetProcAddress");
    FARPROC getProc = GetFunctionAddressByPEB("kernel32.dll", hash);
    
    if (getProc) {
        printf("Resolved GetProcAddress: %p\n", getProc);
    } else {
        printf("Failed to resolve.\n");
    }
    
    return 0;
}