#include <windows.h>
#include <iostream>

FARPROC get_api(const char* lib, const char* func){
    HMODULE hMod = LoadLibrary(lib);
    return GetProcAddress(hMod, func);
}

typedef LPVOID (WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

int main(){
    pVirtualAlloc myVA = (pVirtualAlloc)get_api("kernel32.dll", "VirtualAlloc");
    void* mem = myVA(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return 0;
}