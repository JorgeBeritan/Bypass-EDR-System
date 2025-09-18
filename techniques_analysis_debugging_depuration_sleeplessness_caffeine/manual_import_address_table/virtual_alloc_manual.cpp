#include <windows.h>
#include <iostream>

typedef LPVOID (WINAPI* pVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

int main(){
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if(!hKernel32) {
        std::cerr << "Failed to lad kernel32.dll" << std::endl;
        return 1;
    }

    pVirtualAlloc myVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    if(!myVirtualAlloc) {
        std::cerr << "Failed to get VirtualAlloc address" << std::endl;
        return 1;
    }

    LPVOID mem = myVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem) {
        std::cerr << "Failed to allocate memory" << std::endl;
        return 1;
    }

    return 0;
}