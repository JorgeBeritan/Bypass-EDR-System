#include <windows.h>
#include <iostream>

extern "C" NTSTATUS NtAllocateVirtualMemory (
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main(){
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000; // 4 KB in hexadecimal expresion
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status == 0){
        std::cout << "[+] Memory allocated at " << baseAddress << std::endl;
    } else {
        std::cout << "[-] Syscall failed: " << std::hex << status << std::endl;
    }

    return 0;
}