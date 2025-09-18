#include <windows.h>
#include <stdio.h>


typedef NTSTATUS(NTAPI* SyscallFunction)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main() {

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("Error: No se pudo cargar ntdll.dll\n");
        return 1;
    }

    PVOID pNtAllocateVirtualMemory = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    if (!pNtAllocateVirtualMemory) {
        printf("Error: No se encontró NtAllocateVirtualMemory\n");
        return 1;
    }


    BYTE* pSyscallNumber = (BYTE*)pNtAllocateVirtualMemory + 4;
    DWORD syscallNumber = *(DWORD*)pSyscallNumber;
    printf("Numero de syscall: 0x%X\n", syscallNumber);

    BYTE syscallCode[] = {
        0x4C, 0x8B, 0xD1,       // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, [syscall_number] (reemplazar)
        0x0F, 0x05,             // syscall
        0xC3                    // ret
    };
    *(DWORD*)(syscallCode + 4) = syscallNumber; // Insertar el número real


    PVOID pExecMemory = VirtualAlloc(
        NULL, 
        sizeof(syscallCode), 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    if (!pExecMemory) {
        printf("Error: No se pudo asignar memoria ejecutable\n");
        return 1;
    }

    memcpy(pExecMemory, syscallCode, sizeof(syscallCode));

    SyscallFunction pSyscall = (SyscallFunction)pExecMemory;
    
    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 4096; // 4 KB
    NTSTATUS status = pSyscall(
        hProcess,           // ProcessHandle
        &baseAddress,       // BaseAddress
        0,                  // ZeroBits
        &regionSize,        // RegionSize
        MEM_COMMIT | MEM_RESERVE, // AllocationType
        PAGE_EXECUTE_READWRITE    // Protect
    );

    if (status == 0x00000000) { // STATUS_SUCCESS
        printf("Memoria asignada en: %p\n", baseAddress);
        
        // Probar escribiendo en la memoria
        *(int*)baseAddress = 12345;
        printf("Valor escrito: %d\n", *(int*)baseAddress);
    } else {
        printf("Error en syscall: 0x%X\n", status);
    }

    // Liberar recursos
    VirtualFree(pExecMemory, 0, MEM_RELEASE);
    if (baseAddress) VirtualFree(baseAddress, 0, MEM_RELEASE);

    return 0;
}