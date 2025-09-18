#include <windows.h>
#include <iostream>
#include <winternl.h>

#ifdef _MSC_VER
    #define SECTION_ATTRIBUTE __declspec(allocate(".morph"))
#else
    #define SECTION_ATTRIBUTE __attribute__((section(".morph")))
#endif

#pragma section(".morph", read)

const unsigned char shellcode[] SECTION_ATTRIBUTE = {
	0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0xB8, 0x53, 0x79,
	0x6E, 0x74, 0x68, 0x45, 0x76, 0x61, 0x50, 0x48, 0xFF, 0xE0, 0x41, 0x54,
	0x49, 0x4F, 0x4E, 0x00
};

// --- DEFINICIÓN CORRECTA DE LA FUNCIÓN ---
// Se vuelve a usar PSIZE_T, que es el tipo correcto para el tamaño en sistemas x64.
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize, // <-- CORREGIDO
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

int main() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Error: No se pudo obtener el handle de ntdll.dll" << std::endl;
        return 1;
    }

    pNtProtectVirtualMemory NtProtectVirtualMemory = 
        (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    if (!NtProtectVirtualMemory) {
        std::cerr << "Error: No se pudo encontrar NtProtectVirtualMemory" << std::endl;
        return 1;
    }
    
    std::cout << "Seccion '.morph' actualmente con permisos de solo lectura." << std::endl;
    std::cout << "Presiona Enter para cambiar los permisos a RX y ejecutar..." << std::endl;
    std::cin.get();

    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = (PVOID)shellcode;
    SIZE_T shellcodeSize = sizeof(shellcode); // <-- Usar SIZE_T para coincidir
    ULONG oldProtection = 0;

    NTSTATUS status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &shellcodeSize, // <-- Ahora es un puntero a un SIZE_T, que es lo correcto
        PAGE_EXECUTE_READ,
        &oldProtection
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "Error en NtProtectVirtualMemory. NTSTATUS: 0x" 
                  << std::hex << status << std::endl;
        return 1;
    }

    std::cout << "Permisos cambiados exitosamente. Ejecutando shellcode..." << std::endl;
    
    ((void(*)())shellcode)();

    std::cout << "Shellcode ejecutado." << std::endl;
    return 0;
}