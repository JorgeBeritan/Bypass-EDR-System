#include <iostream>
#include <windows.h>
#include <winternl.h>

// Definición de tipos
typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

// Función para cargar DLL desde archivo
bool LoadDLLFromFile(const char* filename, BYTE** ppBuffer, DWORD* pdwFileSize) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error al abrir archivo: " << GetLastError() << std::endl;
        return false;
    }

    *pdwFileSize = GetFileSize(hFile, NULL);
    if (*pdwFileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    *ppBuffer = new BYTE[*pdwFileSize];
    DWORD dwBytesRead;
    if (!ReadFile(hFile, *ppBuffer, *pdwFileSize, &dwBytesRead, NULL) || 
        dwBytesRead != *pdwFileSize) {
        delete[] *ppBuffer;
        *ppBuffer = nullptr;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return true;
}

// Función para obtener el tipo de arquitectura
const char* GetArchitectureType(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386: return "x86 (32-bit)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (64-bit)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_ARM: return "ARM";
        default: return "Desconocida";
    }
}

// Función principal de manual mapping
bool ManualMap(BYTE* pDllBuffer, DWORD dwFileSize) {
    // Validar buffer y tamaño
    if (!pDllBuffer || dwFileSize < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[-] Error: Buffer inválido o tamaño insuficiente" << std::endl;
        return false;
    }

    // --- PASO 1: PARSEAR HEADERS PE ---
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pDllBuffer);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Error: No es un ejecutable PE válido (firma DOS)" << std::endl;
        return false;
    }

    // Verificar que e_lfanew esté dentro de los límites
    if (pDosHeader->e_lfanew < 0 || 
        static_cast<DWORD>(pDosHeader->e_lfanew) > dwFileSize - sizeof(IMAGE_NT_HEADERS)) {
        std::cerr << "[-] Error: Offset de NT headers inválido" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        pDllBuffer + pDosHeader->e_lfanew);
    
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Error: Firma NT inválida" << std::endl;
        return false;
    }

    // Verificar arquitectura
    std::cout << "[+] Arquitectura de la DLL: " 
              << GetArchitectureType(pNtHeaders->FileHeader.Machine) << std::endl;

#ifdef _WIN64
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "[-] Error: DLL de 32 bits no puede cargarse en proceso de 64 bits" << std::endl;
        return false;
    }
#else
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        std::cerr << "[-] Error: DLL de 64 bits no puede cargarse en proceso de 32 bits" << std::endl;
        return false;
    }
#endif

    // --- PASO 2: ASIGNAR MEMORIA ---
    DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    LPVOID pPreferredBase = reinterpret_cast<LPVOID>(pNtHeaders->OptionalHeader.ImageBase);
    
    std::cout << "[+] Tamaño de imagen: " << dwImageSize << " bytes" << std::endl;
    std::cout << "[+] Base preferida: 0x" << std::hex << pNtHeaders->OptionalHeader.ImageBase 
              << std::dec << std::endl;

    LPVOID pAllocatedBase = VirtualAlloc(pPreferredBase, dwImageSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!pAllocatedBase) {
        std::cout << "[!] No se pudo asignar en base preferida, intentando en cualquier lugar..." << std::endl;
        pAllocatedBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pAllocatedBase) {
            std::cerr << "[-] Error: VirtualAlloc falló: " << GetLastError() << std::endl;
            return false;
        }
    }
    
    std::cout << "[+] Memoria asignada en: 0x" << std::hex << reinterpret_cast<uintptr_t>(pAllocatedBase) 
              << std::dec << std::endl;

    // --- PASO 3: COPIAR HEADERS Y SECCIONES ---
    // Copiar headers
    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    if (sizeOfHeaders > dwFileSize) {
        std::cerr << "[-] Error: SizeOfHeaders mayor que el tamaño del archivo" << std::endl;
        VirtualFree(pAllocatedBase, 0, MEM_RELEASE);
        return false;
    }
    
    memcpy(pAllocatedBase, pDllBuffer, sizeOfHeaders);

    // Copiar secciones
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        // Saltar secciones completamente vacías
        if (pSectionHeader->Misc.VirtualSize == 0 && pSectionHeader->SizeOfRawData == 0) {
            continue;
        }

        // Verificar límites de la sección
        if (pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > dwFileSize) {
            std::cerr << "[-] Error: Sección '" << pSectionHeader->Name 
                      << "' fuera de los límites del archivo" << std::endl;
            VirtualFree(pAllocatedBase, 0, MEM_RELEASE);
            return false;
        }

        // Verificar dirección virtual
        if (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize > dwImageSize) {
            std::cerr << "[-] Error: Sección '" << pSectionHeader->Name 
                      << "' fuera de los límites de la imagen" << std::endl;
            VirtualFree(pAllocatedBase, 0, MEM_RELEASE);
            return false;
        }

        LPVOID pSectionDest = reinterpret_cast<BYTE*>(pAllocatedBase) + pSectionHeader->VirtualAddress;
        LPVOID pSectionSrc = pDllBuffer + pSectionHeader->PointerToRawData;
        
        // Copiar datos de la sección
        if (pSectionHeader->SizeOfRawData > 0) {
            memcpy(pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData);
        }

        // Rellenar con ceros si VirtualSize > SizeOfRawData
        if (pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData) {
            DWORD dwZeroSize = pSectionHeader->Misc.VirtualSize - pSectionHeader->SizeOfRawData;
            memset(reinterpret_cast<BYTE*>(pSectionDest) + pSectionHeader->SizeOfRawData, 
                  0, dwZeroSize);
        }
    }

    std::cout << "[+] Secciones copiadas correctamente" << std::endl;

    // --- PASO 4: RELOCALIZACIONES ---
    uintptr_t delta = reinterpret_cast<uintptr_t>(pAllocatedBase) - 
                     pNtHeaders->OptionalHeader.ImageBase;
    
    if (delta != 0) {
        std::cout << "[+] Aplicando relocalizaciones, delta: 0x" << std::hex << delta << std::dec << std::endl;
        
        IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0 && relocDir.VirtualAddress > 0) {
            // Verificar que la tabla de relocalizaciones esté dentro de la imagen
            if (relocDir.VirtualAddress + relocDir.Size > dwImageSize) {
                std::cerr << "[-] Error: Tabla de relocalizaciones fuera de los límites" << std::endl;
                VirtualFree(pAllocatedBase, 0, MEM_RELEASE);
                return false;
            }

            PIMAGE_BASE_RELOCATION pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(pAllocatedBase) + relocDir.VirtualAddress);
            
            while (pReloc->VirtualAddress != 0 && 
                   reinterpret_cast<BYTE*>(pReloc) < reinterpret_cast<BYTE*>(pAllocatedBase) + 
                   relocDir.VirtualAddress + relocDir.Size) {
                
                UINT count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* typeOffset = reinterpret_cast<WORD*>(pReloc + 1);
                
                for (UINT i = 0; i < count; i++) {
                    if (reinterpret_cast<BYTE*>(typeOffset) + sizeof(WORD) > 
                        reinterpret_cast<BYTE*>(pAllocatedBase) + relocDir.VirtualAddress + relocDir.Size) {
                        break; // Evitar overflow
                    }

                    WORD type = (*typeOffset >> 12);
                    WORD offset = (*typeOffset & 0xFFF);
                    
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        // 32-bit
                        DWORD* pPatch = reinterpret_cast<DWORD*>(
                            reinterpret_cast<BYTE*>(pAllocatedBase) + pReloc->VirtualAddress + offset);
                        *pPatch += static_cast<DWORD>(delta);
                    }
#ifdef _WIN64
                    else if (type == IMAGE_REL_BASED_DIR64) {
                        // 64-bit
                        ULONGLONG* pPatch = reinterpret_cast<ULONGLONG*>(
                            reinterpret_cast<BYTE*>(pAllocatedBase) + pReloc->VirtualAddress + offset);
                        *pPatch += delta;
                    }
#endif
                    typeOffset++;
                }
                
                // Avanzar al siguiente bloque
                pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
            }
            std::cout << "[+] Relocalizaciones aplicadas correctamente" << std::endl;
        } else {
            std::cout << "[!] No hay tabla de relocalizaciones o está vacía" << std::endl;
        }
    } else {
        std::cout << "[+] No se necesitan relocalizaciones (delta = 0)" << std::endl;
    }

    // --- PASO 5: IMPORTACIONES ---
    IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0 && importDir.VirtualAddress > 0) {
        // Verificar que la tabla de imports esté dentro de la imagen
        if (importDir.VirtualAddress + importDir.Size > dwImageSize) {
            std::cerr << "[-] Error: Tabla de imports fuera de los límites" << std::endl;
            VirtualFree(pAllocatedBase, 0, MEM_RELEASE);
            return false;
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            reinterpret_cast<BYTE*>(pAllocatedBase) + importDir.VirtualAddress);
        
        while (pImportDesc->Name != 0) {
            // Verificar que el nombre esté dentro de los límites
            if (pImportDesc->Name >= dwImageSize) {
                std::cerr << "[-] Error: Nombre de DLL importada fuera de los límites" << std::endl;
                break;
            }

            char* szDllName = reinterpret_cast<char*>(
                reinterpret_cast<BYTE*>(pAllocatedBase) + pImportDesc->Name);
            
            HMODULE hModule = LoadLibraryA(szDllName);
            if (!hModule) {
                std::cerr << "[-] Error: No se pudo cargar '" << szDllName << "': " << GetLastError() << std::endl;
                pImportDesc++;
                continue;
            }

            // Procesar thunks
            PIMAGE_THUNK_DATA pThunk = nullptr;
            PIMAGE_THUNK_DATA pOrigThunk = nullptr;

            if (pImportDesc->OriginalFirstThunk) {
                pOrigThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                    reinterpret_cast<BYTE*>(pAllocatedBase) + pImportDesc->OriginalFirstThunk);
                pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                    reinterpret_cast<BYTE*>(pAllocatedBase) + pImportDesc->FirstThunk);
            } else {
                pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                    reinterpret_cast<BYTE*>(pAllocatedBase) + pImportDesc->FirstThunk);
                pOrigThunk = pThunk;
            }

            while (pOrigThunk->u1.AddressOfData != 0) {
                FARPROC pFuncAddr = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    // Importación por ordinal
                    pFuncAddr = GetProcAddress(hModule, 
                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(pOrigThunk->u1.Ordinal)));
                } else {
                    // Importación por nombre
                    PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        reinterpret_cast<BYTE*>(pAllocatedBase) + pOrigThunk->u1.AddressOfData);
                    
                    pFuncAddr = GetProcAddress(hModule, pImportByName->Name);
                }

                if (pFuncAddr) {
                    pThunk->u1.Function = reinterpret_cast<ULONGLONG>(pFuncAddr);
                } else {
                    std::cerr << "[-] Error: No se pudo resolver importación" << std::endl;
                }

                pThunk++;
                pOrigThunk++;
            }

            pImportDesc++;
        }
        std::cout << "[+] Importaciones resueltas correctamente" << std::endl;
    }

    // --- PASO 6: PROTECCIÓN DE MEMORIA ---
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
        // Saltar secciones vacías
        if (pSectionHeader->Misc.VirtualSize == 0) {
            continue;
        }

        LPVOID pSectionBase = reinterpret_cast<BYTE*>(pAllocatedBase) + pSectionHeader->VirtualAddress;
        DWORD dwOldProtect;
        DWORD dwNewProtect = 0;
        DWORD characteristics = pSectionHeader->Characteristics;

        // Determinar permisos basados en características de la sección
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                dwNewProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? 
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else {
                dwNewProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? 
                    PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
            }
        } else {
            if (characteristics & IMAGE_SCN_MEM_READ) {
                dwNewProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? 
                    PAGE_READWRITE : PAGE_READONLY;
            } else {
                dwNewProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? 
                    PAGE_WRITECOPY : PAGE_NOACCESS;
            }
        }

        if (!VirtualProtect(pSectionBase, pSectionHeader->Misc.VirtualSize, dwNewProtect, &dwOldProtect)) {
            std::cerr << "[-] Warning: No se pudo cambiar permisos para sección '" 
                      << pSectionHeader->Name << "': " << GetLastError() << std::endl;
        }
    }
    std::cout << "[+] Permisos de memoria aplicados" << std::endl;

    // --- PASO 7: EJECUTAR DLLMAIN ---
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        LPVOID pEntryPoint = reinterpret_cast<BYTE*>(pAllocatedBase) + 
                            pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        
        std::cout << "[+] Llamando a DllMain en 0x" << std::hex 
                  << reinterpret_cast<uintptr_t>(pEntryPoint) << std::dec << std::endl;
        
        DllEntryPoint DllMain = reinterpret_cast<DllEntryPoint>(pEntryPoint);
        BOOL success = DllMain(reinterpret_cast<HINSTANCE>(pAllocatedBase), 
                              DLL_PROCESS_ATTACH, nullptr);
        
        if (!success) {
            std::cerr << "[-] Warning: DllMain devolvió FALSE" << std::endl;
        } else {
            std::cout << "[+] DllMain ejecutado exitosamente" << std::endl;
        }
    } else {
        std::cout << "[+] DLL cargada (sin DllMain)" << std::endl;
    }

    return true;
}

int main() {
    std::cout << "=== Manual Mapping DLL Loader ===" << std::endl;
    
    const char* dllPath = "test.dll"; // Cambia por tu DLL
    BYTE* pDllBuffer = nullptr;
    DWORD dwFileSize = 0;

    // Cargar DLL desde archivo
    if (!LoadDLLFromFile(dllPath, &pDllBuffer, &dwFileSize)) {
        std::cerr << "[-] Error: No se pudo cargar el archivo DLL" << std::endl;
        return 1;
    }

    std::cout << "[+] DLL cargada, tamaño: " << dwFileSize << " bytes" << std::endl;

    // Realizar manual mapping
    if (ManualMap(pDllBuffer, dwFileSize)) {
        std::cout << "[+] Manual mapping completado exitosamente!" << std::endl;
    } else {
        std::cerr << "[-] Manual mapping falló" << std::endl;
    }

    // Limpiar
    delete[] pDllBuffer;
    
    std::cout << "Presiona Enter para salir...";
    std::cin.get();
    
    return 0;
}