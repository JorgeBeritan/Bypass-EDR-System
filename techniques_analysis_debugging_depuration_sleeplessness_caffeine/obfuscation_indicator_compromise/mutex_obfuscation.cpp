#include <iostream>
#include <windows.h> // Para mutex en Windows
#include <chrono>
#include <string>

// Función para generar un nombre ofuscado (hash simple del tiempo actual)
std::string generateObfuscatedName() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    // Hash simple (solo para ejemplo; no criptográfico)
    std::string name = "MUTEX_";
    for (char c : std::to_string(timestamp)) {
        name += std::to_string((c + 7) % 10); // Transforma cada dígito
    }
    return name;
}

int main() {
    // 1. Genera un nombre ofuscado dinámicamente
    std::string mutexName = generateObfuscatedName();
    std::cout << "[+] Mutex ofuscado creado: " << mutexName << std::endl;

    // 2. Crea o abre el mutex
    HANDLE hMutex = CreateMutexA(NULL, TRUE, mutexName.c_str());
    
    if (hMutex == NULL) {
        std::cerr << "[!] Error al crear el mutex." << std::endl;
        return 1;
    }

    // 3. Verifica si ya existe (ERROR_ALREADY_EXISTS)
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[!] Mutex ya existe. Saliendo..." << std::endl;
        CloseHandle(hMutex);
        return 0;
    }

    // 4. Sección crítica (simulación de operación maliciosa)
    std::cout << "[*] Ejecutando operación protegida por mutex..." << std::endl;
    Sleep(3000); // Simula trabajo

    // 5. Libera el mutex
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}