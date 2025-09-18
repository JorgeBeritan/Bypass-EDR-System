#include <iostream>
#include <windows.h>

int main(){
    std::cout << "[INFO] Intentando reservar memoria con permisos de ejecucion" << std::endl;

    void *mem;

    mem = VirtualAlloc(
        NULL,
        1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (mem == NULL){
        std::cout << "[ERROR] Fallo al reservar memoria" << std::endl;
        return 1;
    }

    std::cout << "[SUCCESS] Memoria reservada exitosamente en la direccion: " << mem << std::endl;

    VirtualFree(mem, 0, MEM_RELEASE);

    std::cout << "[INFO] Se libero la memoria" << std::endl;

    return 0;
}