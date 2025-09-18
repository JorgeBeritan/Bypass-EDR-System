import std/[os, strutils, math, bitops]
import winim/lean

type
  DllEntryProc = proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall.}

  ManualMappingContext = object
    imageBase: pointer
    imageSize: int
    ntHeaders: ptr IMAGE_NT_HEADERS
    is64Bit: bool

proc loadFile(filename: string): tuple[buffer: seq[byte], size: int] =
  ## Carga un archivo completo en memoria
  var file: File
  if not open(file, filename):
    raise newException(IOError, "No se pudo abrir el archivo: " & filename)
  
  let size = getFileSize(file)
  var buffer = newSeq[byte](size)
  
  if readBytes(file, buffer, 0, size) != size:
    close(file)
    raise newException(IOError, "Error al leer el archivo: " & filename)
  
  close(file)
  return (buffer, size)

proc validatePeHeaders(buffer: seq[byte]): ManualMappingContext =
  ## Valida los headers PE y retorna información del contexto
  if buffer.len < sizeof(IMAGE_DOS_HEADER):
    raise newException(ValueError, "Buffer demasiado pequeño para headers DOS")
  
  let dosHeader = cast[ptr IMAGE_DOS_HEADER](unsafeAddr buffer[0])
  if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    raise newException(ValueError, "Firma DOS inválida")
  
  if dosHeader.e_lfanew < 0 or dosHeader.e_lfanew > buffer.len - sizeof(IMAGE_NT_HEADERS):
    raise newException(ValueError, "Offset NT headers inválido")
  
  let ntHeaders = cast[ptr IMAGE_NT_HEADERS](cast[uint](unsafeAddr buffer[0]) + dosHeader.e_lfanew.uint)
  if ntHeaders.Signature != IMAGE_NT_SIGNATURE:
    raise newException(ValueError, "Firma NT inválida")
  
  let is64Bit = ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
  
  when defined(cpu64):
    if not is64Bit:
      raise newException(ValueError, "DLL de 32 bits en proceso de 64 bits")
  else:
    if is64Bit:
      raise newException(ValueError, "DLL de 64 bits en proceso de 32 bits")
  
  result.imageSize = ntHeaders.OptionalHeader.SizeOfImage
  result.ntHeaders = ntHeaders
  result.is64Bit = is64Bit

proc allocateMemory(imageSize: int, preferredBase: pointer): pointer =
  ## Asigna memoria para la imagen PE
  result = VirtualAlloc(preferredBase, imageSize, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if result == nil:
    result = VirtualAlloc(nil, imageSize, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if result == nil:
      raise newException(OSError, "VirtualAlloc falló: " & $GetLastError())

proc copyHeadersAndSections(buffer: seq[byte], ctx: var ManualMappingContext, allocatedBase: pointer) =
  ## Copia headers y secciones a la memoria asignada
  # Copiar headers
  let sizeOfHeaders = ctx.ntHeaders.OptionalHeader.SizeOfHeaders
  if sizeOfHeaders > buffer.len:
    raise newException(ValueError, "SizeOfHeaders mayor que tamaño del buffer")
  
  copyMem(allocatedBase, unsafeAddr buffer[0], sizeOfHeaders)
  
  # Obtener primera sección
  var sectionHeader: ptr IMAGE_SECTION_HEADER
  if ctx.is64Bit:
    let ntHeaders64 = cast[ptr IMAGE_NT_HEADERS64](ctx.ntHeaders)
    sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](ntHeaders64) + sizeof(IMAGE_NT_HEADERS64).uint)
  else:
    let ntHeaders32 = cast[ptr IMAGE_NT_HEADERS32](ctx.ntHeaders)
    sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](ntHeaders32) + sizeof(IMAGE_NT_HEADERS32).uint)
  
  # Copiar secciones
  for i in 0..<ctx.ntHeaders.FileHeader.NumberOfSections.int:
    if sectionHeader.VirtualAddress == 0 and sectionHeader.SizeOfRawData == 0:
      sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](sectionHeader) + sizeof(IMAGE_SECTION_HEADER).uint)
      continue
    
    # Verificar límites
    if sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData > buffer.len:
      raise newException(ValueError, "Sección fuera de los límites del buffer")
    
    if sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize > ctx.imageSize:
      raise newException(ValueError, "Sección fuera de los límites de la imagen")
    
    let sectionDest = cast[pointer](cast[uint](allocatedBase) + sectionHeader.VirtualAddress.uint)
    let sectionSrc = cast[pointer](cast[uint](unsafeAddr buffer[0]) + sectionHeader.PointerToRawData.uint)
    
    # Copiar datos de la sección
    if sectionHeader.SizeOfRawData > 0:
      copyMem(sectionDest, sectionSrc, sectionHeader.SizeOfRawData)
    
    # Rellenar con ceros si es necesario
    if sectionHeader.Misc.VirtualSize > sectionHeader.SizeOfRawData:
      let zeroSize = sectionHeader.Misc.VirtualSize - sectionHeader.SizeOfRawData
      zeroMem(cast[pointer](cast[uint](sectionDest) + sectionHeader.SizeOfRawData.uint), zeroSize)
    
    sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](sectionHeader) + sizeof(IMAGE_SECTION_HEADER).uint)

proc applyRelocations(ctx: ManualMappingContext, allocatedBase: pointer) =
  ## Aplica relocalizaciones si es necesario
  let delta = cast[int](allocatedBase) - ctx.ntHeaders.OptionalHeader.ImageBase
  
  if delta == 0:
    echo "[+] No se necesitan relocalizaciones"
    return
  
  echo "[+] Aplicando relocalizaciones, delta: 0x", toHex(delta)
  
  let relocDir = ctx.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
  if relocDir.Size == 0 or relocDir.VirtualAddress == 0:
    echo "[!] No hay tabla de relocalizaciones"
    return
  
  if relocDir.VirtualAddress + relocDir.Size > ctx.imageSize:
    raise newException(ValueError, "Tabla de relocalizaciones fuera de límites")
  
  var pReloc = cast[ptr IMAGE_BASE_RELOCATION](cast[uint](allocatedBase) + relocDir.VirtualAddress.uint)
  
  while pReloc.VirtualAddress != 0 and
        cast[uint](pReloc) < cast[uint](allocatedBase) + relocDir.VirtualAddress.uint + relocDir.Size.uint:
    
    let count = (pReloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) div sizeof(WORD)
    var typeOffset = cast[ptr WORD](cast[uint](pReloc) + sizeof(IMAGE_BASE_RELOCATION).uint)
    
    for i in 0..<count:
      let typeVal = typeOffset[] shr 12
      let offset = typeOffset[] and 0xFFF
      
      let patchAddr = cast[uint](allocatedBase) + pReloc.VirtualAddress.uint + offset.uint
      
      if ctx.is64Bit and typeVal == IMAGE_REL_BASED_DIR64:
        let patch = cast[ptr uint64](patchAddr)
        patch[] = patch[] + delta.uint64
      elif not ctx.is64Bit and typeVal == IMAGE_REL_BASED_HIGHLOW:
        let patch = cast[ptr uint32](patchAddr)
        patch[] = patch[] + delta.uint32
      
      typeOffset = cast[ptr WORD](cast[uint](typeOffset) + sizeof(WORD).uint)
    
    pReloc = cast[ptr IMAGE_BASE_RELOCATION](cast[uint](pReloc) + pReloc.SizeOfBlock.uint)

proc resolveImports(ctx: ManualMappingContext, allocatedBase: pointer) =
  ## Resuelve las importaciones de la DLL
  let importDir = ctx.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  if importDir.Size == 0 or importDir.VirtualAddress == 0:
    echo "[+] No hay importaciones que resolver"
    return
  
  if importDir.VirtualAddress + importDir.Size > ctx.imageSize:
    raise newException(ValueError, "Tabla de imports fuera de límites")
  
  var pImportDesc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](cast[uint](allocatedBase) + importDir.VirtualAddress.uint)
  
  while pImportDesc.Name != 0:
    if pImportDesc.Name >= ctx.imageSize:
      raise newException(ValueError, "Nombre de DLL importada fuera de límites")
    
    let dllName = cast[cstring](cast[uint](allocatedBase) + pImportDesc.Name.uint)
    let hModule = LoadLibraryA(dllName)
    
    if hModule == 0:
      raise newException(OSError, "No se pudo cargar DLL: " & $dllName & ", error: " & $GetLastError())
    
    var pThunk: pointer
    var pOrigThunk: pointer
    
    if pImportDesc.Characteristics != 0:
      pOrigThunk = cast[pointer](cast[uint](allocatedBase) + pImportDesc.Characteristics.uint)
      pThunk = cast[pointer](cast[uint](allocatedBase) + pImportDesc.FirstThunk.uint)
    else:
      pThunk = cast[pointer](cast[uint](allocatedBase) + pImportDesc.FirstThunk.uint)
      pOrigThunk = pThunk
    
    var thunk = cast[ptr IMAGE_THUNK_DATA](pThunk)
    var origThunk = cast[ptr IMAGE_THUNK_DATA](pOrigThunk)
    
    while origThunk.u1.AddressOfData != 0:
      var procAddr: pointer
      
      if (origThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG) != 0:
        let ordinal = origThunk.u1.Ordinal and 0xFFFF
        procAddr = GetProcAddress(hModule, cast[LPCSTR](ordinal))
      else:
        let importByName = cast[ptr IMAGE_IMPORT_BY_NAME](
          cast[uint](allocatedBase) + origThunk.u1.AddressOfData.uint)
        procAddr = GetProcAddress(hModule, importByName.Name)
      
      if procAddr == nil:
        raise newException(OSError, "No se pudo resolver importación")
      
      thunk.u1.Function = cast[ULONGLONG](procAddr)
      
      inc thunk
      inc origThunk
    
    inc pImportDesc
  
  echo "[+] Importaciones resueltas correctamente"

proc setMemoryProtections(ctx: ManualMappingContext, allocatedBase: pointer) =
  ## Aplica los permisos de memoria correctos a las secciones
  var sectionHeader: ptr IMAGE_SECTION_HEADER
  
  if ctx.is64Bit:
    let ntHeaders64 = cast[ptr IMAGE_NT_HEADERS64](ctx.ntHeaders)
    sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](ntHeaders64) + sizeof(IMAGE_NT_HEADERS64).uint)
  else:
    let ntHeaders32 = cast[ptr IMAGE_NT_HEADERS32](ctx.ntHeaders)
    sectionHeader = cast[ptr IMAGE_SECTION_HEADER](cast[uint](ntHeaders32) + sizeof(IMAGE_NT_HEADERS32).uint)
  
  for i in 0..<ctx.ntHeaders.FileHeader.NumberOfSections:
    if sectionHeader.Misc.VirtualSize == 0:
      inc sectionHeader
      continue
    
    let sectionBase = cast[pointer](cast[uint](allocatedBase) + sectionHeader.VirtualAddress.uint)
    var oldProtect: DWORD
    var newProtect: DWORD
    
    let characteristics = sectionHeader.Characteristics
    
    if (characteristics and IMAGE_SCN_MEM_EXECUTE) != 0:
      if (characteristics and IMAGE_SCN_MEM_READ) != 0:
        newProtect = if (characteristics and IMAGE_SCN_MEM_WRITE) != 0: 
          PAGE_EXECUTE_READWRITE else: PAGE_EXECUTE_READ
      else:
        newProtect = if (characteristics and IMAGE_SCN_MEM_WRITE) != 0: 
          PAGE_EXECUTE_WRITECOPY else: PAGE_EXECUTE
    else:
      if (characteristics and IMAGE_SCN_MEM_READ) != 0:
        newProtect = if (characteristics and IMAGE_SCN_MEM_WRITE) != 0: 
          PAGE_READWRITE else: PAGE_READONLY
      else:
        newProtect = if (characteristics and IMAGE_SCN_MEM_WRITE) != 0: 
          PAGE_WRITECOPY else: PAGE_NOACCESS
    
    if VirtualProtect(sectionBase, sectionHeader.Misc.VirtualSize, newProtect, addr oldProtect) == 0:
      echo "[!] Warning: No se pudieron cambiar permisos para sección: error ", GetLastError()
    
    inc sectionHeader
  
  echo "[+] Permisos de memoria aplicados"

proc callDllMain(ctx: ManualMappingContext, allocatedBase: pointer): bool =
  ## Llama a DllMain de la DLL
  if ctx.ntHeaders.OptionalHeader.AddressOfEntryPoint == 0:
    echo "[+] DLL cargada (sin DllMain)"
    return true
  
  let entryPoint = cast[pointer](cast[uint](allocatedBase) + 
                 ctx.ntHeaders.OptionalHeader.AddressOfEntryPoint.uint)
  
  echo "[+] Llamando a DllMain en: 0x", toHex(cast[int](entryPoint))
  
  let dllMain = cast[DllEntryProc](entryPoint)
  let success = dllMain(cast[HINSTANCE](allocatedBase), DLL_PROCESS_ATTACH, nil)
  
  if success == 0:
    echo "[-] Warning: DllMain devolvió FALSE"
  else:
    echo "[+] DllMain ejecutado exitosamente"
  
  return success != 0

proc manualMap(filename: string): bool =
  ## Función principal de manual mapping
  echo "=== Manual Mapping en Nim ==="
  
  try:
    # Cargar archivo
    let (buffer, size) = loadFile(filename)
    echo "[+] DLL cargada, tamaño: ", size, " bytes"
    
    # Validar headers PE
    var ctx = validatePeHeaders(buffer)
    echo "[+] Arquitectura: ", if ctx.is64Bit: "x64" else: "x86"
    echo "[+] Tamaño de imagen: ", ctx.imageSize, " bytes"
    echo "[+] Base preferida: 0x", toHex(ctx.ntHeaders.OptionalHeader.ImageBase)
    
    # Asignar memoria
    let preferredBase = cast[pointer](ctx.ntHeaders.OptionalHeader.ImageBase)
    let allocatedBase = allocateMemory(ctx.imageSize, preferredBase)
    ctx.imageBase = allocatedBase
    echo "[+] Memoria asignada en: 0x", toHex(cast[int](allocatedBase))
    
    # Copiar headers y secciones
    copyHeadersAndSections(buffer, ctx, allocatedBase)
    echo "[+] Headers y secciones copiados"
    
    # Aplicar relocalizaciones
    applyRelocations(ctx, allocatedBase)
    
    # Resolver importaciones
    resolveImports(ctx, allocatedBase)
    
    # Aplicar protecciones de memoria
    setMemoryProtections(ctx, allocatedBase)
    
    # Llamar a DllMain
    result = callDllMain(ctx, allocatedBase)
    
    if result:
      echo "[+] Manual mapping completado exitosamente!"
    else:
      echo "[-] Manual mapping falló en DllMain"
    
  except Exception as e:
    echo "[-] Error: ", e.msg
    result = false

when isMainModule:
  let dllPath = "test.dll"  # Cambia por tu DLL
  
  if manualMap(dllPath):
    echo "Presiona Enter para salir..."
    discard stdin.readLine()
  else:
    echo "Falló el manual mapping"
    quit(1)