import times, strutils, winim

# Función para generar un nombre ofuscado (hash simple del tiempo actual)
proc generateObfuscatedName(): string =
  let now = times.now()
  let timestamp = now.toTime().toUnix() * 1000 + now.nanosecond div 1_000_000
  
  # Hash simple (solo para ejemplo; no criptográfico)
  result = "MUTEX_"
  for c in $timestamp:
    let digit = parseInt($c)
    result.add($( (digit + 7) mod 10 ))

proc main() =
  # 1. Genera un nombre ofuscado dinámicamente
  let mutexName = generateObfuscatedName()
  echo "[+] Mutex ofuscado creado: ", mutexName
  
  # 2. Crea o abre el mutex
  let hMutex = CreateMutexA(nil, TRUE, mutexName)
  
  if hMutex == 0:
    stderr.writeLine "[!] Error al crear el mutex."
    quit(1)
  
  # 3. Verifica si ya existe (ERROR_ALREADY_EXISTS)
  if GetLastError() == ERROR_ALREADY_EXISTS:
    echo "[!] Mutex ya existe. Saliendo..."
    CloseHandle(hMutex)
    quit(0)
  
  # 4. Sección crítica (simulación de operación maliciosa)
  echo "[*] Ejecutando operación protegida por mutex..."
  sleep(3000) # Simula trabajo
  
  # 5. Libera el mutex
  ReleaseMutex(hMutex)
  CloseHandle(hMutex)

when isMainModule:
  main()