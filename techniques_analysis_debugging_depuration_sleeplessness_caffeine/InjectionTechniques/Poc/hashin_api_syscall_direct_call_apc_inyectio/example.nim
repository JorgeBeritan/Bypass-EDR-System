import std/encodings
import winim

proc demoWideStrings() =
  # String normal UTF-8
  let normalStr = "Español: áéíóú ñandü"
  
  # Convertir a wide string
  let wideStr = convertToWideString(normalStr)
  echo "Longitud wide: ", len(wideStr)
  
  # Convertir de vuelta
  let backToNormal = convertToString(wideStr)
  echo "Texto original: ", backToNormal
  
  # Uso con Windows API
  MessageBoxW(0, newWideCString("Hola desde Nim"), newWideCString("Ejemplo"), 0)

when isMainModule:
  demoWideStrings()