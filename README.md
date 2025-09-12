# Proyecto de Investigación en Técnicas de Evasión de EDR

## 📌 Resumen Ejecutivo
Este proyecto se centra en la **investigación y aplicación de técnicas avanzadas** para evadir soluciones de seguridad de tipo **Endpoint Detection and Response (EDR)**.  
El objetivo es **educativo y defensivo**: comprender cómo los atacantes logran eludir la detección para luego **proponer estrategias de mitigación y detección más robustas**.  

A través del desarrollo de **Pruebas de Concepto (PoCs)**, se explorarán métodos como:
- Ofuscación de código  
- Cifrado de payloads  
- Inyección de procesos  
- Evasión de hooks de API  

Los resultados permitirán formular recomendaciones concretas para **equipos de seguridad (Blue Teams)**.

---

## 🎯 Objetivos del Proyecto
- Investigar el funcionamiento interno de soluciones EDR y sus mecanismos de detección (firmas, comportamiento y heurística).  
- Desarrollar payloads personalizados en **C/C++** y herramientas como **Metasploit**, aplicando técnicas de evasión.  
- Evaluar la efectividad de dichas técnicas frente a **Windows Defender** y **CrowdStrike** en entornos de laboratorio controlados.  
- Documentar resultados y proponer **contramedidas y reglas de detección** para Blue Teams.  

---

## 🛠️ Metodología y Fases
### Semana 1: Investigación y Fundamentos
- Arquitectura de los EDRs.  
- Análisis de técnicas de *hooking* en APIs de Windows (user-land).  
- Estudio de técnicas de evasión: **Process Hollowing**, **DLL Injection**, **cifrado de shellcode**, **syscalls directas**.  

### Semana 2: Desarrollo de Payloads y Ofuscación
- Creación de shellcodes con **Metasploit / Cobalt Strike**.  
- Implementación de PoCs en **C/C++**.  
- Uso de **ofuscadores (Obfuscator-LLVM)**.  

### Semana 3: Pruebas en Laboratorio
- Entornos con Windows 10/11 + Defender + CrowdStrike.  
- Ejecución de PoCs y registro sistemático de resultados.  
- Iteración sobre técnicas para mejorar la evasión.  

### Semana 4: Análisis y Documentación Final
- Identificación de técnicas más efectivas.  
- Redacción de informe final con **binarios, logs y recomendaciones defensivas**.  

---

## ⚗️ Pruebas de Concepto (PoC)

### PoC 1: Ejecución de Shellcode Ofuscado con Syscalls Directas
**Objetivo:** Evadir detección estática y hooks de API mediante:  
- 🔐 **Cifrado AES de shellcode**  
- 🔑 **Ofuscación XOR de clave**  
- 🔍 **Resolución dinámica de APIs**  
- ⚡ **Invocación directa de syscalls**  

**Flujo:**  
1. Deofuscación de clave AES en memoria.  
2. Descifrado de shellcode.  
3. Reserva de memoria con `NtAllocateVirtualMemory` vía syscall directa.  
4. Copia y ejecución del payload en memoria.  

---

### PoC 2: Process Hollowing con Unhooking
**Objetivo:** Inyectar payload en un proceso legítimo (ej. `notepad.exe`) eliminando los hooks de EDR.  

**Técnicas clave:**  
- 🧹 **Unhooking de ntdll.dll** (restauración de sección `.text`).  
- 👻 **Process Hollowing** con `NtUnmapViewOfSection`, `WriteProcessMemory` y manipulación de contexto de hilos.  

**Flujo:**  
1. Eliminación de hooks en `ntdll.dll`.  
2. Lanzamiento de proceso confiable suspendido.  
3. Desmapeo y reemplazo de memoria del proceso.  
4. Redirección del hilo principal al shellcode.  
5. Reanudación del proceso con el payload inyectado.  

---

## 🛡️ Recomendaciones Defensivas (Blue Team)

### Monitorización de Comportamiento
- Detectar procesos creados con **CREATE_SUSPENDED** en contextos sospechosos.  
- Monitorear **relaciones padre-hijo** inusuales.  
- Alertar ante llamadas a **NtUnmapViewOfSection**.  

### Análisis de Memoria y API
- Identificar **syscalls directas** fuera de módulos legítimos.  
- Escanear regiones **PAGE_EXECUTE_READWRITE** en procesos.  
- Verificar integridad de la sección `.text` en DLLs críticas.  

### Reglas de Detección (YARA/Sigma)
- Combinar llamadas sospechosas:  
  `CreateProcessA + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread`.  

---

## 📦 Entregables
- **Binarios PoCs**  
- **Logs de evasión** (detección o bypass en pruebas).  
- **Informe de recomendaciones defensivas**.  

---

## ⚠️ Disclaimer
Este proyecto tiene fines **puramente educativos y de investigación defensiva**.  
**No debe utilizarse con fines maliciosos.**  
El autor no se hace responsable del uso indebido de la información aquí contenida.  

---
