# Análisis de Herramientas para la Evasión de EDR en un Entorno de Red Team

Este documento detalla la evaluación y configuración recomendada de herramientas clave para el análisis en un proyecto de Red Team enfocado en la evasión de Endpoint Detection and Response (EDR).  

Las herramientas seleccionadas —**Sysinternals**, **Ghidra** y **Wireshark**— son fundamentales para comprender cómo el malware interactúa con el sistema operativo, su estructura interna y sus comunicaciones de red, permitiendo así desarrollar y probar técnicas de evasión efectivas.

---

## 📌 Evaluación de Herramientas

### 🔹 Sysinternals Suite
La suite de Sysinternals, un conjunto de utilidades de diagnóstico y solución de problemas para Windows, es indispensable para el análisis dinámico del comportamiento de un sistema.  

**Herramientas destacadas:**
- **Process Explorer**: Vista detallada de procesos en ejecución, hilos, DLLs y objetos abiertos. Crucial para detectar inyecciones y suplantación de procesos.  
- **Process Monitor (Procmon)**: Registro en tiempo real de sistema de archivos, registro y procesos. Útil para analizar persistencia, configuraciones de seguridad y manipulación de componentes monitoreados por EDR.  
- **Autoruns**: Lista de puntos de inicio automático del sistema. Permite detectar mecanismos de persistencia.  
- **TCPView**: Muestra conexiones TCP/UDP activas, útil para identificar comunicaciones de red sospechosas.  

---

### 🔹 Ghidra
Herramienta de ingeniería inversa de código abierto desarrollada por la NSA, usada para análisis estático de malware.  

**Características principales:**
- **Desensamblador y Descompilador**: Convierte binarios a pseudocódigo en C para facilitar la comprensión.  
- **Análisis de funciones y flujos de ejecución**: Identificación de llamadas a APIs sospechosas y visualización de diagramas de flujo.  
- **Búsqueda de cadenas y patrones**: Localización de IoCs (IPs, dominios, nombres de archivos, claves de registro).  
- **Soporte de scripts**: Automatización en **Java** o **Python** para detección de patrones de evasión.  

---

### 🔹 Wireshark
Analizador de protocolos de red esencial para estudiar tráfico generado por malware.  

**Capacidades clave:**
- **Captura y filtrado de paquetes**: Aislamiento de tráfico malicioso con filtros avanzados.  
- **Análisis de protocolos**: Soporte de una gran variedad de protocolos, incluso personalizados.  
- **Seguimiento de flujos TCP/UDP**: Reconstrucción de conversaciones con servidores C2.  
- **Detección de tráfico cifrado**: Análisis de metadatos de conexiones TLS/SSL para detectar anomalías.  

---

## ⚙️ Configuración Recomendada para Análisis

### Sysinternals
- Ejecutar como **Administrador**.  
- Configurar **Filtros en Procmon** por nombre o PID del malware.  
- Usar **símbolos de depuración** desde servidores de Microsoft.  
- Habilitar **verificación de firmas digitales** en Process Explorer y Autoruns.  

### Ghidra
- Usar en un **entorno aislado** (máquina virtual).  
- Permitir **análisis automático inicial**.  
- Explorar **scripts de la comunidad** para detectar cifrado, ofuscación, etc.  
- Sincronizar con un **depurador** como *x64dbg* para combinar análisis estático y dinámico.  

### Wireshark
- Habilitar **modo promiscuo** para capturar todo el tráfico local.  
- Aplicar **filtros de captura** (ejemplo: `host 192.168.1.100`).  
- Usar **filtros de visualización** como:  
  - `ip.addr == <IP_del_C2>`  
  - `dns.qry.name contains "maliciousdomain.com"`  
  - `http.request`  
  - `!arp && !dns && !icmp`  
- Habilitar **resolución de nombres** para identificar servicios.  
- Crear **perfiles de configuración** (ej. HTTP, DNS, tráfico C2).  

---

## ✅ Conclusión
El uso combinado de **Sysinternals**, **Ghidra** y **Wireshark** permite un análisis integral de malware en entornos de Red Team, facilitando la identificación de técnicas de evasión de EDR a nivel de sistema, código y red.

