# Resumen: Mecánica de los EDR (Endpoint Detection and Response)

## 1. Funcionamiento de Windows Defender y CrowdStrike

### Windows Defender (Ahora Microsoft Defender for Endpoint)
- **Enfoque integrado**: Viene preinstalado en Windows y utiliza servicios del sistema operativo como ETW (Event Tracing for Windows) y AMSI (Antimalware Scan Interface).
- **Componentes clave**:
    - **Antimalware Service**: Escaneo en tiempo real y basado en firmas.
    - **Cloud-Delivered Protection**: Análisis en la nube para detección de amenazas emergentes.
    - **EDR capabilities**: Recopila telemetría del endpoint para análisis posterior.
- **Arquitectura**: Agente ligero que se aprovecha de la infraestructura de Microsoft.

### CrowdStrike Falcon
- **Enfoque basado en agente**: Un agiente ligero (`falcon-sensor`) que se instala en el endpoint.
- **Funcionamiento**:
    - **Kernel-Level Driver**: Monitorea la actividad del sistema a nivel de kernel usando hooks.
    - **Streaming de eventos**: Envía telemetría en tiempo real a la nube de CrowdStrike para su análisis.
    - **Inteligencia Artificial**: Usa modelos de ML para detectar comportamientos maliciosos.
- **Arquitectura**: Cloud-native, con análisis centralizado en la plataforma Falcon.

---

## 2. Diagrama de Arquitectura EDR

[Endpoint] → [Hooks (Kernel/Userland)] → [Recolección de Telemetría] → [Análisis Local/Cloud] → [Respuesta]

### Componentes:
- **Hooks**: 
    - Interceptan llamadas al sistema (syscalls), API de usuario, o actividades del kernel.
    - Ejemplo: CrowdStrike usa un driver en kernel mode para monitorizar.
- **Telemetría**: 
    - Datos recolectados: procesos, red, registros, archivos, etc.
    - Se envía a un backend para su análisis (ej: via ETW en Defender).
- **Análisis de Comportamiento**:
    - Motor de reglas y ML para detectar patrones sospechosos (ej: ejecución de PowerShell ofuscado).

---

## 3. Puntos Débiles Identificados

1. **Bypass de Hooks**:
    - Técnicas como Direct System Calls evitan los hooks en userland.
    - Modificación de tablas de syscalls (SSDT) en kernel.

2. **Telemetría Insuficiente o Manipulable**:
    - Los atacantes pueden borrar logs o manipular eventos (ej: usando herramientas como WevtUtil).
    - Limitaciones en la captura de datos en tiempo real (overhead).

3. **Dependencia del Análisis en la Nube**:
    - Si el endpoint pierde conexión, la detección en tiempo real se reduce.
    - Latencia en la respuesta.

4. **Técnicas de Ofuscación**:
    - Scripts ofuscados (ej: PowerShell) pueden evadir detecciones estáticas.
    - Living Off the Land (LOLBins): uso de herramientas legítimas del sistema.

5. **Privilege Escalation/Abuso de Permisos**:
    - Si el agente EDR se ejecuta con privilegios insuficientes, puede ser eludido.
    - Exploits contra el propio agente EDR (ej: vulnerabilidades en drivers).

6. **Falsos Positivos**:
    - El análisis heurístico/ML puede generar alertas falsas, consumiendo recursos de investigación.