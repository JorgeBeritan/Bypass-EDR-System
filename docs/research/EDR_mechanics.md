# Summary: Mechanics of EDR (Endpoint Detection and Response)

## 1. Operation of Windows Defender and CrowdStrike

### Windows Defender (Now Microsoft Defender for Endpoint)
- **Integrated approach**: Preinstalled on Windows and leverages OS services such as ETW (Event Tracing for Windows) and AMSI (Antimalware Scan Interface).
- **Key components**:
    - **Antimalware Service**: Real-time and signature-based scanning.
    - **Cloud-Delivered Protection**: Cloud-based analysis for emerging threats.
    - **EDR capabilities**: Collects endpoint telemetry for further analysis.
- **Architecture**: Lightweight agent leveraging Microsoft’s infrastructure.

### CrowdStrike Falcon
- **Agent-based approach**: A lightweight agent (`falcon-sensor`) installed on the endpoint.
- **Operation**:
    - **Kernel-Level Driver**: Monitors system activity at the kernel level using hooks.
    - **Event streaming**: Sends real-time telemetry to CrowdStrike’s cloud for analysis.
    - **Artificial Intelligence**: Uses ML models to detect malicious behaviors.
- **Architecture**: Cloud-native, with centralized analysis in the Falcon platform.

---

## 2. EDR Architecture Diagram
[Endpoint] → [Hooks (Kernel/Userland)] → [Telemetry Collection] → [Local/Cloud Analysis] → [Response]

### Components:
- **Hooks**:  
    - Intercept system calls (syscalls), userland APIs, or kernel activities.  
    - Example: CrowdStrike uses a kernel-mode driver for monitoring.  
- **Telemetry**:  
    - Collected data: processes, network, logs, files, etc.  
    - Sent to a backend for analysis (e.g., via ETW in Defender).  
- **Behavior Analysis**:  
    - Rules engine and ML to detect suspicious patterns (e.g., execution of obfuscated PowerShell).  

---

## 3. Identified Weaknesses

1. **Hook Bypass**:
    - Techniques such as Direct System Calls avoid userland hooks.  
    - Modification of syscall tables (SSDT) at the kernel level.  

2. **Insufficient or Manipulable Telemetry**:
    - Attackers may delete logs or tamper with events (e.g., using tools like WevtUtil).  
    - Limitations in real-time data capture due to overhead.  

3. **Dependence on Cloud Analysis**:
    - If the endpoint loses connectivity, real-time detection is reduced.  
    - Response latency issues.  

4. **Obfuscation Techniques**:
    - Obfuscated scripts (e.g., PowerShell) can bypass static detections.  
    - Living Off the Land (LOLBins): using legitimate system tools.  

5. **Privilege Escalation/Permission Abuse**:
    - If the EDR agent runs with insufficient privileges, it may be bypassed.  
    - Exploits targeting the EDR agent itself (e.g., driver vulnerabilities).  

6. **False Positives**:
    - Heuristic/ML-based analysis may generate false alerts, consuming investigation resources.  
