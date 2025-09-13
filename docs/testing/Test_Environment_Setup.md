# Test Environment Configuration

This document details the configuration of the virtual machines (VMs) used for the test environment, as well as the monitoring tools installed.

---

## Detailed VM Configuration

### Operating System
- **Edition**: Windows 10 Pro  
- **Version**: 22H2  
- **OS Build**: 19045  

The Windows 10 22H2 release is a quality and security-focused update, including all cumulative updates from version 21H2.  
This ensures a stable and up-to-date operating system for analysis.

---

### Security: Windows Defender
Windows Defender is integrated into the operating system and is the main configured security tool.

- **Real-Time Protection**: Enabled. Continuously monitors activity for malware.  
- **Cloud-Based Protection**: Enabled. Provides faster detection of new and emerging threats.  
- **Tamper Protection**: Enabled. Prevents malicious or unauthorized applications from altering important security settings.  
- **Windows Defender Firewall**: Enabled and configured with default rules for both private and public network profiles.  
- **Vulnerable Driver Blocking**: A key security feature in version 22H2 that prevents the installation of drivers with known vulnerabilities.  
- **App & Browser Control**: Enabled to protect against malicious websites, downloads, and unwanted applications.  

---

## Installed Monitoring Tools

To observe and analyze system behavior, the following monitoring tools were installed:

### 1. Process Monitor (ProcMon)
- **Description**: An advanced Sysinternals suite tool that displays real-time file system, Registry, and process/thread activity.  
- **Primary Use**: Essential for analyzing how applications interact with the operating system, what files they access, and which Registry keys they read or write.  

### 2. Resource Monitor (Resmon)
- **Description**: A native Windows tool providing a detailed real-time view of hardware (CPU, memory, disk, and network) and software resource usage.  
- **Primary Use**: Identifies processes consuming anomalous amounts of resources, which may indicate malicious activity or performance issues.  

---
