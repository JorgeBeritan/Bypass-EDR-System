# Testing Methodology: EDR Evasion Validation

This document describes the procedure for validating the effectiveness of malware Proofs of Concept (POCs), with the primary objective of successfully evading Endpoint Detection and Response (EDR) solutions.

---

## Standardized Testing Procedure

A rigorous process is maintained to ensure that evasion results are consistent and reproducible.

### Environment Preparation
- The standardized **Windows 10 (22H2) + Defender VM** is used as the target.  
- Monitoring tools (**Process Monitor, Wireshark, Sysmon**) are verified to be active in order to perform forensic analysis afterward and understand why the POC succeeded or failed.  
- A clean **snapshot of the VM** is created. Reverting to this state after each test is crucial to avoid contaminating results.  

### POC Preparation
- The latest version of the malware POC is compiled.  
- Its **SHA-256 hash** and the **specific evasion technique** being tested (e.g., "Thread Injection," "DLL Unhooking") are documented.  

### POC Deployment
- Data captures are started across all monitoring tools.  
- The POC is executed on the target VM.  
- The POC is allowed to operate, attempting to complete its attack chain (e.g., establishing persistence, initiating C2 communication).  

### Intelligence Collection & Analysis
- The test is stopped, and all logs are saved regardless of the outcome.  
- The EDR console is analyzed to check for any alerts.  
- The VM is reverted to the clean snapshot.  

---

## Evaluation Criteria (Evasion Perspective)

Each test result is classified based on the success of the malware:

### 🏆 Success (Complete Evasion)
The POC executes, completes all its objectives (payload, persistence, etc.), and the EDR generates **no alerts**.  
The operation is completely invisible to the security solution.  
*This is the primary goal.*

### ⚠️ Partial Success (Successful Execution with Delayed Detection)
The POC executes its main payload (e.g., exfiltrates a file, obtains a shell), but the EDR raises an alert during or after the action.  
Although discovered, the primary objective was achieved.  

### 📉 Failure (Detected & Blocked)
The EDR detects and terminates the POC process before it can achieve its main objective.  
The evasion technique was not effective.  

---

## Quantitative Evasion Metrics

To objectively measure the effectiveness of our techniques, we use the following metrics:

### Evasion Rate (ER)
- **Description**: Percentage of tests where the POC achieved Complete Evasion.  
This is the most important **Key Performance Indicator (KPI)** of the project.  

- **Formula**:  
\[
ER(%) = \left(\frac{\text{Number of Complete Evasions}}{\text{Total Number of Tests}}\right) \times 100
\]

---

### Successful Execution Rate (SER)
- **Description**: Percentage of tests where the malware achieved its main objective, including both Complete Evasions and Partial Successes.  
Measures the actual impact capability.  

- **Formula**:  
\[
SER(%) = \left(\frac{\text{Number of Complete Evasions + Number of Partial Successes}}{\text{Total Number of Tests}}\right) \times 100
\]

---

### Mean Time to Detection (MTTD)
- **Description**: For "Partial Success" cases, this measures the average time the POC was able to operate before being detected.  
A higher MTTD is better, as it provides a larger window of opportunity.  

- **Formula**:  
\[
MTTD = \frac{\sum(\text{Operation Times before Alert})}{\text{Number of Partial Successes}}
\]

---
