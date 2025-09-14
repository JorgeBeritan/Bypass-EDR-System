# Summary of the Evolution of a Payload in PowerShell

This document summarizes the progression of a PowerShell script from a simple download tool to an advanced variant designed to evade system security. The goal is to illustrate common obfuscation and evasion techniques from an educational and defensive perspective. 🛡️

---

## 📜 Script 1: The Direct Downloader

This is the most basic form of the script. Its logic is clear and straightforward: connect to a URL, download a script, and execute it in memory.

- **Technique:** Direct use of `New-Object Net.WebClient` and `Invoke-Expression`.  
- **Vulnerability:** Easily detectable. Strings such as `Invoke-Expression` and suspicious URLs are immediate red flags for any antivirus or EDR. Additionally, its content is instantly blocked by AMSI (Antimalware Scan Interface) before execution.

---

## 🎭 Script 2: Basic Obfuscation

This version attempts to hide its true intention by breaking suspicious strings into smaller pieces.

- **Technique:** String concatenation. `"Invoke-Expression"` becomes `"Invoke" + "-Expression"` to evade simple static signatures that search for the full string.  
- **Vulnerability:** Ineffective against modern defenses. Although it may trick a very basic file scanner, PowerShell reconstructs the complete strings in memory before executing them. AMSI intercepts the already reconstructed string and blocks the payload without issues.

---

## 👻 Script 3: Advanced Evasion and AMSI Bypass

This is the most dangerous variant. Its main goal is not only to hide but to actively disable system defenses before executing.

- **Technique 1 (AMSI Bypass via Reflection):** Accesses internal PowerShell components to set the `amsiInitFailed` flag to `true`. This tricks the current PowerShell session into believing AMSI failed to start, effectively disabling it.  
- **Technique 2 (AMSI Bypass via Memory Patching):** Uses Windows API functions to locate the `AmsiScanBuffer` function in memory and overwrite its initial instructions. The patch forces the function to return an error immediately, neutralizing it without formally disabling it.  

**Result:** Once AMSI is out of play, the script downloads and executes the obfuscated payload in an unmonitored environment, drastically increasing its chances of success.

---

## 🏁 Conclusion

The evolution of these scripts demonstrates the classic "cat and mouse" game in cybersecurity. While attackers develop increasingly sophisticated methods to evade detection (such as memory patching), defenders create behavioral security tools (EDRs) that look for the evasion techniques themselves, rather than only relying on known malware signatures.
