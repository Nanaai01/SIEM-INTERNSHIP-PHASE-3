Here's a sample `README.md` post for **Phase 3** of your repository, written professionally and clearly for documentation on advanced attack scenarios:

---

# 📁 Phase 3: Realistic & Critical Attack Scenarios

This phase simulates advanced threat scenarios that reflect real-world attack techniques commonly used by sophisticated adversaries. Each scenario is designed to test detection and monitoring capabilities in a realistic lab environment using Splunk, Sysmon, and related telemetry sources.

---

## 🧠 Objectives

* Emulate advanced adversarial techniques across multiple phases of the attack lifecycle (Initial Access, Execution, Persistence, Lateral Movement, and Exfiltration).
* Generate telemetry data to evaluate and improve detection rules in Splunk.
* Validate end-to-end visibility, including host-based logging (Sysmon/Event Logs), network telemetry, and Splunk correlation searches.

---

## 🔬 Attack Scenarios

### 1. **Fileless Malware with PowerShell**

* **Vector:** Spear-phishing with a macro-enabled document.
* **Execution:** Malicious PowerShell payload executed in-memory.
* **Detection Focus:**

  * `powershell.exe` spawning unusual child processes.
  * Base64-encoded PowerShell commands.
  * AMSI bypass or suspicious network connections from PowerShell.

### 2. **Lateral Movement via RDP Brute Force**

* **Vector:** Stolen low-privilege credentials.
* **Execution:** Automated brute-force attempts over RDP to internal servers.
* **Detection Focus:**

  * Multiple failed RDP login attempts from a single source.
  * Successful RDP logins followed by privilege escalation or unusual process creation.

### 3. **Persistence via Registry Run Keys**

* **Vector:** Script-based malware establishing persistence.
* **Execution:** Registry key modification to maintain access.
* **Detection Focus:**

  * Changes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
  * Suspicious file paths or encoded scripts set to auto-start.

### 4. **DNS Tunneling for Data Exfiltration**

* **Vector:** DNS protocol abuse for covert data exfiltration.
* **Execution:** Exfiltration of sensitive data via encoded subdomain queries.
* **Detection Focus:**

  * High volume of unusual DNS queries.
  * Long or random subdomain strings (e.g. base32/base64).
  * DNS queries to uncommon or suspicious domains.

### 5. **Credential Dumping and Exfiltration**

* **Vector:** Local privilege escalation or post-compromise activity.
* **Execution:** Use of Mimikatz to dump credentials from `LSASS`, followed by exfiltration over HTTPS.
* **Detection Focus:**

  * Memory access to `lsass.exe`.
  * Execution of known tools like `mimikatz.exe`, `procdump.exe`.
  * Suspicious HTTPS traffic immediately following credential dumping.

---

## 🛠️ Tools Used

* PowerShell
* Mimikatz
* Custom scripts (registry persistence, DNS tunneling)
* RDP brute-force scripts
* Wireshark / Sysmon / Event Viewer for monitoring
* Splunk for log aggregation and analysis

---

## 📌 Goals for Phase 3

* Test and refine Splunk detection rules and dashboards.
* Create YARA or Sigma rules (where applicable) based on generated IOCs.
* Validate end-to-end detection pipeline: from attack simulation → telemetry → Splunk → alerting.

---

## 📂 Folder Structure

```
phase-3/
├── powershell-fileless/
├── rdp-brute-force/
├── registry-persistence/
├── dns-tunneling/
├── credential-dumping/
└── logs-and-iocs/
```

Each folder contains:

* Attack script(s)
* Relevant logs (Sysmon, Event logs)
* Splunk query examples
* Indicators of Compromise (IOCs)

---

## 📈 Next Steps

* Document detection coverage gaps.
* Implement Splunk correlation searches.
* Update Phase 3 with any improved detection techniques or rule tuning.

---

### Response to Interview Questions
---

### 1. **How can you detect fileless malware with Sysmon or Winlogbeat?**

Fileless malware runs in memory, so it doesn’t leave behind typical file-based IOCs. To catch it:

* Use **Sysmon Event ID 1** (Process Creation) to log PowerShell, `wscript`, or `mshta`.
* Look for **base64-encoded commands** or suspicious parent-child relationships.
* Monitor **Event ID 7** (Image Loaded) and **Event ID 10** (Process Access) to see if scripts are accessing LSASS or injecting into other processes.
* Winlogbeat can forward these logs to your SIEM for real-time analysis.

---

### 2. **Can you explain DNS tunneling and how to detect it?**

DNS tunneling hides data in DNS queries. Attackers use it to bypass firewalls and exfiltrate data.

To detect it:

* Look for **unusually long or random subdomains**.
* Check for **high frequency** of DNS requests to rare domains.
* Use tools like **Zeek** or analyze DNS logs in Splunk for patterns like `base64` strings or domain entropy.

---

### 3. **What are common indicators of lateral movement?**

Some signs include:

* **Multiple RDP/SMB logins** across machines.
* A user logging in to **systems they don’t normally access**.
* Use of **`psexec`, `wmic`, `WinRM`**, or **remote services**.
* Abnormal **process creation** following remote logins.

Watch for **Event ID 4624** (logon events) and **Sysmon Event ID 3** (network connections).

---

### 4. **What are common persistence methods in Windows?**

Some common methods are:

* **Registry Run Keys** (like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
* **Scheduled Tasks** or **Startup folder** entries
* **WMI persistence**
* **Services** that auto-start
* **DLL hijacking** or **appinit DLLs**

Persistence often hides in places that auto-load at boot or user login.

---

### 5. **How do you detect Mimikatz and credential dumping?**

Look for:

* **Access to LSASS** (Sysmon Event ID 10: process access targeting `lsass.exe`)
* **Tools like `mimikatz.exe`** or renamed variants.
* **Dump files** created from `procdump` or similar tools.
* Unexpected **logon attempts** using dumped credentials.

Also, set alerts for **command-line flags** like `sekurlsa::logonpasswords`.

---

### 6. **What are key Sysmon event IDs to monitor PowerShell activity?**

* **Event ID 1** – Process Creation: Catch `powershell.exe` and `pwsh.exe` commands.
* **Event ID 3** – Network Connections: Monitor PowerShell making connections.
* **Event ID 7** – Image Load: Detect unusual DLLs loaded by PowerShell.
* Pair this with **Script Block Logging** and **Module Logging** in Windows Event Logs (ID 4104).

---

### 7. **How do attackers evade EDR with PowerShell payloads?**

They often:

* Use **obfuscation** (e.g., base64, string concatenation).
* Disable **AMSI** (Antimalware Scan Interface).
* Run PowerShell in **hidden or non-interactive modes**.
* Use **living off the land binaries (LOLBins)** to stay stealthy.

EDRs can be bypassed if they don’t inspect script content or memory execution.

---

### 8. **How do you detect brute-force RDP attacks?**

* Monitor **Event ID 4625** (failed logons) for a **high number of attempts** from one IP.
* Watch for a **4624 (successful logon)** right after many 4625s.
* Look for RDP connections in **Sysmon Event ID 3** and firewall logs.
* Use threshold-based alerts in Splunk (e.g., >10 failed logins in 1 minute).

---

### 9. **How are honeypots useful in detecting lateral movement?**

* Honeypots are **decoy systems** designed to attract attackers.
* If an internal system **not used in real operations** receives a login or connection, it’s a red flag.
* They help detect **unauthorized access**, **credential misuse**, and **network scanning**.
* You can track commands, tools, and IPs used in lateral movement.

---

### 10. **How do you correlate SIEM logs in an APT scenario?**

* Link logs across **host activity (Sysmon)**, **network (firewall/DNS/NetFlow)**, and **authentication (AD events)**.
* Use correlation searches in Splunk to connect:

  * A phishing email → PowerShell spawn → network beacon → credential dump → lateral move
* Tie events together using **timestamps**, **usernames**, **hostnames**, and **IP addresses**.
* Build timelines to visualize the attack chain.

---

Let me know if you'd like this as a `.md` file or added into your repo directly!
