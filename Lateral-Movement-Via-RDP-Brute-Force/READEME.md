
# 📄 **Lateral Movement via RDP Brute Force**

---

## 📝 **Attack Title**

Lateral Movement via RDP Brute Force — Low-privilege user brute-forces RDP using stolen credentials

---

## 🔎 **Attack Summary**

In this simulation, I performed a lateral movement attack by brute-forcing RDP credentials on a target machine. The purpose was to test detection and monitoring capabilities of Splunk and Windows security logging, as well as observe the events generated by brute-force attacks.

---

## 🧰 **Lab Environment**

* **Attacker Machine**: Kali Linux
* **Target Machine**: Windows 11 VM (RDP enabled)
* **SIEM Platform**: Splunk Enterprise
* **Forwarder**: Splunk Universal Forwarder installed on victim machine
* **Log Sources**:

  * Windows Event Logs (Security)
  * Sysmon Logs (Operational)

---

## 🚩 **Attack Details**

* **Attack Type**: RDP Brute Force
* **Tools Used**: Hydra (could be replaced with PSExec, but original attack used Hydra)
* **Username**: Targeted with known/stolen low-privilege credentials
* **Target Port**: TCP 3389 (RDP default port)

---

## 💻 **Attack Execution**

### 🔐 Step 1 — Enumerate Target RDP Access

Verified RDP is enabled on target Windows 11 machine.

### 🔐 Step 2 — Brute-Force Credentials (Hydra Example)

```bash
hydra -t 4 -V -f -l victimuser -P passwords.txt rdp://192.168.1.15
```

* `victimuser` — username used in attack.
* `passwords.txt` — password list for brute-force.

*In your case, these credentials were successfully brute-forced and access was gained.*

---

## 📊 **Log Evidence Captured**

### 1️⃣ Windows Security Logs

* **Event ID 4625 (Failed logon attempts)**
  Repeated failures captured during brute-force process.

* **Event ID 4624 (Successful logon)**
  Successful logon captured when correct credentials were discovered.

### 2️⃣ Sysmon Logs

* **Event ID 3 (Network Connection Attempted)**
  Shows remote connection activity to RDP port 3389.

---

## 🔍 **Splunk Search Queries**

### 🔎 Failed Logon Attempts

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625
```

or filter specifically for RDP failures:

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 LogonType=10
```

### 🔎 Successful RDP Logon

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4624 LogonType=10
```

### 🔎 Repeated Login Attempts from Same Source (Brute Force Pattern)

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 LogonType=10
| stats count by Account_Name, Workstation_Name, IpAddress
| where count > 10
```

### 🔎 Sysmon Network Connection to RDP

```spl
index=win_logs sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
| search DestinationPort=3389
```

---

## 📈 **Detection Outcome**

* ✅ Windows Security logs successfully captured both failed and successful login attempts.
* ✅ Sysmon successfully logged RDP connection attempts.
* ✅ Splunk dashboards displayed clear brute-force patterns based on frequency and repetition.

---

## 🛡 **Defensive Recommendations**

* Enable account lockout policies.
* Monitor Event IDs 4625 and 4624 for unusual patterns.
* Monitor Sysmon Event ID 3 for repeated RDP connections.
* Limit RDP access using firewalls and VPNs.
* Deploy multi-factor authentication (MFA) for RDP sessions.

---

## 📦 **MITRE ATT\&CK Mapping**

| Tactic           | Technique                                  |
| ---------------- | ------------------------------------------ |
| Lateral Movement | T1110.001 (Brute Force: Password Guessing) |
| Lateral Movement | T1076 (Remote Desktop Protocol)            |

---
