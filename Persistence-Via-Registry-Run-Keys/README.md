### 🛠️ Persistence via Registry Run Keys — Detection & Monitoring

#### 📌 **Attack Description**

This technique involves adding a malicious script or executable path to the Windows Registry `Run` key, which allows the payload to execute every time the user logs in. It is a common persistence method used by threat actors to maintain access after initial compromise.

---

#### 🔧 **Steps to Simulate the Attack**

1. **Create a Malicious Payload**
   A simple PowerShell payload was saved as:

   ```
   C:\Users\victim\Documents\payload.ps1
   ```


2. **Add Persistence via Registry Key**
   Run this command in PowerShell to add persistence:

   ```powershell
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\victim\Documents\payload.ps1"
   ```

3. **Verify the Registry Key Exists**

   ```powershell
   Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
   ```

---

#### 🔍 **Detection in Splunk via Sysmon**

> Sysmon must be configured to capture **RegistryEvent (Event ID 13)**

**Sample Splunk Search Query:**

```spl
index=win_logs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 RegistryValueName="Updater"
```

**Alternative (broader) query:**

```spl
index=win_logs EventCode=13 RegistryKeyPath="*\\Run\\*"
```

---

#### ✅ **Expected Log Sample**

* **EventCode:** 13
* **RegistryKeyPath:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* **RegistryValueName:** `Updater`
* **Details:** Shows the path to the PowerShell payload used for persistence

---

#### 🧠 **Why It Matters**

Persistence allows attackers to maintain access across reboots or logins. Registry-based persistence is stealthy and often overlooked if monitoring isn't in place.

---

