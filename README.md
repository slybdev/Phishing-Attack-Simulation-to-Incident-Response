# 🎯 Phishing to Incident Response Lab Walkthrough

> **⚠️ Educational Purpose Only!** This project simulates a phishing attack and response workflow within a controlled lab environment for blue team skill-building. No part of this should be used maliciously.

---

## 🔥 Scenario Summary

A simulated phishing campaign was launched using a fake online banking page. When a victim clicked the link and submitted credentials, the site triggered a download of a **Meterpreter reverse shell** disguised as `paycheck.txt.exe`. This triggered the attack chain. The system was later detected and remediated using blue team tools.

---

## 🧰 Lab Setup

| Component     | Description                            |
|---------------|----------------------------------------|
| Kali Linux    | Attacker machine, payload/server host |
| Windows VM    | Victim endpoint                        |
| pfSense       | Network segmentation + firewall rules |
| Splunk        | Log aggregation & detection engine     |
| Wireshark     | Network traffic capture                |
| Log Hawk IDS  | Custom Python-based detection tool     |

---

## 🛠️ Red Team Phase (Initial Access)

- **Phishing Page**: Created using Flask and hosted at `http://127.0.0.1:5000`
- **Credential Stealer**: Form submission sends data to `http://127.0.0.1:8080`
- **Payload**: Reverse shell (`paycheck.txt.exe`) generated using `msfvenom`
- **Delivery**: URL shortened via **ngrok**, user tricked into clicking the link



- **Result**: Shell access gained on victim

---

## 🔎 Blue Team Phase (Detection)

### 📌 Sysmon Events

- **Event ID 1**: Process creation for `paycheck.txt.exe`
- **Event ID 7**: DLL loaded by `backgroundTaskHost.exe`
- **Event ID 13**: Registry modification by `svchost.exe` to `HKLM\System\...\UserSettings`

```xml
<Data Name='Image'>C:\Windows\System32\backgroundTaskHost.exe</Data>
<Data Name='ImageLoaded'>C:\Windows\System32\urlmon.dll</Data>
<Data Name='ProcessId'>6972</Data>
<Data Name='Signed'>true</Data>
<Data Name='User'>SILAS\jane</Data>
```

---

## 🌐 Network Traffic Analysis – Wireshark

Captured live traffic between attacker and victim:

### 🔍 Key Observations

- **Outbound Connection**: to external IP on port 4444 after `.exe` was executed
- **Payload Download**:

```
GET /payload.exe HTTP/1.1  
Host: ngrok URL
```

- **POST request with credentials**:
```
username=janedoe&password=p@ssword123
```

### 📥 Packet Export

`/evidence/wireshark-capture.pcap` (password: `infected`)(uploadingsoon)

---

## ⚠️ Detection via Log Hawk IDS

Custom rules in Log Hawk flagged the following:

- Reverse shell to dynamic port
- Abnormal parent-child relationship
- Registry persistence

---

## 🧯 Incident Response Lifecycle

### 1. **Identification**  
Log Hawk flagged abnormal network traffic. Splunk confirmed payload execution.

### 2. **Containment**  
The compromised host was blocked via **pfSense firewall** and isolated from the lab network.

### 3. **Eradication**  
Used PowerShell to:
- Kill malicious process
- Remove reverse shell and persistence key
- Clean registry entry:
```ps
Remove-Item -Path 'HKLM:\System\CurrentControlSet\Services\bam\State\UserSettings\...'
```

### 4. **Recovery**
- Host restored to baseline snapshot
- Verified clean state via hash comparisons & memory dump analysis

---

## 📈 Improvements

- 🔍 Add **YARA rules** to detect `.txt.exe` masquerading
- 🧠 Upgrade to **TheHive** + **Shuffle** for ticketing & automation
- 📦 Enhance EDR logging and integrate **Wazuh**
- 🛜 Add Suricata rules for C2 traffic detection

---

## 🧠 Lessons Learned

- Social engineering remains a potent threat vector
- Evasion techniques like double extensions can easily fool users
- Incident response is effective when detection, isolation, and remediation work together

---

## 📎 Related Projects

| Skill        | Associated Project         |
|--------------|----------------------------|
| Phishing     | [AD Lab](https://github.com/slybdev/Active-Directory/blob/main/README.md) |
| IR & Logging |   [Log Hawk IDS](https://github.com/slybdev/Log_hawk/blob/main/README.md)             |
| Network Forensics |    [This Project](https://github.com/slybdev/Network-Traffic-Monitoring-and-Attack-Detection-/blob/main/README.md)       |

---

## 👋 Final Notes

If you made it this far, thanks for reading! This was a fun exercise simulating both **red team** and **blue team** workflows. Hit that ⭐️ if this helped you or gave you project ideas!

> Built by **SlybDev (Silas)** 💻
