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
username=Silas, password=p@ssword123
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

## 🖼️ Screenshots 

![IMG_20250617_074609](https://github.com/user-attachments/assets/283f6a8a-7fd4-43d0-a23b-1c4c9c1926f7)

![Screenshot 2025-06-17 024023_064557](https://github.com/user-attachments/assets/4bb9c44d-bef2-4685-944d-9a93f48fff52)



![Screenshot 2025-06-17 023945_064556](https://github.com/user-attachments/assets/438ae181-3480-45c5-9ee3-51f4aef896d0)

![IMG_20250617_074847](https://github.com/user-attachments/assets/bef579bd-58ba-4a0e-b178-436bac26a80b)

![Screenshot 2025-06-17 030330_064640](https://github.com/user-attachments/assets/1fea66c8-830a-4999-98c8-421885e087fb)
![Screenshot 2025-06-17 033051_064741](https://github.com/user-attachments/assets/e09b30df-5fc9-48a3-ac6e-e3bf0d3246f2)

![Screenshot 2025-06-17 032212_064708](https://github.com/user-attachments/assets/b27ff60f-c7db-4cf3-a95f-2d0721259d5d)

![Screenshot 2025-06-17 032530_064710](https://github.com/user-attachments/assets/edaf9023-5412-4600-8241-7c99cf72e3d4)

![Screenshot 2025-06-17 033051_064741](https://github.com/user-attachments/assets/2df5e6db-4a94-45b0-bb3b-0c820feda98b)
![Screenshot 2025-06-17 033111_064744](https://github.com/user-attachments/assets/fbfcce34-7a38-4b51-b37a-fbf3e7489280)
![Screenshot 2025-06-17 033231_064747](https://github.com/user-attachments/assets/0bebdaa3-5c3b-4b5b-b814-0471b2bf7ce9)

![Screenshot 2025-06-17 050219_064811](https://github.com/user-attachments/assets/66fe241c-67e4-4d80-b1ce-5435b845e1c3)

![Screenshot 2025-06-17 055423_064821](https://github.com/user-attachments/assets/c5ca57ca-d149-4b5b-8510-535dbe715c30)
![Screenshot 2025-06-17 055829_064827](https://github.com/user-attachments/assets/390e2ce9-4a45-4fec-8ff4-db122f1a52d4)

![Screenshot 2025-06-17 060211_064832](https://github.com/user-attachments/assets/e6485fa0-a0fd-44a0-8364-51b686ffd07d)

![Screenshot 2025-06-17 070420_072110](https://github.com/user-attachments/assets/87f27ec3-ba78-4afd-b16d-fbb651777ca8)
![Screenshot 2025-06-17 080721_080821](https://github.com/user-attachments/assets/0bfebe39-6911-46a3-a62d-430647c9b9c2)



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
