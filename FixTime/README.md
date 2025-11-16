# **TimeFix – Kerberos Clock Skew Auto-Fix Toolkit**

When attacking Windows domains (WinRM, Kerberos auth, Impacket, Evil-WinRM, etc.), you may hit the classic:

```
KRB_AP_ERR_SKEW – Clock skew too great
```

**TimeFix** provides **two small tools (Bash + Python)** that automatically fetch the target machine’s time via its WinRM HTTP `Date:` header and sync your local clock to match it.

Perfect for pentesters doing Kerberos-based operations where precise time alignment is required.

---

## **Features**

* 🔎 Fetches remote Windows system time from WinRM (port **5985**)
* ⏱ Automatically sets your Linux system clock to match the target
* 💥 Instantly fixes Kerberos clock skew errors
* 🛠 Includes **two versions**:

  * **Bash script** for quick usage on Linux
  * **Python3 script** for cross-platform usage and cleaner parsing
* 🔒 Gracefully handles failures & can re-enable system time sync

---

## **Usage**

### **Bash Version**

```bash
sudo ./fixtime <IP>
```

Example:

```bash
sudo ./fixtime 10.10.10.5
```

---

### **Python Version**

```bash
python3 fixtime.py -u <IP>
```

Example:

```bash
python3 fixtime.py -u http://10.10.10.5
```

---

## **Purpose**

These scripts are designed for lab, CTF, and penetration-testing environments where:

* Kerberos authentication breaks due to clock skew
* NTP is disabled or not configurable
* You need a fast, reliable way to sync with the target host
