# 🧩 decPEAS — Linux Persistence Detection Script

**decPEAS** (Detection PEAS) is a **Bash-based security assessment tool for Blue Teamers and DFIR analysts**.  
Inspired by [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), it focuses not on privilege escalation, but on **detecting persistence mechanisms and post-exploitation traces** within Linux systems.

---

## 🕵️‍♂️ Overview

Attackers often establish persistence to maintain access after initial compromise.  
**decPEAS** helps defenders **detect common and advanced persistence methods** by performing a deep inspection of system configurations, startup scripts, and background services.

---

## ⚙️ Features

✅ **System-wide Persistence Checks**
- Startup entries in `/etc/rc.local`, `/etc/init.d/`, and systemd services  
- Cron jobs (`/etc/cron*`, user crontabs, anacron)  
- `at` and `batch` scheduled tasks  

✅ **User-level Persistence**
- `.bashrc`, `.profile`, `.bash_login`, `.zshrc` modifications  
- SSH authorized keys and command options  
- Hidden scripts in home directories  
- Sudoers file abuse for persistence  

✅ **Advanced Techniques Detection**
- Malicious systemd units or timers  
- Modified `/etc/profile` or PAM configuration hooks  
- Suspicious binaries in `$PATH`  
- LD_PRELOAD or LD_LIBRARY_PATH injections  
- Kernel modules or backdoored drivers  

✅ **Forensic Artifacts**
- Recently modified binaries and scripts  
- Unusual files in `/tmp`, `/dev/shm`, `/var/tmp`  
- Abnormal processes or startup entries  
- Potential reverse shells or listener scripts  

✅ **Color-coded Output**
- 🔴 High severity (definitely malicious)
- 🟡 Suspicious or uncommon
- 🟢 Benign / informational

---

## 🧰 Requirements

- Linux (tested on Ubuntu, Debian, CentOS, and Kali)
- `bash` ≥ 4.0  
- Optional tools (auto-detected):
  - `grep`, `awk`, `sed`, `ps`, `ls`, `find`, `systemctl`, `crontab`

---

## 🚀 Installation

```bash
git clone https://github.com/root0x7/decPEAS.git
cd decPEAS
chmod +x decPEAS.sh
```

## 🧪 Usage

Run it as root for full visibility:
```bash
sudo ./decPEAS.sh
````

Or scan only the current user’s environment:

```bash
./decPEAS.sh --user
```

### Example Output

```bash
[+] Checking for systemd persistence...
    🔴 Suspicious service found: /etc/systemd/system/ssh-backdoor.service

[+] Checking for modified bash profiles...
    🟡 /home/user/.bashrc modified recently (possible persistence)

```


### 🧬 Output Options

You can export the results for later analysis:

```bash 
./decPEAS.sh --output report.txt
```