## Banner Grabbing Techniques and Tools

> Identifying running services and their versions via banners is a crucial first step in reconnaissance, guiding vulnerability research and exploitation paths, especially in HTB/THM environments.

---

### 1. Key Tools

- **Nmap**  
  Automated scanning, version detection, scripting.

- **Netcat (`nc`)**  
  Manual TCP/UDP connection, raw interaction.

- **Telnet**  
  Manual interactive TCP connection.

- **cURL**  
  HTTP/S header retrieval and interaction.

- **Wget**  
  HTTP/S header retrieval (alternative to cURL).

- **WhatWeb**  
  Detailed web technology fingerprinting.

---

### 2. Nmap for Automated Scanning & Version Detection

- **Core Command (`-sV`)**  
  ```bash
  nmap -sV <TARGET_IP>
  nmap -p- -sV <TARGET_IP>     # all TCP ports (slow)
  ```
  > `-sV` probes services to identify versions—essential for mapping potential CVEs.  
  > Common in HTB/THM to find initial vectors.

- **Scan Intensity (`--version-intensity`)**  
  ```bash
  nmap -sV --version-intensity 5 <TARGET_IP>
  nmap -sV --version-intensity 9 <TARGET_IP>
  ```
  > 0 (light) → 9 (heavy). Lower values for stealth; higher for accuracy.  
  > ⚠️ Heavy scans are slower and more detectable.

- **Nmap Scripting Engine (NSE)**  
  - **Default Scripts (`-sC`)**  
    ```bash
    nmap -sV -sC <TARGET_IP>
    ```  
    > Safe reconnaissance scripts; often combined with `-sV`.
  - **Banner Script**  
    ```bash
    nmap --script banner -p 21,22,23,80 <TARGET_IP>
    nmap -p 80 --script banner --script-args banner.timeout=2s <TARGET_IP>
    ```  
    > Grabs raw banners when `-sV` misses or for quick checks.
  - **HTTP Headers Script**  
    ```bash
    nmap -p 80,443,8080 --script http-headers <TARGET_IP>
    ```  
    > Reveals `Server:`, cookies, flags—key for web vuln research.
  - **Vulnerability Scripts**  
    ```bash
    nmap -sV --script vuln -p 21,80 <TARGET_IP>
    ```  
    > ⚠️ Very noisy—use only when allowed by rules of engagement.

- **Common Combinations**  
  ```bash
  nmap -p- -sV -sC -T4 -oA nmap_scan <TARGET_IP>
  nmap -F -sV <TARGET_IP>
  ```  
  > Add `-Pn` if ICMP is blocked; `-n` to skip DNS resolution.

---

### 3. Manual Probing with Netcat (`nc`) & Telnet

- **Netcat (`nc`)**  
  ```bash
  nc -nv <TARGET_IP> <PORT>         # basic TCP
  nc -nv -u <TARGET_IP> <PORT>      # UDP (e.g. SNMP 161)
  nc -nv -w1 <TARGET_IP> 21         # FTP banner
  nc -nv <TARGET_IP> 80             # then type: HEAD / HTTP/1.0<Enter><Enter>
  ```  
  > `-n` skips DNS, `-v` verbose, `-w` timeout.  
  > 💡 Use `rlwrap nc` for history/editing.

- **Telnet**  
  ```bash
  telnet <TARGET_IP> <PORT>
  ```  
  > Interactive by default.  
  > ⚠️ Windows may require enabling the Telnet client.

---

### 4. HTTP/S Header Grabbing with cURL & Wget

- **cURL**  
  ```bash
  curl -s -I http://<TARGET>
  curl -s -I -k https://<TARGET>      # ignore cert errors
  curl -s -i http://<TARGET>          # headers + body
  curl -v http://<TARGET>             # verbose req & resp
  curl -s -I -A "Mozilla/5.0" <TARGET>
  ```  
  > Focus on `Server:`, `X-Powered-By`, `Set-Cookie`.

- **Wget**  
  ```bash
  wget --spider -S -q http://<TARGET>
  wget -q -S -O /dev/null http://<TARGET>
  ```  
  > Less flexible than `curl -I`, but available everywhere.

---

### 5. Other Relevant Tools

- **WhatWeb**  
  ```bash
  whatweb http://<TARGET>
  whatweb -a 3 http://<TARGET>
  ```  
  > Profiles CMS, frameworks, JS libs, server versions.

- **Metasploit Auxiliary Scanners**  
  ```bash
  msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS <TARGET>; run; exit"
  msfconsole -q -x "use auxiliary/scanner/ftp/ftp_version; set RHOSTS <TARGET>; run; exit"
  ```  
  > Integrates banner grabbing into exploit workflows.

---

### 6. Protocol-Specific Interaction

- **SMTP**  
  ```bash
  nc -nv <IP> 25         # wait for "220" banner, then EHLO test.com
  ```
- **FTP**  
  ```bash
  nc -nv -w1 <IP> 21     # wait for "220" banner
  ```
- **SSH**  
  ```bash
  nc -nv -w1 <IP> 22     # e.g. SSH-2.0-OpenSSH_8.2p1...
  ```

---

### 7. Common Pitfalls & Pro Tips

- ⚠️ **Firewalls:** May block or filter—use `-Pn` or alternate ports (8080, 8443).  
- ⚠️ **Timeouts:** Use `-w`, `--script-args banner.timeout`.  
- ⚠️ **Obfuscated Banners:** Rely on deeper probes (`-sV`) or fingerprinting tools like WhatWeb.  
- 💡 **Passive First:** Check Shodan/Censys before touching the target.  
- 💡 **Save Outputs:** `nc … | tee banner.txt` for later analysis.  
- 💡 **Cover All Ports:** Don’t forget non-standard HTTP/S (8000, 8443).

---

### 8. Evasion & Defense Notes

- ⚠️ **Detection:** Aggressive scans are logged by IDS/IPS.  
- ⚠️ **Defenses:** Services can hide or fake banners (e.g., `ServerTokens Prod` in Apache).  
- 💡 **Evasion:** Lower timing (`-T2`), reduce intensity, rotate User-Agents, use passive OSINT.

---

### 9. Practice Links

- 🎯 **HTB Academy:** Network Enumeration with Nmap  
- 🎯 **TryHackMe:** Nmap room, Network Security pathway  
- 🎯 **HTB Boxes:** Lame, Blue, Devel (banner-driven exploits)  
- 🎯 **VulnHub:** Kioptrix series, Stapler

---

### 10. Suggested Next Steps & Cross-References

- **Vulnerability Research**  
  ```bash
  searchsploit <service> <version>
  ```  
- **Service-Specific Enumeration**  
  - See Section X.Y: FTP, SSH, SMB, MySQL enumeration  
- **Default Credentials**  
  - See Section X.Y: Default Credentials  
- **Exploitation**  
  - See Section X.Y: Exploitation Techniques  
