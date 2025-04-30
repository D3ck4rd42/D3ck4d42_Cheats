---
title: Banner Grabbing Techniques and Tools
---

# Banner Grabbing Techniques and Tools

Identifying running services and their versions via banners is a crucial first step in reconnaissance, guiding vulnerability research and exploitation paths, especially in HTB/THM environments.

## 1. Key Tools

* **Nmap:** Automated scanning, version detection, scripting.  
* **Netcat (`nc`):** Manual TCP/UDP connection, raw interaction.  
* **Telnet:** Manual interactive TCP connection.  
* **cURL:** HTTP/S header retrieval and interaction.  
* **Wget:** HTTP/S header retrieval (alternative to cURL).  
* **WhatWeb:** Detailed web technology fingerprinting.  

## 2. Nmap for Automated Scanning & Version Detection

Nmap is the primary tool for efficient, automated banner grabbing and service identification across multiple ports.

```bash
# Scan default ports for versions
nmap -sV <TARGET_IP>

# Scan all TCP ports for versions (can be slow)
nmap -p- -sV <TARGET_IP>
```

> **💡 Tip:** `-sV` is essential for identifying potential vulnerabilities based on software versions. Common in HTB/THM for finding initial vectors.

### Scan Intensity

Controls probe aggressiveness (0=light → 9=heavy; default is 7).

```bash
# Slightly less aggressive than default
nmap -sV --version-intensity 5 <TARGET_IP>

# Most probes, potentially noisy
nmap -sV --version-intensity 9 <TARGET_IP>
```

> **⚠️ Warning:** Higher intensity → better identification chance but slower and more detectable. Use lower values (e.g., 0–3) if stealth is required.

### Nmap Scripting Engine (NSE)

Automates specific banner grabbing and enumeration tasks.

- **Default Scripts** (`-sC` or `--script default`):  
  ```bash
  nmap -sV -sC <TARGET_IP>
  ```
- **Banner Script** (`--script banner`):  
  ```bash
  nmap --script banner -p 21,22,23,80 <TARGET_IP>
  nmap -p 80 --script banner --script-args banner.timeout=2s <TARGET_IP>
  ```
- **HTTP Headers Script** (`--script http-headers`):  
  ```bash
  nmap -p 80,443,8080 --script http-headers <TARGET_IP>
  ```
- **Vulnerability Scripts** (`--script vuln`):  
  ```bash
  nmap -sV --script vuln -p 21,80 <TARGET_IP>
  ```

> **⚠️ Warning:** Vulnerability scripts are noisy and potentially intrusive. Use only when permitted and appropriate.

### Common Nmap Combinations

```bash
# Full port scan, version, default scripts, faster timing, output all formats
nmap -p- -sV -sC -T4 -oA nmap_scan <TARGET_IP>

# Fast scan top 100 ports with version detection
nmap -F -sV <TARGET_IP>
```

> **💡 Tip:** Add `-Pn` if target doesn’t respond to pings (common in HTB). Use `-n` to disable DNS resolution (faster).

## 3. Manual Probing with Netcat (`nc`) and Telnet

Essential for direct interaction, verification, and when automated tools fail or require specific input.

### Netcat (`nc`)

The “Swiss army knife” for raw network connections.

```bash
# Basic TCP connection
nc -nv <TARGET_IP> <PORT>

# UDP connection (e.g., SNMP port 161)
nc -nv -u <TARGET_IP> <PORT>

# With timeout (e.g., 1s)
nc -nv -w1 <TARGET_IP> 21
```

> **💡 Tip:** Use `rlwrap nc <TARGET_IP> <PORT>` for better line editing/history.

#### Interactive HTTP

```bash
nc -nv <TARGET_IP> 80
# Then type:
HEAD / HTTP/1.0
<Enter><Enter>
```

### Telnet

Similar to `nc` but inherently interactive.

```bash
telnet <TARGET_IP> <PORT>
```

> **⚠️ Warning:** Telnet transmits data in clear text and is less flexible for scripting.

## 4. HTTP/S Header Grabbing with cURL and Wget

### cURL

```bash
# HEAD request (headers only)
curl -s -I http://<TARGET_IP_OR_DOMAIN>

# Ignore cert errors
curl -s -I -k https://<TARGET_IP_OR_DOMAIN>

# Include headers + body
curl -s -i http://<TARGET_IP_OR_DOMAIN>

# Verbose (request & response headers)
curl -v http://<TARGET_IP_OR_DOMAIN>

# Custom User-Agent
curl -s -I -A "Mozilla/5.0" http://<TARGET_IP_OR_DOMAIN>
```

> **💡 Tip:** Look for `Server:`, `X-Powered-By`, `Set-Cookie` headers for clues.

### Wget

```bash
# Spider mode, print headers to stderr
wget --spider -S -q http://<TARGET_IP_OR_DOMAIN>

# Discard body
wget -q -S -O /dev/null http://<TARGET_IP_OR_DOMAIN>
```

> **💡 Tip:** Less convenient than `curl -I`, but still useful.

## 5. Other Relevant Tools

* **WhatWeb:**  
  ```bash
  whatweb http://<TARGET_IP_OR_DOMAIN>
  whatweb -a 3 http://<TARGET_IP_OR_DOMAIN>
  ```
* **Metasploit Auxiliary Scanners:**  
  ```bash
  msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS <TARGET_IP>; run; exit"
  ```

## 6. Protocol-Specific Interaction

* **HTTP:**  
  Send `GET`/`HEAD` requests manually via `nc`/`telnet` or use `curl`.  
* **SMTP:**  
  ```bash
  nc -nv <IP> 25
  EHLO test.com
  ```
* **FTP:**  
  ```bash
  nc -nv <IP> 21
  USER anonymous
  PASS pass
  ```
* **SSH:** Banner on connect (e.g., `SSH-2.0-OpenSSH_8.2p1`).  

## 7. Common Pitfalls & Pro Tips

> **⚠️ Warning:** Firewalls may block or filter responses. Use `nmap -Pn` and try alternative ports (e.g., 8080, 8443).

> **⚠️ Warning:** Slow services may hang—use timeouts (`-w`, `banner.timeout`, etc.).

> **⚠️ Warning:** Banners can be obfuscated; rely on deeper probes or WhatWeb.

> **💡 Tip:** Check Shodan/Censys/Zoomeye first for passive banners.

> **💡 Tip:** Combine `-sV` with `-sC` for efficient recon.

> **💡 Tip:** Use `tee` to save output:  
```bash
nc -nv <IP> <PORT> | tee banner.txt
```

> **💡 Tip:** For web servers, test both HTTP (80) and HTTPS (443) and common alternatives (8000, 8080, 8443).

## 8. Evasion/Defense Notes

> **⚠️ Warning:** Active scanning is easily logged by IDS/IPS.

> **⚠️ Warning:** Admins can hide banners (e.g., `ServerTokens Prod` in Apache).

> **💡 Tip:** Use less noisy scans (`-T2`, lower intensity), change User-Agents, and leverage passive OSINT first.

## 9. Practice Links 🎯

* **HTB Academy:** Network Enumeration with Nmap  
* **THM:** Nmap room, Network Security pathway  
* **HTB Boxes:** Lame, Blue, Devel  
* **VulnHub:** Kioptrix series, Stapler  

## 10. Suggested Next Steps & Cross-References

* **Vulnerability Research:**  
  ```bash
  searchsploit <service> <version>
  ```
* **Service-Specific Enumeration:**  
  - [Enumerating FTP](#)  
  - [Enumerating SSH](#)  
  - [Web Server Enumeration](#)  
* **Default Credentials:** Try common combos (see [Default Credentials](#)).  
* **Exploitation:** Leverage known exploits (see [Exploitation Techniques](#)).  
