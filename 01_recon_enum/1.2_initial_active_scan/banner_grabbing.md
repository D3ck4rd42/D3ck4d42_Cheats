## Banner Grabbing Techniques and Tools

Identifying running services and their versions via banners is a crucial first step in reconnaissance, guiding vulnerability research and exploitation paths, especially in HTB/THM environments.

#### 1. Key Tools

* **Nmap:** Automated scanning, version detection, scripting.
* **Netcat (`nc`):** Manual TCP/UDP connection, raw interaction.
* **Telnet:** Manual interactive TCP connection.
* **cURL:** HTTP/S header retrieval and interaction.
* **Wget:** HTTP/S header retrieval (alternative to cURL).
* **WhatWeb:** Detailed web technology fingerprinting.

#### 2. Nmap for Automated Scanning & Version Detection

Nmap is the primary tool for efficient, automated banner grabbing and service identification across multiple ports.

* **Core Command (`-sV`):** Enables service version detection probes.
    💻 `nmap -sV <TARGET_IP>` (Scan default ports for versions)
    💻 `nmap -p- -sV <TARGET_IP>` (Scan all TCP ports for versions - can be slow)
    💡 `-sV` is essential for identifying potential vulnerabilities based on software versions. Common in HTB/THM for finding initial vectors.
* **Scan Intensity (`--version-intensity`):** Controls probe aggressiveness (0=light -> 9=heavy). Default is 7.
    💻 `nmap -sV --version-intensity 5 <TARGET_IP>` (Slightly less aggressive than default)
    💻 `nmap -sV --version-intensity 9 <TARGET_IP>` (Most probes, potentially noisy)
    ⚠️ Higher intensity = better identification chance but slower and more detectable. Use lower values (e.g., 0-3) if stealth is required.
* **Nmap Scripting Engine (NSE):** Automates specific banner grabbing and enumeration tasks.
    * **Default Scripts (`-sC` or `--script default`):** Runs a safe set of common reconnaissance scripts. Often combined with `-sV`.
        💻 `nmap -sV -sC <TARGET_IP>` (Standard comprehensive recon scan)
    * **Banner Script (`--script banner`):** Specifically grabs banners by connecting. Can complement `-sV`.
        💻 `nmap --script banner -p 21,22,23,80 <TARGET_IP>`
        💻 `nmap -p 80 --script banner --script-args banner.timeout=2s <TARGET_IP>` (Set timeout)
        💡 Useful if `-sV` fails or for quick checks on specific ports known for banners (FTP, SSH, Telnet).
    * **HTTP Headers Script (`--script http-headers`):** Retrieves detailed HTTP headers.
        💻 `nmap -p 80,443,8080 --script http-headers <TARGET_IP>`
        💡 Excellent for web server recon, revealing server software, cookies, flags. Often a starting point for web vulns.
    * **Vulnerability Scripts (`--script vuln`):** Runs scripts that check for known vulnerabilities based on detected versions.
        💻 `nmap -sV --script vuln -p 21,80 <TARGET_IP>`
        ⚠️ Very noisy and potentially intrusive. Use only when permitted and appropriate. Can quickly identify low-hanging fruit on HTB/THM boxes.
* **Common Nmap Combinations:**
    💻 `nmap -p- -sV -sC -T4 -oA nmap_scan <TARGET_IP>` (Full port scan, version, default scripts, faster timing, output all formats)
    💻 `nmap -F -sV <TARGET_IP>` (Fast scan top 100 ports with version detection)
    💡 Add `-Pn` if target doesn't respond to pings (common in HTB). Use `-n` to disable DNS resolution (faster).

#### 3. Manual Probing with Netcat (`nc`) and Telnet

Essential for direct interaction, verification, and when automated tools fail or require specific input.

* **Netcat (`nc`):** The "Swiss army knife" for raw network connections.
    * **Basic Connection:**
        💻 `nc -nv <TARGET_IP> <PORT>`
        💡 `-n` skips DNS, `-v` gives verbose connection status. Add `-w <seconds>` (e.g., `-w1`) for connection timeout.
    * **UDP Connection:**
        💻 `nc -nv -u <TARGET_IP> <PORT>` (e.g., for SNMP port 161)
    * **Examples:**
        💻 `nc -nv -w1 <TARGET_IP> 21` (FTP Banner)
        💻 `nc -nv -w1 <TARGET_IP> 22` (SSH Banner)
        💻 `nc -nv -w1 <TARGET_IP> 25` (SMTP Banner)
        💻 `nc -nv -w1 <TARGET_IP> 3306` (MySQL Banner)
    * **Interactive HTTP:** Requires sending a request manually after connecting.
        💻 `nc -nv <TARGET_IP> 80`
        **(Type Manually):** `HEAD / HTTP/1.0` followed by `Enter` twice (`\r\n\r\n`).
        💡 Use `rlwrap nc <TARGET_IP> <PORT>` for better line editing/history during interactive sessions.
* **Telnet:** Similar to `nc` but inherently interactive.
    * **Connection:**
        💻 `telnet <TARGET_IP> <PORT>`
    * **Examples:**
        💻 `telnet <TARGET_IP> 21` (FTP)
        💻 `telnet <TARGET_IP> 23` (Telnet Service)
        💻 `telnet <TARGET_IP> 80` (Then type HTTP request like `HEAD / HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n`)
    ⚠️ Telnet client might need enabling (Windows: `Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient`). Less flexible than `nc` for scripting. Sends data in clear text.

#### 4. HTTP/S Header Grabbing with cURL and Wget

Specialized tools for inspecting web server responses.

* **cURL:** Preferred tool for flexible HTTP/S interaction.
    * **Headers Only (HEAD request):** Most efficient way.
        💻 `curl -s -I http://<TARGET_IP_OR_DOMAIN>`
        💻 `curl -s -I -k https://<TARGET_IP_OR_DOMAIN>` (`-k` ignores certificate errors)
    * **Include Headers with Body:**
        💻 `curl -s -i http://<TARGET_IP_OR_DOMAIN>`
    * **Verbose Output (Shows Request & Response Headers):**
        💻 `curl -v http://<TARGET_IP_OR_DOMAIN>`
    * **Custom User-Agent:**
        💻 `curl -s -I -A "Mozilla/5.0" http://<TARGET_IP_OR_DOMAIN>`
    💡 `Server:` header is the primary banner. Look for `X-Powered-By`, `Set-Cookie`, and other non-standard headers for clues. Essential for web challenges.
* **Wget:** Primarily a downloader, but can grab headers.
    * **Spider Mode (No Download):**
        💻 `wget --spider -S -q http://<TARGET_IP_OR_DOMAIN>` (`-S` prints headers to stderr, `-q` quiet)
    * **Discard Body:**
        💻 `wget -q -S -O /dev/null http://<TARGET_IP_OR_DOMAIN>`
    💡 Generally less convenient than `curl -I` for just grabbing headers.

#### 5. Other Relevant Tools

* **WhatWeb:** Identifies web technologies (CMS, frameworks, JS libraries, server versions). More detailed than simple banner grabbing for web targets.
    💻 `whatweb http://<TARGET_IP_OR_DOMAIN>`
    💻 `whatweb -a 3 http://<TARGET_IP_OR_DOMAIN>` (Aggression level 3 - more requests, potentially noisy)
    💡 Very useful on HTB/THM web challenges to quickly profile the application stack.
* **Metasploit:** Contains auxiliary scanners.
    💻 `msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS <TARGET_IP>; run; exit"`
    💻 `msfconsole -q -x "use auxiliary/scanner/ftp/ftp_version; set RHOSTS <TARGET_IP>; run; exit"`
    💡 Useful if already working within Metasploit.

#### 6. Protocol-Specific Interaction

* **HTTP:** Requires sending a request (e.g., `GET / HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n` or `HEAD / HTTP/1.0\r\n\r\n`). Use `curl` or `nc`/`telnet` followed by manual input.
* **SMTP:** Sends a `220` banner on connect. Use `EHLO domain.com` or `HELO domain.com` for more info. Use `nc` or `telnet`.
    📖 Connect `nc -nv <IP> 25`, wait for `220` banner, type `EHLO test.com`.
* **FTP:** Sends `220` banner on connect. Can send `USER anonymous`, `PASS pass` etc. Use `nc` or `telnet`.
* **SSH:** Sends banner on connect (e.g., `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3`). `nc` or `telnet` is sufficient.

#### 7. Common Pitfalls & Pro Tips (⚠️, 💡)

* ⚠️ **Firewalls:** May block connections or filter responses. Use `nmap -Pn` if pings are blocked. Try common alternative ports (e.g., 8080, 8443 for HTTP/S).
* ⚠️ **Timeouts:** Slow services can hang tools. Use `-w` (nc), `--script-args banner.timeout` (nmap), connection timeouts in other tools.
* ⚠️ **Protocol Interaction:** Forgetting to send required commands (e.g., HTTP `GET`/`HEAD`) after connecting with `nc`/`telnet`.
* ⚠️ **Banner Obfuscation/Modification:** Admins may hide or fake banners. Rely on `nmap -sV` 's deeper probes or tools like `whatweb` for confirmation.
* 💡 **HTB/THM Context:** Banner grabbing is fundamental. Expect common services (SSH, FTP, HTTP, SMB) but also non-standard ports found via full port scans (`nmap -p-`). Outdated versions are common flags for exploitation.
* 💡 **Pro Tip:** Check Shodan/Censys/Zoomeye for the target IP first. Passive banner info might already exist without touching the target.
* 💡 **Pro Tip:** Combine `-sV` with `-sC` in Nmap for efficient recon (`nmap -sV -sC <IP>`).
* 💡 **Pro Tip:** Use `tee` to save `nc`/`telnet` session output: `nc -nv <IP> <PORT> | tee banner.txt`.
* 💡 **Pro Tip:** For web servers, always check both HTTP (80) and HTTPS (443), and common alternatives (8000, 8080, 8443). Headers/banners might differ.

#### 8. Evasion/Defense Notes (⚠️, 💡)

* ⚠️ **Detection:** Active banner grabbing (especially aggressive Nmap scans) is easily logged and detected by IDS/IPS/Firewalls.
* ⚠️ **Defenses:** Admins can reconfigure services to hide/change banners (e.g., `ServerTokens Prod` in Apache). WAFs can block suspicious requests or User-Agents.
* 💡 **Basic Evasion (CTF Scope):** Use less noisy Nmap scans (`-T2`, lower `--version-intensity`), change User-Agents (`curl -A`, `wget --user-agent`), use passive OSINT sources first.

#### 9. Practice Links (🎯)

* **HTB Academy:** Network Enumeration with Nmap module.
* **THM:** Nmap room, Network Security pathway rooms (e.g., Vulnversity).
* **HTB Boxes:** Many Starting Point/Easy/Medium boxes rely on finding vulnerable versions via banners (e.g., look for old FTP, SSH, web servers). Examples: Lame, Blue, Devel.
* **VulnHub:** Kioptrix series, Stapler.

#### 10. Suggested Next Steps & Cross-References (💡, 🔗)

* **Vulnerability Research:** Use identified service/version (e.g., "ProFTPD 1.3.5", "Apache 2.4.29") to search:
    * `searchsploit <service> <version>`
    * Google: `<service> <version> exploit cve`
    * NVD/CVE Mitre databases.
* **Service-Specific Enumeration:** Based on the service found:
    * 🔗 `[See Section X.Y: Enumerating FTP]`
    * 🔗 `[See Section X.Y: Enumerating SSH]`
    * 🔗 `[See Section X.Y: Web Server Enumeration]`
    * 🔗 `[See Section X.Y: Enumerating SMB]`
    * 🔗 `[See Section X.Y: Enumerating MySQL]`
* **Default Credentials:** Try default username/password combinations for the identified service. 🔗 `[See Section X.Y: Default Credentials]`
* **Exploitation:** If a known exploit exists, attempt exploitation. 🔗 `[See Section X.Y: Exploitation Techniques]`
