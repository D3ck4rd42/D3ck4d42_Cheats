## Active Host Discovery in Network Reconnaissance

Identifying live hosts within a target scope is the foundational step of active network reconnaissance. It filters the potential IP space down to operational systems, optimizing subsequent, more resource-intensive scans like port scanning and vulnerability analysis. Essential for efficiency in pentests and CTFs (HTB/THM).

#### 1. Goal & Concept

* **Identify Live Systems:** Determine which IP addresses within a defined range correspond to active devices (servers, workstations, routers, etc.) that respond to network probes.
* **Optimize Subsequent Scans:** Create a confirmed list of live targets to avoid wasting time and resources scanning inactive IPs during port scanning, service enumeration, and vulnerability analysis.
* **Initial Network Mapping:** Provide the first active map of reachable devices within the target environment.

#### 2. Key Tools

* **Nmap:** The primary, most versatile tool for host discovery and network scanning.
* **Netdiscover / Arp-scan:** Specialized, highly effective ARP scanners for local network discovery. 💡 Crucial for finding target IPs on local CTF networks (HTB/THM labs).
* **Masscan:** Extremely fast scanner designed for large network ranges or even the entire internet. Good for initial identification of open ports across vast spaces.
* **Metasploit:** Includes auxiliary modules like `arp_sweep` and `udp_sweep`.

#### 3. Core Host Discovery Techniques (Focus on Nmap)

Active discovery relies on sending network probes and analyzing responses (or lack thereof). The choice depends on network location (local vs. remote) and potential filtering. Privileged access (root/Administrator) enables more techniques.

* **ARP Ping (Local Network Only - `-PR`)**
    * **Mechanism:** Sends ARP requests ("Who has IP X?") on the local Ethernet/Wi-Fi segment. Hosts must respond with their MAC address to communicate locally.
    * **Nmap Usage:** 💻 `nmap -sn -PR <LOCAL_NETWORK_RANGE>` (e.g., `192.168.1.0/24`)
        💡 Nmap uses ARP ping automatically (`-PR`) by default when run as root against targets on the local network unless `--send-ip` is specified.
        💡 Extremely fast and reliable on LAN as it bypasses IP-level firewalls. The go-to method for local discovery.
* **ICMP Ping Methods**
    * **ICMP Echo Request (`-PE`):** Standard "ping". Sends ICMP type 8, expects type 0 reply.
        💻 `nmap -sn -PE <TARGET_IP_OR_RANGE>`
        ⚠️ Very often blocked by firewalls. Requires root for raw packet access.
    * **ICMP Timestamp Request (`-PP`):** Sends ICMP type 13, expects type 14. Alternative if Echo is blocked.
        💻 `nmap -sn -PP <TARGET_IP_OR_RANGE>` (Requires root)
    * **ICMP Address Mask Request (`-PM`):** Sends ICMP type 17, expects type 18. Less common alternative.
        💻 `nmap -sn -PM <TARGET_IP_OR_RANGE>` (Requires root)
* **TCP Ping Methods**
    * **TCP SYN Ping (`-PS<portlist>`):** Sends TCP SYN packets to specified ports (default: 80 if not specified, Nmap default discovery uses 443). Response (SYN/ACK for open, RST for closed) confirms host is up.
        💻 `nmap -sn -PS80,443,8080 <TARGET_IP_OR_RANGE>` (Requires root for raw SYN)
        💡 Often effective as firewalls typically allow SYN packets to common web ports (80, 443). Good alternative when ICMP is blocked.
    * **TCP ACK Ping (`-PA<portlist>`):** Sends TCP ACK packets (default: 80). Active hosts should respond with RST.
        💻 `nmap -sn -PA21,22,23,80,443 <TARGET_IP_OR_RANGE>` (Requires root for raw ACK)
        💡 Can bypass some *stateless* firewalls that filter SYN but allow ACK (assuming part of an existing connection).
    * **TCP Connect Ping (Non-root fallback):** Nmap uses the `connect()` system call to attempt full TCP handshakes on common ports (default discovery uses 80, 443) if raw packet privileges are unavailable. More "noisy" and easily logged.
* **UDP Ping (`-PU<portlist>`)**
    * **Mechanism:** Sends UDP packets to specified ports (default: 40125). Expects UDP response (port open) or ICMP Port Unreachable (port closed).
        💻 `nmap -sn -PU53,161,137 <TARGET_IP_OR_RANGE>` (Requires root)
    * ⚠️ Less reliable due to UDP's connectionless nature. Lack of response is ambiguous (host down, packet loss, or firewall drop). Can be useful if TCP/ICMP are blocked but specific UDP services (like DNS on 53) are allowed.

#### 4. Nmap Host Discovery Workflow & Key Options

* **Default Nmap Behavior:** Nmap performs host discovery *before* port scanning unless `-Pn` is used.
    * **Root on Local Network:** ARP scan (`-PR`).
    * **Root on Remote Network:** ICMP Echo (`-PE`), TCP SYN to 443 (`-PS443`), TCP ACK to 80 (`-PA80`), ICMP Timestamp (`-PP`).
    * **Non-Root User:** TCP Connect scan to ports 80 and 443.
* **Core Discovery Options:**
    * 💻 `nmap -sn <TARGETS>`: **Ping Scan.** Performs *only* host discovery using default or specified probes. Does not port scan. Ideal first step.
    * 💻 `nmap -Pn <TARGETS>`: **No Ping.** Skips host discovery entirely and assumes all targets are online. Proceeds directly to port scan, etc. 💡 Essential when discovery probes are blocked or you *know* the targets are up. Critical in many HTB/THM scenarios where boxes block pings.
    * 💻 `nmap -sL <TARGETS>`: **List Scan.** Lists targets within the range and performs reverse DNS lookup (unless `-n`). Sends *no* packets to targets. Good for scope verification.
    * 💻 `nmap -n <TARGETS>`: **No DNS Resolution.** Speeds up scans, avoids DNS logs. Recommended unless hostnames are crucial.
    * 💻 `nmap --disable-arp-ping <TARGETS>`: Forces IP-level probes (ICMP, TCP, UDP) even on a local network. Useful for testing firewall rules bypassing ARP.
* **Combining Probes:** Nmap uses multiple probes by default. You can specify exact probes:
    💻 `nmap -sn -PS80 -PA22 -PE <TARGETS>` (Use TCP SYN to 80, TCP ACK to 22, and ICMP Echo)
* **Outputting Live Hosts:**
    💻 `nmap -sn <TARGETS> -oG - | awk '/Up$/{print $2}' > live_hosts.txt` (Grepable output, extract IPs of hosts marked 'Up')

#### 5. Specialized & High-Speed Tools

* **Netdiscover / Arp-scan (Local Network):**
    💻 `sudo netdiscover -r 192.168.1.0/24` (Active ARP scan)
    💻 `sudo netdiscover -p` (Passive ARP listening)
    💻 `sudo arp-scan -l` or `sudo arp-scan -I eth0 --localnet`
    💡 Very fast for finding local IPs. Often the first command run in a CTF lab environment.
* **Masscan (Large Networks):**
    💻 `sudo masscan <RANGE> -p<PORTS> --rate <PACKETS_PER_SEC>` (e.g., `10.0.0.0/8 -p80,443 --rate 10000`)
    💻 `sudo masscan -iL targets.txt -p22,80 --rate 5000 -oL results.list` (Scan list, specific ports, output live hosts/ports)
    💡 Sacrifices features for speed. Excellent for quickly finding specific open ports across huge IP ranges. Often used before Nmap for targeted follow-up scans on identified hosts.

#### 6. Challenges & Evasion Techniques

* **Firewalls/IDS/IPS:** The main obstacle. Block specific protocols (ICMP), ports, or packet types (SYN). Detect scan patterns.
* **Ambiguity:** No response doesn't always mean host is down (packet loss, silent firewall drops, especially with UDP).
* **Nmap Evasion Options:**
    * **Timing (`-T<0-5>`):** Control scan speed. `-T0` (paranoid), `-T1` (sneaky), `-T2` (polite) are slower/stealthier. `-T4` (aggressive), `-T5` (insane) are faster but noisy. Default is `-T3` (normal).
        💻 `nmap -sn -T2 <TARGETS>` (Slower, potentially less detectable scan)
    * **Skip Ping (`-Pn`):** Assume hosts are up if discovery is blocked.
    * **Probe Selection:** Use probes likely allowed (`-PS80,443`, `-PA80`) instead of easily blocked ones (`-PE`).
    * **Decoys (`-D <decoy1,decoy2,ME,...>` or `-D RND:10`):** Obscure source IP among fake ones (`ME` represents your real IP).
        💻 `nmap -sn -D RND:5 <TARGETS>`
    * **Source Port Spoofing (`-g` or `--source-port <port>`):** Send probes from common ports (e.g., 53, 80). May bypass some firewall rules.
        💻 `nmap -sn -g 53 <TARGETS>`
    * **Packet Fragmentation (`-f`, `--mtu <offset>`):** Split probe packets. Can evade some signature-based detection.
        💻 `nmap -sn -f <TARGETS>`
    * **No DNS/ARP (`-n`, `--disable-arp-ping`):** Reduce network noise.

#### 7. Scenarios & Examples (📖)

* 📖 **Scenario: Internal Pentest / CTF Lab (Local Network)**
    1.  Find your own IP (`ip a`). Identify subnet (e.g., 192.168.1.0/24).
    2.  Try `sudo netdiscover -r 192.168.1.0/24` or `sudo arp-scan -l`.
    3.  Alternatively: `sudo nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}'` (Nmap uses ARP here).
    4.  Result: Quick list of live IPs on the local segment.
* 📖 **Scenario: External Network / Blocked ICMP**
    1.  Default `nmap -sn <REMOTE_RANGE>` seems to miss hosts.
    2.  Hypothesis: ICMP is blocked, but web ports might be open.
    3.  Try TCP SYN/ACK probes: `nmap -sn -PS80,443 -PA80,443 <REMOTE_RANGE>`
    4.  If still no results: Consider `-Pn` and scan likely ports directly, assuming hosts are up but stealthy: `nmap -Pn -p 21,22,80,443 --open <REMOTE_RANGE>`

#### 8. Common Pitfalls & Pro Tips (⚠️, 💡)

* ⚠️ **Assuming No Reply = Offline:** Especially with UDP or heavy filtering, lack of response is unreliable. Try different probe types or `-Pn`.
* ⚠️ **Scope Definition:** Ensure target ranges are correct. Use `-sL` to verify before active scanning.
* ⚠️ **Privileges:** Many advanced/stealthy techniques (`-PE`, `-PS`, `-PA`, `-PU`, `-PR`) require root/administrator privileges. Non-root scans are limited and often noisier.
* ⚠️ **Network Impact:** Aggressive scans (`-T4`/`-T5`, `masscan` high rates) can overload networks or crash unstable devices. Respect Rules of Engagement.
* 💡 **Pro Tip (HTB/THM):** Start local scans with `netdiscover` or `arp-scan`. If `nmap` finds nothing initially, immediately try `nmap -Pn ...` as ping/discovery blocking is very common.
* 💡 **Pro Tip:** Always use `-n` unless you specifically need hostnames (can slow down scans and leave DNS traces).
* 💡 **Pro Tip:** Combine host discovery with initial port check: `nmap -sn -PS80,443 --open <RANGE>` (Reports hosts responding to SYN on 80/443, implies web server might be present).
* 💡 **Pro Tip:** Output live hosts to a file for subsequent targeted scans: `nmap -sn <RANGE> -oN nmap_livediscovery.txt; grep "Nmap scan report for" nmap_livediscovery.txt | cut -d " " -f 5 > live_hosts.txt`

#### 9. Practice Links (🎯)

* **HTB Academy:** Network Enumeration with Nmap module.
* **THM:** Nmap room, Network Security pathway, Intro to LAN room.
* **HTB Boxes:** Essential for almost all boxes. Starting Point tier often requires local discovery. Boxes like `Blue`, `Lame`, `Legacy` involve scanning Windows/Linux hosts.
* **VulnHub:** Many VMs require initial host discovery within a local network (e.g., Kioptrix).

#### 10. Suggested Next Steps & Cross-References (💡, 🔗)

* **Input Live Hosts List:** Use the generated list (`live_hosts.txt`) as input for detailed scanning:
    💻 `nmap -sV -sC -p- -iL live_hosts.txt -oA full_scan`
* **Port Scanning:** The immediate next step after identifying live hosts. 🔗 `[See Section X.Y: TCP Port Scanning Techniques]` & 🔗 `[See Section X.Y: UDP Port Scanning Techniques]`
* **Service Enumeration:** Identify services and versions running on open ports. 🔗 `[See Section X.Y: Service Enumeration]`
* **OS Detection:** Attempt to identify the operating system. 🔗 `[See Section X.Y: OS Fingerprinting]`
* **Vulnerability Analysis:** Based on identified services/versions. 🔗 `[See Section X.Y: Vulnerability Scanning]`
