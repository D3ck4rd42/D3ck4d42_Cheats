# Summary

### 🚀 Introduction & Winning Strategy

* [0. How to Use & Winning Strategy](00_introduction/README.md)
    * [How to Leverage This Cheatsheet](00_introduction/how_to_leverage.md)  _(Includes Visual Markers Axis 1)_
    * [Effective CTF Philosophy & Mindset](00_introduction/philosophy_mindset.md)
    * [Optimal Environment & Structured Note-Taking](00_introduction/environment_notes.md)

### 🧠 Phase 1: Reconnaissance & Enumeration

* [1. Reconnaissance & Enumeration: The Map](01_recon_enum/README.md)
    * [1.1 Passive Reconnaissance & OSINT](01_recon_enum/1.1_passive_recon_osint/README.md)
        * [DNS Lookups & Whois](01_recon_enum/1.1_passive_recon_osint/dns_whois.md)
        * [Subdomain Enumeration](01_recon_enum/1.1_passive_recon_osint/subdomain_enum.md)
        * [OSINT Techniques](01_recon_enum/1.1_passive_recon_osint/osint_techniques.md) _(Google Dorks, Leak DBs...)_
    * [1.2 Initial Active Network Scanning](01_recon_enum/1.2_initial_active_scan/README.md)
        * [Port Scanning](01_recon_enum/1.2_initial_active_scan/port_scanning.md) _(Nmap, Masscan, RustScan)_
        * [Host Discovery](01_recon_enum/1.2_initial_active_scan/host_discovery.md) _(Ping Sweep, ARP Scan)_
        * [Banner Grabbing & Service ID](01_recon_enum/1.2_initial_active_scan/banner_grabbing.md)
    * [1.3 Enumerating Classic Network Services](01_recon_enum/1.3_classic_services/README.md)
        * [FTP (21)](01_recon_enum/1.3_classic_services/ftp.md)
        * [SSH (22)](01_recon_enum/1.3_classic_services/ssh.md)
        * [Telnet (23)](01_recon_enum/1.3_classic_services/telnet.md)
        * [SMTP (25)](01_recon_enum/1.3_classic_services/smtp.md)
        * [DNS (53)](01_recon_enum/1.3_classic_services/dns.md)
        * [SMB / NetBIOS (139/445)](01_recon_enum/1.3_classic_services/smb_netbios.md)
        * [SNMP (161)](01_recon_enum/1.3_classic_services/snmp.md)
        * [LDAP (389/636)](01_recon_enum/1.3_classic_services/ldap.md)
        * [NFS (2049)](01_recon_enum/1.3_classic_services/nfs.md)
        * [SQL (MySQL 3306, MSSQL 1433...)](01_recon_enum/1.3_classic_services/sql.md)
        * [RDP (3389)](01_recon_enum/1.3_classic_services/rdp.md)
        * [Other Services (POP3, IMAP, Proxy...)](01_recon_enum/1.3_classic_services/other_services.md)
    * [1.4 Enumerating Web Applications (HTTP/HTTPS)](01_recon_enum/1.4_enum_web_apps/README.md)
        * [Directory & File Enumeration](01_recon_enum/1.4_enum_web_apps/dir_file_enum.md) _(Dirbusting)_
        * [Technology & CMS Scanning](01_recon_enum/1.4_enum_web_apps/tech_cms_scan.md)
        * [Form & Parameter Enumeration](01_recon_enum/1.4_enum_web_apps/form_param_enum.md)
        * [Web Authentication Bruteforce](01_recon_enum/1.4_enum_web_apps/web_auth_bruteforce.md)
    * [Thematic Connections (Recon/Enum)](01_recon_enum/thematic_connections_recon.md) _(Axis 2)_

### 🔥 Phase 2: Exploitation

* [2. Exploitation: Breaching the Door](02_exploitation/README.md)
    * [2.1 Common Web Attacks](02_exploitation/2.1_web_attacks/README.md)
        * [SQL Injection (SQLi)](02_exploitation/2.1_web_attacks/sqli.md)
        * [Cross-Site Scripting (XSS)](02_exploitation/2.1_web_attacks/xss.md)
        * [File Inclusion (LFI/RFI)](02_exploitation/2.1_web_attacks/file_inclusion.md)
        * [Command Injection](02_exploitation/2.1_web_attacks/command_injection.md)
        * [Insecure File Upload](02_exploitation/2.1_web_attacks/file_upload.md)
        * [Insecure Deserialization](02_exploitation/2.1_web_attacks/deserialization.md)
        * [Server-Side Request Forgery (SSRF)](02_exploitation/2.1_web_attacks/ssrf.md)
        * [XML External Entity (XXE)](02_exploitation/2.1_web_attacks/xxe.md)
        * [Other Web Vulns (CSRF, IDOR...)](02_exploitation/2.1_web_attacks/other_web_vulns.md)
    * [2.2 Exploiting Network & System Services](02_exploitation/2.2_exploit_services/README.md)
        * [Simple Buffer Overflows (Stack BOF)](02_exploitation/2.2_exploit_services/buffer_overflow.md)
        * [Using Public Exploits](02_exploitation/2.2_exploit_services/public_exploits.md) _(Searchsploit, Metasploit)_
        * [Online Brute Force Attacks](02_exploitation/2.2_exploit_services/bruteforce.md) _(Hydra, Medusa)_
    * [2.3 Obtaining & Stabilizing Shells](02_exploitation/2.3_get_stabilize_shells.md) _(Reverse/Bind Shells, Web Shells, TTY Upgrade...)_
    * [2.4 Living Off The Land (LotL) - Initial](02_exploitation/2.4_lotl_initial.md)
    * [Thematic Connections (Exploitation)](02_exploitation/thematic_connections_exploit.md) _(Axis 2)_

### 🚀 Phase 3: Post-Exploitation, Persistence & Elevation

* [3. Post-Exploitation & Elevation: Taking the Castle](03_post_exploitation/README.md)
    * [3.1 Systematic Local Enumeration](03_post_exploitation/3.1_local_enumeration.md) _(LinPEAS, WinPEAS, Manual Enum...)_
    * [3.2 Privilege Escalation (PrivEsc) - Linux](03_post_exploitation/3.2_privesc_linux/README.md)
        * [Sudo Misconfigurations](03_post_exploitation/3.2_privesc_linux/sudo_rules.md)
        * [SUID / SGID Binaries](03_post_exploitation/3.2_privesc_linux/suid_sgid.md)
        * [Cron Jobs](03_post_exploitation/3.2_privesc_linux/cron_jobs.md)
        * [Capabilities Abuse](03_post_exploitation/3.2_privesc_linux/capabilities.md)
        * [Kernel Exploits (Linux)](03_post_exploitation/3.2_privesc_linux/kernel_exploits.md)
        * [Service Misconfigurations (Linux)](03_post_exploitation/3.2_privesc_linux/service_misconfigs.md)
        * [Credential Searching (Linux)](03_post_exploitation/3.2_privesc_linux/credential_search_linux.md)
        * [Container Escapes (Docker, LXC)](03_post_exploitation/3.2_privesc_linux/container_escapes.md)
    * [3.3 Privilege Escalation (PrivEsc) - Windows](03_post_exploitation/3.3_privesc_windows/README.md)
        * [Service Permissions & Unquoted Paths](03_post_exploitation/3.3_privesc_windows/service_perms_paths.md)
        * [Registry Misconfigurations](03_post_exploitation/3.3_privesc_windows/registry_keys.md) _(AlwaysInstallElevated, Autoruns)_
        * [Scheduled Tasks](03_post_exploitation/3.3_privesc_windows/scheduled_tasks.md)
        * [DLL Hijacking](03_post_exploitation/3.3_privesc_windows/dll_hijacking.md)
        * [Token Impersonation / Abuse](03_post_exploitation/3.3_privesc_windows/token_impersonation.md) _(Potatoes)_
        * [Stored Credentials (Windows)](03_post_exploitation/3.3_privesc_windows/stored_credentials_win.md) _(SAM, LSA, Vault)_
        * [Software Vulns & UAC Bypasses](03_post_exploitation/3.3_privesc_windows/software_vulns_uac.md)
    * [3.4 Active Directory Attacks & PrivEsc](03_post_exploitation/3.4_ad_attacks/README.md)
        * [AD Enumeration & Mapping](03_post_exploitation/3.4_ad_attacks/ad_enum_mapping.md) _(PowerView, BloodHound)_
        * [Kerberos Attacks](03_post_exploitation/3.4_ad_attacks/kerberos_attacks.md) _(ASREPRoast, Kerberoasting)_
        * [NTLM Relaying & Pass-the-Hash](03_post_exploitation/3.4_ad_attacks/ntlm_relay_pth.md) _(Responder, Impacket)_
        * [Ticket Abuse](03_post_exploitation/3.4_ad_attacks/ticket_abuse.md) _(Pass-the-Ticket, Silver/Golden Tickets)_
        * [Domain Compromise Techniques](03_post_exploitation/3.4_ad_attacks/domain_compromise.md) _(DCSync, Skeleton Key...)_
        * [Delegation & Trust Abuse](03_post_exploitation/3.4_ad_attacks/delegation_trusts.md)
    * [3.5 Credential Harvesting](03_post_exploitation/3.5_credential_harvesting.md) _(Mimikatz, SAM/Shadow Dump, Keys, Tokens, Browser...)_
    * [3.6 Lateral Movement & Pivoting](03_post_exploitation/3.6_lateral_movement/README.md)
        * [Port Forwarding](03_post_exploitation/3.6_lateral_movement/port_forwarding.md) _(SSH -L/-R)_
        * [Tunneling & Proxying](03_post_exploitation/3.6_lateral_movement/tunneling_proxying.md) _(SOCKS, Chisel, SSHuttle)_
        * [Remote Execution](03_post_exploitation/3.6_lateral_movement/remote_execution.md) _(PsExec, WinRM, WMI, SSH)_
        * [Pivoting Tooling](03_post_exploitation/3.6_lateral_movement/tooling_pivoting.md) _(ProxyChains, Metasploit Route)_
    * [3.7 Persistence (Maintaining Access)](03_post_exploitation/3.7_persistence/README.md)
        * [Windows Persistence](03_post_exploitation/3.7_persistence/windows.md) _(User, Services, Run Keys, Tasks, WMI...)_
        * [Linux Persistence](03_post_exploitation/3.7_persistence/linux.md) _(SSH Keys, Cron, Services, Alias, SUID...)_
    * [3.8 Exfiltration & CTF Goals](03_post_exploitation/3.8_exfiltration_ctf_goals.md) _(Data Discovery, Transfer Methods, Compression...)_
    * [3.9 Stealth & Cleaning Tracks](03_post_exploitation/3.9_stealth_cleaning_tracks.md) _(Logs, Hidden Files, Encrypted Channels...)_
    * [Thematic Connections (Post-Exploit)](03_post_exploitation/thematic_connections_postexploit.md) _(Axis 2)_

### 🛠️ Phase 4: Arsenal, Transversal Techniques & Bypasses

* [4. Arsenal & Transversal Techniques](04_arsenal_transversal/README.md)
    * [4.1 Essential Tools & Useful Commands](04_arsenal_transversal/4.1_essential_tools.md) _(List and categorize major tools here)_
    * [4.2 AV / EDR Evasion](04_arsenal_transversal/4.2_av_edr_evasion/README.md)
        * [Obfuscation & Encoding](04_arsenal_transversal/4.2_av_edr_evasion/obfuscation_encoding.md) _(AMSI Bypass)_
        * [In-Memory Execution](04_arsenal_transversal/4.2_av_edr_evasion/in_memory_execution.md) _(Shellcode Injection)_
        * [Living Off The Land Binaries (LOLBins)](04_arsenal_transversal/4.2_av_edr_evasion/lolbins.md)
        * [Payload Generation & Modification](04_arsenal_transversal/4.2_av_edr_evasion/payload_generation.md) _(Veil, Shellter)_
    * [4.3 Automation & Scripting (CTF)](04_arsenal_transversal/4.3_automation_scripting.md) _(Python requests, Bash Templates...)_
    * [4.4 Crypto & Stego (CTF)](04_arsenal_transversal/4.4_crypto_stego.md) _(CyberChef, Ciphey, Recognition...)_
    * [4.5 Tooling Intelligence & Effective Choices](04_arsenal_transversal/4.5_tooling_intelligence.md)
    * [4.6 AI in Pentest/CTF](04_arsenal_transversal/4.6_ai_pentest_ctf.md)

### 🔍 Phase 5: Index & Matrices

* [5. Thematic Index & Attack Matrix](05_index_matrix/README.md) _(Axis 2)_
    * [Index by Service / Port](05_index_matrix/index_service_port.md)
    * [Index by Vulnerability / Technique](05_index_matrix/index_vuln_technique.md)
    * [Technology -> Common Vectors Matrix](05_index_matrix/matrix_tech_vectors.md)

### 📚 Phase 6: Appendices

* [6. Appendices](06_appendices/README.md)
    * [Glossary](06_appendices/glossary.md)
    * [Essential Links](06_appendices/essential_links.md)
    * [Guided Learning Path (HTB/THM)](06_appendices/learning_path.md) _(Axis 3)_
    * [Acknowledgements / Contributors](06_appendices/acknowledgements.md) 