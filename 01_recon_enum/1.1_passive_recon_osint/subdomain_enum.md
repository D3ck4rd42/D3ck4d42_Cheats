### **Subdomain Enumeration – Essential Tools & Commands**

💡 Goal: Identify valid subdomains for a target domain to expand the attack surface. Crucial for finding hidden applications, APIs, or staging environments in Pentesters & CTFs (HTB/THM). Combines passive (OSINT) and active (DNS querying/brute-force) techniques.

#### Key Tools

* **Amass:** Comprehensive OSINT, active enumeration, and brute-forcing.
* **Subfinder:** Fast passive OSINT discovery (ProjectDiscovery).
* **Assetfinder:** Simple, quick OSINT discovery (mainly cert transparency).
* **dnsenum:** Perl script for DNS info gathering & brute-force.
* **DNSRecon:** Python script for DNS enumeration, records check, AXFR, brute-force.
* **crt.sh:** Web service & CLI access for Certificate Transparency logs.
* **DNSX:** DNS resolver & toolkit, good for validation & filtering (ProjectDiscovery).

#### Core Techniques & Workflow

##### 1. Passive Reconnaissance (OSINT - Stealthy)

* **Amass (Passive):** Gather subdomains using only external data sources.
    💻 `amass enum -passive -norecursive -noalts -d target.htb -o amass_passive.txt`
    💡 Use `-passive` when avoiding direct contact with target infrastructure is critical (e.g., strict ROE, initial stealth phase). `-norecursive` and `-noalts` ensure purely OSINT findings without generating extra names.

* **Subfinder (Passive - Fast):** Quickly query multiple online APIs & services.
    💻 `subfinder -d target.htb -all -o subfinder_passive.txt`
    💡 `-all` uses all configured sources (slower but more comprehensive). Configure API keys in `~/.config/subfinder/config.yaml` for max results (Shodan, VT, etc.).
    💡 **Pro Tip:** Subfinder is often the fastest way to get an initial passive list on HTB/THM boxes.

* **Assetfinder (Passive - Cert Focused):** Scrapes public datasets, primarily certificates.
    💻 `assetfinder --subs-only target.htb | anew assetfinder_passive.txt`
    💡 `anew` (from Tomnomnom's tools) appends unique lines. Assetfinder is very fast but may include wildcards (`*.target.htb`).
    ⚠️ Filter wildcards: `assetfinder --subs-only target.htb | grep -v '*' | anew assetfinder_passive.txt`

* **crt.sh (Passive - Cert Specific):** Directly query Certificate Transparency logs.
    💻 `curl -s "https://crt.sh?q=%.target.htb&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew crtsh_subs.txt`
    💡 This `curl` command fetches, extracts names using `jq`, removes leading `*.` wildcard indicators, sorts uniquely, and appends. Excellent for finding internal/dev names exposed via certs.

##### 2. Active Reconnaissance (Direct Interaction - Noisier)

* **Amass (Active):** Combine OSINT with active DNS resolution, AXFR checks, cert scraping etc.
    💻 `amass enum -active -d target.htb -o amass_active.txt`
    💡 Finds more subdomains than passive, including unindexed ones, but directly queries target DNS. Use when allowed by ROE.

* **Amass (Brute-Force):** Dictionary attack combined with enumeration.
    💻 `amass enum -brute -w /path/to/subdomains.txt -d target.htb -o amass_brute.txt`
    💡 Requires a good wordlist (`-w`). SecLists has excellent subdomain lists (e.g., `Discovery/DNS/subdomains-top1million-5000.txt`).
    💡 **Pro Tip:** Amass can use permutations (`-alts`) and alterations (`-aw /path/to/alterations.txt`) to generate more candidates based on discovered names (e.g., dev-, staging-, api-).

* **dnsenum (Brute-Force & DNS Checks):** Classic tool for DNS enumeration.
    💻 `dnsenum --noreverse -f /path/to/subdomains.txt -o dnsenum_results.xml target.htb`
    💡 Uses wordlist (`-f`) for brute-force. `--noreverse` speeds it up by skipping PTR lookups. Automatically attempts AXFR. Output can be XML (`-o`).
    ⚠️ Default wordlist is small; always provide a custom one with `-f`. Watch out for wildcard domains potentially causing false positives (test resolving a random non-existent subdomain).

* **DNSRecon (Brute-Force & Specific Checks):** Flexible DNS tool.
    💻 `dnsrecon -d target.htb -D /path/to/subdomains.txt -t brt -j dnsrecon_brute.json`
    💡 `-t brt` enables brute-force using the dictionary specified by `-D`. Saves output as JSON (`-j`).
    ⚠️ DNSRecon doesn't automatically filter wildcards in brute-force mode; manually verify results if many subdomains resolve to the same IP.

* **DNSX (Active Brute-Force & Validation):** Resolve generated names.
    💻 `dnsx -d target.htb -w /path/to/names.txt -a -aaaa -cname -resp -silent -o dnsx_brute.txt`
    💡 Brute-forces using `-w` wordlist, checks A (`-a`), AAAA (`-aaaa`), CNAME (`-cname`), includes response data (`-resp`), and saves results. Auto-detects and filters wildcards.
    💡 **Pro Tip:** Excellent for validating lists from other tools or directly brute-forcing with high concurrency (`-t 100`). Use `-rL /path/to/resolvers.txt` with a list of reliable public/private DNS resolvers for better speed and reliability.

##### 3. Advanced Techniques & Zone Transfers

* **AXFR (Zone Transfer) Check:** Attempt to download the entire DNS zone.
    💻 `dig axfr @ns1.target.htb target.htb` (Classic `dig` command)
    💻 `dnsrecon -d target.htb -t axfr` (Checks all NS servers for the domain)
    💻 `dnsenum --dnsserver ns1.target.htb target.htb` (Also attempts AXFR)
    💡 Rarely successful on properly configured servers but provides *all* DNS records if it works. A goldmine in CTFs where it's sometimes intentionally enabled.

* **DNSSEC Zone Walking (NSEC/NSEC3):** Exploit DNSSEC records to enumerate zone contents (if NSEC is used).
    💻 `dnsrecon -d target.htb -t zonewalk`
    💻 `ldns-walk @ns1.target.htb target.htb` (Requires `ldnsutils`)
    💡 Less common than AXFR, relies on specific DNSSEC configurations (NSEC). NSEC3 makes this much harder.

#### Scenarios & Examples (📖)

* 📖 **Scenario 1 (Initial Foothold - HTB/THM):** Target `megacorp.htb`. Start passively.
    1.  Run `subfinder -d megacorp.htb -o subs_passive.txt`.
    2.  Run `assetfinder --subs-only megacorp.htb | grep -v '*' | anew subs_passive.txt`.
    3.  Run `amass enum -passive -d megacorp.htb | anew subs_passive.txt`.
    4.  Validate live hosts: `cat subs_passive.txt | dnsx -silent -a -resp -o subs_live.txt`.
    5.  Feed `subs_live.txt` into HTTP probing: `cat subs_live.txt | httpx -silent -title -status-code -o web_hosts.txt`.
    💡 Look for interesting names like `dev.*`, `staging.*`, `vpn.*`, `internal.*`, `api.*`.

* 📖 **Scenario 2 (Deep Dive - Allowed Active):** Target `corp.com`. Passive recon done, need more.
    1.  Combine passive lists: `cat *_passive.txt | sort -u > all_passive.txt`.
    2.  Run Amass active: `amass enum -active -d corp.com -o amass_active.txt`.
    3.  Run Amass brute-force: `amass enum -brute -w ~/SecLists/Discovery/DNS/subdomains-top1million-10000.txt -d corp.com -o amass_brute.txt`.
    4.  Combine all results: `cat all_passive.txt amass_active.txt amass_brute.txt | sort -u > all_subs_combined.txt`.
    5.  Validate & get IPs: `dnsx -l all_subs_combined.txt -a -resp -o final_live_subs.txt`.
    💡 This comprehensive approach maximizes discovery but is noisy.

#### Common Pitfalls & Pro Tips (⚠️ / 💡)

* ⚠️ **Wildcard DNS:** Many domains resolve `*.domain.com` to a single IP (e.g., parking page). Tools like `dnsx` and recent `amass` versions try to detect this automatically. Always manually check by resolving a random non-existent subdomain (e.g., `dig th1s1sn0t4re4lsubd0main.target.htb`). If it resolves, wildcard is likely active.
* ⚠️ **Rate Limiting:** Aggressive brute-forcing or querying APIs can get your IP blocked or rate-limited. Use sensible thread counts (`-t` in `dnsx`, `-threads` in `subfinder`), configure API keys (`subfinder`, `amass`), and consider using proxy/VPN rotations for large scans.
* ⚠️ **Scope Creep:** Ensure discovered subdomains belong to the target organization and are within the pentest/CTF scope. Subdomains might point to third-party services.
* 💡 **Combine Tools:** No single tool finds everything. Combine outputs from passive tools (`subfinder`, `assetfinder`, `amass passive`, `crt.sh`) then validate/enrich with active methods (`amass active`/`brute`, `dnsx`, `dnsrecon`). Use `anew` or `sort -u` to merge lists.
* 💡 **Custom Wordlists:** Supplement standard lists (SecLists) with target-specific words (company name variations, product names, discovered usernames/groups). Tools like `commonspeak2` can help generate these.
* 💡 **Resolver Lists:** Using a large, reliable list of public DNS resolvers (`-rL` in `dnsx`, configured in `amass`) improves speed and success rate, bypassing potential blocks on single resolvers. Public lists are available online (e.g., Trickest's `resolvers.txt`).
* 💡 **Recursive Enumeration:** Once you find `dev.target.htb`, try enumerating subdomains of that too (e.g., `api.dev.target.htb`). Some tools do this recursively (`amass`).
* 💡 **Virtual Host (VHost) Discovery:** Use your subdomain list to check if multiple domains resolve to the same IP but serve different web content.
    💻 `ffuf -w final_live_subs.txt -u http://TARGET_IP -H "Host: FUZZ.target.htb" -fs <size_of_default_page>`
    🔗 `[See Section X.Y: Web Enumeration - VHost Discovery]`

#### Evasion & Defense Notes (⚠️ / 💡)

* ⚠️ **Defenses:** DNS monitoring (detecting excessive queries, AXFR attempts), rate limiting, wildcard DNS, restricted API access for OSINT sources.
* 💡 **Evasion:** Use passive methods primarily, slow down active scanning (`-t` flags), use distributed sources/IPs, leverage public resolvers (`-rL`), focus queries on specific nameservers if known.

#### Practice Links (🎯)

* 🎯 **Hack The Box Academy:** Information Gathering -> DNS Enumeration Module.
* 🎯 **TryHackMe:** Rooms like Relevant, Skynet (initial recon phases often involve subdomain finding), Introduction to Enumeration.
* 🎯 **VulnHub:** Many beginner/intermediate boxes require subdomain discovery.

#### Suggested Next Steps & Cross-References (💡 / 🔗)

* 💡 **Validate & Probe:** Use `dnsx` to resolve found domains and get IPs.
* 💡 **Port Scanning:** Feed live subdomains/IPs into Nmap or Naabu.
    💻 `cat final_live_subs.txt | dnsx -a -resp -silent | cut -d' ' -f2 | naabu -p - -silent -o ports.txt`
* 💡 **Web Enumeration:** Feed live web hosts (port 80/443) into HTTP probing tools (`httpx`, `httprobe`) and directory/file brute-forcers (`gobuster`, `ffuf`, `dirsearch`).
    💻 `cat final_live_subs.txt | httpx -silent -title -tech-detect -status-code -o web_details.txt`
    🔗 `[See Section 3.1: Port Scanning]`
    🔗 `[See Section 4.2: Web Content Discovery]`
    🔗 `[See Section 4.3: Web Technology Identification]`

---
