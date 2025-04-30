## Subdomain Enumeration – Essential Tools & Commands

> **Goal:**  
> Identify valid subdomains for a target domain to expand the attack surface. Crucial for finding hidden applications, APIs, or staging environments in pentests & CTFs (HTB/THM). Combines passive (OSINT) and active (DNS querying/brute-force) techniques.

---

### Key Tools

- **Amass**  
  Comprehensive OSINT, active enumeration, and brute-forcing.

- **Subfinder**  
  Fast passive OSINT discovery (ProjectDiscovery).

- **Assetfinder**  
  Simple, quick OSINT discovery (mainly cert transparency).

- **dnsenum**  
  Perl script for DNS info gathering & brute-force.

- **DNSRecon**  
  Python script for DNS enumeration, records check, AXFR, brute-force.

- **crt.sh**  
  Web service & CLI access for Certificate Transparency logs.

- **DNSX**  
  DNS resolver & toolkit, good for validation & filtering (ProjectDiscovery).

---

### Core Techniques & Workflow

#### 1. Passive Reconnaissance (OSINT – Stealthy)

- **Amass (Passive)**
  ```bash
  amass enum -passive -norecursive -noalts -d target.htb -o amass_passive.txt
  ```
  > Use `-passive` when avoiding direct contact with target infrastructure is critical (e.g. strict ROE, initial stealth phase).  
  > `-norecursive` and `-noalts` ensure purely OSINT findings without generating extra names.

- **Subfinder (Passive – Fast)**
  ```bash
  subfinder -d target.htb -all -o subfinder_passive.txt
  ```
  > `-all` uses all configured sources (slower but more comprehensive).  
  > Configure API keys in `~/.config/subfinder/config.yaml` for max results (Shodan, VT, etc.).  
  > **Pro Tip:** Subfinder is often the fastest way to get an initial passive list on HTB/THM boxes.

- **Assetfinder (Passive – Cert Focused)**
  ```bash
  assetfinder --subs-only target.htb | anew assetfinder_passive.txt
  ```
  > `anew` (from Tomnomnom’s tools) appends unique lines. Assetfinder is very fast but may include wildcards (`*.target.htb`).  
  > **Filter wildcards:**
  ```bash
  assetfinder --subs-only target.htb | grep -v '*' | anew assetfinder_passive.txt
  ```

- **crt.sh (Passive – Cert Specific)**
  ```bash
  curl -s "https://crt.sh?q=%.target.htb&output=json" \
    | jq -r '.[].name_value' \
    | sed 's/\*\.//g' \
    | sort -u \
    | anew crtsh_subs.txt
  ```
  > Fetches Certificate Transparency logs, strips wildcards, sorts uniquely, then appends. Excellent for finding internal/dev names exposed via certs.

#### 2. Active Reconnaissance (Direct Interaction – Noisier)

- **Amass (Active)**
  ```bash
  amass enum -active -d target.htb -o amass_active.txt
  ```
  > Finds more subdomains than passive, including unindexed ones, but directly queries target DNS. Use when allowed by ROE.

- **Amass (Brute-Force)**
  ```bash
  amass enum -brute -w /path/to/subdomains.txt -d target.htb -o amass_brute.txt
  ```
  > Requires a good wordlist (`-w`). SecLists has excellent lists (e.g. `Discovery/DNS/subdomains-top1million-5000.txt`).  
  > **Pro Tip:** Amass can use permutations (`-alts`) and alterations (`-aw /path/to/alterations.txt`) to generate more candidates based on discovered names (e.g. `dev-`, `staging-`, `api-`).

- **dnsenum (Brute-Force & DNS Checks)**
  ```bash
  dnsenum --noreverse -f /path/to/subdomains.txt -o dnsenum_results.xml target.htb
  ```
  > Uses wordlist (`-f`) for brute-force. `--noreverse` skips PTR lookups. Attempts AXFR. Output can be XML (`-o`).  
  > ⚠️ Default wordlist is small; always specify a custom one. Be wary of wildcard domains causing false positives.

- **DNSRecon (Brute-Force & Specific Checks)**
  ```bash
  dnsrecon -d target.htb -D /path/to/subdomains.txt -t brt -j dnsrecon_brute.json
  ```
  > `-t brt` enables brute-force. Saves output as JSON (`-j`).  
  > ⚠️ Doesn’t filter wildcards automatically; manually verify duplicates.

- **DNSX (Active Brute-Force & Validation)**
  ```bash
  dnsx -d target.htb -w /path/to/names.txt -a -aaaa -cname -resp -silent -o dnsx_brute.txt
  ```
  > Brute-forces using `-w`, checks A/AAAA/CNAME, includes response data. Auto-detects and filters wildcards.  
  > **Pro Tip:** Great for validating lists from other tools or high-concurrency brute-forcing (`-t 100`). Use `-rL /path/to/resolvers.txt` for reliable DNS resolvers.

#### 3. Advanced Techniques & Zone Transfers

- **AXFR (Zone Transfer) Check**
  ```bash
  dig axfr @ns1.target.htb target.htb
  dnsrecon -d target.htb -t axfr
  dnsenum --dnsserver ns1.target.htb target.htb
  ```
  > Rarely successful on properly configured servers, but yields *all* DNS records if it works.

- **DNSSEC Zone Walking (NSEC/NSEC3)**
  ```bash
  dnsrecon -d target.htb -t zonewalk
  ldns-walk @ns1.target.htb target.htb
  ```
  > Exploits DNSSEC NSEC records. NSEC3 makes this much harder.

---

### Scenarios & Examples

**Scenario 1: Initial Foothold (HTB/THM)**  
Target `megacorp.htb`. Start passively:

1. `subfinder -d megacorp.htb -o subs_passive.txt`  
2. `assetfinder --subs-only megacorp.htb | grep -v '*' | anew subs_passive.txt`  
3. `amass enum -passive -d megacorp.htb | anew subs_passive.txt`  
4. `cat subs_passive.txt \| dnsx -silent -a -resp -o subs_live.txt`  
5. `cat subs_live.txt \| httpx -silent -title -status-code -o web_hosts.txt`  

> Look for names like `dev.*`, `staging.*`, `vpn.*`, `internal.*`, `api.*`.

**Scenario 2: Deep Dive (Allowed Active)**  
Target `corp.com`. Passive done, need more:

1. `cat *_passive.txt | sort -u > all_passive.txt`  
2. `amass enum -active -d corp.com -o amass_active.txt`  
3. `amass enum -brute -w ~/SecLists/Discovery/DNS/subdomains-top1million-10000.txt -d corp.com -o amass_brute.txt`  
4. `cat all_passive.txt amass_active.txt amass_brute.txt | sort -u > all_subs_combined.txt`  
5. `dnsx -l all_subs_combined.txt -a -resp -o final_live_subs.txt`

---

### Common Pitfalls & Pro Tips

- ⚠️ **Wildcard DNS:** Test with a non-existent subdomain (e.g. `dig th1s1sn0t4re4lsubd0main.target.htb`).  
- ⚠️ **Rate Limiting:** Use sensible thread counts (`-t`), API keys, or proxy rotations.  
- ⚠️ **Scope Creep:** Verify subdomains belong to target scope.  
- 💡 **Combine Tools:** Merge passive results, then validate actively. Use `anew` or `sort -u`.  
- 💡 **Custom Wordlists:** Supplement with target-specific terms (company names, product names).  
- 💡 **Resolver Lists:** Use large, reliable public resolvers (`-rL`).  
- 💡 **Recursive Enumeration:** After finding `dev.target.htb`, enumerate its subdomains.  
- 💡 **VHost Discovery:**  
  ```bash
  ffuf -w final_live_subs.txt \
    -u http://TARGET_IP \
    -H "Host: FUZZ.target.htb" \
    -fs <size_of_default_page>
  ```

---

### Evasion & Defense Notes

- ⚠️ **Defenses:** DNS monitoring, rate limiting, wildcard DNS, restricted API access.  
- 💡 **Evasion:** Rely on passive methods, slow scanning, distribute queries, use public resolvers, target specific name servers.

---

### Practice Links

- 🔗 Hack The Box Academy: DNS Enumeration Module  
- 🔗 TryHackMe: “Relevant”, “Skynet” rooms  
- 🔗 VulnHub: Beginner/intermediate boxes often require subdomain discovery

---

### Suggested Next Steps & Cross-References

- **Validate & Probe:** Use `dnsx` to resolve domains and get IPs.  
- **Port Scanning:**  
  ```bash
  cat final_live_subs.txt \
    | dnsx -a -resp -silent \
    | cut -d' ' -f2 \
    | naabu -p - -silent -o ports.txt
  ```
- **Web Enumeration:**  
  ```bash
  cat final_live_subs.txt \
    | httpx -silent -title -tech-detect -status-code -o web_details.txt
  ```
- See also:  
  - Section 3.1: Port Scanning  
  - Section 4.2: Web Content Discovery  
  - Section 4.3: Web Technology Identification  
```
