Passive Reconnaissance & OSINT CheatsheetPassive reconnaissance, often intertwined with Open Source Intelligence (OSINT), forms the bedrock of any effective penetration test or Capture The Flag (CTF) engagement. It involves gathering information about a target from publicly available sources without directly interacting with the target's systems, thereby avoiding detection. This crucial initial phase aims to map the target's external footprint, identify potential entry points, understand its infrastructure, and gather intelligence on its personnel and technologies. A thorough passive reconnaissance phase significantly increases the chances of success in subsequent active phases.WHOIS LookupsConcept/Goal: Obtain domain registration information to understand ownership, administrative contacts, associated network infrastructure (like ASNs), and the domain's operational status. This is often the very first step when reconnaissance begins with a domain name.1Key Tools:
whois (Command-Line): The standard utility, typically pre-installed on Linux and macOS distributions.1
Online Lookups: Numerous web-based services provide WHOIS information, often aggregating data or offering cleaner interfaces. Examples include ICANN Lookup (lookup.icann.org), registrar-specific tools (Namecheap, GoDaddy), and aggregators like whois.domaintools.com, viewdns.info, whois.net, pentest-tools.com/utils/whois-lookup-online.1
Core Techniques:
Basic Query: The simplest form, querying the default WHOIS servers.
💻 whois targetdomain.com 1
Specify WHOIS Server: If the default query yields minimal information or fails, specifying a Regional Internet Registry (RIR) like ARIN, APNIC, RIPE, LACNIC, or the domain's specific registrar server using the -h flag can provide more detailed or accurate data.1
💻 whois targetdomain.com -h whois.arin.net
💻 whois targetdomain.com -h whois.godaddy.com 1
Verbose Output: Some whois client versions might support flags like -verbose for potentially more detailed output, although this is not standard across all implementations.3
Information Gathered:
Contacts: Registrant, Administrative, and Technical contact details (Name, Organization, Address, Email, Phone). However, this is the information most commonly obscured by privacy services.2
Registrar: The accredited organization that manages the domain's registration.1
Nameservers (NS): The authoritative DNS servers responsible for the domain's DNS records. This is critical information for pivoting to DNS Reconnaissance.2
Dates: Domain Creation, Expiration, and Last Updated dates. These can occasionally offer context for social engineering or indicate domain lifecycle events.2
Domain Status: Codes indicating the domain's status, such as clientTransferProhibited or serverHold.
Autonomous System Number (ASN): Often listed in the WHOIS record for the domain's hosting IP range or associated network blocks. This is a key pivot point to understanding the target's network presence.4
Pitfalls & Tips:
⚠️ Privacy Protection: A significant limitation of modern WHOIS lookups is the prevalence of privacy protection services. These services replace the actual registrant's contact information with the details of a proxy service ("redacted for privacy", "Domains By Proxy", etc.).3 Consequently, relying on WHOIS for direct contact harvesting (emails, phone numbers) is often unreliable. However, the technical information, such as the Nameservers (NS) and potentially the ASN, is fundamental to the domain's operation and network routing, making it less likely to be obscured by standard privacy services. This technical data remains a primary reason WHOIS lookups are essential for mapping infrastructure links.3
💡 ASN Pivot: The ASN identified via WHOIS is a crucial piece of intelligence. It links the abstract domain name to tangible network infrastructure. Use this ASN to query databases like bgp.he.net (e.g., bgp.he.net/ASXXXXX) or perform IP-based WHOIS lookups to identify the specific IP address ranges owned or operated by the target organization. This helps define the network scope for subsequent scanning phases.4 WHOIS effectively acts as the bridge connecting domain-level OSINT to network-level reconnaissance via the ASN.
💡 Registrar Clues: The choice of registrar might occasionally offer subtle clues about the target's size, technical maturity, or geographical location. Some registrars are also known to be more or less responsive to security issues or law enforcement requests.
⚠️ Rate Limiting/Abuse: WHOIS servers often implement rate limiting to prevent abuse. Performing high-volume, automated queries from a single IP address can lead to temporary or permanent blocks.2 Use queries judiciously or distribute them if automation is necessary.
Cross-References: 🔗 DNS Reconnaissance (using NS records found), 🔗 Network Scanning (using ASN/IP ranges identified).DNS ReconnaissanceConcept/Goal: Querying Domain Name System (DNS) servers to resolve domain names to IP addresses, discover associated services (like mail servers), understand security configurations (like SPF), and map out the target's DNS infrastructure. This involves retrieving various DNS record types.6Key Tools:
dig (Domain Information Groper): A powerful and flexible command-line tool, standard on Linux/macOS. It's preferred for detailed analysis, specific record type queries, and scripting due to its predictable output.1
nslookup: Widely available, including on Windows. Useful for basic lookups and interactive exploration, though sometimes considered less powerful or script-friendly than dig.1
host: A simple utility for quick name-to-IP and IP-to-name conversions. Its concise output makes it suitable for shell scripting.1
dnsrecon: A versatile Perl script designed for DNS enumeration. It automates common tasks like querying standard records (SOA, NS, A, MX, SRV), attempting zone transfers (AXFR), subdomain brute-forcing, reverse lookups on IP ranges, and DNS cache snooping.1
fierce: Another popular Perl script, focused on locating non-contiguous IP space and hostnames associated with a domain. It performs DNS lookups, attempts zone transfers, checks for wildcard records, and includes brute-force capabilities.1
Online Tools: Numerous websites offer DNS lookup capabilities, often presenting data visually. Examples include DNSDumpster, ViewDNS.info, HackerTarget DNS Lookup, MXToolbox, SecurityTrails DNS Trails.3
Core Techniques & Record Types:Understanding the purpose of different DNS record types is crucial for effective reconnaissance.
A Record (Address - IPv4): Maps a hostname to its 32-bit IPv4 address. Fundamental for finding server IPs.
💻 dig target.com A
💻 nslookup target.com (Default query type)
💻 host target.com (Default query type) 1
AAAA Record (Address - IPv6): Maps a hostname to its 128-bit IPv6 address. Increasingly important as IPv6 adoption grows.
💻 dig target.com AAAA 12
MX Record (Mail Exchanger): Identifies the mail servers responsible for accepting email for the domain, listed with priority values. Essential for understanding email infrastructure and planning phishing or spoofing assessments.
💻 dig target.com MX
💻 nslookup -query=mx target.com
💻 host -t mx target.com 1
TXT Record (Text): Stores arbitrary text data. Critically important for finding email security records (SPF, DKIM, DMARC), domain ownership verification tokens (Google Site Verification, Microsoft 365), and potentially other informational notes.
💻 dig target.com TXT
💻 nslookup -type=TXT target.com
💻 host -t txt target.com 1
NS Record (Nameserver): Lists the authoritative DNS servers for the domain zone. These are the primary servers to query for the most accurate information and are the targets for zone transfer attempts.
💻 dig target.com NS
💻 nslookup -query=ns target.com
💻 host -t ns target.com 1
CNAME Record (Canonical Name): Creates an alias, pointing one hostname to another (the canonical name). Useful for identifying relationships between services or tracking redirects.
💻 dig www.target.com CNAME (or just dig www.target.com)
💻 nslookup -type=CNAME www.target.com 7
SOA Record (Start of Authority): Provides administrative details about the DNS zone, including the primary nameserver, administrator's email (often obfuscated), zone serial number (indicates changes), and various timers (refresh, retry, expire).
💻 dig target.com SOA 13
PTR Record (Pointer): Performs a reverse DNS lookup, mapping an IP address back to its associated hostname. Used for validating IP ownership and mapping network infrastructure.
💻 dig -x <IP_ADDRESS>
💻 nslookup <IP_ADDRESS>
💻 host <IP_ADDRESS> 1
ANY Record: A special query type requesting all available DNS records for a name. While useful in theory, it's often blocked by servers, rate-limited, or returns incomplete results due to UDP packet size limitations or server policies. Use with caution and don't rely on it for completeness.6
💻 dig target.com ANY
💻 nslookup -type=any target.com
SRV Record (Service): Specifies the location (hostname and port) for specific services, often used by protocols like LDAP, Kerberos, SIP, XMPP. Crucial for finding internal service endpoints.
💻 dig _ldap._tcp.target.com SRV
💻 dnsrecon -d target.com -t srv 12
Specify DNS Server: Direct queries to a specific server (e.g., one of the authoritative NS found earlier, or a public resolver like Google's 8.8.8.8 or Cloudflare's 1.1.1.1).
💻 dig @ns1.target.com target.com MX
💻 nslookup target.com 8.8.8.8
💻 host target.com 1.1.1.1 1
Short Output: Get concise results, ideal for scripting or quick checks.
💻 dig target.com A +short 9
Trace Resolution: Show the delegation path from the root servers down to the authoritative nameserver for the query. Useful for debugging DNS issues.
💻 dig +trace target.com 9
Advanced Variations:
Zone Transfer (AXFR): An attempt to request a full copy of the zone database from an authoritative nameserver. If successful, this provides a complete list of all DNS records for the zone, often revealing internal or unlinked hostnames. However, AXFR is usually restricted to authorized servers only for security reasons.1 The frequent failure of AXFR attempts underscores the need for proficiency in alternative subdomain enumeration techniques, shifting the recon focus from a single high-yield (but often blocked) method to aggregating data from multiple sources like passive DNS, CT logs, and brute-forcing.6
💻 dig @ns1.target.com target.com AXFR
💻 dnsrecon -d target.com -t axfr
💻 fierce --domain target.com --dns-servers ns1.target.com
DNS Cache Snooping: A technique to infer information about a target's activity by querying a recursive DNS server (e.g., an internal resolver if accessible, or sometimes public resolvers) to see if it has recently cached records for specific domains. This can reveal internal hostnames or recently visited external sites.6
💻 dnsrecon -t snoop -n <DNS_IP> -D names_to_check.txt
DNS Banner Grabbing / Version Check: Attempting to identify the specific software and version of a DNS server. This information can be used to find known vulnerabilities.6
💻 dig @<DNS_IP> version.bind chaos txt
💻 nmap --script dns-nsid <DNS_IP>
💻 nc -nv -u <DNS_IP> 53 (followed by a version query if protocol allows)
Reverse Lookup on Range: Performing PTR lookups for an entire IP range to discover associated hostnames. Useful after identifying target network blocks via ASN lookups.1
💻 for ip in $(seq 1 254); do host 192.168.1.$ip; done | grep -v "not found"
💻 dnsrecon -r 192.168.1.0/24
Information Leakage via nslookup: A specific technique where interactive nslookup commands might trick a misconfigured DNS server into revealing its own hostname during reverse lookups of loopback or its own IP address.11
💻 nslookup > server <ip_of_target_dns> > 127.0.0.1 (Observe if hostname is revealed)
Scenarios/Examples:
📖 Mapping Core Infrastructure: Use A, AAAA, and CNAME lookups on the main domain and known subdomains (www, mail, vpn, etc.) to find primary server IP addresses.
📖 Assessing Email Security: Query MX records to find mail gateways. Query TXT records for target.com to check for SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance) policies. Weak or missing records indicate potential spoofing vulnerabilities.
📖 Finding Hidden or Internal Services: Attempt AXFR on all authoritative NS servers. Perform subdomain brute-forcing (active recon, covered later) or passive enumeration. Look for revealing TXT records or SRV records (_ldap, _kerberos, _sip, etc.).
📖 Validating Network Scope: After finding IP ranges via ASN lookup (from WHOIS), use PTR record lookups (reverse DNS) across the range to confirm which IPs resolve to hostnames within the target domain(s).
Pitfalls & Tips:
⚠️ AXFR Failure is Common: Do not expect zone transfers to succeed against external authoritative nameservers. They are almost always disabled for public access. Have alternative subdomain enumeration strategies ready.6
⚠️ ANY Query Unreliability: ANY queries are often incomplete or blocked. Query specific record types (A, MX, TXT, NS, etc.) individually for more reliable results.9
⚠️ Wildcard DNS Records: A wildcard record (e.g., *.target.com) can make subdomain brute-forcing difficult, as it causes non-existent subdomains to resolve successfully (usually to a default page or IP). Tools like dnsrecon (using --iw) and fierce attempt to detect wildcards, but manual verification might be needed.11
💡 Examine TXT Records Closely: Go beyond just checking for SPF/DKIM/DMARC. Look for domain verification strings (e.g., google-site-verification=..., MS=...), comments, service discovery hints, or potentially forgotten sensitive information.1
💡 Target Authoritative NS Servers: Always identify the authoritative nameservers for the domain using an NS lookup first. Direct your AXFR attempts and critical queries (like SOA) to these servers for the most accurate information.6
💡 Tool Selection Strategy: Use dig for detailed, controlled queries and reliable output, especially when scripting.9 Use nslookup for quick interactive checks or on systems where dig isn't available.7 Use host for simple, fast lookups, particularly in shell scripts.8 Employ tools like dnsrecon or fierce for automating multiple enumeration tasks (standard lookups, AXFR checks, brute-forcing).7 Understanding the strengths of each tool allows for an efficient workflow.
💡 Combine with Passive Discovery: Use active DNS queries (like A or CNAME lookups) to validate the existence and resolution of subdomains discovered through passive methods (CT Logs, search engines, etc.).
Table: Common DNS Record Types & Pentesting RelevanceRecord TypeFull NameDescriptionPentesting RelevanceAAddress (IPv4)Maps hostname to IPv4 addressFind server IP addresses, map infrastructureAAAAAddress (IPv6)Maps hostname to IPv6 addressFind server IPv6 addresses, map modern infrastructureCNAMECanonical NameAlias pointing a hostname to another hostnameIdentify service relationships, track redirects, find true hostnames behind aliasesMXMail ExchangerLists mail servers and their priorityIdentify email gateways, assess email infrastructure, target for phishing/spoofingNSName ServerLists authoritative DNS servers for the zoneIdentify primary DNS infra, target for AXFR, find authoritative data sourceTXTTextStores arbitrary text stringsCheck SPF/DKIM/DMARC (email security), find domain verification keys, potential info leaksSOAStart of AuthorityZone administrative info (primary NS, email, serial)Identify primary NS, admin contact (rarely useful), zone change frequency (serial)PTRPointer (Reverse DNS)Maps IP address back to a hostnameValidate IP ownership, map network blocks, identify hosts within a rangeSRVService LocatorSpecifies hostname and port for specific servicesDiscover hidden services (LDAP, Kerberos, SIP, etc.), identify internal endpointsAXFRAuthoritative Zone TransferRequest to transfer the entire zone file(If successful) Complete DNS record dump, reveals all hosts including internal/hidden onesPractice Links: 🎯 HTB Machines: Domain, Active, Haystack; THM Rooms: DNS Manipulation, Enumeration modules (e.g., Network Services, Nmap Live Host Discovery).Cross-References: 🔗 WHOIS Lookups (provides initial NS records), 🔗 Subdomain Enumeration (Passive) (provides lists to validate), 🔗 Subdomain Enumeration (Active) (brute-forcing relies on DNS), 🔗 Network Scanning (uses resolved IPs).Subdomain Enumeration (Passive)Concept/Goal: Discover subdomains associated with a target domain by querying third-party data sources and analyzing publicly available information, without sending any network traffic directly to the target's infrastructure. The primary goal is to map the potential attack surface while maintaining maximum stealth.16Key Tools & Sources:Passive subdomain enumeration relies heavily on aggregating data from diverse sources. Tools often act as frameworks to query multiple sources simultaneously.

Aggregators/Frameworks:

subfinder: A fast, popular Go-based tool. Queries numerous passive sources like Shodan, VirusTotal, Censys, crt.sh, GitHub, Wayback Machine, etc. Requires API keys for many sources to achieve comprehensive results.3
amass: An extensive OWASP framework for attack surface mapping. The amass enum -passive command specifically utilizes OSINT sources (similar to subfinder, plus WHOIS, ASN info, etc.). Also heavily reliant on API keys for effective passive scanning.15
assetfinder: A simpler Go tool by tomnomnom. Queries a smaller set of sources (crt.sh, certspotter, HackerTarget, ThreatCrowd, Wayback) and generally doesn't require API keys by default, but offers less coverage than subfinder/amass.24
theHarvester: A classic OSINT tool written in Python. Gathers emails, employee names, hosts, and subdomains from sources like search engines (Google, Bing), PGP key servers, Shodan, Hunter.io, etc..11
Sublist3r: Python tool using search engines, SSL/TLS certificates (crt.sh), and Passive DNS sources (VirusTotal, DNSDumpster).3
Knockpy: Another Python tool for subdomain discovery, including passive sources.21
OSINT Framework: A web-based collection of OSINT tools, categorized for easy discovery, including many for subdomain enumeration.15



Specific Data Sources/Techniques:

Certificate Transparency (CT) Logs: Public logs of all issued SSL/TLS certificates. Key sources: crt.sh, Censys, Facebook CT Tool.15
Search Engines: Google, Bing, DuckDuckGo, Baidu, Yandex using advanced search operators (dorks).12
Passive DNS Databases: Aggregated historical and current DNS resolution data. Key sources: VirusTotal, SecurityTrails, DNSDumpster, RiskIQ PassiveTotal, Shodan, Censys, CIRCL, Mnemonic, Netlas, BinaryEdge.3
Web Archives: Historical snapshots of websites. Key sources: Wayback Machine (Archive.org), CommonCrawl, Arquivo.pt.18
Public Code Repositories: Searching GitHub, GitLab, Bitbucket for mentions of subdomains in code or configuration files.12
WHOIS Data: Analyzing related domains or nameservers found in WHOIS records.3
Threat Intelligence Platforms: AlienVault OTX, ThreatCrowd, etc., often contain subdomain data related to malicious activity.20
Online Scanners/Aggregators: Websites like DNSDumpster, Spyse, Netcraft provide aggregated views.3


Core Techniques:
Leveraging Tool APIs: The most effective way to use tools like subfinder and amass is by configuring them with API keys for various services (VirusTotal, SecurityTrails, Shodan, Censys, GitHub, etc.). This unlocks access to vastly larger datasets than unauthenticated queries.20 The quality and quantity of discovered subdomains are directly proportional to the number and quality of API keys configured, as free tiers or unauthenticated access provide significantly limited data.18
Querying CT Logs: Utilize dedicated websites like crt.sh or tools (subfinder, amass) that integrate CT log searching capabilities.17
Search Engine Dorking: Employ specific search queries like site:*.target.com -site:www.target.com on Google, Bing, etc., to find indexed subdomains.12
Querying Passive DNS Aggregators: Use the web interfaces of services like VirusTotal or DNSDumpster, or leverage tools that query their APIs.15
Analyzing Web Archives: Use tools or manual browsing on sites like the Wayback Machine to find subdomains referenced in historical versions of websites.18
Combining Tool Outputs: Run multiple passive enumeration tools, collect their outputs into separate files, and then combine and deduplicate the results for a more comprehensive list.
💻 cat subfinder_out.txt amass_passive_out.txt assetfinder_out.txt | sort -u > unique_passive_subdomains.txt 17
Scenarios/Examples:
💻 Comprehensive Scan (Subfinder): subfinder -d target.com -all -o subfinder_out.txt (Requires API keys configured in ~/.config/subfinder/provider-config.yaml) 20
💻 Comprehensive Scan (Amass): amass enum -passive -d target.com -config /path/to/config.ini -o amass_passive_out.txt (Requires API keys configured in config.ini) 26
💻 Basic Scan (Assetfinder): assetfinder --subs-only target.com > assetfinder_out.txt (Simpler, fewer sources, no keys needed by default) 29
💻 Broader OSINT (theHarvester): theHarvester -d target.com -b all -f harvester_report.html (Finds emails, hosts too) 11
📄 Google Dork: site:*.target.com -site:www.target.com 17
📖 Manual Check: Query crt.sh website for %.target.com.32
📖 Manual Check: Search VirusTotal website for target.com and examine the 'Subdomains' or 'Relations' tab.23
Pitfalls & Tips:
⚠️ API Key Management is Crucial: The effectiveness of tools like subfinder and amass hinges on obtaining and correctly configuring API keys for sources like VirusTotal, SecurityTrails, Shodan, Censys, GitHub, etc. Store keys securely in the respective configuration files (e.g., ~/.config/subfinder/provider-config.yaml for subfinder, config.ini for amass).20
⚠️ Stale Data: Passive sources often contain historical records. Subdomains found might no longer be active or resolve. Validation is essential.17
⚠️ Rate Limiting: Public websites and free API tiers impose request limits. Excessive querying can lead to temporary blocks or incomplete results. Pace your queries or use tools with built-in delay/retry logic.2
💡 Aggregate, Aggregate, Aggregate: No single tool or source provides a complete picture. The best results come from running multiple tools/queries against diverse sources and combining the unique findings.17
💡 Source Diversity Matters: Ensure your chosen tools query different types of passive data (CT Logs, Passive DNS, Search Engines, Web Archives, Code Repos) for maximum coverage.22
💡 Check for Recursive Discovery: Some tools (subfinder -recursive, amass) can attempt to find sub-subdomains (e.g., dev.team.target.com). Explore tool options for this capability.20
💡 Validation is the Next Step: Passively discovered subdomains are merely potential targets. Use DNS resolution tools (like dnsx, massdns) or HTTP probing tools (like httpx, httprobe) to determine which subdomains are actually live and resolvable.
💻 cat unique_passive_subdomains.txt | dnsx -resp -o resolved_subdomains.txt
💻 cat resolved_subdomains.txt | httpx -o live_webservers.txt -sc -title -tech-detect 18
Table: Passive Subdomain Tool ComparisonToolPrimary Technique(s)Key Data SourcesAPI Keys RequiredStrengthsWeaknessessubfinderAPI Aggregation (Passive DNS, CT, Search, etc.)VT, Shodan, Censys, SecurityTrails, GitHub, CT, etc.Yes (Extensive)Fast, Good Coverage (w/ keys), Actively MaintainedHighly dependent on API keys for good resultsamassAPI Aggregation, WHOIS/ASN Analysis, Web ScrapingSimilar to subfinder + WHOIS, ASN DBs, more sourcesYes (Extensive)Very Comprehensive Coverage, Multiple ModesSlower, Complex, Highly dependent on API keysassetfinderAPI Aggregation (Smaller Set)crt.sh, CertSpotter, ThreatCrowd, Wayback, etc.No (Default)Simple, Fast, No initial key setup neededLimited coverage compared to otherstheHarvesterSearch Engine Scraping, API Queries (Hunter, Shodan)Google, Bing, PGP, Hunter, Shodan, VT, etc.OptionalGathers Emails/Hosts too, Broad OSINTCan be slow, Search engine CAPTCHAsSublist3rSearch Engine Scraping, CT Logs, Passive DNSGoogle, Bing, Yahoo, VT, DNSDumpster, crt.sh, etc.No (Mostly)Easy to use, Decent coverageLess maintained?, Can hit CAPTCHAscrt.shCT Log QueryingCertificate Transparency LogsNo (Web/Basic API)Direct access to CT data, Good for new domainsOnly finds domains with TLS certs, Historical dataVirusTotalPassive DNS DatabaseVT's internal DNS resolution dataYes (API) / No (Web)Large dataset (esp. malware related)Web UI limited, API rate limits/costsPractice Links: 🎯 HTB Machines: Topology, Popcorn; THM Rooms: Relevant enumeration rooms in paths like Complete Beginner or Offensive Pentesting (e.g., modules on information gathering).Cross-References: 🔗 DNS Reconnaissance (for validation), 🔗 Certificate Transparency Logs (as a data source), 🔗 Search Engine Dorking (as a technique), 🔗 Subdomain Enumeration (Active) (the next logical step after passive recon and validation).Certificate Transparency LogsConcept/Goal: Leverage the public, append-only logs mandated for SSL/TLS certificate issuance to discover hostnames (primarily subdomains) associated with a target domain. Certificate Authorities (CAs) are required to log every certificate they issue, creating a rich, publicly auditable dataset.17Key Tools:
crt.sh: The most prominent web interface and data source for querying CT logs. Developed by Sectigo (formerly Comodo CA), it provides a search function and a basic JSON API endpoint accessible via scripts or tools like curl.15
Censys.io: A search engine indexing internet-wide data, including CT logs. Offers more advanced search capabilities but may require an account or API key for extensive use.15
Facebook Certificate Transparency Monitoring Tool: An alternative web interface provided by Facebook for searching CT logs.33
subfinder, amass: These comprehensive enumeration tools integrate CT log searching (often by querying crt.sh or other CT sources/APIs) as part of their passive discovery workflow.15
ctfr: A Python tool specifically designed for scraping subdomains from crt.sh.
Core Techniques:
Web Interface Search: The simplest method is to use the search bar on crt.sh, Censys, or the Facebook tool. Enter the target domain (e.g., target.com) or use a wildcard query (e.g., %.target.com) to find all certificates related to the domain and its subdomains.33
API/Scripted Queries: For automation or integration into workflows, query the crt.sh JSON endpoint. This typically involves using curl to fetch the data and tools like jq to parse the JSON output and extract relevant hostnames.30
💻 curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '..name_value' | sed 's/\*\.//g' | sort -u
Extracting SANs: When examining certificate details (either via web UI or API), pay close attention to the 'Common Name' (CN) field and, more importantly, the 'Subject Alternative Name' (SAN) extension. The SAN field explicitly lists all hostnames (domains and subdomains) that the certificate is valid for, making it a primary source for subdomain discovery within CT logs.32
Scenarios/Examples:
📖 Discovering non-publicly linked subdomains used for development, testing, or staging environments (e.g., dev.target.com, uat.api.target.com, staging-portal.target.com) which might have valid certificates but lower security postures.
📖 Identifying subdomains associated with specific products, services, or marketing campaigns that might not be easily found through other means.
📖 Finding newly provisioned subdomains shortly after their certificates are issued, potentially before they are widely known or secured. CT logs provide a near real-time view of infrastructure requiring TLS certificates, often revealing emerging attack surfaces faster than web crawlers or passive DNS systems, which rely on observation over time.18 This near-instantaneous logging by CAs offers a significant advantage for timely reconnaissance.
Pitfalls & Tips:
⚠️ Historical Data: CT logs are append-only and contain records for all certificates ever issued and logged, including those that are expired or belong to servers/subdomains that have been decommissioned. Findings from CT logs must be validated (e.g., via DNS resolution or HTTP probing) to confirm they represent currently active hosts.17
⚠️ Wildcard Certificates: Certificates issued for wildcard domains (e.g., *.target.com) are frequently found in CT logs. While they confirm the existence of a wildcard setup, they don't reveal specific subdomain names beyond the pattern itself. Scripts used to parse CT data should ideally filter out or handle these wildcard entries appropriately (e.g., using sed 's/\*\.//g' to remove the leading *.).30
💡 Excellent Source for New Subdomains: Because certificate issuance is logged almost immediately by participating CAs, CT logs are one of the best passive sources for discovering newly created subdomains, often before search engines index them or passive DNS systems observe traffic to them.32
💡 Broaden Search Terms: Don't just search for the primary domain (target.com). If the target organization has other known domain names or variations, search for those as well (target-corp.com, %.target.co.uk, etc.).
💡 Integrate Findings: Use the subdomains discovered from CT logs as input for further reconnaissance steps, such as DNS record checks (A, CNAME, MX, TXT), port scanning, and web application analysis.
Practice Links: 🎯 Use the crt.sh website to explore certificates for domains associated with active HTB or THM machines.Cross-References: 🔗 Subdomain Enumeration (Passive) (CT is a key data source), 🔗 DNS Reconnaissance (for validating CT findings).Search Engine DorkingConcept/Goal: Utilizing advanced search operators provided by search engines (like Google, Bing, DuckDuckGo) and specialized search platforms (Shodan, Censys, GitHub) to uncover publicly indexed information that was not intended for public disclosure. This includes sensitive files, configuration errors, login pages, leaked credentials, and infrastructure details.4Key Tools:
Web Search Engines: Google, Bing, DuckDuckGo, Yandex, Baidu. Google is often the primary focus due to its extensive index.
Specialized Search Engines:

Shodan: Searches for internet-connected devices (servers, IoT, ICS), filtering by port, product, organization, location, etc.
Censys: Similar to Shodan, focuses on host/network data and certificates.
PublicWWW: Searches the source code (HTML, JS, CSS) of web pages.
GreyNoise: Identifies internet scanners and background noise, helping to differentiate targeted attacks from mass scanning.


Code Repositories: GitHub, GitLab, Bitbucket search features.12
Google Hacking Database (GHDB): A curated collection of Google dorks maintained by Exploit Database, categorized by vulnerability type or information leakage.
Core Techniques & Operators:Mastering search operators is key to effective dorking.
site: Restricts results to a specific domain, subdomain, or top-level domain (TLD). Essential for targeting.

Examples: site:target.com, site:*.target.com, site:internal.target.com 12


inurl: Finds pages with specific keywords in their URL path or parameters.

Examples: inurl:admin, inurl:login.php, inurl:/app/config 4


intitle: Finds pages with specific keywords in the HTML title tag.

Examples: intitle:"index of /", intitle:"Login Panel" 4


filetype: or ext: Restricts results to specific file extensions. Extremely useful for finding sensitive documents or configuration files.

Examples: filetype:pdf, ext:sql, ext:log, ext:bak, ext:cfg, ext:env, ext:pem 4


intext: Searches for specific keywords within the body text of the page.

Examples: intext:"password", intext:"Internal Server Error", intext:"DB_PASSWORD" 4


"" (Quotes): Searches for the exact phrase enclosed in quotes.

Example: "Welcome to the admin console"


- (Minus): Excludes results containing the term following the minus sign. Crucial for refining searches.

Example: site:*.target.com -site:www.target.com 12


* (Wildcard): Acts as a placeholder for one or more words within a query.
cache: Displays Google's cached version of a page, useful if the live page is down or has changed.
GitHub/GitLab Search: Use specific keywords (password, secret, api_key, config, BEGIN RSA PRIVATE KEY), organization filters (org:target-org), filename filters (filename:.env), language filters (language:python).12
Shodan/Censys Search: Utilize filters like hostname:target.com, org:"Target Org Name", port:22, product:nginx, ssl:"target.com".
Scenarios/Examples (Dorks):
📄 Subdomain Discovery: site:*.target.com -site:www.target.com 12
📄 Login Portals: site:target.com (inurl:login | inurl:signin | intitle:Login | intitle:"Sign In")
📄 Exposed Directories: site:target.com intitle:"index of /"
📄 Configuration Files: site:target.com (ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env)
📄 Database Files/Dumps: site:target.com (ext:sql | ext:dbf | ext:mdb | ext:db)
📄 Log Files: site:target.com ext:log
📄 Backup Files: site:target.com (ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup | ext:zip | ext:tar.gz)
📄 SQL Errors: site:target.com intext:"sql syntax near" | intext:"syntax error has occurred"
📄 PHP Info/Errors: site:target.com (ext:php intitle:"phpinfo()") | intext:"PHP Parse error" | intext:"PHP Warning"
📄 Sensitive Documents: site:target.com (filetype:pdf | filetype:docx | filetype:xlsx | filetype:pptx) (intitle:"confidential" | intext:"internal use only")
📄 GitHub Secrets: org:TargetCompany "Authorization: Bearer", filename:.npmrc _auth
📄 Shodan Exposed Services: org:"Target Org" port:3389, hostname:.target.com product:"mongodb", port:5900 authentication disabled
Pitfalls & Tips:
⚠️ CAPTCHAs & Rate Limiting: Automated dorking tools or rapid manual searching can trigger CAPTCHAs or temporary IP blocks from search engines. Implement delays or use rotating proxies/VPNs if automating.18
⚠️ Information Overload: Broad dorks can return thousands of irrelevant results. Refine queries iteratively using multiple operators, exact phrases (""), and exclusions (-).
💡 Explore the GHDB: The Google Hacking Database on Exploit DB is an invaluable resource for finding pre-crafted dorks targeting specific vulnerabilities, technologies, and file types.
💡 Combine Operators Powerfully: Create highly specific queries by chaining operators. Example: site:dev.target.com filetype:log intext:"password" -inurl:test.
💡 Think Like a Developer/Admin: Consider target-specific application names, internal project codenames, common error messages, or default credentials.
💡 Go Beyond Google: Different search engines (Bing, DuckDuckGo) and specialized platforms (Shodan, Censys, GitHub, PublicWWW) have different indexing priorities and capabilities. Query multiple platforms for unique findings.12 Dorking effectively transforms public search indexes into powerful passive vulnerability scanners by leveraging their ability to index file contents, URL paths, and specific error messages, thereby uncovering data exposed outside of intended access controls.4
Insight: Dorking represents a method to uncover deep information leakage by querying vast, publicly indexed datasets for specific patterns indicative of misconfigurations, exposed credentials, or sensitive files.
Table: Common Google/Search Dork OperatorsOperatorDescriptionExample Usagesite:Restricts search to a specific domain/subdomain/TLDsite:target.com, site:*.target.cominurl:Finds keywords within the URL path or parametersinurl:admin, inurl:?id=intitle:Finds keywords within the HTML page titleintitle:"index of /", intitle:"Login"filetype:Searches for specific file extensionsfiletype:pdf, filetype:sqlext:Alternative syntax for filetype:ext:log, ext:bakintext:Searches for keywords within the page body contentintext:"password", intext:"Internal Server Error"""Searches for the exact phrase"confidential internal report"-Excludes results containing the specified termsite:*.target.com -site:www.target.com*Wildcard placeholder for one or more words"Forgot * password"cache:Displays Google's cached version of a URLcache:http://target.com/oldpage.htmlrelated:Finds sites related to a given domainrelated:target.comlink:Finds pages linking to a specific URL (use varies)link:http://target.comPractice Links: 🎯 Google Hacking Database (GHDB) on Exploit DB. Many HTB/THM boxes hide flags or credentials in publicly indexed files discoverable via dorking.Cross-References: 🔗 Subdomain Enumeration (Passive), 🔗 Public Code Repository Search, 🔗 Metadata Analysis, 🔗 Initial Access (using information/credentials found).Email & Username GatheringConcept/Goal: Identify valid email addresses and usernames associated with the target organization and its employees. This information is crucial for social engineering (phishing), credential attacks (password spraying, brute-force), and mapping the organization's personnel structure.15Key Tools:
theHarvester: A highly recommended OSINT tool that aggregates data from numerous sources (search engines like Google/Bing, PGP key servers, Shodan, LinkedIn, Hunter.io, VirusTotal, etc.) to find emails, subdomains, hosts, and employee names.11
Hunter.io, Skrapp.io, Snov.io: Commercial services (often with limited free tiers) specifically designed to find and verify professional email addresses based on company domains and employee names.
OSINT Framework: Provides links to various tools dedicated to email and username discovery.15
Search Engines (Dorking): Using specific search operators to find email addresses mentioned on websites or in public documents.12
WHOIS Data: Occasionally contains administrative or technical contact emails, though frequently obscured by privacy services.2
Public Breach Databases: Services like Have I Been Pwned (HIBP) and DeHashed allow checking if company domains or specific email addresses have appeared in known data breaches.15
LinkedIn / Social Media: Platforms like LinkedIn are primary sources for employee names and job titles, which can be used to guess email addresses based on common patterns. Tools may scrape this data (use ethically).15
Metadata Extraction Tools: Tools like exiftool can sometimes extract author names or usernames from the metadata of publicly available documents.15
Core Techniques:
Automated Aggregation: Utilize tools like theHarvester to query multiple sources simultaneously.
💻 theharvester -d target.com -b all (Queries all supported sources) 12
💻 theharvester -d target.com -b google,linkedin,hunter (Queries specific sources)
Search Engine Dorking: Craft specific queries to find email addresses.
📄 site:target.com intext:"@target.com"
📄 site:target.com filetype:pdf "email" | "contact"
📄 site:linkedin.com "VP of Engineering" "Target Company" (To find names)
Email Format Pattern Analysis: Once a few valid emails are found (e.g., john.doe@target.com, j.doe@target.com), infer the common company format(s) (e.g., first.last, flast, firstl, first). Generate potential email addresses for known employee names using these patterns.
WHOIS Lookup: Check the Admin, Tech, and Registrant contact fields, but expect privacy redactions.2
Metadata Extraction: Analyze publicly hosted documents from the target.
💻 exiftool target_document.pdf | grep -i "Author\|Creator" 15
Social Media Scraping (Manual/Automated): Identify employee names and roles from LinkedIn, Twitter, company website ('About Us' pages), etc..15
Breach Data Checking: Query Have I Been Pwned (domain search for subscribers, individual email check for anyone) or DeHashed (paid service) to see if company emails or usernames have been exposed in breaches.15
Scenarios/Examples:
📖 Phishing Campaign: Compile a list of validated email addresses belonging to employees in specific departments (e.g., Finance, HR) for targeted spear-phishing attacks.
📖 Password Spraying: Generate a list of potential usernames (often derived from email formats, e.g., jdoe from john.doe@target.com) to use in low-and-slow password guessing attacks against external login portals (VPN, OWA, M365, Citrix).
📖 Social Engineering Pretexting: Identify key personnel (IT support, executives, administrative assistants) and their contact information to build more believable social engineering scenarios.
📖 Risk Assessment: Check if company email addresses appear frequently in data breaches via HIBP, indicating a higher risk of credential reuse among employees.15
Pitfalls & Tips:
⚠️ Email Validity: Information gathered from public sources can be outdated. Emails might belong to former employees, be misspelled, or represent defunct mailboxes. Validation is often necessary but must be done carefully to avoid alerting the target (e.g., avoid sending actual emails). Some tools claim to validate without sending, but reliability varies.15
⚠️ Privacy & Legality: Collecting and using personal data like email addresses is subject to regulations (e.g., GDPR, CCPA) and ethical guidelines. Always operate within the rules of engagement and applicable laws. Focus on information relevant to the security assessment.
💡 Infer Email Patterns: Discovering even one or two valid corporate email addresses is often enough to deduce the standard naming convention(s) used by the organization. Combine known employee names with these patterns to generate a larger list of probable emails.
💡 Combine Multiple Sources: Aggregate results from theHarvester, specialized tools (Hunter.io), manual LinkedIn searching, and pattern guessing for the most comprehensive list.
💡 HIBP Indicates Risk: Finding company emails in Have I Been Pwned suggests those credentials might have been compromised. This increases the likelihood of successful credential stuffing or password reuse attacks if employees haven't changed passwords.15
💡 Target Role-Based & Generic Emails: Don't forget common role-based addresses like info@, support@, sales@, admin@, security@, hr@, careers@, as these can be valuable entry points or information sources.
Practice Links: 🎯 THM rooms in the Phishing or Initial Access modules often require email gathering. Fictional targets in CTFs sometimes have discoverable email patterns.Cross-References: 🔗 WHOIS Lookups, 🔗 Social Media Analysis, 🔗 Metadata Analysis, 🔗 Search Engine Dorking, 🔗 Initial Access (Phishing, Password Spraying).Social Media AnalysisConcept/Goal: Gather intelligence about a target organization, its employees, technology stack, internal culture, physical locations, and potential vulnerabilities by analyzing information publicly shared on social media platforms.15Key Tools:
Platforms:

LinkedIn: Primary source for professional information - employee names, job titles, skills, work history, connections, company updates, technologies mentioned in profiles or job postings.
Twitter: Real-time information, employee chatter, tech discussions, conference attendance, customer service interactions, casual mentions of internal tools or projects.
Facebook: Personal information (hobbies, interests, location check-ins, events), company pages, public groups employees might belong to.
Instagram: Visual intelligence - photos/videos of office spaces, equipment, employee badges (rarely!), events, locations.
GitHub/GitLab/Stack Overflow: Developer activity, code repositories, technical skills, preferred technologies, potential code leaks (often linked from professional profiles).12


Username Checkers: Tools like Sherlock, Maigret, or WhatsMyName.app help find profiles associated with a known username across hundreds of platforms.
Search Engines: Use dorking techniques to find profiles or specific posts.

Example: site:linkedin.com "DevOps Engineer" "Target Company"


OSINT Framework: Links to specialized social media search tools and resources.15
Core Techniques:
Employee Identification & Profiling: Search LinkedIn, Twitter, etc., for individuals listing the target company as their employer. Focus on roles relevant to potential attack vectors: IT/Security personnel, developers, system administrators, executives, administrative assistants. Analyze their profiles for skills (e.g., AWS, Python, Cisco IOS), technologies used, projects mentioned, education background, work anniversaries, and connections.31
Public Post Monitoring: Systematically review public posts, tweets, and updates from the company and known employees. Look for mentions of specific software/hardware, internal project names, company news or reorganizations, common complaints (potential pain points), upcoming events, and casual discussions about work.
Image & Video Analysis: Carefully examine photos and videos posted publicly by the company or employees. Look for details in the background: whiteboard notes, computer screens, equipment models, security badges, office layouts, visible documents. Check for geotags if available (though often stripped). Use reverse image search to find other instances or contexts of an image.
Network & Relationship Mapping: Analyze connections, followers, and following lists on platforms like LinkedIn and Twitter to understand organizational structure, identify key influencers, or map relationships with partners, vendors, or former employees.
Group Membership Analysis: Identify public groups (on LinkedIn, Facebook, Reddit, etc.) that employees belong to. Tech-focused groups might reveal specific technical interests or problems they are trying to solve.
Scenarios/Examples:
📖 Identifying the names and email patterns of IT administrators for targeted phishing or password spraying attacks.
📖 Discovering that the company heavily uses a specific cloud provider (e.g., AWS, Azure) or SaaS platform from job postings or employee skill endorsements on LinkedIn, guiding further reconnaissance towards those platforms.
📖 Finding developers discussing issues with a particular framework or library on Twitter or Stack Overflow, potentially revealing versions or configurations.
📖 Gathering personal details about a high-value target (e.g., CEO, CFO) from their public Facebook or Instagram profiles (hobbies, recent travel, family names) to craft highly personalized social engineering pretexts.
📖 Spotting a photo posted from a conference where an employee's badge is partially visible, potentially revealing their name or access level.
📖 Learning about internal project codenames or upcoming product releases mentioned casually in tweets or blog posts.
Pitfalls & Tips:
⚠️ Information Accuracy & Timeliness: Social media profiles and posts can be outdated, contain embellishments, or be intentionally misleading. Always attempt to cross-verify critical information using multiple independent sources.
⚠️ Privacy Settings & Ethics: Respect user privacy settings and the terms of service of each platform. Focus on information that is clearly public. Avoid overly intrusive methods or excessive scraping that could be deemed unethical or illegal. Ensure all activities align with the engagement's rules of engagement.
⚠️ Signal vs. Noise: Social media generates a massive amount of data. Filter aggressively and focus searches on information directly relevant to potential attack vectors (e.g., technical details, key personnel, security practices). Avoid getting lost in irrelevant personal details.
💡 LinkedIn is Often the Gold Standard: For professional context, employee roles, skills, and company structure, LinkedIn is typically the most valuable and structured source.
💡 Follow the Developers: Check GitHub, GitLab, Bitbucket, and Stack Overflow profiles linked from developers' social media accounts. These often contain code snippets, configuration examples, or technical discussions revealing valuable insights.12
💡 Maintain Operational Security (OpSec): Use dedicated reconnaissance accounts (sock puppets) that are not linked to your real identity. Avoid direct interactions (liking, commenting, following, connecting) with target individuals or company profiles unless it's a deliberate part of the engagement strategy (e.g., social engineering). Social media OSINT provides crucial context that complements technical findings. Understanding the people, processes, and technologies within an organization, gleaned from platforms like LinkedIn or Twitter, can significantly increase the effectiveness of both technical exploitation and social engineering attempts.16 While technical scans show what is exposed, social media can reveal who manages it and how it's used.
Practice Links: 🎯 Include searching for fictional company employees on LinkedIn/Twitter as part of the reconnaissance phase in CTF walkthroughs or practice labs.Cross-References: 🔗 Email & Username Gathering, 🔗 Metadata Analysis, 🔗 Search Engine Dorking, 🔗 Public Code Repository Search, 🔗 Social Engineering (SE).Metadata AnalysisConcept/Goal: Extracting hidden information (metadata or EXIF data) embedded within publicly accessible files such as documents, images, videos, and presentations discovered during reconnaissance. This data can reveal details about the file's origin, authors, software used, and sometimes location information.15Key Tools:
exiftool: By Phil Harvey, this is the de facto standard command-line tool. It supports a vast range of file types and metadata formats, providing comprehensive extraction capabilities.
Online Metadata Viewers: Websites like Jeffrey's Exif Viewer or Metadata2Go allow uploading files or providing URLs to view metadata without installing software.
Operating System File Properties: Basic metadata (author, creation/modification dates, software) can often be viewed using the built-in file properties dialog in Windows (Right-click -> Properties -> Details) or macOS (Cmd+I -> More Info).
Web Browser Developer Tools: Can sometimes reveal metadata embedded in HTTP response headers (e.g., Server, X-Powered-By) or within the file content itself when previewing certain file types.
Core Techniques:
File Discovery: Locate potentially interesting files hosted by the target. Use search engine dorking with filetype: or ext: operators (e.g., site:target.com filetype:pdf, site:target.com ext:docx) or crawl the target website(s).4
Metadata Extraction: Download the discovered files and process them using exiftool.
💻 exiftool downloaded_document.pdf
💻 exiftool -r /path/to/downloaded_files/ (Recursive scan of a directory)
Targeted Analysis: Examine the exiftool output, specifically looking for fields that could provide valuable intelligence.
Information Potentially Gathered:
Author/Creator Information: Usernames (e.g., Windows login names), real names, initials. Can help identify employees or standard username formats.
Software Information: Software used to create or modify the file (e.g., Microsoft Word 16.0, Adobe Photoshop CC 2023, Canon EOS Utility). Can reveal internal software stack and versions, potentially highlighting vulnerable software.
Location Data: GPS coordinates (latitude, longitude, altitude), especially common in photos taken with smartphones or GPS-enabled cameras. Can pinpoint office locations, event venues, or employee locations. Printer names or network paths might also be embedded.
Timestamps: Precise creation date, modification date, last printed date. Can provide context about the document's lifecycle.
Device Information: Camera make and model, scanner model, potentially mobile device details.
Hidden Content: Comments, annotations, revision history (especially in Office documents), hidden slides in presentations.
Scenarios/Examples:
📖 Finding the Windows username of the person who created a publicly available PDF report, potentially revealing the internal username format (e.g., j.smith).
📖 Identifying that marketing materials were created using an old, vulnerable version of Adobe InDesign by examining image metadata.
📖 Discovering internal network printer names (e.g., \\PRINTSRV01\MarketingColor) embedded in the metadata of a DOCX file.
📖 Extracting precise GPS coordinates from photos posted on a company's "Team Building Event" blog post, confirming the location.
📖 Finding hidden comments or tracked changes in a Word document that reveal internal discussions or sensitive data.
Pitfalls & Tips:
⚠️ Metadata Stripping is Common: Many online platforms (social media sites like Facebook/Twitter/Instagram, image hosting services like Imgur) automatically strip most metadata from uploaded files to protect user privacy. Therefore, the value of metadata analysis is highest for files downloaded directly from the target organization's own websites or servers, as these are less likely to have undergone automated stripping.15 Prioritize dorking for files specifically on the target domain (site:target.com filetype:...).
⚠️ Inaccurate or Generic Data: Metadata fields can be empty, inaccurate, outdated, or contain generic values (e.g., Author: "Admin", Software: "Microsoft Word"). Don't treat all findings as definitive truth; correlate where possible.
💡 Focus on Direct Downloads: Prioritize analyzing files obtained directly from the target's web servers, file shares (if accessible), or code repositories.
💡 Automate Extraction: If dealing with many files, script exiftool to run recursively and potentially filter for specific interesting tags (grep -i 'Author\|Creator\|Software\|GPS').
💡 Check Diverse File Types: Don't limit analysis to PDFs and JPEGs. Office documents (DOCX, XLSX, PPTX), audio/video files (MP3, MP4, MOV), and even some archive formats can contain valuable metadata.
💡 Combine with Other OSINT: Use usernames found in metadata to search social media or guess email addresses. Use software versions found to search for known vulnerabilities.
Practice Links: 🎯 Many CTFs hide flags or clues within the metadata of provided image or document files. THM rooms covering OSINT or Forensics often include metadata challenges.Cross-References: 🔗 Search Engine Dorking (for finding files), 🔗 Email & Username Gathering (using found usernames), 🔗 Social Media Analysis (correlating author names).Public Code Repository SearchConcept/Goal: Searching public code repositories like GitHub, GitLab, and Bitbucket for sensitive information inadvertently committed by the target organization or its employees. This can include credentials, API keys, internal hostnames, configuration details, or proprietary source code.12Key Tools:
Repository Search Interfaces: The built-in search features within GitHub, GitLab, and Bitbucket platforms. These allow searching code, commits, issues, etc., using keywords and filters.
Automated Secret Scanners:

gitleaks: A popular open-source tool that scans Git repositories (including history) for secrets using regular expressions and entropy analysis.
truffleHog: Another widely used tool that focuses on finding high-entropy strings and specific keywords throughout the entire commit history of a repository.
git-secrets: Primarily designed to prevent committing secrets, but its patterns can be used for scanning existing repositories.
Commercial Platforms: Services like GitGuardian offer continuous secret scanning as a service.


Manual/Scripted Search: Cloning repositories (git clone) and using command-line search tools like grep or, more effectively, rg (ripgrep) to search for patterns within the codebase and history (git log -S<string>).
Core Techniques:
Targeted Searching (Web UI/API): Use the platform's search bar with specific keywords relevant to secrets (password, secret, api_key, private_key, token, credentials, config, connectionstring), combined with filters for the target organization (org:TargetCompany), specific users (known developers), repositories (repo:TargetCompany/project), filenames (filename:.env, filename:config.php), or programming languages (language:java).12
Commit History Analysis: Secrets are often committed accidentally and then removed in a later commit. However, they remain in the Git history. Tools like truffleHog are specifically designed to scan the entire commit history, not just the current state of the code. Manually, git log -p or git log -S"keyword" can be used to inspect changes introducing or removing potential secrets. This historical analysis is critical because simply scanning the latest code version provides an incomplete view of leaked data.12
Configuration File Hunting: Actively search for common configuration file names or extensions that frequently contain sensitive data: .env, config.yaml, settings.py, database.yml, web.config, credentials.json, *.pem, *.key.
Automated Scanning: Clone repositories belonging to the target organization or its developers and run automated scanners against the local copies. These tools use predefined patterns and entropy checks to identify potential secrets efficiently.
🐍 Example script snippet using gitleaks: git clone <repo_url> && cd <repo_name> && gitleaks detect --source. -v --report leaks_report.json
Fork and Gist Exploration: Don't forget to check public forks of the organization's repositories (secrets might exist in forks that are not in the original) and public gists created by employees, as these are sometimes used for sharing code snippets that might contain sensitive information.
Scenarios/Examples:
📄 GitHub Search Dork: org:TargetCompany filename:.env DB_PASSWORD
📄 GitHub Search Dork: "target.internal.domain" org:TargetCompany
📄 GitHub Search Dork: path:config language:yaml "api_key"
💻 Scanning a Cloned Repo: truffleHog git file:///path/to/cloned/repo
📖 Finding hardcoded AWS access keys (AKIA...) and secret keys in a developer's public utility script repository.
📖 Discovering database connection strings, including usernames and passwords, within a settings.py file for a Django application.
📖 Locating internal API endpoints, hostnames (server.corp.local), or private IP addresses mentioned in comments, test cases, or configuration files.
📖 Finding proprietary algorithms, business logic, or customer data structures accidentally committed to a public repository.
Pitfalls & Tips:
⚠️ High Volume of False Positives: Searching for generic terms like "password" or using entropy scanning alone can generate many false positives (e.g., example credentials, test keys, random strings). Careful manual review and context analysis are required to validate potential findings.
⚠️ Secrets Reside in History: A critical mistake is only scanning the latest version of the code. Secrets are often committed and then removed. Use tools (truffleHog, gitleaks) that explicitly scan the entire commit history.12
⚠️ Obfuscated or Indirect Secrets: Secrets might be weakly encoded (e.g., Base64), split across multiple variables, loaded from environment variables (check Dockerfiles or CI/CD scripts), or stored in external configuration management systems mentioned in the code.
💡 Target Employee Accounts: Identify developers through LinkedIn or other OSINT methods and specifically scrutinize their public repositories and contributions.
💡 Prioritize Configuration Files: Focus searches on common configuration filenames and patterns, as these are high-probability locations for credentials, API keys, and internal paths.
💡 Check Forks, Gists, and Issue Trackers: Sensitive information can leak through forks, public gists used for collaboration, or even comments in public issue trackers associated with the repositories.
💡 Automate Strategically: Cloning and scanning every related repository can be time-consuming and resource-intensive. Prioritize repositories based on perceived relevance: those directly under the company's organization, repositories actively maintained by key developers, or those whose names suggest critical functions (e.g., 'infra-config', 'auth-service').
Practice Links: 🎯 HTB and THM challenges occasionally require finding credentials or sensitive information within public GitHub repositories linked from a target web application or mentioned in reconnaissance clues. Explore bug bounty write-ups for real-world examples.Cross-References: 🔗 Search Engine Dorking (using GitHub's search features), 🔗 Social Media Analysis (identifying developers), 🔗 Initial Access (using found credentials/API keys).ConclusionPassive reconnaissance and OSINT are indispensable first steps in modern cybersecurity assessments. By meticulously gathering information from public sources like WHOIS records, DNS servers, Certificate Transparency logs, search engines, social media, public code repositories, and file metadata, penetration testers and CTF players can build a comprehensive understanding of a target's digital footprint without triggering alarms. The techniques outlined provide a framework for discovering potential attack vectors, identifying infrastructure components, understanding organizational structures, and uncovering inadvertently exposed sensitive information. Success in this phase relies on employing a diverse range of tools and techniques, understanding their strengths and limitations (especially regarding data timeliness and the necessity of API keys for comprehensive coverage), diligently correlating findings from multiple sources, and systematically validating potential leads before transitioning to active reconnaissance or exploitation phases. Thorough passive reconnaissance significantly enhances the efficiency and effectiveness of subsequent security testing activities.