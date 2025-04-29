# Passive Reconnaissance & OSINT Cheatsheet

La reconnaissance passive, souvent étroitement liée à l'Open Source Intelligence (OSINT), constitue le fondement de tout test d'intrusion efficace ou engagement Capture The Flag (CTF). Elle consiste à collecter des informations sur une cible à partir de sources publiques sans interagir directement avec les systèmes de la cible, évitant ainsi la détection. Cette phase initiale cruciale vise à cartographier l'empreinte externe de la cible, à identifier les points d'entrée potentiels, à comprendre son infrastructure et à recueillir des renseignements sur son personnel et ses technologies. Une phase de reconnaissance passive approfondie augmente considérablement les chances de succès dans les phases actives ultérieures.

## WHOIS Lookups

**Concept/Goal:** Obtenir les informations d'enregistrement de domaine pour comprendre la propriété, les contacts administratifs, l'infrastructure réseau associée (comme les ASN) et le statut opérationnel du domaine. C'est souvent la toute première étape lorsque la reconnaissance commence avec un nom de domaine.1

**Key Tools:**
* `whois` (Ligne de commande) : L'utilitaire standard, généralement pré-installé sur les distributions Linux et macOS.1
* Recherches en ligne : De nombreux services web fournissent des informations WHOIS, souvent en agrégeant des données ou en offrant des interfaces plus claires. Exemples : ICANN Lookup (`lookup.icann.org`), outils spécifiques aux registrars (Namecheap, GoDaddy) et agrégateurs comme `whois.domaintools.com`, `viewdns.info`, `whois.net`, `pentest-tools.com/utils/whois-lookup-online`.1

**Core Techniques:**
* Requête de base : La forme la plus simple, interrogeant les serveurs WHOIS par défaut.
    ```bash
    whois targetdomain.com 1
    ```
* Spécifier le serveur WHOIS : Si la requête par défaut donne peu d'informations ou échoue, spécifier un Registre Internet Régional (RIR) comme ARIN, APNIC, RIPE, LACNIC, ou le serveur spécifique du registrar du domaine en utilisant l'option `-h` peut fournir des données plus détaillées ou précises.1
    ```bash
    whois targetdomain.com -h whois.arin.net
    whois targetdomain.com -h whois.godaddy.com 1
    ```
* Sortie verbeuse : Certaines versions du client `whois` peuvent prendre en charge des options comme `-verbose` pour une sortie potentiellement plus détaillée, bien que cela ne soit pas standardisé sur toutes les implémentations.3

**Information Gathered:**
* Contacts : Détails des contacts Registrant, Administratif et Technique (Nom, Organisation, Adresse, Email, Téléphone). Cependant, ce sont les informations les plus souvent masquées par les services de confidentialité.2
* Registrar : L'organisation accréditée qui gère l'enregistrement du domaine.1
* Serveurs de noms (NS) : Les serveurs DNS faisant autorité responsables des enregistrements DNS du domaine. C'est une information critique pour pivoter vers la reconnaissance DNS.2
* Dates : Dates de création, d'expiration et de dernière mise à jour du domaine. Celles-ci peuvent parfois offrir un contexte pour l'ingénierie sociale ou indiquer des événements du cycle de vie du domaine.2
* Statut du domaine : Codes indiquant le statut du domaine, tels que `clientTransferProhibited` ou `serverHold`.
* Numéro de Système Autonome (ASN) : Souvent listé dans l'enregistrement WHOIS pour la plage IP d'hébergement du domaine ou les blocs réseau associés. C'est un point de pivot clé pour comprendre la présence réseau de la cible.4

**Pitfalls & Tips:**
* ⚠️ Protection de la vie privée : Une limitation significative des recherches WHOIS modernes est la prévalence des services de protection de la vie privée. Ces services remplacent les coordonnées réelles du registrant par celles d'un service proxy ("redacted for privacy", "Domains By Proxy", etc.).3 Par conséquent, se fier au WHOIS pour la collecte directe de contacts (emails, numéros de téléphone) est souvent peu fiable. Cependant, les informations techniques, telles que les serveurs de noms (NS) et potentiellement l'ASN, sont fondamentales pour le fonctionnement du domaine et le routage réseau, ce qui les rend moins susceptibles d'être obscurcies par les services de confidentialité standards. Ces données techniques restent une raison principale pour laquelle les recherches WHOIS sont essentielles pour cartographier les liens d'infrastructure.3
* 💡 Pivot ASN : L'ASN identifié via WHOIS est une information cruciale. Il relie le nom de domaine abstrait à une infrastructure réseau tangible. Utilisez cet ASN pour interroger des bases de données comme `bgp.he.net` (par exemple, `bgp.he.net/ASXXXXX`) ou effectuez des recherches WHOIS basées sur IP pour identifier les plages d'adresses IP spécifiques détenues ou exploitées par l'organisation cible. Cela aide à définir la portée du réseau pour les phases de scan ultérieures.4 WHOIS agit efficacement comme le pont reliant l'OSINT au niveau du domaine à la reconnaissance au niveau du réseau via l'ASN.
* 💡 Indices du Registrar : Le choix du registrar peut parfois offrir des indices subtils sur la taille de la cible, sa maturité technique ou sa localisation géographique. Certains registrars sont également connus pour être plus ou moins réactifs aux problèmes de sécurité ou aux demandes des forces de l'ordre.
* ⚠️ Limitation de débit/Abus : Les serveurs WHOIS mettent souvent en œuvre une limitation de débit pour prévenir les abus. Effectuer des requêtes automatisées à haut volume depuis une seule adresse IP peut entraîner des blocages temporaires ou permanents.2 Utilisez les requêtes judicieusement ou distribuez-les si l'automatisation est nécessaire.

**Cross-References:** 🔗 Reconnaissance DNS (en utilisant les enregistrements NS trouvés), 🔗 Scan réseau (en utilisant les plages ASN/IP identifiées).

## DNS Reconnaissance

**Concept/Goal:** Interroger les serveurs du Domain Name System (DNS) pour résoudre les noms de domaine en adresses IP, découvrir les services associés (comme les serveurs de messagerie), comprendre les configurations de sécurité (comme SPF) et cartographier l'infrastructure DNS de la cible. Cela implique de récupérer divers types d'enregistrements DNS.6

**Key Tools:**
* `dig` (Domain Information Groper) : Un outil en ligne de commande puissant et flexible, standard sur Linux/macOS. Préféré pour une analyse détaillée, des requêtes de types d'enregistrements spécifiques et le scripting en raison de sa sortie prévisible.1
* `nslookup` : Largement disponible, y compris sur Windows. Utile pour les recherches de base et l'exploration interactive, bien que parfois considéré comme moins puissant ou moins adapté au scripting que `dig`.1
* `host` : Un utilitaire simple pour des conversions rapides nom-vers-IP et IP-vers-nom. Sa sortie concise le rend adapté au scripting shell.1
* `dnsrecon` : Un script Perl polyvalent conçu pour l'énumération DNS. Il automatise des tâches courantes comme l'interrogation des enregistrements standard (SOA, NS, A, MX, SRV), les tentatives de transfert de zone (AXFR), le brute-forcing de sous-domaines, les recherches inversées sur les plages IP et le snooping de cache DNS.1
* `fierce` : Un autre script Perl populaire, axé sur la localisation d'espace IP non contigu et de noms d'hôtes associés à un domaine. Il effectue des recherches DNS, tente des transferts de zone, vérifie les enregistrements wildcard et inclut des capacités de brute-force.1
* Outils en ligne : De nombreux sites web offrent des capacités de recherche DNS, présentant souvent les données visuellement. Exemples : DNSDumpster, ViewDNS.info, HackerTarget DNS Lookup, MXToolbox, SecurityTrails DNS Trails.3

**Core Techniques & Record Types:**
Comprendre le but des différents types d'enregistrements DNS est crucial pour une reconnaissance efficace.
* Enregistrement A (Adresse - IPv4) : Mappe un nom d'hôte à son adresse IPv4 32 bits. Fondamental pour trouver les IP des serveurs.
    ```bash
    dig target.com A
    nslookup target.com # (Type de requête par défaut)
    host target.com # (Type de requête par défaut) 1
    ```
* Enregistrement AAAA (Adresse - IPv6) : Mappe un nom d'hôte à son adresse IPv6 128 bits. De plus en plus important avec l'adoption croissante d'IPv6.
    ```bash
    dig target.com AAAA 12
    ```
* Enregistrement MX (Mail Exchanger) : Identifie les serveurs de messagerie responsables de l'acceptation des e-mails pour le domaine, listés avec des valeurs de priorité. Essentiel pour comprendre l'infrastructure de messagerie et planifier des évaluations de phishing ou de spoofing.
    ```bash
    dig target.com MX
    nslookup -query=mx target.com
    host -t mx target.com 1
    ```
* Enregistrement TXT (Texte) : Stocke des données textuelles arbitraires. Très important pour trouver les enregistrements de sécurité e-mail (SPF, DKIM, DMARC), les jetons de vérification de propriété de domaine (Google Site Verification, Microsoft 365) et potentiellement d'autres notes informatives.
    ```bash
    dig target.com TXT
    nslookup -type=TXT target.com
    host -t txt target.com 1
    ```
* Enregistrement NS (Nameserver) : Liste les serveurs DNS faisant autorité pour la zone du domaine. Ce sont les serveurs principaux à interroger pour obtenir les informations les plus précises et sont les cibles des tentatives de transfert de zone.
    ```bash
    dig target.com NS
    nslookup -query=ns target.com
    host -t ns target.com 1
    ```
* Enregistrement CNAME (Nom Canonique) : Crée un alias, pointant un nom d'hôte vers un autre (le nom canonique). Utile pour identifier les relations entre les services ou suivre les redirections.
    ```bash
    dig [www.target.com](https://www.target.com) CNAME # (ou juste dig [www.target.com](https://www.target.com))
    nslookup -type=CNAME [www.target.com](https://www.target.com) 7
    ```
* Enregistrement SOA (Start of Authority) : Fournit des détails administratifs sur la zone DNS, y compris le serveur de noms primaire, l'e-mail de l'administrateur (souvent obscurci), le numéro de série de la zone (indique les changements) et divers temporisateurs (refresh, retry, expire).
    ```bash
    dig target.com SOA 13
    ```
* Enregistrement PTR (Pointeur) : Effectue une recherche DNS inversée, mappant une adresse IP à son nom d'hôte associé. Utilisé pour valider la propriété IP et cartographier l'infrastructure réseau.
    ```bash
    dig -x <IP_ADDRESS>
    nslookup <IP_ADDRESS>
    host <IP_ADDRESS> 1
    ```
* Enregistrement ANY : Un type de requête spécial demandant tous les enregistrements DNS disponibles pour un nom. Bien qu'utile en théorie, il est souvent bloqué par les serveurs, limité en débit ou renvoie des résultats incomplets en raison des limitations de taille des paquets UDP ou des politiques serveur. À utiliser avec prudence et ne pas s'y fier pour l'exhaustivité.6
    ```bash
    dig target.com ANY
    nslookup -type=any target.com
    ```
* Enregistrement SRV (Service) : Spécifie l'emplacement (nom d'hôte et port) pour des services spécifiques, souvent utilisés par des protocoles comme LDAP, Kerberos, SIP, XMPP. Crucial pour trouver les points de terminaison de services internes.
    ```bash
    dig _ldap._tcp.target.com SRV
    dnsrecon -d target.com -t srv 12
    ```
* Spécifier le serveur DNS : Requêtes directes vers un serveur spécifique (par exemple, l'un des NS faisant autorité trouvés précédemment, ou un résolveur public comme 8.8.8.8 de Google ou 1.1.1.1 de Cloudflare).
    ```bash
    dig @ns1.target.com target.com MX
    nslookup target.com 8.8.8.8
    host target.com 1.1.1.1 1
    ```
* Sortie courte : Obtenir des résultats concis, idéal pour le scripting ou les vérifications rapides.
    ```bash
    dig target.com A +short 9
    ```
* Tracer la résolution : Afficher le chemin de délégation depuis les serveurs racine jusqu'au serveur de noms faisant autorité pour la requête. Utile pour déboguer les problèmes DNS.
    ```bash
    dig +trace target.com 9
    ```

**Advanced Variations:**
* Transfert de Zone (AXFR) : Tentative de demander une copie complète de la base de données de zone à un serveur de noms faisant autorité. En cas de succès, cela fournit une liste complète de tous les enregistrements DNS pour la zone, révélant souvent des noms d'hôtes internes ou non liés. Cependant, l'AXFR est généralement restreint aux serveurs autorisés uniquement pour des raisons de sécurité.1 L'échec fréquent des tentatives AXFR souligne la nécessité de maîtriser des techniques alternatives d'énumération de sous-domaines, déplaçant l'accent de la reconnaissance d'une méthode unique à haut rendement (mais souvent bloquée) vers l'agrégation de données provenant de multiples sources comme le DNS passif, les logs CT et le brute-forcing.6
    ```bash
    dig @ns1.target.com target.com AXFR
    dnsrecon -d target.com -t axfr
    fierce --domain target.com --dns-servers ns1.target.com
    ```
* DNS Cache Snooping : Technique pour déduire des informations sur l'activité d'une cible en interrogeant un serveur DNS récursif (par exemple, un résolveur interne s'il est accessible, ou parfois des résolveurs publics) pour voir s'il a récemment mis en cache des enregistrements pour des domaines spécifiques. Cela peut révéler des noms d'hôtes internes ou des sites externes récemment visités.6
    ```bash
    dnsrecon -t snoop -n <DNS_IP> -D names_to_check.txt
    ```
* DNS Banner Grabbing / Version Check : Tentative d'identification du logiciel spécifique et de la version d'un serveur DNS. Cette information peut être utilisée pour trouver des vulnérabilités connues.6
    ```bash
    dig @<DNS_IP> version.bind chaos txt
    nmap --script dns-nsid <DNS_IP>
    nc -nv -u <DNS_IP> 53 # (suivi d'une requête de version si le protocole le permet)
    ```
* Recherche inversée sur une plage : Effectuer des recherches PTR pour une plage IP entière afin de découvrir les noms d'hôtes associés. Utile après avoir identifié les blocs réseau cibles via les recherches ASN.1
    ```bash
    # Exemple pour une plage /24
    for ip in $(seq 1 254); do host 192.168.1.$ip; done | grep -v "not found"
    dnsrecon -r 192.168.1.0/24
    ```
* Fuite d'information via nslookup : Technique spécifique où les commandes interactives de `nslookup` peuvent tromper un serveur DNS mal configuré pour révéler son propre nom d'hôte lors de recherches inversées de l'adresse de loopback ou de sa propre adresse IP.11
    ```bash
    # Lancer nslookup en mode interactif
    # > server <ip_of_target_dns>
    # > 127.0.0.1
    # (Observer si le nom d'hôte est révélé)
    ```

**Scenarios/Examples:**
* 📖 Cartographie de l'infrastructure de base : Utiliser les recherches A, AAAA et CNAME sur le domaine principal et les sous-domaines connus (www, mail, vpn, etc.) pour trouver les adresses IP des serveurs primaires.
* 📖 Évaluation de la sécurité e-mail : Interroger les enregistrements MX pour trouver les passerelles de messagerie. Interroger les enregistrements TXT pour `target.com` afin de vérifier les politiques SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) et DMARC (Domain-based Message Authentication, Reporting, and Conformance). Des enregistrements faibles ou manquants indiquent des vulnérabilités potentielles au spoofing.
* 📖 Trouver des services cachés ou internes : Tenter AXFR sur tous les serveurs NS faisant autorité. Effectuer un brute-forcing de sous-domaines (reconnaissance active, abordée plus tard) ou une énumération passive. Rechercher des enregistrements TXT révélateurs ou des enregistrements SRV (_ldap, _kerberos, _sip, etc.).
* 📖 Validation de la portée du réseau : Après avoir trouvé des plages IP via la recherche ASN (depuis WHOIS), utiliser les recherches d'enregistrements PTR (DNS inversé) sur la plage pour confirmer quelles IP se résolvent en noms d'hôtes dans le(s) domaine(s) cible(s).

**Pitfalls & Tips:**
* ⚠️ L'échec d'AXFR est courant : Ne vous attendez pas à ce que les transferts de zone réussissent contre les serveurs de noms externes faisant autorité. Ils sont presque toujours désactivés pour l'accès public. Préparez des stratégies alternatives d'énumération de sous-domaines.6
* ⚠️ Manque de fiabilité de la requête ANY : Les requêtes ANY sont souvent incomplètes ou bloquées. Interrogez les types d'enregistrements spécifiques (A, MX, TXT, NS, etc.) individuellement pour des résultats plus fiables.9
* ⚠️ Enregistrements DNS Wildcard : Un enregistrement wildcard (par exemple, `*.target.com`) peut rendre le brute-forcing de sous-domaines difficile, car il fait en sorte que les sous-domaines inexistants se résolvent avec succès (généralement vers une page ou une IP par défaut). Des outils comme `dnsrecon` (en utilisant `--iw`) et `fierce` tentent de détecter les wildcards, mais une vérification manuelle peut être nécessaire.11
* 💡 Examiner attentivement les enregistrements TXT : Allez au-delà de la simple vérification de SPF/DKIM/DMARC. Recherchez les chaînes de vérification de domaine (par exemple, `google-site-verification=...`, `MS=...`), les commentaires, les indices de découverte de services ou les informations sensibles potentiellement oubliées.1
* 💡 Cibler les serveurs NS faisant autorité : Identifiez toujours d'abord les serveurs de noms faisant autorité pour le domaine en utilisant une recherche NS. Dirigez vos tentatives AXFR et vos requêtes critiques (comme SOA) vers ces serveurs pour obtenir les informations les plus précises.6
* 💡 Stratégie de sélection d'outils : Utilisez `dig` pour des requêtes détaillées et contrôlées et une sortie fiable, surtout pour le scripting.9 Utilisez `nslookup` pour des vérifications interactives rapides ou sur les systèmes où `dig` n'est pas disponible.7 Utilisez `host` pour des recherches simples et rapides, particulièrement dans les scripts shell.8 Employez des outils comme `dnsrecon` ou `fierce` pour automatiser plusieurs tâches d'énumération (recherches standard, vérifications AXFR, brute-forcing).7 Comprendre les forces de chaque outil permet un flux de travail efficace.
* 💡 Combiner avec la découverte passive : Utilisez des requêtes DNS actives (comme les recherches A ou CNAME) pour valider l'existence et la résolution des sous-domaines découverts par des méthodes passives (Logs CT, moteurs de recherche, etc.).

**Table: Common DNS Record Types & Pentesting Relevance**

| Record Type | Full Name                   | Description                                                  | Pentesting Relevance                                                                        |
| :---------- | :-------------------------- | :----------------------------------------------------------- | :------------------------------------------------------------------------------------------ |
| A           | Address (IPv4)              | Mappe le nom d'hôte à l'adresse IPv4                       | Trouver les adresses IP des serveurs, cartographier l'infrastructure                          |
| AAAA        | Address (IPv6)              | Mappe le nom d'hôte à l'adresse IPv6                       | Trouver les adresses IPv6 des serveurs, cartographier l'infrastructure moderne                |
| CNAME       | Canonical Name              | Alias pointant un nom d'hôte vers un autre nom d'hôte       | Identifier les relations de service, suivre les redirections, trouver les vrais noms d'hôtes |
| MX          | Mail Exchanger              | Liste les serveurs de messagerie et leur priorité            | Identifier les passerelles e-mail, évaluer l'infra e-mail, cibler pour phishing/spoofing  |
| NS          | Name Server                 | Liste les serveurs DNS faisant autorité pour la zone       | Identifier l'infra DNS primaire, cibler pour AXFR, trouver la source de données faisant autorité |
| TXT         | Text                        | Stocke des chaînes de texte arbitraires                     | Vérifier SPF/DKIM/DMARC (sécurité e-mail), trouver clés de vérif. domaine, fuites d'info pot. |
| SOA         | Start of Authority          | Info admin. de la zone (NS primaire, email, série)       | Identifier NS primaire, contact admin (rarement utile), fréquence changements zone (série) |
| PTR         | Pointer (Reverse DNS)       | Mappe l'adresse IP vers un nom d'hôte                      | Valider propriété IP, cartographier blocs réseau, identifier hôtes dans une plage       |
| SRV         | Service Locator             | Spécifie nom d'hôte et port pour services spécifiques         | Découvrir services cachés (LDAP, Kerberos, SIP, etc.), identifier points terminaison internes |
| AXFR        | Authoritative Zone Transfer | Requête pour transférer le fichier de zone entier            | (Si succès) Dump complet enregistrements DNS, révèle tous hôtes y compris internes/cachés   |

**Practice Links:** 🎯 Machines HTB : Domain, Active, Haystack ; Salles THM : DNS Manipulation, modules d'énumération (par ex., Network Services, Nmap Live Host Discovery).

**Cross-References:** 🔗 WHOIS Lookups (fournit les enregistrements NS initiaux), 🔗 Énumération de sous-domaines (Passive) (fournit des listes à valider), 🔗 Énumération de sous-domaines (Active) (le brute-forcing repose sur le DNS), 🔗 Scan réseau (utilise les IP résolues).

## Subdomain Enumeration (Passive)

**Concept/Goal:** Découvrir les sous-domaines associés à un domaine cible en interrogeant des sources de données tierces et en analysant les informations publiques disponibles, sans envoyer de trafic réseau directement à l'infrastructure de la cible. L'objectif principal est de cartographier la surface d'attaque potentielle tout en maintenant une discrétion maximale.16

**Key Tools & Sources:**
L'énumération passive de sous-domaines repose fortement sur l'agrégation de données provenant de sources diverses. Les outils agissent souvent comme des frameworks pour interroger plusieurs sources simultanément.

* **Agrégateurs/Frameworks:**
    * `subfinder`: Outil rapide et populaire basé sur Go. Interroge de nombreuses sources passives comme Shodan, VirusTotal, Censys, crt.sh, GitHub, Wayback Machine, etc. Nécessite des clés API pour de nombreuses sources afin d'obtenir des résultats complets.3
    * `amass`: Framework OWASP étendu pour la cartographie de la surface d'attaque. La commande `amass enum -passive` utilise spécifiquement des sources OSINT (similaires à subfinder, plus infos WHOIS, ASN, etc.). Fortement dépendant des clés API pour un scan passif efficace.15
    * `assetfinder`: Outil Go plus simple par tomnomnom. Interroge un ensemble plus restreint de sources (crt.sh, certspotter, HackerTarget, ThreatCrowd, Wayback) et ne nécessite généralement pas de clés API par défaut, mais offre moins de couverture que subfinder/amass.24
    * `theHarvester`: Outil OSINT classique écrit en Python. Collecte emails, noms d'employés, hôtes et sous-domaines à partir de sources comme les moteurs de recherche (Google, Bing), les serveurs de clés PGP, Shodan, Hunter.io, etc.11
    * `Sublist3r`: Outil Python utilisant les moteurs de recherche, les certificats SSL/TLS (crt.sh) et les sources DNS passives (VirusTotal, DNSDumpster).3
    * `Knockpy`: Autre outil Python pour la découverte de sous-domaines, incluant des sources passives.21
    * OSINT Framework : Collection web d'outils OSINT, catégorisés pour une découverte facile, incluant beaucoup pour l'énumération de sous-domaines.15

* **Specific Data Sources/Techniques:**
    * Logs de Transparence des Certificats (CT) : Logs publics de tous les certificats SSL/TLS émis. Sources clés : `crt.sh`, Censys, Facebook CT Tool.15
    * Moteurs de recherche : Google, Bing, DuckDuckGo, Baidu, Yandex utilisant des opérateurs de recherche avancés (dorks).12
    * Bases de données DNS passives : Données de résolution DNS historiques et actuelles agrégées. Sources clés : VirusTotal, SecurityTrails, DNSDumpster, RiskIQ PassiveTotal, Shodan, Censys, CIRCL, Mnemonic, Netlas, BinaryEdge.3
    * Archives Web : Instantanés historiques de sites web. Sources clés : Wayback Machine (Archive.org), CommonCrawl, Arquivo.pt.18
    * Dépôts de code publics : Recherche sur GitHub, GitLab, Bitbucket de mentions de sous-domaines dans le code ou les fichiers de configuration.12
    * Données WHOIS : Analyse des domaines ou serveurs de noms liés trouvés dans les enregistrements WHOIS.3
    * Plateformes de Threat Intelligence : AlienVault OTX, ThreatCrowd, etc., contiennent souvent des données de sous-domaines liées à des activités malveillantes.20
    * Scanners/Agrégateurs en ligne : Sites web comme DNSDumpster, Spyse, Netcraft fournissent des vues agrégées.3

**Core Techniques:**
* Exploitation des API d'outils : Le moyen le plus efficace d'utiliser des outils comme `subfinder` et `amass` est de les configurer avec des clés API pour divers services (VirusTotal, SecurityTrails, Shodan, Censys, GitHub, etc.). Cela débloque l'accès à des ensembles de données beaucoup plus importants que les requêtes non authentifiées.20 La qualité et la quantité des sous-domaines découverts sont directement proportionnelles au nombre et à la qualité des clés API configurées, car les niveaux gratuits ou l'accès non authentifié fournissent des données significativement limitées.18
* Interrogation des logs CT : Utiliser des sites web dédiés comme `crt.sh` ou des outils (`subfinder`, `amass`) qui intègrent les capacités de recherche dans les logs CT.17
* Dorking sur les moteurs de recherche : Employer des requêtes de recherche spécifiques comme `site:*.target.com -site:www.target.com` sur Google, Bing, etc., pour trouver des sous-domaines indexés.12
* Interrogation des agrégateurs DNS passifs : Utiliser les interfaces web de services comme VirusTotal ou DNSDumpster, ou exploiter des outils qui interrogent leurs API.15
* Analyse des archives web : Utiliser des outils ou la navigation manuelle sur des sites comme la Wayback Machine pour trouver des sous-domaines référencés dans les versions historiques des sites web.18
* Combinaison des sorties d'outils : Exécuter plusieurs outils d'énumération passive, collecter leurs sorties dans des fichiers séparés, puis combiner et dédupliquer les résultats pour une liste plus complète.
    ```bash
    cat subfinder_out.txt amass_passive_out.txt assetfinder_out.txt | sort -u > unique_passive_subdomains.txt 17
    ```

**Scenarios/Examples:**
* 💻 Scan complet (Subfinder) : `subfinder -d target.com -all -o subfinder_out.txt` (Nécessite des clés API configurées dans `~/.config/subfinder/provider-config.yaml`) 20
* 💻 Scan complet (Amass) : `amass enum -passive -d target.com -config /path/to/config.ini -o amass_passive_out.txt` (Nécessite des clés API configurées dans `config.ini`) 26
* 💻 Scan de base (Assetfinder) : `assetfinder --subs-only target.com > assetfinder_out.txt` (Plus simple, moins de sources, pas de clés nécessaires par défaut) 29
* 💻 OSINT plus large (theHarvester) : `theHarvester -d target.com -b all -f harvester_report.html` (Trouve aussi emails, hôtes) 11
* 📄 Google Dork : `site:*.target.com -site:www.target.com` 17
* 📖 Vérification manuelle : Interroger le site web `crt.sh` pour `%.target.com`.32
* 📖 Vérification manuelle : Rechercher `target.com` sur le site web de VirusTotal et examiner l'onglet 'Subdomains' ou 'Relations'.23

**Pitfalls & Tips:**
* ⚠️ La gestion des clés API est cruciale : L'efficacité d'outils comme `subfinder` et `amass` dépend de l'obtention et de la configuration correcte des clés API pour des sources comme VirusTotal, SecurityTrails, Shodan, Censys, GitHub, etc. Stockez les clés en toute sécurité dans les fichiers de configuration respectifs (par ex., `~/.config/subfinder/provider-config.yaml` pour `subfinder`, `config.ini` pour `amass`).20
* ⚠️ Données périmées : Les sources passives contiennent souvent des enregistrements historiques. Les sous-domaines trouvés peuvent ne plus être actifs ou ne plus se résoudre. La validation est essentielle.17
* ⚠️ Limitation de débit : Les sites web publics et les niveaux d'API gratuits imposent des limites de requêtes. Des requêtes excessives peuvent entraîner des blocages temporaires ou des résultats incomplets. Rythmez vos requêtes ou utilisez des outils avec une logique intégrée de délai/réessai.2
* 💡 Agréger, Agréger, Agréger : Aucun outil ou source unique ne fournit une image complète. Les meilleurs résultats proviennent de l'exécution de plusieurs outils/requêtes contre diverses sources et de la combinaison des découvertes uniques.17
* 💡 La diversité des sources compte : Assurez-vous que les outils choisis interrogent différents types de données passives (Logs CT, DNS passif, Moteurs de recherche, Archives Web, Dépôts de code) pour une couverture maximale.22
* 💡 Vérifier la découverte récursive : Certains outils (`subfinder -recursive`, `amass`) peuvent tenter de trouver des sous-sous-domaines (par ex., `dev.team.target.com`). Explorez les options des outils pour cette capacité.20
* 💡 La validation est l'étape suivante : Les sous-domaines découverts passivement ne sont que des cibles potentielles. Utilisez des outils de résolution DNS (comme `dnsx`, `massdns`) ou des outils de sondage HTTP (comme `httpx`, `httprobe`) pour déterminer quels sous-domaines sont réellement actifs et résolubles.
    ```bash
    cat unique_passive_subdomains.txt | dnsx -resp -o resolved_subdomains.txt
    cat resolved_subdomains.txt | httpx -o live_webservers.txt -sc -title -tech-detect 18
    ```

**Table: Passive Subdomain Tool Comparison**

| Tool         | Primary Technique(s)                          | Key Data Sources                                        | API Keys Required | Strengths                                   | Weaknesses                                      |
| :----------- | :-------------------------------------------- | :------------------------------------------------------ | :---------------- | :------------------------------------------ | :---------------------------------------------- |
| `subfinder`  | API Aggregation (Passive DNS, CT, Search, etc.) | VT, Shodan, Censys, SecurityTrails, GitHub, CT, etc.    | Yes (Extensive)   | Rapide, Bonne couverture (avec clés), Maintenu | Très dépendant des clés API pour bons résultats |
| `amass`      | API Aggregation, WHOIS/ASN Analysis, Web Scraping | Similaire à subfinder + WHOIS, ASN DBs, plus de sources | Yes (Extensive)   | Couverture très complète, Plusieurs modes   | Plus lent, Complexe, Très dépendant des clés API |
| `assetfinder`| API Aggregation (Smaller Set)                 | crt.sh, CertSpotter, ThreatCrowd, Wayback, etc.         | No (Default)      | Simple, Rapide, Pas de clé initiale requise | Couverture limitée comparée aux autres          |
| `theHarvester`| Search Engine Scraping, API Queries (Hunter, Shodan) | Google, Bing, PGP, Hunter, Shodan, VT, etc.          | Optional          | Collecte Emails/Hôtes aussi, OSINT large     | Peut être lent, CAPTCHAs des moteurs recherche  |
| `Sublist3r`  | Search Engine Scraping, CT Logs, Passive DNS  | Google, Bing, Yahoo, VT, DNSDumpster, crt.sh, etc.      | No (Mostly)       | Facile à utiliser, Couverture correcte      | Moins maintenu ?, Peut rencontrer des CAPTCHAs   |
| `crt.sh`     | CT Log Querying                               | Certificate Transparency Logs                           | No (Web/Basic API)| Accès direct aux données CT, Bon pour nvx domaines | Trouve slmt domaines avec certs TLS, Données histo. |
| VirusTotal   | Passive DNS Database                          | VT's internal DNS resolution data                       | Yes (API) / No (Web) | Grand jeu de données (surtout lié malwares) | UI Web limitée, Limites débit/coûts API        |

**Practice Links:** 🎯 Machines HTB : Topology, Popcorn ; Salles THM : Salles d'énumération pertinentes dans des parcours comme Complete Beginner ou Offensive Pentesting (par ex., modules sur la collecte d'informations).

**Cross-References:** 🔗 Reconnaissance DNS (pour validation), 🔗 Logs de Transparence des Certificats (comme source de données), 🔗 Dorking sur les moteurs de recherche (comme technique), 🔗 Énumération de sous-domaines (Active) (l'étape logique suivante après la reco passive et la validation).

## Certificate Transparency Logs

**Concept/Goal:** Exploiter les logs publics, en ajout seul, mandatés pour l'émission de certificats SSL/TLS afin de découvrir des noms d'hôtes (principalement des sous-domaines) associés à un domaine cible. Les Autorités de Certification (AC) sont tenues de logger chaque certificat qu'elles émettent, créant ainsi un ensemble de données riche et publiquement auditable.17

**Key Tools:**
* `crt.sh`: L'interface web et la source de données la plus proéminente pour interroger les logs CT. Développé par Sectigo (anciennement Comodo CA), il fournit une fonction de recherche et un point de terminaison API JSON basique accessible via des scripts ou des outils comme `curl`.15
* `Censys.io`: Moteur de recherche indexant des données à l'échelle d'Internet, y compris les logs CT. Offre des capacités de recherche plus avancées mais peut nécessiter un compte ou une clé API pour une utilisation extensive.15
* Facebook Certificate Transparency Monitoring Tool : Interface web alternative fournie par Facebook pour rechercher dans les logs CT.33
* `subfinder`, `amass`: Ces outils d'énumération complets intègrent la recherche dans les logs CT (souvent en interrogeant `crt.sh` ou d'autres sources/API CT) dans le cadre de leur flux de travail de découverte passive.15
* `ctfr`: Outil Python spécifiquement conçu pour scraper les sous-domaines de `crt.sh`.

**Core Techniques:**
* Recherche via interface web : La méthode la plus simple est d'utiliser la barre de recherche sur `crt.sh`, Censys, ou l'outil Facebook. Entrez le domaine cible (par ex., `target.com`) ou utilisez une requête wildcard (par ex., `%.target.com`) pour trouver tous les certificats liés au domaine et à ses sous-domaines.33
* Requêtes API/Scriptées : Pour l'automatisation ou l'intégration dans des flux de travail, interrogez le point de terminaison JSON de `crt.sh`. Cela implique généralement d'utiliser `curl` pour récupérer les données et des outils comme `jq` pour parser la sortie JSON et extraire les noms d'hôtes pertinents.30
    ```bash
    curl -s "[https://crt.sh/?q=%.target.com&output=json](https://crt.sh/?q=%.target.com&output=json)" | jq -r '.. | .name_value? // empty' | sed 's/\*\.//g' | sort -u
    ```
* Extraction des SANs : Lors de l'examen des détails du certificat (via l'interface web ou l'API), portez une attention particulière au champ 'Common Name' (CN) et, plus important encore, à l'extension 'Subject Alternative Name' (SAN). Le champ SAN liste explicitement tous les noms d'hôtes (domaines et sous-domaines) pour lesquels le certificat est valide, ce qui en fait une source primaire pour la découverte de sous-domaines dans les logs CT.32

**Scenarios/Examples:**
* 📖 Découverte de sous-domaines non liés publiquement utilisés pour des environnements de développement, de test ou de pré-production (par ex., `dev.target.com`, `uat.api.target.com`, `staging-portal.target.com`) qui pourraient avoir des certificats valides mais des postures de sécurité plus faibles.
* 📖 Identification de sous-domaines associés à des produits, services ou campagnes marketing spécifiques qui pourraient ne pas être facilement trouvés par d'autres moyens.
* 📖 Trouver des sous-domaines nouvellement provisionnés peu après l'émission de leurs certificats, potentiellement avant qu'ils ne soient largement connus ou sécurisés. Les logs CT fournissent une vue quasi temps réel de l'infrastructure nécessitant des certificats TLS, révélant souvent des surfaces d'attaque émergentes plus rapidement que les crawlers web ou les systèmes DNS passifs, qui reposent sur l'observation au fil du temps.18 Cet enregistrement quasi instantané par les AC offre un avantage significatif pour une reconnaissance opportune.

**Pitfalls & Tips:**
* ⚠️ Données historiques : Les logs CT sont en ajout seul et contiennent des enregistrements pour tous les certificats jamais émis et logués, y compris ceux qui sont expirés ou appartiennent à des serveurs/sous-domaines qui ont été décommissionnés. Les découvertes issues des logs CT doivent être validées (par ex., via résolution DNS ou sondage HTTP) pour confirmer qu'elles représentent des hôtes actuellement actifs.17
* ⚠️ Certificats Wildcard : Des certificats émis pour des domaines wildcard (par ex., `*.target.com`) sont fréquemment trouvés dans les logs CT. Bien qu'ils confirment l'existence d'une configuration wildcard, ils ne révèlent pas de noms de sous-domaines spécifiques au-delà du motif lui-même. Les scripts utilisés pour parser les données CT devraient idéalement filtrer ou gérer ces entrées wildcard de manière appropriée (par ex., en utilisant `sed 's/\*\.//g'` pour supprimer le `*.` initial).30
* 💡 Excellente source pour les nouveaux sous-domaines : Parce que l'émission de certificats est loguée presque immédiatement par les AC participantes, les logs CT sont l'une des meilleures sources passives pour découvrir des sous-domaines nouvellement créés, souvent avant que les moteurs de recherche ne les indexent ou que les systèmes DNS passifs n'observent du trafic vers eux.32
* 💡 Élargir les termes de recherche : Ne cherchez pas seulement le domaine principal (`target.com`). Si l'organisation cible a d'autres noms de domaine connus ou des variations, recherchez-les également (`target-corp.com`, `%.target.co.uk`, etc.).
* 💡 Intégrer les découvertes : Utilisez les sous-domaines découverts à partir des logs CT comme entrée pour d'autres étapes de reconnaissance, telles que les vérifications d'enregistrements DNS (A, CNAME, MX, TXT), le scan de ports et l'analyse d'applications web.

**Practice Links:** 🎯 Utilisez le site web `crt.sh` pour explorer les certificats de domaines associés à des machines HTB ou THM actives.

**Cross-References:** 🔗 Énumération de sous-domaines (Passive) (CT est une source de données clé), 🔗 Reconnaissance DNS (pour valider les découvertes CT).

## Search Engine Dorking

**Concept/Goal:** Utiliser des opérateurs de recherche avancés fournis par les moteurs de recherche (comme Google, Bing, DuckDuckGo) et des plateformes de recherche spécialisées (Shodan, Censys, GitHub) pour découvrir des informations publiquement indexées qui n'étaient pas destinées à la divulgation publique. Cela inclut des fichiers sensibles, des erreurs de configuration, des pages de connexion, des identifiants divulgués et des détails d'infrastructure.4

**Key Tools:**
* Moteurs de recherche Web : Google, Bing, DuckDuckGo, Yandex, Baidu. Google est souvent le principal focus en raison de son index étendu.
* Moteurs de recherche spécialisés :
    * Shodan : Recherche les appareils connectés à Internet (serveurs, IoT, ICS), filtrant par port, produit, organisation, localisation, etc.
    * Censys : Similaire à Shodan, se concentre sur les données d'hôte/réseau et les certificats.
    * PublicWWW : Recherche dans le code source (HTML, JS, CSS) des pages web.
    * GreyNoise : Identifie les scanners Internet et le bruit de fond, aidant à différencier les attaques ciblées du scan de masse.
* Dépôts de code : Fonctionnalités de recherche de GitHub, GitLab, Bitbucket.12
* Google Hacking Database (GHDB) : Collection organisée de dorks Google maintenue par Exploit Database, catégorisée par type de vulnérabilité ou fuite d'information.

**Core Techniques & Operators:**
Maîtriser les opérateurs de recherche est la clé d'un dorking efficace.
* `site:` : Restreint les résultats à un domaine, sous-domaine ou domaine de premier niveau (TLD) spécifique. Essentiel pour le ciblage. Exemples : `site:target.com`, `site:*.target.com`, `site:internal.target.com` 12
* `inurl:` : Trouve les pages avec des mots-clés spécifiques dans leur chemin d'URL ou leurs paramètres. Exemples : `inurl:admin`, `inurl:login.php`, `inurl:/app/config` 4
* `intitle:` : Trouve les pages avec des mots-clés spécifiques dans la balise titre HTML. Exemples : `intitle:"index of /"`, `intitle:"Login Panel"` 4
* `filetype:` ou `ext:` : Restreint les résultats à des extensions de fichiers spécifiques. Extrêmement utile pour trouver des documents sensibles ou des fichiers de configuration. Exemples : `filetype:pdf`, `ext:sql`, `ext:log`, `ext:bak`, `ext:cfg`, `ext:env`, `ext:pem` 4
* `intext:` : Recherche des mots-clés spécifiques dans le corps du texte de la page. Exemples : `intext:"password"`, `intext:"Internal Server Error"`, `intext:"DB_PASSWORD"` 4
* `""` (Guillemets) : Recherche l'expression exacte entre guillemets. Exemple : `"Welcome to the admin console"`
* `-` (Moins) : Exclut les résultats contenant le terme suivant le signe moins. Crucial pour affiner les recherches. Exemple : `site:*.target.com -site:www.target.com` 12
* `*` (Wildcard) : Agit comme un espace réservé pour un ou plusieurs mots dans une requête.
* `cache:` : Affiche la version en cache de Google d'une page, utile si la page en direct est inaccessible ou a changé.
* Recherche GitHub/GitLab : Utiliser des mots-clés spécifiques (`password`, `secret`, `api_key`, `config`, `BEGIN RSA PRIVATE KEY`), des filtres d'organisation (`org:target-org`), des filtres de nom de fichier (`filename:.env`), des filtres de langage (`language:python`).12
* Recherche Shodan/Censys : Utiliser des filtres comme `hostname:target.com`, `org:"Target Org Name"`, `port:22`, `product:nginx`, `ssl:"target.com"`.

**Scenarios/Examples (Dorks):**
* 📄 Découverte de sous-domaines : `site:*.target.com -site:www.target.com` 12
* 📄 Portails de connexion : `site:target.com (inurl:login | inurl:signin | intitle:Login | intitle:"Sign In")`
* 📄 Répertoires exposés : `site:target.com intitle:"index of /"`
* 📄 Fichiers de configuration : `site:target.com (ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env)`
* 📄 Fichiers/Dumps de base de données : `site:target.com (ext:sql | ext:dbf | ext:mdb | ext:db)`
* 📄 Fichiers journaux : `site:target.com ext:log`
* 📄 Fichiers de sauvegarde : `site:target.com (ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup | ext:zip | ext:tar.gz)`
* 📄 Erreurs SQL : `site:target.com intext:"sql syntax near" | intext:"syntax error has occurred"`
* 📄 Infos/Erreurs PHP : `site:target.com (ext:php intitle:"phpinfo()") | intext:"PHP Parse error" | intext:"PHP Warning"`
* 📄 Documents sensibles : `site:target.com (filetype:pdf | filetype:docx | filetype:xlsx | filetype:pptx) (intitle:"confidential" | intext:"internal use only")`
* 📄 Secrets GitHub : `org:TargetCompany "Authorization: Bearer"`, `filename:.npmrc _auth`
* 📄 Services exposés Shodan : `org:"Target Org" port:3389`, `hostname:.target.com product:"mongodb"`, `port:5900 authentication disabled`

**Pitfalls & Tips:**
* ⚠️ CAPTCHAs & Limitation de débit : Les outils de dorking automatisés ou la recherche manuelle rapide peuvent déclencher des CAPTCHAs ou des blocages IP temporaires par les moteurs de recherche. Implémentez des délais ou utilisez des proxies rotatifs/VPN si vous automatisez.18
* ⚠️ Surcharge d'informations : Les dorks larges peuvent retourner des milliers de résultats non pertinents. Affinez les requêtes itérativement en utilisant plusieurs opérateurs, des phrases exactes (`""`) et des exclusions (`-`).
* 💡 Explorer la GHDB : La Google Hacking Database sur Exploit DB est une ressource inestimable pour trouver des dorks pré-faits ciblant des vulnérabilités, technologies et types de fichiers spécifiques.
* 💡 Combiner puissamment les opérateurs : Créez des requêtes très spécifiques en enchaînant les opérateurs. Exemple : `site:dev.target.com filetype:log intext:"password" -inurl:test`.
* 💡 Penser comme un développeur/admin : Considérez les noms d'applications spécifiques à la cible, les noms de code de projets internes, les messages d'erreur courants ou les identifiants par défaut.
* 💡 Aller au-delà de Google : Différents moteurs de recherche (Bing, DuckDuckGo) et plateformes spécialisées (Shodan, Censys, GitHub, PublicWWW) ont des priorités et des capacités d'indexation différentes. Interrogez plusieurs plateformes pour des découvertes uniques.12 Le dorking transforme efficacement les index de recherche publics en puissants scanners de vulnérabilités passifs en exploitant leur capacité à indexer le contenu des fichiers, les chemins d'URL et les messages d'erreur spécifiques, découvrant ainsi des données exposées en dehors des contrôles d'accès prévus.4

> **Insight:** Le Dorking représente une méthode pour découvrir des fuites d'informations profondes en interrogeant de vastes ensembles de données publiquement indexées à la recherche de motifs spécifiques indicatifs de mauvaises configurations, d'identifiants exposés ou de fichiers sensibles.

**Table: Common Google/Search Dork Operators**

| Operator   | Description                                        | Example Usage                                      |
| :--------- | :------------------------------------------------- | :------------------------------------------------- |
| `site:`    | Restreint la recherche à un domaine/sous-domaine/TLD | `site:target.com`, `site:*.target.com`             |
| `inurl:`   | Trouve des mots-clés dans le chemin ou les paramètres URL | `inurl:admin`, `inurl:?id=`                      |
| `intitle:` | Trouve des mots-clés dans le titre HTML de la page   | `intitle:"index of /"`, `intitle:"Login"`          |
| `filetype:`| Recherche des extensions de fichiers spécifiques      | `filetype:pdf`, `filetype:sql`                     |
| `ext:`     | Syntaxe alternative pour `filetype:`                | `ext:log`, `ext:bak`                               |
| `intext:`  | Recherche des mots-clés dans le corps de la page    | `intext:"password"`, `intext:"Internal Server Error"` |
| `""`       | Recherche l'expression exacte                      | `"confidential internal report"`                   |
| `-`        | Exclut les résultats contenant le terme spécifié   | `site:*.target.com -site:www.target.com`           |
| `*`        | Placeholder wildcard pour un ou plusieurs mots      | `"Forgot * password"`                              |
| `cache:`   | Affiche la version en cache de Google d'une URL    | `cache:http://target.com/oldpage.html`             |
| `related:` | Trouve des sites liés à un domaine donné           | `related:target.com`                             |
| `link:`    | Trouve des pages pointant vers une URL spécifique (usage varie) | `link:http://target.com`                     |

**Practice Links:** 🎯 Google Hacking Database (GHDB) sur Exploit DB. De nombreuses boîtes HTB/THM cachent des flags ou des identifiants dans des fichiers publiquement indexés découvrables via le dorking.

**Cross-References:** 🔗 Énumération de sous-domaines (Passive), 🔗 Recherche dans les dépôts de code publics, 🔗 Analyse de métadonnées, 🔗 Accès initial (en utilisant les informations/identifiants trouvés).

## Email & Username Gathering

**Concept/Goal:** Identifier les adresses e-mail et les noms d'utilisateur valides associés à l'organisation cible et à ses employés. Ces informations sont cruciales pour l'ingénierie sociale (phishing), les attaques d'identifiants (password spraying, brute-force) et la cartographie de la structure du personnel de l'organisation.15

**Key Tools:**
* `theHarvester`: Outil OSINT fortement recommandé qui agrège les données de nombreuses sources (moteurs de recherche comme Google/Bing, serveurs de clés PGP, Shodan, LinkedIn, Hunter.io, VirusTotal, etc.) pour trouver des emails, sous-domaines, hôtes et noms d'employés.11
* `Hunter.io`, `Skrapp.io`, `Snov.io`: Services commerciaux (souvent avec des niveaux gratuits limités) spécifiquement conçus pour trouver et vérifier les adresses e-mail professionnelles basées sur les domaines d'entreprise et les noms d'employés.
* OSINT Framework : Fournit des liens vers divers outils dédiés à la découverte d'emails et de noms d'utilisateur.15
* Moteurs de recherche (Dorking) : Utilisation d'opérateurs de recherche spécifiques pour trouver des adresses e-mail mentionnées sur des sites web ou dans des documents publics.12
* Données WHOIS : Contiennent occasionnellement des emails de contact administratifs ou techniques, bien que fréquemment obscurcis par des services de confidentialité.2
* Bases de données de fuites publiques : Services comme Have I Been Pwned (HIBP) et DeHashed permettent de vérifier si des domaines d'entreprise ou des adresses e-mail spécifiques sont apparus dans des fuites de données connues.15
* LinkedIn / Médias Sociaux : Plateformes comme LinkedIn sont des sources primaires pour les noms d'employés et les titres de poste, qui peuvent être utilisés pour deviner les adresses e-mail basées sur des motifs courants. Les outils peuvent scraper ces données (utiliser éthiquement).15
* Outils d'extraction de métadonnées : Des outils comme `exiftool` peuvent parfois extraire des noms d'auteurs ou des noms d'utilisateur des métadonnées de documents publiquement disponibles.15

**Core Techniques:**
* Agrégation automatisée : Utiliser des outils comme `theHarvester` pour interroger plusieurs sources simultanément.
    ```bash
    theharvester -d target.com -b all # (Interroge toutes les sources supportées) 12
    theharvester -d target.com -b google,linkedin,hunter # (Interroge des sources spécifiques)
    ```
* Dorking sur les moteurs de recherche : Élaborer des requêtes spécifiques pour trouver des adresses e-mail.
    * 📄 `site:target.com intext:"@target.com"`
    * 📄 `site:target.com filetype:pdf "email" | "contact"`
    * 📄 `site:linkedin.com "VP of Engineering" "Target Company"` (Pour trouver des noms)
* Analyse des motifs de format d'email : Une fois quelques emails valides trouvés (par ex., `john.doe@target.com`, `j.doe@target.com`), déduire le(s) format(s) courant(s) de l'entreprise (par ex., `prenom.nom`, `pnom`, `prenomn`, `prenom`). Générer des adresses e-mail potentielles pour les noms d'employés connus en utilisant ces motifs.
* Recherche WHOIS : Vérifier les champs de contact Admin, Tech et Registrant, mais s'attendre à des occultations de confidentialité.2
* Extraction de métadonnées : Analyser les documents hébergés publiquement par la cible.
    ```bash
    exiftool target_document.pdf | grep -i "Author\|Creator" 15
    ```
* Scraping des médias sociaux (Manuel/Automatisé) : Identifier les noms et rôles des employés sur LinkedIn, Twitter, le site web de l'entreprise (pages 'À propos'), etc.15
* Vérification des données de fuites : Interroger Have I Been Pwned (recherche de domaine pour les abonnés, vérification d'email individuel pour tous) ou DeHashed (service payant) pour voir si des emails ou noms d'utilisateur de l'entreprise ont été exposés dans des fuites.15

**Scenarios/Examples:**
* 📖 Campagne de phishing : Compiler une liste d'adresses e-mail validées appartenant à des employés de départements spécifiques (par ex., Finance, RH) pour des attaques de spear-phishing ciblées.
* 📖 Password Spraying : Générer une liste de noms d'utilisateur potentiels (souvent dérivés des formats d'email, par ex., `jdoe` de `john.doe@target.com`) à utiliser dans des attaques de devinette de mot de passe lentes et à faible volume contre les portails de connexion externes (VPN, OWA, M365, Citrix).
* 📖 Prétextes d'ingénierie sociale : Identifier le personnel clé (support IT, cadres, assistants administratifs) et leurs coordonnées pour construire des scénarios d'ingénierie sociale plus crédibles.
* 📖 Évaluation des risques : Vérifier si les adresses e-mail de l'entreprise apparaissent fréquemment dans les fuites de données via HIBP, indiquant un risque plus élevé de réutilisation d'identifiants parmi les employés.15

**Pitfalls & Tips:**
* ⚠️ Validité des emails : Les informations recueillies à partir de sources publiques peuvent être obsolètes. Les emails peuvent appartenir à d'anciens employés, être mal orthographiés ou représenter des boîtes aux lettres défuntes. La validation est souvent nécessaire mais doit être effectuée avec soin pour éviter d'alerter la cible (par ex., éviter d'envoyer des emails réels). Certains outils prétendent valider sans envoyer, mais la fiabilité varie.15
* ⚠️ Confidentialité & Légalité : La collecte et l'utilisation de données personnelles comme les adresses e-mail sont soumises à des réglementations (par ex., RGPD, CCPA) et à des directives éthiques. Opérez toujours dans le cadre des règles d'engagement et des lois applicables. Concentrez-vous sur les informations pertinentes pour l'évaluation de la sécurité.
* 💡 Déduire les motifs d'email : Découvrir même une ou deux adresses e-mail d'entreprise valides suffit souvent à déduire la ou les conventions de nommage standard utilisées par l'organisation. Combinez les noms d'employés connus avec ces motifs pour générer une liste plus large d'emails probables.
* 💡 Combiner plusieurs sources : Agréger les résultats de `theHarvester`, des outils spécialisés (`Hunter.io`), de la recherche manuelle sur LinkedIn et de la devinette de motifs pour obtenir la liste la plus complète.
* 💡 HIBP indique un risque : Trouver des emails d'entreprise dans Have I Been Pwned suggère que ces identifiants pourraient avoir été compromis. Cela augmente la probabilité de succès des attaques de credential stuffing ou de réutilisation de mot de passe si les employés n'ont pas changé leurs mots de passe.15
* 💡 Cibler les emails basés sur les rôles et génériques : N'oubliez pas les adresses courantes basées sur les rôles comme `info@`, `support@`, `sales@`, `admin@`, `security@`, `hr@`, `careers@`, car elles peuvent être des points d'entrée ou des sources d'information précieuses.

**Practice Links:** 🎯 Les salles THM dans les modules Phishing ou Initial Access nécessitent souvent la collecte d'emails. Les cibles fictives dans les CTF ont parfois des motifs d'email découvrables.

**Cross-References:** 🔗 WHOIS Lookups, 🔗 Analyse des médias sociaux, 🔗 Analyse de métadonnées, 🔗 Dorking sur les moteurs de recherche, 🔗 Accès Initial (Phishing, Password Spraying).

## Social Media Analysis

**Concept/Goal:** Recueillir des renseignements sur une organisation cible, ses employés, sa pile technologique, sa culture interne, ses emplacements physiques et ses vulnérabilités potentielles en analysant les informations partagées publiquement sur les plateformes de médias sociaux.15

**Key Tools:**
* Plateformes :
    * LinkedIn : Source principale d'informations professionnelles - noms d'employés, titres de poste, compétences, historique professionnel, connexions, mises à jour de l'entreprise, technologies mentionnées dans les profils ou les offres d'emploi.
    * Twitter : Informations en temps réel, discussions d'employés, discussions techniques, participation à des conférences, interactions avec le service client, mentions occasionnelles d'outils ou de projets internes.
    * Facebook : Informations personnelles (loisirs, intérêts, enregistrements de localisation, événements), pages d'entreprise, groupes publics auxquels les employés pourraient appartenir.
    * Instagram : Renseignements visuels - photos/vidéos d'espaces de bureau, d'équipements, de badges d'employés (rarement !), d'événements, de lieux.
    * GitHub/GitLab/Stack Overflow : Activité des développeurs, dépôts de code, compétences techniques, technologies préférées, fuites de code potentielles (souvent liées depuis les profils professionnels).12
* Vérificateurs de noms d'utilisateur : Des outils comme `Sherlock`, `Maigret`, ou `WhatsMyName.app` aident à trouver des profils associés à un nom d'utilisateur connu sur des centaines de plateformes.
* Moteurs de recherche : Utiliser des techniques de dorking pour trouver des profils ou des publications spécifiques. Exemple : `site:linkedin.com "DevOps Engineer" "Target Company"`
* OSINT Framework : Liens vers des outils de recherche spécialisés dans les médias sociaux et des ressources.15

**Core Techniques:**
* Identification et profilage des employés : Rechercher sur LinkedIn, Twitter, etc., les personnes indiquant l'entreprise cible comme employeur. Se concentrer sur les rôles pertinents pour les vecteurs d'attaque potentiels : personnel IT/Sécurité, développeurs, administrateurs système, cadres, assistants administratifs. Analyser leurs profils pour les compétences (par ex., AWS, Python, Cisco IOS), les technologies utilisées, les projets mentionnés, le parcours éducatif, les anniversaires de travail et les connexions.31
* Surveillance des publications publiques : Examiner systématiquement les publications publiques, les tweets et les mises à jour de l'entreprise et des employés connus. Rechercher les mentions de logiciels/matériels spécifiques, les noms de projets internes, les actualités ou réorganisations de l'entreprise, les plaintes courantes (points faibles potentiels), les événements à venir et les discussions informelles sur le travail.
* Analyse d'images et de vidéos : Examiner attentivement les photos et vidéos postées publiquement par l'entreprise ou les employés. Rechercher des détails en arrière-plan : notes sur tableau blanc, écrans d'ordinateur, modèles d'équipement, badges de sécurité, plans de bureau, documents visibles. Vérifier les géotags si disponibles (bien que souvent supprimés). Utiliser la recherche d'images inversée pour trouver d'autres instances ou contextes d'une image.
* Cartographie des réseaux et des relations : Analyser les connexions, les abonnés et les listes d'abonnements sur des plateformes comme LinkedIn et Twitter pour comprendre la structure organisationnelle, identifier les influenceurs clés ou cartographier les relations avec les partenaires, les fournisseurs ou les anciens employés.
* Analyse de l'appartenance à des groupes : Identifier les groupes publics (sur LinkedIn, Facebook, Reddit, etc.) auxquels appartiennent les employés. Les groupes axés sur la technologie pourraient révéler des intérêts techniques spécifiques ou des problèmes qu'ils essaient de résoudre.

**Scenarios/Examples:**
* 📖 Identification des noms et des motifs d'email des administrateurs IT pour des attaques ciblées de phishing ou de password spraying.
* 📖 Découverte que l'entreprise utilise fortement un fournisseur de cloud spécifique (par ex., AWS, Azure) ou une plateforme SaaS à partir des offres d'emploi ou des validations de compétences des employés sur LinkedIn, guidant ainsi la reconnaissance ultérieure vers ces plateformes.
* 📖 Trouver des développeurs discutant de problèmes avec un framework ou une bibliothèque particulière sur Twitter ou Stack Overflow, révélant potentiellement des versions ou des configurations.
* 📖 Collecte de détails personnels sur une cible de grande valeur (par ex., PDG, DAF) à partir de leurs profils publics Facebook ou Instagram (loisirs, voyages récents, noms de famille) pour élaborer des prétextes d'ingénierie sociale très personnalisés.
* 📖 Repérer une photo postée depuis une conférence où le badge d'un employé est partiellement visible, révélant potentiellement son nom ou son niveau d'accès.
* 📖 Apprendre les noms de code de projets internes ou les lancements de produits à venir mentionnés de manière informelle dans des tweets ou des articles de blog.

**Pitfalls & Tips:**
* ⚠️ Exactitude et actualité de l'information : Les profils et publications sur les médias sociaux peuvent être obsolètes, contenir des embellissements ou être intentionnellement trompeurs. Essayez toujours de recouper les informations critiques en utilisant plusieurs sources indépendantes.
* ⚠️ Paramètres de confidentialité & Éthique : Respectez les paramètres de confidentialité des utilisateurs et les conditions d'utilisation de chaque plateforme. Concentrez-vous sur les informations clairement publiques. Évitez les méthodes trop intrusives ou le scraping excessif qui pourraient être considérés comme contraires à l'éthique ou illégaux. Assurez-vous que toutes les activités sont conformes aux règles d'engagement de la mission.
* ⚠️ Signal vs. Bruit : Les médias sociaux génèrent une quantité massive de données. Filtrez agressivement et concentrez les recherches sur les informations directement pertinentes pour les vecteurs d'attaque potentiels (par ex., détails techniques, personnel clé, pratiques de sécurité). Évitez de vous perdre dans des détails personnels non pertinents.
* 💡 LinkedIn est souvent la référence : Pour le contexte professionnel, les rôles des employés, les compétences et la structure de l'entreprise, LinkedIn est généralement la source la plus précieuse et structurée.
* 💡 Suivre les développeurs : Vérifiez les profils GitHub, GitLab, Bitbucket et Stack Overflow liés depuis les comptes de médias sociaux des développeurs. Ceux-ci contiennent souvent des extraits de code, des exemples de configuration ou des discussions techniques révélant des informations précieuses.12
* 💡 Maintenir la sécurité opérationnelle (OpSec) : Utilisez des comptes de reconnaissance dédiés (sock puppets) qui ne sont pas liés à votre identité réelle. Évitez les interactions directes (aimer, commenter, suivre, se connecter) avec les individus cibles ou les profils d'entreprise, sauf si cela fait partie délibérément de la stratégie d'engagement (par ex., ingénierie sociale).

> L'OSINT sur les médias sociaux fournit un contexte crucial qui complète les découvertes techniques. Comprendre les personnes, les processus et les technologies au sein d'une organisation, glanés sur des plateformes comme LinkedIn ou Twitter, peut augmenter considérablement l'efficacité de l'exploitation technique et des tentatives d'ingénierie sociale.16 Alors que les scans techniques montrent ce qui est exposé, les médias sociaux peuvent révéler qui le gère et comment il est utilisé.

**Practice Links:** 🎯 Inclure la recherche d'employés d'entreprises fictives sur LinkedIn/Twitter dans le cadre de la phase de reconnaissance dans les walkthroughs CTF ou les labs pratiques.

**Cross-References:** 🔗 Collecte d'emails & noms d'utilisateur, 🔗 Analyse de métadonnées, 🔗 Dorking sur les moteurs de recherche, 🔗 Recherche dans les dépôts de code publics, 🔗 Ingénierie Sociale (SE).

## Metadata Analysis

**Concept/Goal:** Extraire des informations cachées (métadonnées ou données EXIF) intégrées dans des fichiers publiquement accessibles tels que des documents, images, vidéos et présentations découverts lors de la reconnaissance. Ces données peuvent révéler des détails sur l'origine du fichier, les auteurs, les logiciels utilisés et parfois des informations de localisation.15

**Key Tools:**
* `exiftool`: Par Phil Harvey, c'est l'outil en ligne de commande standard de facto. Il prend en charge une vaste gamme de types de fichiers et de formats de métadonnées, offrant des capacités d'extraction complètes.
* Visualiseurs de métadonnées en ligne : Des sites web comme Jeffrey's Exif Viewer ou Metadata2Go permettent de télécharger des fichiers ou de fournir des URL pour afficher les métadonnées sans installer de logiciel.
* Propriétés de fichier du système d'exploitation : Les métadonnées de base (auteur, dates de création/modification, logiciel) peuvent souvent être consultées à l'aide de la boîte de dialogue des propriétés de fichier intégrée dans Windows (Clic droit -> Propriétés -> Détails) ou macOS (Cmd+I -> Plus d'infos).
* Outils de développement du navigateur Web : Peuvent parfois révéler des métadonnées intégrées dans les en-têtes de réponse HTTP (par ex., `Server`, `X-Powered-By`) ou dans le contenu du fichier lui-même lors de l'aperçu de certains types de fichiers.

**Core Techniques:**
* Découverte de fichiers : Localiser les fichiers potentiellement intéressants hébergés par la cible. Utiliser le dorking sur les moteurs de recherche avec les opérateurs `filetype:` ou `ext:` (par ex., `site:target.com filetype:pdf`, `site:target.com ext:docx`) ou crawler le(s) site(s) web cible(s).4
* Extraction de métadonnées : Télécharger les fichiers découverts et les traiter à l'aide d'`exiftool`.
    ```bash
    exiftool downloaded_document.pdf
    exiftool -r /path/to/downloaded_files/ # (Scan récursif d'un répertoire)
    ```
* Analyse ciblée : Examiner la sortie d'`exiftool`, en recherchant spécifiquement les champs qui pourraient fournir des renseignements précieux.

**Information Potentially Gathered:**
* Informations sur l'auteur/créateur : Noms d'utilisateur (par ex., noms de connexion Windows), vrais noms, initiales. Peut aider à identifier les employés ou les formats de noms d'utilisateur standard.
* Informations logicielles : Logiciel utilisé pour créer ou modifier le fichier (par ex., Microsoft Word 16.0, Adobe Photoshop CC 2023, Canon EOS Utility). Peut révéler la pile logicielle interne et les versions, mettant potentiellement en évidence des logiciels vulnérables.
* Données de localisation : Coordonnées GPS (latitude, longitude, altitude), particulièrement courantes dans les photos prises avec des smartphones ou des appareils photo compatibles GPS. Peut localiser les bureaux, les lieux d'événements ou les emplacements des employés. Les noms d'imprimantes ou les chemins réseau peuvent également être intégrés.
* Horodatages : Date de création précise, date de modification, date de dernière impression. Peut fournir un contexte sur le cycle de vie du document.
* Informations sur l'appareil : Marque et modèle de l'appareil photo, modèle du scanner, potentiellement détails de l'appareil mobile.
* Contenu caché : Commentaires, annotations, historique des révisions (en particulier dans les documents Office), diapositives masquées dans les présentations.

**Scenarios/Examples:**
* 📖 Trouver le nom d'utilisateur Windows de la personne qui a créé un rapport PDF publiquement disponible, révélant potentiellement le format de nom d'utilisateur interne (par ex., `j.smith`).
* 📖 Identifier que les supports marketing ont été créés à l'aide d'une ancienne version vulnérable d'Adobe InDesign en examinant les métadonnées d'une image.
* 📖 Découvrir des noms d'imprimantes réseau internes (par ex., `\\PRINTSRV01\MarketingColor`) intégrés dans les métadonnées d'un fichier DOCX.
* 📖 Extraire des coordonnées GPS précises à partir de photos postées sur le blog "Événement de team building" d'une entreprise, confirmant l'emplacement.
* 📖 Trouver des commentaires cachés ou des modifications suivies dans un document Word qui révèlent des discussions internes ou des données sensibles.

**Pitfalls & Tips:**
* ⚠️ La suppression des métadonnées est courante : De nombreuses plateformes en ligne (sites de médias sociaux comme Facebook/Twitter/Instagram, services d'hébergement d'images comme Imgur) suppriment automatiquement la plupart des métadonnées des fichiers téléchargés pour protéger la vie privée des utilisateurs. Par conséquent, la valeur de l'analyse des métadonnées est la plus élevée pour les fichiers téléchargés directement depuis les propres sites web ou serveurs de l'organisation cible, car ceux-ci sont moins susceptibles d'avoir subi une suppression automatisée.15 Prioriser le dorking pour les fichiers spécifiquement sur le domaine cible (`site:target.com filetype:...`).
* ⚠️ Données inexactes ou génériques : Les champs de métadonnées peuvent être vides, inexacts, obsolètes ou contenir des valeurs génériques (par ex., Auteur : "Admin", Logiciel : "Microsoft Word"). Ne traitez pas toutes les découvertes comme une vérité définitive ; corrélez si possible.
* 💡 Se concentrer sur les téléchargements directs : Prioriser l'analyse des fichiers obtenus directement depuis les serveurs web de la cible, les partages de fichiers (si accessibles) ou les dépôts de code.
* 💡 Automatiser l'extraction : Si vous traitez de nombreux fichiers, scriptez `exiftool` pour qu'il s'exécute récursivement et filtre potentiellement les balises intéressantes spécifiques (`grep -i 'Author\|Creator\|Software\|GPS'`).
* 💡 Vérifier divers types de fichiers : Ne limitez pas l'analyse aux PDF et JPEG. Les documents Office (DOCX, XLSX, PPTX), les fichiers audio/vidéo (MP3, MP4, MOV) et même certains formats d'archive peuvent contenir des métadonnées précieuses.
* 💡 Combiner avec d'autres OSINT : Utilisez les noms d'utilisateur trouvés dans les métadonnées pour rechercher sur les médias sociaux ou deviner des adresses e-mail. Utilisez les versions logicielles trouvées pour rechercher des vulnérabilités connues.

**Practice Links:** 🎯 De nombreux CTF cachent des flags ou des indices dans les métadonnées des fichiers image ou document fournis. Les salles THM couvrant l'OSINT ou la Forensique incluent souvent des défis de métadonnées.

**Cross-References:** 🔗 Dorking sur les moteurs de recherche (pour trouver des fichiers), 🔗 Collecte d'emails & noms d'utilisateur (en utilisant les noms d'utilisateur trouvés), 🔗 Analyse des médias sociaux (en corrélant les noms d'auteurs).

## Public Code Repository Search

**Concept/Goal:** Rechercher dans les dépôts de code publics comme GitHub, GitLab et Bitbucket des informations sensibles commises par inadvertance par l'organisation cible ou ses employés. Cela peut inclure des identifiants, des clés API, des noms d'hôtes internes, des détails de configuration ou du code source propriétaire.12

**Key Tools:**
* Interfaces de recherche des dépôts : Les fonctionnalités de recherche intégrées dans les plateformes GitHub, GitLab et Bitbucket. Celles-ci permettent de rechercher du code, des commits, des issues, etc., en utilisant des mots-clés et des filtres.
* Scanners de secrets automatisés :
    * `gitleaks`: Outil open-source populaire qui scanne les dépôts Git (y compris l'historique) à la recherche de secrets en utilisant des expressions régulières et une analyse d'entropie.
    * `truffleHog`: Autre outil largement utilisé qui se concentre sur la recherche de chaînes à haute entropie et de mots-clés spécifiques dans tout l'historique des commits d'un dépôt.
    * `git-secrets`: Principalement conçu pour empêcher de commettre des secrets, mais ses motifs peuvent être utilisés pour scanner des dépôts existants.
* Plateformes commerciales : Des services comme GitGuardian offrent un scan continu des secrets en tant que service.
* Recherche manuelle/scriptée : Cloner des dépôts (`git clone`) et utiliser des outils de recherche en ligne de commande comme `grep` ou, plus efficacement, `rg` (ripgrep) pour rechercher des motifs dans la base de code et l'historique (`git log -S<string>`).

**Core Techniques:**
* Recherche ciblée (UI Web/API) : Utiliser la barre de recherche de la plateforme avec des mots-clés spécifiques pertinents pour les secrets (`password`, `secret`, `api_key`, `private_key`, `token`, `credentials`, `config`, `connectionstring`), combinés avec des filtres pour l'organisation cible (`org:TargetCompany`), des utilisateurs spécifiques (développeurs connus), des dépôts (`repo:TargetCompany/project`), des noms de fichiers (`filename:.env`, `filename:config.php`), ou des langages de programmation (`language:java`).12
* Analyse de l'historique des commits : Les secrets sont souvent commis accidentellement puis supprimés dans un commit ultérieur. Cependant, ils restent dans l'historique Git. Des outils comme `truffleHog` sont spécifiquement conçus pour scanner l'ensemble de l'historique des commits, pas seulement l'état actuel du code. Manuellement, `git log -p` ou `git log -S"keyword"` peuvent être utilisés pour inspecter les changements introduisant ou supprimant des secrets potentiels. Cette analyse historique est critique car scanner simplement la dernière version du code fournit une vue incomplète des données divulguées.12
* Chasse aux fichiers de configuration : Rechercher activement les noms ou extensions de fichiers de configuration courants qui contiennent fréquemment des données sensibles : `.env`, `config.yaml`, `settings.py`, `database.yml`, `web.config`, `credentials.json`, `*.pem`, `*.key`.
* Scan automatisé : Cloner les dépôts appartenant à l'organisation cible ou à ses développeurs et exécuter des scanners automatisés sur les copies locales. Ces outils utilisent des motifs prédéfinis et des vérifications d'entropie pour identifier efficacement les secrets potentiels.
    ```python
    # 🐍 Exemple de snippet de script utilisant gitleaks:
    # git clone <repo_url> && cd <repo_name> && gitleaks detect --source . -v --report leaks_report.json
    ```
* Exploration des Forks et Gists : N'oubliez pas de vérifier les forks publics des dépôts de l'organisation (des secrets pourraient exister dans des forks qui ne sont pas dans l'original) et les gists publics créés par les employés, car ceux-ci sont parfois utilisés pour partager des extraits de code qui pourraient contenir des informations sensibles.

**Scenarios/Examples:**
* 📄 GitHub Search Dork : `org:TargetCompany filename:.env DB_PASSWORD`
* 📄 GitHub Search Dork : `"target.internal.domain" org:TargetCompany`
* 📄 GitHub Search Dork : `path:config language:yaml "api_key"`
* 💻 Scan d'un dépôt cloné : `truffleHog git file:///path/to/cloned/repo`
* 📖 Trouver des clés d'accès AWS codées en dur (`AKIA...`) et des clés secrètes dans le dépôt de scripts utilitaires public d'un développeur.
* 📖 Découvrir des chaînes de connexion de base de données, y compris les noms d'utilisateur et les mots de passe, dans un fichier `settings.py` pour une application Django.
* 📖 Localiser des points de terminaison d'API internes, des noms d'hôtes (`server.corp.local`) ou des adresses IP privées mentionnés dans des commentaires, des cas de test ou des fichiers de configuration.
* 📖 Trouver des algorithmes propriétaires, une logique métier ou des structures de données client commis accidentellement dans un dépôt public.

**Pitfalls & Tips:**
* ⚠️ Volume élevé de faux positifs : La recherche de termes génériques comme "password" ou l'utilisation seule du scan d'entropie peut générer de nombreux faux positifs (par ex., identifiants d'exemple, clés de test, chaînes aléatoires). Un examen manuel attentif et une analyse contextuelle sont nécessaires pour valider les découvertes potentielles.
* ⚠️ Les secrets résident dans l'historique : Une erreur critique est de ne scanner que la dernière version du code. Les secrets sont souvent commis puis supprimés. Utilisez des outils (`truffleHog`, `gitleaks`) qui scannent explicitement l'ensemble de l'historique des commits.12
* ⚠️ Secrets obfusqués ou indirects : Les secrets peuvent être faiblement encodés (par ex., Base64), divisés entre plusieurs variables, chargés à partir de variables d'environnement (vérifiez les Dockerfiles ou les scripts CI/CD), ou stockés dans des systèmes de gestion de configuration externes mentionnés dans le code.
* 💡 Cibler les comptes des employés : Identifier les développeurs via LinkedIn ou d'autres méthodes OSINT et examiner spécifiquement leurs dépôts publics et contributions.
* 💡 Prioriser les fichiers de configuration : Concentrer les recherches sur les noms de fichiers et motifs de configuration courants, car ce sont des emplacements à haute probabilité pour les identifiants, les clés API et les chemins internes.
* 💡 Vérifier les Forks, Gists et Suivis d'issues : Des informations sensibles peuvent fuiter via les forks, les gists publics utilisés pour la collaboration, ou même les commentaires dans les suivis d'issues publics associés aux dépôts.
* 💡 Automatiser stratégiquement : Cloner et scanner chaque dépôt lié peut être chronophage et gourmand en ressources. Priorisez les dépôts en fonction de leur pertinence perçue : ceux directement sous l'organisation de l'entreprise, les dépôts activement maintenus par les développeurs clés, ou ceux dont les noms suggèrent des fonctions critiques (par ex., 'infra-config', 'auth-service').

**Practice Links:** 🎯 Les challenges HTB et THM nécessitent parfois de trouver des identifiants ou des informations sensibles dans des dépôts GitHub publics liés depuis une application web cible ou mentionnés dans des indices de reconnaissance. Explorez les write-ups de bug bounty pour des exemples du monde réel.

**Cross-References:** 🔗 Dorking sur les moteurs de recherche (en utilisant les fonctionnalités de recherche de GitHub), 🔗 Analyse des médias sociaux (identification des développeurs), 🔗 Accès Initial (en utilisant les identifiants/clés API trouvés).

## Conclusion

La reconnaissance passive et l'OSINT sont des premières étapes indispensables dans les évaluations de cybersécurité modernes. En collectant méticuleusement des informations à partir de sources publiques telles que les enregistrements WHOIS, les serveurs DNS, les logs de Transparence des Certificats, les moteurs de recherche, les médias sociaux, les dépôts de code publics et les métadonnées de fichiers, les testeurs d'intrusion et les joueurs de CTF peuvent construire une compréhension complète de l'empreinte numérique d'une cible sans déclencher d'alarmes. Les techniques décrites fournissent un cadre pour découvrir des vecteurs d'attaque potentiels, identifier les composants de l'infrastructure, comprendre les structures organisationnelles et découvrir des informations sensibles exposées par inadvertance. Le succès dans cette phase repose sur l'emploi d'une gamme diversifiée d'outils et de techniques, la compréhension de leurs forces et limitations (en particulier concernant l'actualité des données et la nécessité des clés API pour une couverture complète), la corrélation diligente des découvertes provenant de multiples sources, et la validation systématique des pistes potentielles avant de passer aux phases de reconnaissance active ou d'exploitation. Une reconnaissance passive approfondie améliore considérablement l'efficience et l'efficacité des activités de test de sécurité ultérieures.
