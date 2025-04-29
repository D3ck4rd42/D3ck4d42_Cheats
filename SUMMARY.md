# Summary

### 🚀 Introduction & Stratégie

* [0. Mode d'Emploi & Stratégie Gagnante](00_mode_emploi/README.md)
    * [Comment Exploiter cette Cheatsheet](00_mode_emploi/exploiter_cheatsheet.md)
    * [Philosophie & Mindset CTF](00_mode_emploi/philosophie_mindset.md)
    * [Environnement & Prise de Notes](00_mode_emploi/environnement_notes.md)

### 🧠 Phase 1 : Reconnaissance & Énumération

* [1. Reconnaissance & Énumération : La Carte](01_reconnaissance/README.md)
    * [Reconnaissance Passive (OSINT)](01_reconnaissance/recon_passive_osint.md)
    * [Scan Actif & Découverte Réseau](01_reconnaissance/scan_actif_decouverte.md)
        * [Nmap : Le Maître Explorateur](01_reconnaissance/nmap.md)
        * [Scans Rapides (Rustscan, Naabu...)](01_reconnaissance/scans_rapides.md)
    * [Énumération des Services](01_reconnaissance/enum_services/README.md)
        * [Web (HTTP/HTTPS)](01_reconnaissance/enum_services/web_http_https.md)
        * [SMB (139, 445)](01_reconnaissance/enum_services/smb.md)
        * [NFS (2049)](01_reconnaissance/enum_services/nfs.md)
        * [DNS (53)](01_reconnaissance/enum_services/dns.md)
        * [SNMP (161)](01_reconnaissance/enum_services/snmp.md)
        * [Autres Services (FTP, SSH, SMTP...)](01_reconnaissance/enum_services/autres_services.md)
        * [API & Web Services](01_reconnaissance/enum_services/api_web_services.md)
    * [Connexions Thématiques (Recon)](01_reconnaissance/connexions_thematiques_recon.md)

### 🔥 Phase 2 : Exploitation

* [2. Exploitation : Forcer la Porte](02_exploitation/README.md)
    * [Vulnérabilités Web Courantes](02_exploitation/vulns_web/README.md)
        * [SQL Injection (SQLi)](02_exploitation/vulns_web/sqli.md)
        * [Command Injection](02_exploitation/vulns_web/command_injection.md)
        * [Autres Vulns Web (XSS, SSRF, LFI...)](02_exploitation/vulns_web/autres_vulns_web.md)
    * [Exploitation Services Réseau & Système](02_exploitation/exploit_services/README.md)
        * [Buffer Overflow (Simple Stack BOF)](02_exploitation/exploit_services/bof.md)
        * [Utilisation d'Exploits Publics](02_exploitation/exploit_services/exploits_publics.md)
        * [Force Brute (Hydra...)](02_exploitation/exploit_services/force_brute.md)
    * [Living Off The Land (LotL)](02_exploitation/lotl.md)
    * [Obtention & Stabilisation de Shell](02_exploitation/get_stabilize_shell.md)
    * [Connexions Thématiques (Exploitation)](02_exploitation/connexions_thematiques_exploit.md)

### 🚀 Phase 3 : Post-Exploitation & Élévation

* [3. Post-Exploitation & Élévation : Prendre le Château](03_post_exploitation/README.md)
    * [Énumération Locale Systématique](03_post_exploitation/enum_locale.md)
    * [Élévation de Privilèges (PrivEsc)](03_post_exploitation/privesc/README.md)
        * [Linux PrivEsc](03_post_exploitation/privesc/linux_privesc.md)
        * [Windows PrivEsc](03_post_exploitation/privesc/windows_privesc.md)
        * [Active Directory PrivEsc (Bases)](03_post_exploitation/privesc/ad_privesc.md)
    * [Mouvement Latéral & Pivoting](03_post_exploitation/mouvement_lateral_pivoting.md)
    * [Exfiltration & Objectifs CTF](03_post_exploitation/exfiltration_objectifs.md)
    * [Connexions Thématiques (Post-Exploit)](03_post_exploitation/connexions_thematiques_postexploit.md)

### 🛠️ Transversal & Arsenal

* [4. Arsenal & Techniques Transversales](04_arsenal/README.md)
    * [Tooling Intelligence](04_arsenal/tooling_intelligence.md)
    * [Automatisation & Scripting](04_arsenal/automatisation_scripting.md)
    * [Crypto & Stégano (CTF)](04_arsenal/crypto_stegano.md)
    * [IA en Pentest/CTF](04_arsenal/ia_pentest_ctf.md)

### 🔍 Index & Matrices

* [5. Index Thématique & Matrice d'Attaque](05_index/README.md)
    * [Index par Service / Port](05_index/index_service_port.md)
    * [Index par Vulnérabilité / Technique](05_index/index_vuln_technique.md)
    * [Matrice Technologie -> Vecteurs](05_index/matrice_techno_vecteurs.md)

### 🆘 Aide & Communauté

* [6. Dépannage & Communauté](06_depannage/README.md)
    * [Diagnostic Rapide](06_depannage/diagnostic_rapide.md)
    * [Erreurs Fréquentes](06_depannage/erreurs_frequentes.md)
    * [Savoir Chercher & Demander Aide](06_depannage/chercher_demander_aide.md)

### 📚 Annexes

* [7. Annexes](07_annexes/README.md)
    * [Glossaire](07_annexes/glossaire.md)
    * [Liens Essentiels](07_annexes/liens_essentiels.md)
    * [Parcours d'Apprentissage Guidé](07_annexes/parcours_apprentissage.md)
    * [Remerciements / Contributeurs](07_annexes/remerciements.md) 