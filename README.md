# Premium House Lights: The Heist

## Executive Summary

This project presents a full-scope digital forensics investigation and incident response simulation following a cyberattack targeting Premium House Lights, a fictional small business. The documentation guides both technical and non-technical readers through breach detection, log analysis, attacker tracing, and remediation recommendations. The project serves as a real-world case study showing effective security controls and strategies to prevent similar incidents.

***

## Project Highlights

| Skill | Tools/Technology | Result/Outcome |
| :-- | :-- | :-- |
| Log Forensics | Bash, text processing | Reconstructed timeline of attacker entry/escalation |
| Network Architecture | draw.io, Visio | Identified segmentation gaps, mapped breach impact |
| Incident Response | Markdown, reporting | Produced executive \& technical reports |
| Vulnerability Analysis | Enumeration, WAF, MFA | Pinpointed gaps, recommended controls |
| Professional Comms | Email, PDF | Delivered actionable findings to leadership |


***

## Investigation Scenario

### Steps Overview

- **Detection:** Abnormal web activity was flagged, prompting investigation.
- **Initial Access:** Attacker exploited an unrestricted file upload vulnerability.
- **Lateral Movement:** Weak firewall segmentation and overprivileged database access enabled attacker movement.
- **Data Exfiltration:** Data stolen via SCP/SSH to an external server.

***

## Visual Evidence \& Documentation

This project provides strong visual and written evidence to support the investigation and remediation process.

- **Network Diagram:**
![Premium House Lights Network Diagram](images/phl_network_diagram.png)
Shows VLAN structure, firewall placement, and business services.
- **Attack Path \& Security Gaps:**
![Attacker Steps and Security Gaps](images/Premium%20House%20Lights%20Network%20%E2%80%93%20Annotated%20Attack%20Path%20and%20Security%20Gaps.drawio.png)
Highlights the attacker’s pivot steps with callouts for missing security controls.
- **Sample Access Log:**
Redacted logs available in `phlaccesslog.txt` and `phldatabaseaccesslog.txt`.
- **Full Forensics Report (Main Project File):**
[Project-12-Forensics-Report-and-Documentation.pdf](Project-12-Forensics-Report-and-Documentation.pdf)
Contains the complete case report with findings and detailed analysis.
- **Management Summary:**
[Project-12-Email-To-Your-Manager.pdf](Project-12-Email-To-Your-Manager.pdf)
A one-page executive summary suitable for non-technical audiences.

***

## File Index

- [`Project 12 - Forensics Report and Documentation.pdf`](Project%2012%20-%20Forensics%20Report%20and%20Documentation.pdf) — Main technical report (primary deliverable)
- [`Premium House Lights_ Email To Your Manager.pdf`](Premium%20House%20Lights_%20Email%20To%20Your%20Manager.pdf) — Executive summary communication
- [`Premium House Lights_ The Heist.pdf`](Premium%20House%20Lights_%20The%20Heist.pdf) — Presentation slides
- [`digital forensic artifacts/`](digital%20forensic%20artifacts/) — All appendices, logs, network captures, and evidence
- [`images/`](images/) — Project diagrams, visuals for reports


## Lessons Learned

- Critical business data may be compromised quickly without basic segmentation and privilege limitations.
- Simple controls such as Web Application Firewall (WAF), multi-factor authentication (MFA) or segmented networks could have stoped or contained such breaches.
- Clear communication of risk accelerates leadership buy-in for security investments.

***

## Replication \& Analysis

- This project is strictly for demonstration purposes.
- For replication, detailed log analysis, or further study, consult provided Markdown/PDF reports and raw logs.

***

## References

- NIST SP 800-61 Computer Security Incident Handling Guide
- MITRE ATT\&CK Framework (adversary tactics)
- SANS Forensic Methodology
- Open-source log review practices

See the main report for detailed citations and source list.

***
## Digital Forensic Artifacts (Appendices)

All supporting evidence, logs, and raw data referenced in the main reports are located in the [`digital forensic artifacts`](digital%20forensic%20artifacts/) folder:

- [`phl_access_log.txt`](digital%20forensic%20artifacts/phl_access_log.txt) — Web/server access logs (redacted)
- [`phl_database_access_log.txt`](digital%20forensic%20artifacts/phl_database_access_log.txt) — Database access logs
- [`phl_database.pcap`](digital%20forensic%20artifacts/phl_database.pcap) — Network packet capture (database)
- [`phl_webserver.pcap`](digital%20forensic%20artifacts/phl_webserver.pcap) — Network packet capture (web server)
- [`phl_database_shell.txt`](digital%20forensic%20artifacts/phl_database_shell.txt) — Database shell session transcript
- [`phl_database_tables.db`](digital%20forensic%20artifacts/phl_database_tables.db) — Sample database (for investigation)
- [`sha256sum.txt`](digital%20forensic%20artifacts/sha256sum.txt) — File hashes for evidence verification

***
