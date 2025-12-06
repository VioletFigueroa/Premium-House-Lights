# Premium House Lights: The Heist

![GitHub last commit](https://img.shields.io/github/last-commit/VioletFigueroa/Premium-House-Lights?style=flat-square)
![GitHub repo size](https://img.shields.io/github/repo-size/VioletFigueroa/Premium-House-Lights?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-blue?style=flat-square)
![Release](https://img.shields.io/github/v/release/VioletFigueroa/Premium-House-Lights?style=flat-square)

**Quick Links:** [Documentation](README.md) | [Security Policy](SECURITY.md) | [Contributing](CONTRIBUTING.md) | [Release](https://github.com/VioletFigueroa/Premium-House-Lights/releases/tag/v1.0.0)

---

## Overview
Full-scope digital forensics investigation and incident response simulation following a cyberattack at Premium House Lights, a fictional small business. This project demonstrates breach detection, log analysis, attacker tracing, and remediation recommendations. It serves as a real-world case study showing effective security controls and strategies to prevent similar incidents.

## Objectives
- Investigate and document a cyberattack on a small business network
- Reconstruct the timeline of attacker entry and lateral movement
- Identify security gaps that enabled the breach
- Provide actionable recommendations for remediation
- Deliver findings to leadership in both technical and executive formats

## Methodology
**Investigation Approach:**
- Detection of abnormal web activity triggering investigation
- Analysis of file upload vulnerability exploitation
- Log forensics to trace attacker entry point
- Network traffic analysis using PCAP captures
- Database access log examination
- Timeline correlation of malicious activities

**Forensic Analysis:**
- Bash scripting for log processing and analysis
- PCAP analysis to reconstruct network communications
- Database shell session examination
- Web server and database access log correlation
- Evidence preservation and chain of custody documentation

**Architecture Assessment:**
- Network segmentation evaluation
- Privilege management review
- Security control gap analysis
- MITRE ATT&CK mapping of attacker techniques

## Key Findings
- Attacker exploited unrestricted file upload vulnerability
- Weak firewall segmentation enabled lateral movement
- Overprivileged database access facilitated data exfiltration
- Data stolen via SCP/SSH to external server
- Multiple critical security controls were missing or misconfigured
- Simple controls (WAF, MFA, segmentation) could have stopped or contained the breach

## Technologies Used
- **Log Analysis:** Bash scripting, text processing
- **Network Analysis:** Wireshark, PCAP analysis
- **Architecture Documentation:** draw.io, Visio
- **Incident Response:** Markdown reporting, PDF documentation
- **Database Analysis:** SQL query analysis, database shell examination
- **Vulnerability Assessment:** Enumeration tools, WAF evaluation, MFA analysis

## Files Included
- [Project 12 - Forensics Report and Documentation.pdf](Project%2012%20-%20Forensics%20Report%20and%20Documentation.pdf) - Main technical report with complete investigation findings
- [Premium House Lights_ Email To Your Manager.pdf](Premium%20House%20Lights_%20Email%20To%20Your%20Manager.pdf) - Executive summary communication to leadership
- [Premium House Lights_ The Heist.pdf](Premium%20House%20Lights_%20The%20Heist.pdf) - Presentation slides with visual findings

## Supporting Evidence & Documentation

**Digital Forensic Artifacts:**
Located in the [`digital forensic artifacts`](digital%20forensic%20artifacts/) folder:
- [`phl_access_log.txt`](digital%20forensic%20artifacts/phl_access_log.txt) — Web/server access logs
- [`phl_database_access_log.txt`](digital%20forensic%20artifacts/phl_database_access_log.txt) — Database access logs
- [`phl_database.pcap`](digital%20forensic%20artifacts/phl_database.pcap) — Network packet capture (database)
- [`phl_webserver.pcap`](digital%20forensic%20artifacts/phl_webserver.pcap) — Network packet capture (web server)
- [`phl_database_shell.txt`](digital%20forensic%20artifacts/phl_database_shell.txt) — Database shell session transcript
- [`sha256sum.txt`](digital%20forensic%20artifacts/sha256sum.txt) — File hashes for evidence verification

**Visual Evidence:**
- **Network Diagram:** Shows VLAN structure, firewall placement, and business services
- **Attack Path Diagram:** Highlights attacker's pivot steps with security gap callouts

## Key Takeaways
- Critical business data can be compromised quickly without proper segmentation and privilege limitations
- Foundational security controls (WAF, MFA, network segmentation) could have prevented or contained this breach
- Clear communication of risk accelerates leadership buy-in for security investments
- Proper forensic documentation is essential for both technical understanding and legal proceedings

---

## References
- NIST SP 800-61 Computer Security Incident Handling Guide
- MITRE ATT&CK Framework (adversary tactics)
- SANS Forensic Methodology
- Open-source log review practices

See the main report for detailed citations and source list.
