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


- to be updated once the remaining files are uploaded correctly.

***

## Timeline of Key Breach Events

| Time | Event |
| :-- | :-- |
| 21:59:04 | Attacker uploads malicious file (vulnerability exploit) |
| 22:00:55 | Lateral movement (webserver → database, privilege abuse) |
| 22:02:26 | Data exfiltrated to outside IP via SCP/SSH |


***

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

## File Index

- to be updated once the remaining files are uploaded correctly.
