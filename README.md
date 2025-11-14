# Premium House Lights Network

## Executive Summary

This project presents a full-scope digital forensics investigation and incident response simulation following a cyberattack targeting Premium House Lights—a fictional small business. The documentation guides both technical and non-technical readers through breach detection, log analysis, attacker tracing, and remediation recommendations. The project serves as a real-world case study showing effective security controls and strategies to prevent similar incidents.[^1]

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
- **Data Exfiltration:** Data stolen via SCP/SSH to an external server.[^1]

***

## Visual Evidence \& Documentation

- **Network Diagram:** VLAN structure, firewall placement, and business services layout.
- **Attack Path \& Security Gaps:** Diagram/annotations identify attacker movements and missing controls.
- **Sample Access Logs:** Redacted samples in `phlaccesslog.txt` and `phldatabaseaccesslog.txt`.
- **Full Forensics Report:** See `Project-12-Forensics-Report-and-Documentation.md`.
- **Communication Example:** Management summary in `Project-12-Email-To-Your-Manager.md`.[^1]

***

## Timeline of Key Breach Events

| Time | Event |
| :-- | :-- |
| 21:59:04 | Attacker uploads malicious file (vulnerability exploit) |
| 22:00:55 | Lateral movement (webserver → database, privilege abuse) |
| 22:02:26 | Data exfiltrated to outside IP via SCP/SSH |


***

## Lessons Learned

- Critical business data may be compromised quickly without basic segmentation and privilege limitations.[^1]
- Simple controls—Web Application Firewall (WAF), multi-factor authentication (MFA), segmented networks—could stop or contain such breaches.
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

See the main report for detailed citations and source list.[^1]

***

## File Index

- `phlaccesslog.txt` — Web/server access logs (redacted)
- `phldatabaseaccesslog.txt` — Database access logs (redacted)
- `Project-12-Forensics-Report-and-Documentation.md` — Full case report
- `Project-12-Email-To-Your-Manager.md` — Management summary
