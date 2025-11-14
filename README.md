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
![Premium House Lights Network Diagram](images/network-diagram.png structure, firewall placement, and business services.)
Shows VLAN structure, firewall placement, and business services.
- **Attack Path \& Security Gaps:**
![Attacker Steps and Security Gap Callouts](images/security-gaps-path the attacker’s pivot steps with callouts for missing security controls.)
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

## Main Project Files

The key deliverables are PDF documents, which contain the primary case analysis and formal communications:


| File Name | Description |
| :-- | :-- |
| Project-12-Forensics-Report-and-Documentation.pdf | Main report, timeline, technical analysis, conclusions |
| Project-12-Email-To-Your-Manager.pdf | Executive summary, recommendations |

Supplemental appendices (logs, diagrams, source documentation) are included to support and illustrate the findings.



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
## Appendix: Additional Files

- `phlaccesslog.txt` — Web/server access logs
- `phldatabaseaccesslog.txt` — Database access logs

***
