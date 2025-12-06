

A simulated business network compromise led to full digital forensics and incident response, focusing on a file upload vulnerability and lack of network segmentation. This project delivers both technical and executive-level documentation, highlighting lessons for SMBs and IT professionals.

## Project Deliverables

- [Technical Forensics Report (PDF)](./Project%2012%20-%20Forensics%20Report%20and%20Documentation.pdf)
- [Executive Summary Email (PDF)](./Premium%20House%20Lights_%20Email%20To%20Your%20Manager.pdf)
- [Incident Response Slides (PDF)](./Premium%20House%20Lights_%20The%20Heist.pdf)
- [Full Project Repository on GitHub](https://github.com/VioletFigueroa/Premium-House-Lights)

---

## Key Skills & Tools

| Skill/Focus         | Tools/Methods                  | Result/Outcome                                    |
|---------------------|-------------------------------|---------------------------------------------------|
| Log Forensics       | Bash, text processing          | Mapped attacker entry/escalation timeline         |
| Network Analysis    | draw.io, Wireshark             | Identified segmentation gaps & mapped attack path |
| Reporting & Comms   | Markdown, PDF, Email           | Delivered actionable findings to stakeholders     |
| Vulnerability Assess| MITRE ATT&CK, enumeration      | Pinpointed gaps, recommended clear controls       |

---

## Project Highlights

- **Detection:** Abnormal web activity triggered investigation.
- **Initial Access:** Attacker exploited a file upload vuln (no WAF or MFA).
- **Lateral Movement:** Poor segmentation and excessive database privileges allowed further compromise.
- **Data Exfiltration:** Stolen via SCP/SSH to external server.

---

## Visual Evidence

**Network Architecture:**
![Premium House Lights Network Diagram](./images/phl_network_diagram.png "Network: VLANs, servers, employee WiFi")

**Attack Path & Security Gaps:**
![Attack Path & Security Gaps](./images/Premium%20House%20Lights%20Network%20%E2%80%93%20Annotated%20Attack%20Path%20and%20Security%20Gaps.drawio.png "Red path: attacker movement; highlights: missing controls")

---

## Supporting Artifacts & Evidence

- Webserver/database access logs
- PCAP network captures
- Evidence transcripts, hash files

## Lessons Learned

- Network segmentation, firewalls, WAF, and MFA are critical even in small business environments.
- Documentation and multi-level reporting accelerate remediation and executive buy-in.
- Proactive controls and clear incident response methodology reduce breach impact.

---
