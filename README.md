# Premium-House-Lights-Network
Executive Summary
This project details a full-scope digital forensics investigation and incident response following a cyberattack at Premium House Lights, a fictional small business. The case includes discovery, log analysis, lateral movement tracing, and business-focused incident remediation recommendations. Both technical and non-technical audiences can see how real-world breach events unfold and how targeted controls can mitigate future risk.

Project Highlights Table
Skill Demonstrated	Tools/Technology	Result/Outcome
Log Forensics	Bash, text processing	Reconstructed timeline of attacker entry, escalation
Network Architecture	draw.io, Visio	Identified segmentation gaps, mapped breach impact
Incident Response	Markdown, report writing	Produced clear executive and technical reports
Vulnerability Analysis	Network/service enumeration	Pinpointed security gaps: WAF, MFA, privilege control
Professional Comms	Business email, PDF summary	Delivered actionable findings to leadership
Project Scenario & Investigation Steps
The investigation began after abnormal web activity was detected. Working from server and database access logs, the breach path was reconstructed, revealing:

Initial access through an unrestricted file upload vulnerability.

Lateral movement enabled by lack of internal firewall segmentation and excessive database privileges.

Data exfiltration via SCP/SSH to an attacker-controlled server.

Visual Evidence & Documentation
Network Diagram:

Shows VLAN structure, firewall placement, and business services.

Attack Path & Security Gaps:

Highlights attacker steps with callouts for missing controls.

Sample Access Log (Redacted):
Logs available in phl_access_log.txt and phl_database_access_log.txt.

Full Forensics Report:
See Project-12-Forensics-Report-and-Documentation.md

Communication Sample:
Management summary can be found in Project-12-Email-To-Your-Manager.md

Timeline of Key Breach Events
Time	Event
21:59:04	Attacker uploads malicious file (via vulnerability)
22:00:55	Lateral movement—webserver to database (privilege abuse)
22:02:26	Data exfiltrated to outside IP via SCP/SSH
Lessons Learned / Business Impact
Critical business data can be compromised rapidly without basic network segmentation and server privilege limiting.

Simple controls—WAF, stronger authentication, and segmented networks—could have prevented or contained this breach.

Communicating impact in plain language accelerates leadership buy-in for security investment.

Replication & Review
This project is for demonstration only. For replication or in-depth log analysis, see included Markdown/PDF report and logs.

References & Citations
This documentation and analysis were informed by:

NIST SP 800-61 (“Computer Security Incident Handling Guide”)

MITRE ATT&CK framework for adversary tactics

SANS forensic methodology and open-source log review practices

[See main report citation section for full list of references and sources]

