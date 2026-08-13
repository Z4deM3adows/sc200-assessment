"""
SC-200 Question Generator — Microsoft Defender XDR Module (100 Questions)
Each question has a stable id (xdr-001 .. xdr-100) for easy tracking,
unique scenario, varied stem, 4 options, per-option explanations, and SOC tips.
"""
import json

QUESTIONS = [
  {
    "id": "xdr-001",
    "topic": "Incident queue triage and priority assignment",
    "scenario": "Contoso's SOC receives over 200 alerts daily in Microsoft Defender XDR. A new analyst notices that many alerts are correlated into incidents, but the queue is cluttered with low-severity informational incidents alongside genuine high-severity threats. The SOC manager asks the analyst to configure the queue for efficient triage.",
    "question": "What should the analyst do FIRST to efficiently triage the incident queue?",
    "options": [
      "Filter the incident queue by severity and status, then assign high-severity active incidents to Tier 2 analysts",
      "Create a Power Automate flow to automatically close all informational incidents",
      "Disable alert correlation so each alert appears as its own incident",
      "Export all incidents to a CSV file and triage them in Excel"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Queue Management in Microsoft Defender XDR",
      "analysis": [
        "Option A is CORRECT: The incident queue supports filtering by severity (High, Medium, Low, Informational) and status (Active, In Progress, Resolved). Assigning high-severity incidents to experienced analysts follows the standard SOC triage workflow and uses the built-in assignment feature.",
        "Option B is INCORRECT: Automatically closing all informational incidents could suppress legitimate alerts that were initially classified as low severity but correlate to larger attack chains. This violates least-privilege triage principles.",
        "Option C is INCORRECT: Disabling alert correlation would dramatically increase the alert volume, creating thousands of individual incidents instead of correlated groups. This makes triage harder, not easier.",
        "Option D is INCORRECT: Exporting to CSV loses the interactive investigation context (incident graph, evidence, automated investigation results) that makes Defender XDR powerful. Triage should happen within the portal."
      ],
      "codeSnippet": "// KQL: Find high-severity incidents created in the last 24 hours\\nSecurityIncident\\n| where TimeGenerated > ago(24h)\\n| where Severity == \\\"High\\\"\\n| where Status == \\\"Active\\\"\\n| project IncidentNumber, Title, Severity, CreatedTime\\n| order by CreatedTime desc",
      "socTip": "Use the 'Assign to me' feature in the incident queue to take ownership. Set status to 'In Progress' immediately to signal other analysts that you're investigating.",
      "docRef": "Microsoft Learn: Prioritize incidents in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-002",
    "topic": "Advanced Hunting — DeviceProcessEvents table",
    "scenario": "A SOC analyst at Fabrikam detects a suspicious PowerShell process spawning from winword.exe on multiple endpoints. The analyst needs to write a KQL query in Advanced Hunting to identify all instances of this behavior across the organization.",
    "question": "Which KQL query correctly identifies Word spawning PowerShell processes?",
    "options": [
      "DeviceProcessEvents | where InitiatingProcessFileName =~ 'winword.exe' and FileName =~ 'powershell.exe' | project Timestamp, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine",
      "DeviceEvents | where ActionType == 'ProcessCreated' and ProcessName == 'powershell.exe'",
      "EmailEvents | where SenderFromAddress contains 'powershell' | project Timestamp, Subject",
      "DeviceNetworkEvents | where RemotePort == 443 and InitiatingProcessFileName == 'powershell.exe'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Advanced Hunting — Process Chain Analysis",
      "analysis": [
        "Option A is CORRECT: DeviceProcessEvents is the correct table for process creation telemetry. The query filters where the parent process (InitiatingProcessFileName) is winword.exe and the child process (FileName) is powershell.exe, which is a classic malicious macro indicator.",
        "Option B is INCORRECT: DeviceEvents does not have a 'ProcessName' column — it uses FileName and InitiatingProcessFileName. Additionally, DeviceEvents covers miscellaneous events, not specifically process creation. The correct table for process events is DeviceProcessEvents.",
        "Option C is INCORRECT: EmailEvents tracks email metadata (sender, recipient, subject) not endpoint process execution. This query would search for emails mentioning 'powershell', which is unrelated to the investigation.",
        "Option D is INCORRECT: DeviceNetworkEvents tracks network connections, not process parent-child relationships. While PowerShell making outbound connections could be suspicious, this query doesn't identify the Word-to-PowerShell spawn chain."
      ],
      "codeSnippet": "// Extended query with command line analysis\\nDeviceProcessEvents\\n| where Timestamp > ago(7d)\\n| where InitiatingProcessFileName =~ \\\"winword.exe\\\"\\n| where FileName in~ (\\\"powershell.exe\\\", \\\"cmd.exe\\\", \\\"wscript.exe\\\")\\n| project Timestamp, DeviceName, AccountName,\\n    InitiatingProcessCommandLine, ProcessCommandLine\\n| order by Timestamp desc",
      "socTip": "Word spawning PowerShell is a strong indicator of malicious macro execution. Check ProcessCommandLine for encoded commands (-enc, -encodedcommand) which attackers use to obfuscate payloads.",
      "docRef": "Microsoft Learn: DeviceProcessEvents table in Advanced Hunting"
    }
  },
  {
    "id": "xdr-003",
    "topic": "Automated Investigation and Response (AIR)",
    "scenario": "Northwind Traders has enabled Automated Investigation and Response in Microsoft Defender XDR. After a phishing email was detected, AIR automatically triggered an investigation. The investigation found that 3 mailboxes received the malicious email and one user clicked the link, resulting in credential theft. AIR has pending remediation actions.",
    "question": "What happens to the pending remediation actions identified by AIR?",
    "options": [
      "They are queued in the Action Center and require explicit analyst approval before execution",
      "They are automatically executed without any analyst review",
      "They are sent to the user's manager for approval via email",
      "They are logged but no remediation occurs unless manually scripted"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AIR Remediation Actions and the Action Center",
      "analysis": [
        "Option A is CORRECT: When the automation level is set to 'Semi' (the default for most organizations), pending remediation actions appear in the Action Center under the Pending tab. An analyst must approve or reject each action (e.g., soft-delete emails, disable compromised accounts, quarantine files).",
        "Option B is INCORRECT: Full automation where actions execute without review is only enabled when the automation level is set to 'Full'. Most organizations use Semi-automatic to maintain analyst oversight, especially for destructive actions like account disabling.",
        "Option C is INCORRECT: AIR does not integrate with management approval chains or send emails to managers. Remediation approval is handled exclusively through the Defender XDR Action Center by security team members.",
        "Option D is INCORRECT: AIR provides concrete, actionable remediation steps that can be approved with a single click — not just logs. The Action Center tracks all automated and manual remediation actions with full audit trails."
      ],
      "codeSnippet": "// KQL: Review AIR investigation actions\\nAlertEvidence\\n| where Timestamp > ago(7d)\\n| where ServiceSource == \\\"Microsoft Defender XDR\\\"\\n| where EntityType == \\\"MailMessage\\\" or EntityType == \\\"User\\\"\\n| project Timestamp, AlertId, EntityType, RemediationStatus\\n| summarize count() by RemediationStatus",
      "socTip": "Check the Action Center daily. Pending actions have an SLA — approving phishing remediation within 1 hour dramatically reduces lateral movement risk from credential theft.",
      "docRef": "Microsoft Learn: Automated investigation and response in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-004",
    "topic": "Custom detection rules with KQL",
    "scenario": "Litware Inc. wants to create a custom detection rule in Microsoft Defender XDR that triggers an alert whenever a user downloads an executable file from a newly registered domain (registered within the last 30 days). The security team has written a KQL query that identifies this pattern.",
    "question": "Which frequency and action should be configured for this custom detection rule?",
    "options": [
      "Set the rule to run every 24 hours because custom detections look back over historical data, and configure it to generate an alert and isolate the device",
      "Set the rule to run every 1 hour and configure it to generate a high-severity alert with automatic device isolation",
      "Set the rule to continuous real-time monitoring with instant response",
      "Set the rule to run weekly and send an email notification to the SOC team"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Custom Detection Rules — Frequency and Response Actions",
      "analysis": [
        "Option A is INCORRECT: While custom detections can run every 24 hours, downloading an executable from a newly registered domain is a high-risk activity that warrants more frequent detection. A 24-hour delay could allow an attacker significant dwell time.",
        "Option B is CORRECT: Custom detection rules can run at intervals of 1, 3, 12, or 24 hours. For high-risk file downloads from suspicious domains, hourly detection is appropriate. The rule can be configured to both generate an alert AND take automated response actions like isolating the device.",
        "Option C is INCORRECT: Custom detection rules do not support continuous real-time monitoring. They run on a scheduled frequency (1h, 3h, 12h, 24h) against Advanced Hunting data. Real-time detection is handled by built-in detection engines.",
        "Option D is INCORRECT: Custom detection rules cannot send email notifications directly. They generate alerts and can trigger automated response actions (isolate device, quarantine file, disable user). Email notifications require integration with Logic Apps or Power Automate."
      ],
      "codeSnippet": "// Custom detection: Executable download from new domain\\nDeviceFileEvents\\n| where Timestamp > ago(1h)\\n| where ActionType == \\\"FileCreated\\\"\\n| where FileName endswith \\\".exe\\\" or FileName endswith \\\".dll\\\"\\n| join kind=inner (\\n    DeviceNetworkEvents\\n    | where RemoteUrl has_any (\\\"newdomain.com\\\")\\n) on DeviceId\\n| project Timestamp, DeviceName, FileName, RemoteUrl",
      "socTip": "When creating custom detections, use the 'impacted entities' mapping to ensure the alert automatically links to the affected device, user, and file for quick investigation in the incident graph.",
      "docRef": "Microsoft Learn: Create and manage custom detection rules"
    }
  },
  {
    "id": "xdr-005",
    "topic": "Threat Analytics reports",
    "scenario": "A new zero-day vulnerability (CVE-2026-XXXX) affecting Microsoft Exchange Server is being actively exploited globally. The Adatum Corporation CISO requests an immediate assessment of their exposure. The SOC team opens Threat Analytics in Microsoft Defender XDR.",
    "question": "What information does the Threat Analytics report provide to assess organizational exposure?",
    "options": [
      "A list of all Exchange Server patches that have been released in the last 12 months",
      "The number of exposed devices and users, recommended mitigations, detection coverage status, and a detailed analyst report from Microsoft threat intelligence researchers",
      "A penetration test report that actively scans all Exchange servers for the vulnerability",
      "A comparison chart of your security posture against industry benchmarks"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Threat Analytics — Exposure Assessment and Mitigation Tracking",
      "analysis": [
        "Option A is INCORRECT: Threat Analytics does not provide a historical patch list. It focuses on the specific active threat and shows which devices in your environment are vulnerable, not a general patch history.",
        "Option B is CORRECT: Threat Analytics reports include: (1) an analyst report with threat description and TTPs, (2) exposed devices/users count showing organizational impact, (3) mitigation status showing which recommended actions are completed, and (4) detection coverage showing which Defender sensors can detect the threat.",
        "Option C is INCORRECT: Threat Analytics does not perform active penetration testing or vulnerability scanning. It correlates Microsoft's threat intelligence with your organization's existing telemetry and configuration to assess exposure passively.",
        "Option D is INCORRECT: Threat Analytics does not provide industry benchmarking. It focuses on your specific organizational exposure to a particular threat, not relative comparisons to other organizations."
      ],
      "codeSnippet": "// KQL: Check for Exchange exploitation indicators\\nDeviceProcessEvents\\n| where Timestamp > ago(30d)\\n| where InitiatingProcessFileName =~ \\\"w3wp.exe\\\"\\n| where FileName in~ (\\\"cmd.exe\\\", \\\"powershell.exe\\\")\\n| where ProcessCommandLine has_any (\\\"proxyshell\\\", \\\"proxylogon\\\")\\n| project Timestamp, DeviceName, ProcessCommandLine",
      "socTip": "Bookmark critical Threat Analytics reports and check the 'Mitigations' tab weekly. The exposure count updates automatically as you patch systems or apply configuration changes.",
      "docRef": "Microsoft Learn: Threat analytics in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-006",
    "topic": "Incident graph investigation",
    "scenario": "A Tier 2 analyst at Contoso is investigating a high-severity incident in Microsoft Defender XDR. The incident contains 12 correlated alerts spanning email, endpoint, and identity. The analyst opens the incident graph to understand the full attack chain.",
    "question": "What does the incident graph visualize?",
    "options": [
      "A network topology map showing all firewalls and routers in the organization",
      "The relationships between entities (users, devices, mailboxes, files, processes, IPs) involved in the incident, showing how alerts are connected across the attack chain",
      "A Gantt chart showing the timeline of all security projects in progress",
      "A heatmap of global threat activity from Microsoft's threat intelligence feed"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Incident Graph — Cross-Domain Attack Visualization",
      "analysis": [
        "Option A is INCORRECT: The incident graph does not show network infrastructure topology. It visualizes the relationships between entities involved in a specific security incident, not the physical or logical network layout.",
        "Option B is CORRECT: The incident graph provides a visual map of all entities (users, devices, mailboxes, files, processes, IP addresses) connected to the incident. It shows how alerts from different Defender workloads (Office 365, Endpoint, Identity, Cloud Apps) are correlated, revealing the full attack chain from initial access to impact.",
        "Option C is INCORRECT: The incident graph is a security investigation tool, not a project management visualization. It shows attack chain relationships, not project timelines.",
        "Option D is INCORRECT: Global threat heatmaps are available in Threat Analytics, not the incident graph. The incident graph is specific to a single incident in your organization."
      ],
      "codeSnippet": "// KQL: Get all entities linked to a specific incident\\nAlertInfo\\n| where Timestamp > ago(30d)\\n| join AlertEvidence on AlertId\\n| where Title contains \\\"suspicious\\\"\\n| project AlertId, Title, EntityType, EvidenceRole,\\n    AccountName, DeviceName, FileName, RemoteIP\\n| order by AlertId",
      "socTip": "In the incident graph, click on any entity node to see its full timeline and related evidence. Use 'Go hunt' from any entity to pivot directly into Advanced Hunting with pre-populated queries.",
      "docRef": "Microsoft Learn: Investigate incidents in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-007",
    "topic": "Unified RBAC permissions",
    "scenario": "Fabrikam's CISO wants to create a custom role in Microsoft Defender XDR that allows Tier 1 analysts to view and manage security alerts across all workloads, but prevents them from modifying detection rules, managing device groups, or accessing raw Advanced Hunting data.",
    "question": "Which approach should the CISO use to create this custom role?",
    "options": [
      "Create individual roles in each workload (Defender for Endpoint, Defender for Office 365, Defender for Identity) separately",
      "Use Microsoft Defender XDR Unified RBAC to create a single custom role with specific permissions scoped to 'Security operations — Alerts (manage)' while excluding 'Security data — Advanced Hunting' and 'Authorization — Security settings'",
      "Assign the Global Reader role in Microsoft Entra ID, which provides read-only access to all security data",
      "Create an Azure Policy that restricts access to specific blade URLs in the Defender portal"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Microsoft Defender XDR Unified RBAC",
      "analysis": [
        "Option A is INCORRECT: Managing individual roles in each workload creates inconsistency and administrative overhead. Microsoft Defender XDR Unified RBAC was specifically designed to replace this fragmented approach with a single, centralized permission model.",
        "Option B is CORRECT: Unified RBAC in Microsoft Defender XDR allows creating custom roles with granular permissions organized into categories: Security operations (alerts, incidents, response actions), Security data (raw data, Advanced Hunting), and Authorization (security settings, detection rules). Permissions can be granted or denied at each level.",
        "Option C is INCORRECT: Global Reader is an Entra ID directory role that grants read-only access across all Microsoft 365 services, not just security. It cannot manage (acknowledge, assign, resolve) alerts, only view them. It also exposes data beyond security, violating least privilege.",
        "Option D is INCORRECT: Azure Policy manages Azure resource compliance, not Microsoft Defender XDR portal access. You cannot restrict Defender portal navigation using Azure Policy."
      ],
      "codeSnippet": "// KQL: Audit RBAC role assignments in your tenant\\nCloudAppEvents\\n| where Timestamp > ago(30d)\\n| where ActionType == \\\"Add member to role\\\"\\n| where Application == \\\"Microsoft 365 Defender\\\"\\n| project Timestamp, AccountDisplayName,\\n    RawEventData.ResultStatus, RawEventData.Target",
      "socTip": "When creating Unified RBAC roles, use data sources scoping to limit which workload data the role can access. A Tier 1 analyst might only need Endpoint + Email data, not Identity or Cloud Apps.",
      "docRef": "Microsoft Learn: Microsoft Defender XDR Unified RBAC"
    }
  },
  {
    "id": "xdr-008",
    "topic": "Email entity investigation in Defender for Office 365",
    "scenario": "Northwind Traders' SOC receives an alert that a user clicked a phishing link in an email. The analyst needs to investigate the full scope of the email campaign — how many users received the same email, who clicked, and whether any credentials were compromised.",
    "question": "Which investigation approach provides the MOST comprehensive view of this email threat?",
    "options": [
      "Search the Exchange admin center message trace for the sender address",
      "Use Threat Explorer in Defender for Office 365 to filter by sender/subject, review the email timeline showing delivery, clicks, and ZAP actions, then pivot to the user entity page to check for sign-in anomalies",
      "Ask the affected user to forward the suspicious email to the SOC shared mailbox for manual analysis",
      "Run a full antivirus scan on the user's device using Defender for Endpoint"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Threat Explorer and Email Entity Investigation",
      "analysis": [
        "Option A is INCORRECT: Exchange admin center message trace shows delivery status but lacks security context — it doesn't show click data, ZAP actions, threat verdicts, or URL detonation results. It's an email flow tool, not a security investigation tool.",
        "Option B is CORRECT: Threat Explorer provides the full security context: delivery actions (delivered, blocked, ZAPped), user click data, URL detonation results, and email metadata. The email entity page shows the complete timeline. Pivoting to the user entity page reveals sign-in anomalies that indicate credential compromise.",
        "Option C is INCORRECT: Asking users to forward phishing emails is a reporting mechanism, not an investigation workflow. The original email metadata may be altered during forwarding, and this doesn't scale when hundreds of users received the campaign.",
        "Option D is INCORRECT: An antivirus scan addresses endpoint malware but doesn't investigate the email campaign scope. The primary risk from phishing links is credential theft, which requires identity investigation (sign-in logs, impossible travel), not just endpoint scanning."
      ],
      "codeSnippet": "// KQL: Find all recipients of a phishing campaign\\nEmailEvents\\n| where Timestamp > ago(7d)\\n| where SenderFromAddress == \\\"attacker@malicious.com\\\"\\n| join EmailUrlInfo on NetworkMessageId\\n| project Timestamp, RecipientEmailAddress,\\n    Subject, Url, UrlLocation, DeliveryAction\\n| summarize Recipients=dcount(RecipientEmailAddress),\\n    ClickCount=countif(UrlLocation == \\\"ClickedUrl\\\")",
      "socTip": "After identifying a phishing campaign in Threat Explorer, use 'Trigger investigation' to launch AIR on all affected mailboxes simultaneously. This auto-remediates (soft-deletes) the malicious email from every recipient's mailbox.",
      "docRef": "Microsoft Learn: Threat Explorer and real-time detections"
    }
  },
  {
    "id": "xdr-009",
    "topic": "Microsoft Defender for Identity — lateral movement paths",
    "scenario": "Adatum Corporation's SOC discovers that a compromised service account has been used for lateral movement. Microsoft Defender for Identity has detected Kerberos ticket anomalies and NTLM relay attempts. The analyst needs to map the lateral movement path to identify which sensitive accounts or domain controllers are at risk.",
    "question": "Which Defender for Identity feature should the analyst use to visualize the attack path to sensitive accounts?",
    "options": [
      "The Identity Security Posture Assessments page, which shows configuration weaknesses",
      "The Lateral Movement Paths (LMP) feature, which maps the shortest path from the compromised account to sensitive accounts and domain controllers",
      "The Microsoft Secure Score for Identity recommendations page",
      "The Azure AD Sign-in logs filtered by the compromised account"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Lateral Movement Path Analysis in Defender for Identity",
      "analysis": [
        "Option A is INCORRECT: Identity Security Posture Assessments show proactive security configuration issues (e.g., accounts with weak passwords, unconstrained delegation). They don't map active lateral movement from a compromised account.",
        "Option B is CORRECT: Lateral Movement Paths (LMP) in Defender for Identity uses graph analysis to map all possible paths an attacker could take from the compromised account to reach sensitive accounts (Domain Admins, Enterprise Admins) or domain controllers. It shows which intermediate accounts and devices would need to be compromised along the way.",
        "Option C is INCORRECT: Secure Score for Identity provides general security improvement recommendations, not investigation data for an active compromise. It's a posture management tool, not an incident response tool.",
        "Option D is INCORRECT: Azure AD (Entra ID) Sign-in logs track cloud authentication events. Lateral movement via Kerberos/NTLM is an on-premises Active Directory attack that Defender for Identity monitors through domain controller sensors, not Azure AD sign-in logs."
      ],
      "codeSnippet": "// KQL: Detect Kerberos ticket anomalies indicating lateral movement\\nIdentityLogonEvents\\n| where Timestamp > ago(24h)\\n| where LogonType == \\\"RemoteInteractive\\\" or LogonType == \\\"Network\\\"\\n| where Application == \\\"Active Directory\\\"\\n| summarize LogonCount=count(),\\n    DistinctDevices=dcount(DestinationDeviceName)\\n    by AccountName\\n| where DistinctDevices > 5",
      "socTip": "When investigating lateral movement, check if the compromised account has local admin rights on multiple machines. Use LMP to identify 'choke point' accounts that appear on many paths and prioritize resetting their credentials.",
      "docRef": "Microsoft Learn: Lateral movement paths in Microsoft Defender for Identity"
    }
  },
  {
    "id": "xdr-010",
    "topic": "Microsoft Defender for Cloud Apps — OAuth app governance",
    "scenario": "Litware's security team notices that several third-party OAuth applications have been granted excessive permissions in the Microsoft 365 tenant. One app has Mail.ReadWrite and Files.ReadWrite.All permissions but is described as a simple calendar scheduling tool. The team needs to assess and govern these risky OAuth apps.",
    "question": "Which feature in Defender for Cloud Apps should the team use to manage risky OAuth applications?",
    "options": [
      "Create a Cloud Discovery policy to block the app's network traffic",
      "Use App Governance to review OAuth app permissions, set policies to auto-revoke overprivileged apps, and monitor app behavior for anomalous data access patterns",
      "Disable all third-party app registrations in Microsoft Entra ID",
      "Configure a DLP policy in Microsoft Purview to prevent the app from accessing sensitive files"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "App Governance in Microsoft Defender for Cloud Apps",
      "analysis": [
        "Option A is INCORRECT: Cloud Discovery policies block or sanction cloud apps based on network traffic. OAuth app governance is about managing API permissions within your tenant, not blocking network-level traffic. The calendar app is already authorized within your tenant.",
        "Option B is CORRECT: App Governance (part of Defender for Cloud Apps) provides visibility into all OAuth apps registered in your tenant, their API permissions, and data access patterns. You can create app policies that automatically revoke consent for apps with excessive permissions or anomalous behavior.",
        "Option C is INCORRECT: Disabling all third-party app registrations is overly restrictive and would break legitimate business applications. The correct approach is granular governance — reviewing and revoking only the overprivileged apps.",
        "Option D is INCORRECT: DLP policies in Purview protect data based on content classification, not app-level API permissions. While DLP could detect sensitive data being accessed, it cannot revoke OAuth app consent or reduce app permissions."
      ],
      "codeSnippet": "// KQL: Audit OAuth app consent grants\\nCloudAppEvents\\n| where Timestamp > ago(90d)\\n| where ActionType == \\\"Consent to application\\\"\\n| project Timestamp, AccountDisplayName,\\n    Application, RawEventData.Target\\n| order by Timestamp desc",
      "socTip": "Review OAuth apps monthly. Apps with Mail.ReadWrite, Files.ReadWrite.All, or Directory.ReadWrite.All are high risk. Use App Governance policies to auto-alert when new apps request these permissions.",
      "docRef": "Microsoft Learn: App governance in Microsoft Defender for Cloud Apps"
    }
  },
  {
    "id": "xdr-011",
    "topic": "Alert tuning and suppression rules",
    "scenario": "Contoso's SOC is experiencing alert fatigue due to a known vulnerability scanner running daily from an authorized IP range (10.10.50.0/24). The scanner triggers hundreds of 'Suspicious network connection' alerts that the team has confirmed are false positives. The SOC lead wants to suppress these specific alerts without disabling the detection entirely.",
    "question": "What is the BEST way to suppress these false positive alerts?",
    "options": [
      "Disable the 'Suspicious network connection' detection rule globally across the organization",
      "Create an alert suppression rule that matches the specific alert title and the authorized scanner IP range, setting the rule to hide matching alerts automatically",
      "Delete the alerts manually from the queue each day",
      "Create an exclusion in Windows Defender Antivirus for the scanner's executable"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Alert Suppression Rules in Microsoft Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Disabling the detection globally would prevent legitimate detections of suspicious network connections from all sources, creating a significant security blind spot. You should never disable a detection rule to address false positives from a single source.",
        "Option B is CORRECT: Alert suppression rules let you define conditions (alert title, specific IP addresses, device groups) that automatically suppress matching alerts. The detection continues running and would still fire for connections from non-scanner IPs. This is the targeted approach to reducing false positives without losing coverage.",
        "Option C is INCORRECT: Manually deleting hundreds of alerts daily is an enormous waste of analyst time and doesn't scale. Suppression rules automate this process permanently for matching criteria.",
        "Option D is INCORRECT: Antivirus exclusions prevent file/process-level detections, not network-level EDR detections. The 'Suspicious network connection' alert is generated by the EDR sensor monitoring network telemetry, not by the antivirus engine scanning files."
      ],
      "codeSnippet": "// KQL: Identify false positive alert patterns for suppression\\nAlertInfo\\n| where Timestamp > ago(7d)\\n| where Title == \\\"Suspicious network connection\\\"\\n| join AlertEvidence on AlertId\\n| where EntityType == \\\"Ip\\\"\\n| where RemoteIP startswith \\\"10.10.50.\\\"\\n| summarize AlertCount=count() by bin(Timestamp, 1d)\\n| order by Timestamp desc",
      "socTip": "Always scope suppression rules as narrowly as possible. Include the specific alert title, source IP, and device group. Review suppression rules quarterly to ensure they're still valid and haven't been hiding real threats.",
      "docRef": "Microsoft Learn: Suppress alerts in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-012",
    "topic": "Cross-domain incident correlation",
    "scenario": "Fabrikam's Microsoft Defender XDR detects an attack spanning multiple domains: (1) a phishing email with a malicious attachment was delivered, (2) the attachment executed a payload on the endpoint creating a reverse shell, (3) the compromised user's credentials were used to access SharePoint from an anomalous location. Three separate alerts fire from Defender for Office 365, Defender for Endpoint, and Defender for Cloud Apps.",
    "question": "How does Microsoft Defender XDR handle these three related alerts?",
    "options": [
      "Each alert creates a separate incident that must be manually linked by an analyst",
      "Defender XDR automatically correlates the three alerts into a single unified incident because they share common entities (user, device, email) across the attack chain",
      "Only the highest severity alert creates an incident; the other two are suppressed",
      "The alerts are forwarded to Microsoft Sentinel for correlation since Defender XDR cannot correlate cross-workload alerts"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Automatic Attack Chain Correlation in Microsoft Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Manual linking is the legacy approach used before Microsoft Defender XDR existed. The primary value of XDR (Extended Detection and Response) is its ability to automatically correlate alerts across different security domains.",
        "Option B is CORRECT: Microsoft Defender XDR's correlation engine automatically groups related alerts into a single incident when they share common entities (same user clicked the phishing link, same device executed the payload, same user credentials accessed SharePoint). This provides analysts with a complete attack story in one incident.",
        "Option C is INCORRECT: All alerts are preserved and included in the incident regardless of severity. No alerts are suppressed during correlation — each alert provides evidence for a different stage of the attack chain.",
        "Option D is INCORRECT: Microsoft Defender XDR has native cross-workload correlation capabilities. While Sentinel can ingest and correlate Defender XDR incidents for additional SIEM analysis, the initial correlation happens within Defender XDR itself."
      ],
      "codeSnippet": "// KQL: Find correlated multi-domain incidents\\nAlertInfo\\n| where Timestamp > ago(7d)\\n| join AlertEvidence on AlertId\\n| summarize AlertCount=count(),\\n    Services=make_set(ServiceSource),\\n    Entities=make_set(EntityType)\\n    by AttackTechniques\\n| where array_length(Services) > 1\\n| order by AlertCount desc",
      "socTip": "When investigating multi-domain incidents, start with the incident graph to understand the full attack chain, then follow the timeline chronologically: initial access (email) → execution (endpoint) → persistence/lateral movement (identity/cloud apps).",
      "docRef": "Microsoft Learn: Incidents overview in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-013",
    "topic": "Advanced Hunting — EmailEvents and EmailAttachmentInfo tables",
    "scenario": "A SOC analyst at Northwind Traders needs to write a KQL query in Advanced Hunting to find all emails with password-protected ZIP attachments that were delivered to the organization in the last 7 days. These attachments bypass standard scanning and may contain malware.",
    "question": "Which KQL query correctly identifies emails with password-protected ZIP attachments?",
    "options": [
      "EmailAttachmentInfo | where Timestamp > ago(7d) | where FileType == 'zip' and FileName endswith '.zip' | join EmailEvents on NetworkMessageId | where DeliveryAction == 'Delivered' | project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName, SHA256",
      "EmailEvents | where Subject contains 'zip' | project RecipientEmailAddress",
      "DeviceFileEvents | where FileName endswith '.zip' | where FolderPath contains 'Outlook'",
      "CloudAppEvents | where Application == 'Microsoft Exchange Online' and ActionType == 'MailReceived'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Email Attachment Investigation with Advanced Hunting",
      "analysis": [
        "Option A is CORRECT: EmailAttachmentInfo contains file details (name, type, SHA256) for all email attachments. Joining with EmailEvents on NetworkMessageId provides delivery context. Filtering for ZIP files that were successfully delivered identifies the risky attachments that reached user mailboxes.",
        "Option B is INCORRECT: Searching email subjects for 'zip' is unreliable — not all emails with ZIP attachments mention 'zip' in the subject line, and some legitimate emails might mention ZIP codes. Attachment analysis requires the EmailAttachmentInfo table.",
        "Option C is INCORRECT: DeviceFileEvents shows files saved to disk on endpoints. While this could find ZIP files in Outlook temp folders, it doesn't capture the email metadata (sender, delivery action) needed for investigation. It also misses emails that haven't been opened yet.",
        "Option D is INCORRECT: CloudAppEvents tracks application-level events but doesn't provide email attachment details like file names, types, or hashes. The dedicated EmailAttachmentInfo table is the correct data source."
      ],
      "codeSnippet": "// KQL: Full email attachment threat hunting query\\nEmailAttachmentInfo\\n| where Timestamp > ago(7d)\\n| where FileType in (\\\"zip\\\", \\\"rar\\\", \\\"7z\\\")\\n| join kind=inner (\\n    EmailEvents\\n    | where DeliveryAction == \\\"Delivered\\\"\\n) on NetworkMessageId\\n| project Timestamp, SenderFromAddress,\\n    RecipientEmailAddress, Subject, FileName,\\n    FileType, SHA256, ThreatTypes\\n| order by Timestamp desc",
      "socTip": "Password-protected archives bypass Safe Attachments sandboxing. Track SHA256 hashes of delivered archives and monitor for subsequent file extraction events on endpoints via DeviceFileEvents.",
      "docRef": "Microsoft Learn: EmailAttachmentInfo table"
    }
  },
  {
    "id": "xdr-014",
    "topic": "Action Center management",
    "scenario": "Adatum Corporation's SOC manager needs to review all remediation actions taken by analysts and automated investigations in the past 30 days. The manager wants to audit which actions were approved, which were rejected, and track any undo operations performed on remediation actions.",
    "question": "Where should the SOC manager go to review the complete history of all remediation actions?",
    "options": [
      "The Microsoft 365 compliance center audit log",
      "The Unified Action Center in Microsoft Defender XDR, which shows both pending and completed actions across all workloads with full history and undo capability",
      "The Azure Activity Log for the Microsoft 365 tenant",
      "The Windows Event Viewer on individual endpoints"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Unified Action Center in Microsoft Defender XDR",
      "analysis": [
        "Option A is INCORRECT: The compliance center audit log records administrative actions across Microsoft 365 but doesn't provide the security-specific remediation context (approve/reject decisions, automated investigation actions, undo operations) that the Action Center provides.",
        "Option B is CORRECT: The Unified Action Center has two tabs: Pending (awaiting analyst approval) and History (completed actions). It shows all automated and manual remediation actions across Defender for Endpoint, Office 365, Identity, and Cloud Apps. Analysts can undo certain completed actions (e.g., un-isolate a device, restore a quarantined file).",
        "Option C is INCORRECT: Azure Activity Log tracks Azure resource management operations (VM creation, policy changes), not Microsoft Defender XDR security remediation actions. These are completely different audit systems.",
        "Option D is INCORRECT: Windows Event Viewer shows local endpoint events but cannot display cross-workload remediation actions for email quarantine, user account suspension, or cloud app blocking. The Action Center is a centralized, cloud-based console."
      ],
      "codeSnippet": "// KQL: Track remediation actions across the tenant\\nDeviceEvents\\n| where Timestamp > ago(30d)\\n| where ActionType in (\\\"AntivirusDetection\\\",\\n    \\\"IsolateDevice\\\", \\\"RestrictCodeExecution\\\")\\n| project Timestamp, DeviceName, ActionType,\\n    InitiatingProcessAccountName\\n| summarize count() by ActionType, bin(Timestamp, 1d)",
      "socTip": "Review the Action Center weekly for audit purposes. Any 'Undo' actions should be documented with justification — they indicate a remediation that was reversed, which could mean a false positive or a disagreement on response actions.",
      "docRef": "Microsoft Learn: The Action Center"
    }
  },
  {
    "id": "xdr-015",
    "topic": "Microsoft Secure Score",
    "scenario": "Litware Inc. has a Microsoft Secure Score of 48% and the CISO wants to improve it. The security team reviews the improvement actions in Secure Score and sees recommendations across Identity, Device, Apps, and Data categories. Some actions are marked 'Completed by third party' and others as 'Risk accepted'.",
    "question": "What is the impact of marking a Secure Score improvement action as 'Risk accepted'?",
    "options": [
      "The action's points are permanently added to your Secure Score as if completed",
      "The action is removed from the score calculation entirely and does not affect your total Secure Score positively or negatively",
      "The action remains in the list but is tagged, and the points are NOT earned — it simply acknowledges that the risk was reviewed and intentionally accepted",
      "The action triggers an alert to Microsoft's security team for review"
    ],
    "correctIndex": 2,
    "explanation": {
      "concept": "Secure Score — Risk Acceptance and Score Calculation",
      "analysis": [
        "Option A is INCORRECT: Marking an action as 'Risk accepted' does NOT grant the improvement points. Only actually implementing the recommendation or marking it as 'Resolved through third party' (with proof) adjusts the score. Risk acceptance is an acknowledgment, not a bypass.",
        "Option B is INCORRECT: The action is not removed from the score calculation. It remains in your improvement actions list and still shows as unrealized points. Your total achievable score remains unchanged.",
        "Option C is CORRECT: When you mark an action as 'Risk accepted', it means your organization has reviewed the recommendation and decided not to implement it due to business reasons (cost, compatibility, operational impact). The points are not earned, but the action is tracked as reviewed. This provides audit trail documentation.",
        "Option D is INCORRECT: Microsoft is not notified when you accept risk. Secure Score status changes are internal to your organization. Microsoft does not review or override your risk acceptance decisions."
      ],
      "codeSnippet": "// KQL: Track Secure Score trends over time\\n// Use the Microsoft Secure Score API:\\n// GET /security/secureScores?$top=90\\n// This returns daily score snapshots\\n// Graph API endpoint for historical scores\\n// No direct KQL table — use API or\\n// Microsoft 365 Defender reports",
      "socTip": "Schedule monthly Secure Score review meetings. Focus on high-impact improvement actions first (those with the most points). Even a 5-point improvement can close significant security gaps.",
      "docRef": "Microsoft Learn: Microsoft Secure Score"
    }
  },
  {
    "id": "xdr-016",
    "topic": "Attack simulation training",
    "scenario": "Contoso wants to test their employees' susceptibility to phishing attacks. The security awareness team decides to use Attack Simulation Training in Microsoft Defender for Office 365 to launch a simulated credential harvesting campaign targeting the finance department.",
    "question": "What does Attack Simulation Training provide after the simulation completes?",
    "options": [
      "A report showing only the total number of emails sent, with no per-user breakdown",
      "A detailed report showing which users were compromised (clicked and entered credentials), which users only clicked the link, which users reported the email, and a completion rate for follow-up training modules",
      "An automatic termination notice for users who failed the simulation",
      "A network packet capture of all email traffic during the simulation period"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Attack Simulation Training — Results and Training Assignment",
      "analysis": [
        "Option A is INCORRECT: Attack Simulation Training provides granular per-user results, not just aggregate counts. You can see exactly which users were compromised, which opened the email, and which reported it. This granularity is essential for targeted remediation.",
        "Option B is CORRECT: The simulation report categorizes users into: Compromised (entered credentials), Clicked (clicked the link but didn't submit credentials), Reported (used the Report Message add-in), and Unaffected. Users who were compromised can be automatically assigned training modules relevant to the attack type.",
        "Option C is INCORRECT: Attack Simulation Training is a security awareness tool, not an HR disciplinary tool. It never triggers termination or HR actions. The goal is to educate employees, not punish them.",
        "Option D is INCORRECT: Attack Simulation Training operates at the application level through Microsoft 365 email, not at the network packet level. It doesn't capture raw network traffic — it tracks email interactions (open, click, submit) through embedded tracking mechanisms."
      ],
      "codeSnippet": "// Note: Attack Simulation Training data is accessed\\n// through the Defender portal or via Graph API:\\n// GET /security/attackSimulation/simulations\\n// GET /security/attackSimulation/simulationAutomations\\n// Results include per-user completion and training status",
      "socTip": "Run simulations monthly with different social engineering techniques (credential harvesting, link in attachment, drive-by URL). Track repeat offenders and assign mandatory security awareness training.",
      "docRef": "Microsoft Learn: Attack simulation training in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-017",
    "topic": "Safe Attachments policies in Defender for Office 365",
    "scenario": "Fabrikam configures Safe Attachments in Microsoft Defender for Office 365. The policy is set to 'Dynamic Delivery' mode for all users. An executive receives an email with a large PDF attachment. The executive reports that the attachment initially appeared as a placeholder, then appeared normally after a few minutes.",
    "question": "What explains this behavior?",
    "options": [
      "The email was blocked by a DLP policy and then released by an administrator",
      "Dynamic Delivery mode delivers the email immediately with a placeholder attachment while the original attachment is being scanned in a sandbox. Once scanning completes and the file is deemed safe, the real attachment replaces the placeholder",
      "The email was caught in a mail flow rule and was delayed in the transport queue",
      "The PDF was too large for Safe Attachments to scan, so it was delivered without scanning after a timeout"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Safe Attachments — Dynamic Delivery Mode",
      "analysis": [
        "Option A is INCORRECT: DLP policies operate on content classification (credit card numbers, SSNs), not attachment sandboxing. A DLP release would not show the placeholder → real attachment transition that Dynamic Delivery produces.",
        "Option B is CORRECT: Dynamic Delivery is a Safe Attachments mode that avoids email delivery delays. The email body is delivered immediately with a temporary placeholder file. The original attachment is detonated in a sandbox environment. If clean, the real attachment is retroactively inserted. If malicious, the placeholder remains and the user sees a notification.",
        "Option C is INCORRECT: Mail flow rules (transport rules) can delay emails, but they don't create placeholder attachments. A transport rule delay would hold the entire email, not deliver it with a modified attachment.",
        "Option D is INCORRECT: Safe Attachments does not skip scanning due to file size timeouts. Large files may take longer to scan, but Dynamic Delivery ensures the user receives the email body immediately while scanning continues. The attachment is always scanned."
      ],
      "codeSnippet": "// KQL: Monitor Safe Attachments verdicts\\nEmailEvents\\n| where Timestamp > ago(7d)\\n| where EmailDirection == \\\"Inbound\\\"\\n| where isnotempty(LatestDeliveryAction)\\n| join EmailAttachmentInfo on NetworkMessageId\\n| where ThreatTypes has \\\"Malware\\\"\\n| project Timestamp, SenderFromAddress,\\n    RecipientEmailAddress, FileName,\\n    LatestDeliveryAction, ThreatTypes",
      "socTip": "Dynamic Delivery is the recommended mode for executives and VIPs who cannot tolerate email delays. For standard users, 'Block' mode prevents any delivery until scanning completes, which is more secure but may cause brief delays.",
      "docRef": "Microsoft Learn: Safe Attachments in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-018",
    "topic": "Hunting queries and bookmarks",
    "scenario": "A SOC analyst at Northwind Traders is conducting a proactive threat hunt in Advanced Hunting. The analyst runs a KQL query that identifies 5 devices with suspicious PowerShell encoded command execution. The analyst wants to save these findings for further investigation and share them with the team.",
    "question": "What is the recommended way to preserve these hunting results for team investigation?",
    "options": [
      "Take a screenshot of the query results and email it to the team",
      "Add the suspicious results as bookmarks in Advanced Hunting, which links them to an existing or new incident for collaborative investigation",
      "Copy the results into a Word document and save it to the team SharePoint site",
      "Re-run the query every hour and hope the team notices the same results"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Hunting Bookmarks and Incident Linking",
      "analysis": [
        "Option A is INCORRECT: Screenshots lose the interactive context — you can't pivot from a screenshot to investigate entities, run related queries, or take response actions. This is not a scalable or auditable investigation workflow.",
        "Option B is CORRECT: Advanced Hunting bookmarks allow you to save specific result rows (entities like devices, users, IPs) and link them to a new or existing incident. This creates a formal investigation artifact that other analysts can access, enriched with the full entity context and timeline data from Defender XDR.",
        "Option C is INCORRECT: Copying to Word loses the Defender XDR context and cannot be acted upon. Bookmarked results remain connected to the live investigation data, enabling pivoting, entity pages, and response actions.",
        "Option D is INCORRECT: Relying on others to independently find the same results is unreliable and wastes time. Bookmarks provide a formal hand-off mechanism with full context preservation."
      ],
      "codeSnippet": "// Save this hunting query for reuse\\n// KQL: Detect encoded PowerShell commands\\nDeviceProcessEvents\\n| where Timestamp > ago(24h)\\n| where FileName =~ \\\"powershell.exe\\\"\\n| where ProcessCommandLine has_any\\n    (\\\"-enc\\\", \\\"-encodedcommand\\\", \\\"frombase64\\\")\\n| project Timestamp, DeviceName,\\n    AccountName, ProcessCommandLine\\n| order by Timestamp desc",
      "socTip": "Create a shared hunting query library in your team. Save proven detection queries as 'Shared queries' in Advanced Hunting so all analysts can run them. Tag queries by MITRE ATT&CK technique for easy retrieval.",
      "docRef": "Microsoft Learn: Use hunting bookmarks in Advanced Hunting"
    }
  },
  {
    "id": "xdr-019",
    "topic": "Device timeline and evidence collection",
    "scenario": "During an incident investigation, a Contoso analyst identifies a suspicious device that may have been used for data exfiltration. The analyst needs to review the complete history of processes, network connections, file operations, and registry changes on this device over the past 48 hours.",
    "question": "Which feature provides the most detailed device-level forensic timeline?",
    "options": [
      "The Device Inventory page showing hardware and software specifications",
      "The device timeline in the device entity page, which shows a chronological sequence of all processes, network events, file events, and registry modifications with filtering and search capabilities",
      "The Windows Event Viewer logs exported from the device",
      "The Microsoft Intune device compliance report"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Device Timeline — Forensic Investigation in Defender XDR",
      "analysis": [
        "Option A is INCORRECT: The Device Inventory page shows device properties (OS version, last seen, risk level, onboarding status) but not the forensic event timeline. It's for device management, not forensic investigation.",
        "Option B is CORRECT: The device timeline in Defender XDR shows a chronological view of all telemetry collected by the EDR sensor: process creations, network connections, file operations, registry modifications, logon events, and more. Analysts can filter by event type, search for specific indicators, and flag events for the investigation.",
        "Option C is INCORRECT: Windows Event Viewer provides local event logs but requires direct access to the device. The Defender XDR device timeline provides the same (and often more) telemetry remotely through the cloud portal, without needing to access the device directly.",
        "Option D is INCORRECT: Intune compliance reports show whether a device meets organizational compliance policies (encryption enabled, OS updated). They don't provide forensic process/network/file event timelines."
      ],
      "codeSnippet": "// KQL: Reconstruct device activity timeline\\nlet targetDevice = \\\"WORKSTATION-05\\\";\\nunion DeviceProcessEvents, DeviceNetworkEvents,\\n    DeviceFileEvents, DeviceRegistryEvents\\n| where Timestamp > ago(48h)\\n| where DeviceName =~ targetDevice\\n| project Timestamp, ActionType,\\n    FileName, ProcessCommandLine,\\n    RemoteIP, RemoteUrl, RegistryKey\\n| order by Timestamp asc",
      "socTip": "When reviewing the device timeline, use the 'Flags' feature to mark important events. Export the flagged events to create a formal forensic timeline document for incident reports or legal proceedings.",
      "docRef": "Microsoft Learn: Investigate devices in Microsoft Defender for Endpoint"
    }
  },
  {
    "id": "xdr-020",
    "topic": "Live Response session",
    "scenario": "Adatum's SOC confirms that a device has an active reverse shell connection to a C2 server. The device needs immediate forensic analysis, but the analyst cannot physically access it because it's a remote employee's laptop. The analyst decides to use Live Response in Microsoft Defender for Endpoint.",
    "question": "Which actions can the analyst perform through a Live Response session?",
    "options": [
      "Only view running processes — no interactive commands are allowed",
      "Run built-in commands (dir, cd, processes, connections), collect forensic files, upload and run investigation scripts, and remediate by quarantining files — all remotely through the portal",
      "Full remote desktop access with GUI control of the device",
      "Only reboot the device and trigger a full antivirus scan"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Live Response — Remote Forensic Investigation and Remediation",
      "analysis": [
        "Option A is INCORRECT: Live Response provides a full command-line interface with multiple built-in commands and the ability to upload custom scripts. Viewing processes is just one of many capabilities.",
        "Option B is CORRECT: Live Response provides a remote command-line shell on the device. Built-in commands include: dir (list files), processes (running processes), connections (network connections), getfile (download forensic artifacts), putfile (upload investigation tools), run (execute scripts), remediate (quarantine files). Advanced Live Response also allows running PowerShell and Python scripts.",
        "Option C is INCORRECT: Live Response is a command-line interface, not a remote desktop (RDP) session. It provides text-based interaction for forensic analysis, not graphical user interface control.",
        "Option D is INCORRECT: Live Response provides granular forensic capabilities far beyond just rebooting and scanning. Analysts can examine individual files, dump process memory, collect registry hives, and execute investigation scripts."
      ],
      "codeSnippet": "// Live Response built-in commands example:\\n// List running processes:\\nprocesses\\n\\n// Show active network connections:\\nconnections\\n\\n// Download a suspicious file for analysis:\\ngetfile \\\"C:\\\\Users\\\\Public\\\\payload.exe\\\"\\n\\n// Upload and run a forensic script:\\nputfile hunter.ps1\\nrun hunter.ps1",
      "socTip": "Before starting a Live Response session on a device with active C2, consider isolating the device first to cut the attacker's access. Then use Live Response to collect forensic artifacts. Order matters: isolate → investigate → remediate.",
      "docRef": "Microsoft Learn: Investigate entities on devices using live response"
    }
  },
  {
    "id": "xdr-021",
    "topic": "Safe Links policies",
    "scenario": "Litware has Safe Links enabled in Microsoft Defender for Office 365. An employee receives an email containing a URL that passes initial scanning (appears clean at delivery time). However, 4 hours later, the URL is weaponized — the attacker activates the malicious payload on the destination website.",
    "question": "How does Safe Links handle this time-of-click weaponization scenario?",
    "options": [
      "Safe Links only scans URLs at the time of email delivery and cannot detect post-delivery weaponization",
      "Safe Links wraps URLs and performs real-time scanning at the time of click, so when the user clicks the link 4 hours later, Safe Links re-evaluates the URL and blocks it if it has become malicious",
      "Safe Links requires the user to manually check the URL reputation before clicking",
      "Safe Links sends a daily digest of all clicked URLs for the SOC to review manually"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Safe Links — Time-of-Click URL Protection",
      "analysis": [
        "Option A is INCORRECT: This describes the limitation of traditional URL scanning. Safe Links was specifically designed to overcome this by performing real-time scanning at click time, not just delivery time.",
        "Option B is CORRECT: Safe Links rewrites URLs in emails to route through Microsoft's URL detonation service. When a user clicks the link (even hours or days after delivery), Safe Links scans the destination in real-time. If the URL has been weaponized since delivery, Safe Links blocks the user from accessing it and shows a warning page.",
        "Option C is INCORRECT: Safe Links operates transparently — users don't need to manually check URLs. The protection is automatic through URL rewriting and real-time detonation.",
        "Option D is INCORRECT: Safe Links provides real-time blocking, not post-hoc daily reports. If a URL is malicious at click time, the user is immediately blocked from accessing it."
      ],
      "codeSnippet": "// KQL: Track Safe Links click verdicts\\nUrlClickEvents\\n| where Timestamp > ago(7d)\\n| where ActionType == \\\"ClickBlocked\\\"\\n| project Timestamp, AccountUpn, Url,\\n    UrlChain, ActionType, IsClickedThrough\\n| summarize BlockedClicks=count() by AccountUpn\\n| order by BlockedClicks desc",
      "socTip": "Monitor UrlClickEvents for 'IsClickedThrough == true' — this means a user bypassed the Safe Links warning page and accessed the malicious URL anyway. These users need immediate investigation and potentially credential reset.",
      "docRef": "Microsoft Learn: Safe Links in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-022",
    "topic": "Advanced Hunting — IdentityLogonEvents table",
    "scenario": "Contoso's SOC receives a Defender for Identity alert indicating potential password spray activity against on-premises Active Directory. The analyst needs to use Advanced Hunting to quantify the attack — identifying which accounts were targeted and from which source IPs.",
    "question": "Which KQL query correctly analyzes the password spray activity?",
    "options": [
      "SigninLogs | where ResultType == '50126' | summarize count() by UserPrincipalName, IPAddress",
      "IdentityLogonEvents | where Timestamp > ago(24h) | where LogonType == 'Failed' | where Application == 'Active Directory' | summarize FailedAttempts=count(), TargetAccounts=dcount(AccountUpn) by IPAddress | where TargetAccounts > 10",
      "DeviceLogonEvents | where LogonType == 'Interactive' | where ActionType == 'LogonFailed'",
      "EmailEvents | where Subject contains 'password' | project RecipientEmailAddress"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Identity Threat Detection with IdentityLogonEvents",
      "analysis": [
        "Option A is INCORRECT: SigninLogs tracks Azure AD (Entra ID) cloud sign-ins, not on-premises Active Directory logons. Password spray against on-premises AD is captured by Defender for Identity sensors on domain controllers, which populates the IdentityLogonEvents table.",
        "Option B is CORRECT: IdentityLogonEvents captures on-premises AD authentication events detected by Defender for Identity sensors. The query filters for failed logons against Active Directory, then groups by source IP to find IPs attempting many accounts — the signature pattern of a password spray attack (many accounts, few attempts per account, from one or few IPs).",
        "Option C is INCORRECT: DeviceLogonEvents tracks local device logons (interactive, RDP, service), not centralized AD authentication events. A password spray typically targets the domain controller, which is captured in IdentityLogonEvents, not individual device logon events.",
        "Option D is INCORRECT: EmailEvents is completely unrelated to authentication events. This query searches for emails with 'password' in the subject, which has nothing to do with detecting password spray attacks."
      ],
      "codeSnippet": "// KQL: Full password spray detection query\\nIdentityLogonEvents\\n| where Timestamp > ago(24h)\\n| where Application == \\\"Active Directory\\\"\\n| where ActionType == \\\"LogonFailed\\\"\\n| summarize\\n    FailedAttempts = count(),\\n    TargetAccounts = dcount(AccountUpn),\\n    AccountsList = make_set(AccountUpn, 10)\\n    by IPAddress, bin(Timestamp, 1h)\\n| where TargetAccounts > 10 and FailedAttempts > 50\\n| order by FailedAttempts desc",
      "socTip": "Password spray attacks try common passwords against many accounts. Key indicators: high distinct account count per source IP, low attempts per individual account (to avoid lockout), and attempts spread over time. Alert when TargetAccounts > 10 from a single IP.",
      "docRef": "Microsoft Learn: IdentityLogonEvents table"
    }
  },
  {
    "id": "xdr-023",
    "topic": "Zero-hour auto purge (ZAP)",
    "scenario": "A phishing email bypasses initial scanning and is delivered to 50 mailboxes at Fabrikam. Thirty minutes later, Microsoft's threat intelligence identifies the URL in the email as malicious. Zero-hour Auto Purge (ZAP) is enabled in the organization.",
    "question": "What action does ZAP take on the already-delivered emails?",
    "options": [
      "ZAP sends a warning email to the 50 recipients advising them not to click the link",
      "ZAP automatically moves the malicious emails from the recipients' inboxes to their Junk Email folders or quarantine, retroactively remediating the threat",
      "ZAP deletes the emails permanently without any notification or audit trail",
      "ZAP only works on new incoming emails, not emails already delivered to mailboxes"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Zero-hour Auto Purge (ZAP) — Post-Delivery Remediation",
      "analysis": [
        "Option A is INCORRECT: ZAP does not send warning emails. It takes direct remediation action on the emails themselves (moving or quarantining them). Relying on user warnings would not be effective for urgent threat remediation.",
        "Option B is CORRECT: ZAP retroactively processes already-delivered emails when new threat intelligence identifies them as malicious. Depending on the policy configuration, ZAP moves messages to Junk Email or quarantine. For phishing emails, ZAP quarantines them regardless of mail flow rules. An audit trail is maintained in Threat Explorer.",
        "Option C is INCORRECT: ZAP does not permanently delete emails without trace. It moves them to Junk or quarantine, maintaining an audit trail visible in Threat Explorer and the Admin Quarantine. This ensures forensic evidence is preserved.",
        "Option D is INCORRECT: ZAP was specifically designed to address the gap between delivery-time scanning and post-delivery threat intelligence. Its entire purpose is to remediate emails that were already delivered and later identified as malicious."
      ],
      "codeSnippet": "// KQL: Track ZAP remediation actions\\nEmailEvents\\n| where Timestamp > ago(7d)\\n| where LatestDeliveryAction == \\\"Junked\\\" or\\n    LatestDeliveryAction == \\\"Quarantined\\\"\\n| where DeliveryAction == \\\"Delivered\\\"\\n| where LatestDeliveryAction != DeliveryAction\\n| project Timestamp, RecipientEmailAddress,\\n    SenderFromAddress, Subject,\\n    DeliveryAction, LatestDeliveryAction\\n| order by Timestamp desc",
      "socTip": "Monitor the difference between DeliveryAction and LatestDeliveryAction in EmailEvents. When they differ, it means ZAP took post-delivery action. Track these to measure how many threats bypass initial scanning.",
      "docRef": "Microsoft Learn: Zero-hour auto purge in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-024",
    "topic": "Device isolation",
    "scenario": "A Northwind Traders analyst confirms that a workstation is actively communicating with a command-and-control (C2) server. The analyst needs to immediately contain the threat while preserving the ability to investigate the device remotely through Defender for Endpoint.",
    "question": "What happens when the analyst isolates the device from the network?",
    "options": [
      "The device is completely disconnected from all networks, including the connection to the Defender for Endpoint cloud service",
      "The device is disconnected from the local network and internet, but maintains its connection to the Microsoft Defender for Endpoint cloud service, allowing continued remote investigation through the portal",
      "The device is only blocked from accessing the internet but can still communicate with other devices on the local network",
      "The device requires a physical restart before isolation takes effect"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Network Device Isolation in Defender for Endpoint",
      "analysis": [
        "Option A is INCORRECT: Full isolation cuts ALL network connections would make the device unmanageable. Defender for Endpoint specifically maintains its own cloud service connection so analysts can continue remote investigation via the device timeline, Live Response, and remediation actions.",
        "Option B is CORRECT: Device isolation in Defender for Endpoint uses Windows Filtering Platform (WFP) rules to block all network communication except the Defender for Endpoint cloud service channel. This stops C2 communication and lateral movement while preserving the analyst's ability to investigate remotely.",
        "Option C is INCORRECT: Partial isolation that only blocks internet while allowing local network would not prevent lateral movement to other internal devices. Isolation blocks both local network and internet traffic, keeping only the Defender cloud channel.",
        "Option D is INCORRECT: Device isolation takes effect within seconds — no restart required. The WFP filter rules are applied dynamically to the running network stack."
      ],
      "codeSnippet": "// KQL: Verify isolation status of devices\\nDeviceEvents\\n| where Timestamp > ago(24h)\\n| where ActionType == \\\"DeviceNetworkIsolation\\\"\\n| project Timestamp, DeviceName,\\n    InitiatingProcessAccountName, ActionType\\n| order by Timestamp desc\\n\\n// Isolate via API:\\n// POST /api/machines/{id}/isolate\\n// Body: {\\\"IsolationType\\\": \\\"Full\\\"}",
      "socTip": "Always isolate BEFORE starting Live Response forensics on a C2-compromised device. If you investigate first, the attacker may notice your commands and destroy evidence or escalate the attack.",
      "docRef": "Microsoft Learn: Isolate devices from the network"
    }
  },
  {
    "id": "xdr-025",
    "topic": "Advanced Hunting — DeviceNetworkEvents table",
    "scenario": "Adatum's threat intelligence team receives IOCs (Indicators of Compromise) including 5 suspicious IP addresses associated with a known APT group. The SOC analyst needs to search the last 30 days of network telemetry to determine if any devices in the organization communicated with these IPs.",
    "question": "Which KQL query correctly searches for connections to the IOC IP addresses?",
    "options": [
      "DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in ('198.51.100.10', '203.0.113.20', '192.0.2.30', '198.51.100.40', '203.0.113.50') | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName | summarize ConnectionCount=count() by DeviceName, RemoteIP",
      "DeviceProcessEvents | where ProcessCommandLine contains '198.51.100.10'",
      "EmailUrlInfo | where Url contains '198.51.100' | project Url, NetworkMessageId",
      "IdentityQueryEvents | where QueryTarget contains '198.51.100'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IOC Sweeping with DeviceNetworkEvents",
      "analysis": [
        "Option A is CORRECT: DeviceNetworkEvents contains all outbound and inbound network connections recorded by the EDR sensor. Using the 'in' operator to match against a list of IOC IPs efficiently searches all connection records. The summarize clause groups by device and IP to show which devices connected and how often.",
        "Option B is INCORRECT: DeviceProcessEvents tracks process execution, not network connections. While a command line might contain an IP address (e.g., 'ping 198.51.100.10'), this would miss connections initiated by processes that don't embed the IP in their command line arguments (which is most network traffic).",
        "Option C is INCORRECT: EmailUrlInfo tracks URLs in emails, not raw network connections from devices. An IP address in a URL is only a small subset of all network communication. Most C2 connections are direct TCP/UDP, not URLs in emails.",
        "Option D is INCORRECT: IdentityQueryEvents tracks Active Directory queries (LDAP, DNS), not general network connections to external IPs. This table is specific to Defender for Identity telemetry."
      ],
      "codeSnippet": "// KQL: Complete IOC sweep with process context\\nlet IOC_IPs = dynamic([\\\"198.51.100.10\\\",\\n    \\\"203.0.113.20\\\", \\\"192.0.2.30\\\"]);\\nDeviceNetworkEvents\\n| where Timestamp > ago(30d)\\n| where RemoteIP in (IOC_IPs)\\n| project Timestamp, DeviceName, RemoteIP,\\n    RemotePort, RemoteUrl,\\n    InitiatingProcessFileName,\\n    InitiatingProcessCommandLine\\n| order by Timestamp desc",
      "socTip": "When sweeping IOCs, always check DeviceNetworkEvents (raw connections), EmailUrlInfo (URLs in emails), and DeviceFileEvents (file hashes) together. Attackers often reuse infrastructure across different attack vectors.",
      "docRef": "Microsoft Learn: DeviceNetworkEvents table"
    }
  },
  {
    "id": "xdr-026",
    "topic": "Defender for Office 365 — anti-phishing policies",
    "scenario": "Litware's CEO is being impersonated in phishing emails sent to employees. The attacker uses the display name 'John Smith CEO' with an external email address. The SOC team needs to configure anti-phishing protection to detect and quarantine these impersonation attempts.",
    "question": "Which anti-phishing policy setting specifically addresses user impersonation?",
    "options": [
      "Enable SPF (Sender Policy Framework) hard fail for the company domain",
      "Enable user impersonation protection in the anti-phishing policy, add the CEO's email to the protected users list, and configure the action to quarantine impersonating emails",
      "Create a mail flow rule that blocks all emails with the display name 'John Smith'",
      "Enable DKIM (DomainKeys Identified Mail) signing for outbound emails"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Anti-Phishing — User Impersonation Protection",
      "analysis": [
        "Option A is INCORRECT: SPF validates that the sending mail server is authorized for the sender's domain. It does not detect display name impersonation where an attacker uses a different domain but mimics the CEO's name. SPF is important but addresses domain spoofing, not impersonation.",
        "Option B is CORRECT: User impersonation protection in anti-phishing policies uses AI to detect when incoming emails attempt to impersonate specific protected users. Adding the CEO to the protected users list means any external email with a similar display name or address pattern will be flagged. The action can be set to quarantine, deliver to Junk, or add a safety tip.",
        "Option C is INCORRECT: Blocking all emails with the CEO's display name would block legitimate emails from the CEO themselves and any external person with the same name. This is overly broad and will cause false positives.",
        "Option D is INCORRECT: DKIM signs your outbound emails for authenticity. It does not protect against inbound emails impersonating your users. DKIM helps receiving organizations verify your emails are legitimate, but doesn't help you detect impersonation of your executives."
      ],
      "codeSnippet": "// KQL: Detect impersonation attempts\\nEmailEvents\\n| where Timestamp > ago(7d)\\n| where EmailDirection == \\\"Inbound\\\"\\n| where ThreatTypes has \\\"Phish\\\"\\n| where DetectionMethods has \\\"Impersonation\\\"\\n| project Timestamp, SenderFromAddress,\\n    SenderDisplayName, RecipientEmailAddress,\\n    Subject, DeliveryAction\\n| order by Timestamp desc",
      "socTip": "Add all C-suite executives and board members to the user impersonation protection list. Also enable mailbox intelligence, which uses machine learning to understand each user's communication patterns to detect impersonation more accurately.",
      "docRef": "Microsoft Learn: Anti-phishing policies in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-027",
    "topic": "Microsoft Sentinel integration with Defender XDR",
    "scenario": "Contoso uses both Microsoft Defender XDR and Microsoft Sentinel. The security team wants to stream all Defender XDR incidents and raw Advanced Hunting data into Sentinel for extended retention, cross-platform correlation with non-Microsoft data sources, and custom analytics rules.",
    "question": "How should the team connect Defender XDR data to Microsoft Sentinel?",
    "options": [
      "Manually export CSV files from Defender XDR and import them into Sentinel daily",
      "Enable the Microsoft Defender XDR data connector in Sentinel, which streams incidents, alerts, and raw Advanced Hunting tables (DeviceEvents, EmailEvents, IdentityLogonEvents, etc.) into the Sentinel workspace",
      "Configure Defender XDR to send syslog data to the Sentinel syslog collector agent",
      "Use Azure Event Grid to forward Defender XDR webhooks to a Sentinel-connected Azure Function"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Microsoft Defender XDR Data Connector for Sentinel",
      "analysis": [
        "Option A is INCORRECT: Manual CSV export is not a sustainable or real-time integration. The official data connector provides near-real-time streaming of all Defender XDR data into Sentinel automatically.",
        "Option B is CORRECT: The Microsoft Defender XDR data connector in Sentinel provides native integration that streams incidents and all raw Advanced Hunting tables directly into your Sentinel Log Analytics workspace. This enables creating custom Sentinel analytics rules against Defender data, extended data retention beyond Defender XDR's 30-day limit, and cross-correlation with non-Microsoft data sources.",
        "Option C is INCORRECT: Defender XDR does not send syslog data. Syslog is used for Linux/network devices. The Defender XDR connector uses a direct API-based integration with the Microsoft security graph, not syslog.",
        "Option D is INCORRECT: While Event Grid and Azure Functions could theoretically process webhook data, this is an overly complex, fragile architecture. The native Defender XDR connector is the Microsoft-supported integration method."
      ],
      "codeSnippet": "// In Sentinel, query Defender XDR data directly:\\nSecurityIncident\\n| where ProviderName == \\\"Microsoft 365 Defender\\\"\\n| where Severity == \\\"High\\\"\\n| project TimeGenerated, IncidentNumber, Title,\\n    Severity, Status, Owner\\n| order by TimeGenerated desc\\n\\n// Raw hunting data also available:\\nDeviceProcessEvents\\n| where TimeGenerated > ago(7d)\\n| take 10",
      "socTip": "Enable bi-directional sync between Defender XDR and Sentinel incidents. When an analyst updates incident status in one portal, it automatically syncs to the other, preventing duplicate investigation work.",
      "docRef": "Microsoft Learn: Connect Microsoft Defender XDR to Microsoft Sentinel"
    }
  },
  {
    "id": "xdr-028",
    "topic": "Advanced Hunting — CloudAppEvents table",
    "scenario": "Fabrikam suspects that a compromised account is downloading large volumes of files from SharePoint Online. The SOC analyst needs to use Advanced Hunting to quantify the data access and identify the specific files that were downloaded.",
    "question": "Which table and query approach should the analyst use?",
    "options": [
      "DeviceFileEvents | where ActionType == 'FileDownloaded' | where FolderPath contains 'SharePoint'",
      "CloudAppEvents | where Timestamp > ago(7d) | where ActionType == 'FileDownloaded' | where Application == 'Microsoft SharePoint Online' | project Timestamp, AccountDisplayName, ObjectName, RawEventData | summarize DownloadCount=count(), TotalFiles=dcount(ObjectName) by AccountDisplayName",
      "EmailAttachmentInfo | where FileName contains 'sharepoint'",
      "DeviceNetworkEvents | where RemoteUrl contains 'sharepoint.com'"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Cloud Application Activity Investigation with CloudAppEvents",
      "analysis": [
        "Option A is INCORRECT: DeviceFileEvents tracks local file system operations on endpoints (file creation, modification, deletion). SharePoint Online file downloads are cloud application events that occur within the SaaS platform, tracked by CloudAppEvents through the Defender for Cloud Apps integration.",
        "Option B is CORRECT: CloudAppEvents is the correct table for SaaS application activity including SharePoint, OneDrive, Teams, Exchange Online, and third-party connected apps. Filtering by ActionType 'FileDownloaded' and Application 'Microsoft SharePoint Online' isolates the specific behavior. The summarize clause quantifies the download activity per account.",
        "Option C is INCORRECT: EmailAttachmentInfo tracks attachments in emails, not SharePoint file downloads. SharePoint sharing links in emails would appear in EmailUrlInfo, but the actual download activity is recorded in CloudAppEvents.",
        "Option D is INCORRECT: DeviceNetworkEvents would show connections to sharepoint.com domains but cannot tell you which specific files were downloaded, who downloaded them, or the volume of data. CloudAppEvents provides the application-level context."
      ],
      "codeSnippet": "// KQL: Detect bulk file download from SharePoint\\nCloudAppEvents\\n| where Timestamp > ago(7d)\\n| where Application == \\\"Microsoft SharePoint Online\\\"\\n| where ActionType == \\\"FileDownloaded\\\"\\n| summarize\\n    DownloadCount = count(),\\n    UniqueFiles = dcount(ObjectName),\\n    FileList = make_set(ObjectName, 20)\\n    by AccountDisplayName, bin(Timestamp, 1h)\\n| where DownloadCount > 100\\n| order by DownloadCount desc",
      "socTip": "A user downloading more than 100 files in an hour from SharePoint is a strong data exfiltration indicator. Cross-reference with IdentityLogonEvents to check if the account logged in from an unusual location or device.",
      "docRef": "Microsoft Learn: CloudAppEvents table"
    }
  },
  {
    "id": "xdr-029",
    "topic": "Automated investigation scope and entities",
    "scenario": "After a high-severity incident triggers Automated Investigation and Response (AIR) in Microsoft Defender XDR, the investigation automatically expands its scope. The SOC analyst notices that AIR has investigated not just the initial alert entity but also related entities that were discovered during the investigation.",
    "question": "How does AIR determine which additional entities to investigate?",
    "options": [
      "AIR only investigates the single entity mentioned in the original alert and never expands scope",
      "AIR uses entity-based expansion — it follows relationships (same user, same device, same email campaign, related processes) to automatically investigate connected entities, building a comprehensive picture of the incident",
      "AIR randomly selects 10 additional entities from the tenant for comparison analysis",
      "AIR sends a request to Microsoft support to manually identify related entities"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "AIR Entity-Based Investigation Expansion",
      "analysis": [
        "Option A is INCORRECT: AIR is specifically designed to expand beyond the initial alert entity. Its strength lies in automatic entity-based investigation that discovers related threats that human analysts might miss due to time constraints.",
        "Option B is CORRECT: AIR follows entity relationships to expand its investigation scope. For example, if a phishing email is the initial entity, AIR investigates the sender, all recipients, the URL/attachment, any devices that were accessed after credential theft, and any suspicious sign-ins from the compromised account. This entity expansion creates a comprehensive investigation.",
        "Option C is INCORRECT: AIR does not randomly select entities. It uses deterministic, intelligence-driven expansion based on known entity relationships (user → device → email → process → network connection chains).",
        "Option D is INCORRECT: AIR is a fully automated engine that does not require human intervention from Microsoft support. It operates autonomously using Microsoft's detection algorithms and threat intelligence."
      ],
      "codeSnippet": "// KQL: Review AIR investigation entity expansion\\nAlertEvidence\\n| where Timestamp > ago(7d)\\n| where DetectionSource == \\\"Automated investigation\\\"\\n| summarize\\n    EntityCount = count(),\\n    EntityTypes = make_set(EntityType)\\n    by AlertId, Title\\n| where EntityCount > 3\\n| order by EntityCount desc",
      "socTip": "Review AIR investigation reports for entities you didn't initially consider suspicious. AIR often discovers compromised accounts, additional phishing recipients, or lateral movement that the original alert didn't capture.",
      "docRef": "Microsoft Learn: Automated investigation details and results"
    }
  },
  {
    "id": "xdr-030",
    "topic": "Submission of false positives and false negatives",
    "scenario": "A Northwind Traders analyst discovers that a legitimate business email from a trusted partner was incorrectly quarantined by Defender for Office 365 as malware. The partner is unable to communicate critical contract information. The analyst needs to release the email and report it as a false positive.",
    "question": "What is the correct process to handle this false positive?",
    "options": [
      "Add the partner's domain to the Tenant Allow/Block List, release the email from quarantine, and submit the email through the Submissions portal for Microsoft to re-evaluate the detection",
      "Disable all Defender for Office 365 policies until the partner's emails stop being blocked",
      "Ask the partner to resend the email from a different email address",
      "Create a mail flow rule that bypasses all security scanning for the partner's domain"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Admin Submissions and Tenant Allow/Block List",
      "analysis": [
        "Option A is CORRECT: The proper workflow is: (1) Release the email from quarantine so the recipient gets it, (2) Add a temporary allow entry in the Tenant Allow/Block List for the sender/domain to prevent future blocks, (3) Submit the email via the Submissions portal (security.microsoft.com > Email & collaboration > Submissions) so Microsoft's threat analysts can update the detection models. Microsoft may then remove the need for the allow entry.",
        "Option B is INCORRECT: Disabling all Defender for Office 365 policies exposes the entire organization to email threats. Never disable security controls to resolve a single false positive.",
        "Option C is INCORRECT: Asking the partner to resend from a different address is a workaround, not a fix. The underlying false positive detection would continue blocking future legitimate emails. The detection model needs to be updated.",
        "Option D is INCORRECT: Bypassing all security scanning for an entire domain is extremely dangerous. If the partner's domain is later compromised, attackers could send malware that completely bypasses your email security. Always use granular allow entries, not blanket bypass rules."
      ],
      "codeSnippet": "// Steps to handle via PowerShell:\\n// 1. Release from quarantine:\\n// Release-QuarantineMessage -Identity <ID> -ReleaseToAll\\n//\\n// 2. Add Tenant Allow/Block List entry:\\n// New-TenantAllowBlockListItems \\n//   -ListType Sender \\n//   -Entries 'partner@trusted.com' \\n//   -Allow -NoExpiration",
      "socTip": "Track false positive rates by source in the Submissions portal. If a specific partner's emails are frequently flagged, consider configuring a specific anti-malware policy with a more permissive threshold for that relationship, rather than blanket allow rules.",
      "docRef": "Microsoft Learn: Admin submissions in Microsoft Defender for Office 365"
    }
  },
  {
    "id": "xdr-031",
    "topic": "Advanced Hunting — DeviceFileEvents table",
    "scenario": "Adatum Corporation's incident response team is investigating a potential ransomware attack. They need to identify files that have been rapidly renamed or encrypted on affected devices. The team suspects the ransomware is appending a '.locked' extension to encrypted files.",
    "question": "Which KQL query identifies potential ransomware file encryption activity?",
    "options": [
      "DeviceFileEvents | where Timestamp > ago(1h) | where ActionType == 'FileRenamed' | where FileName endswith '.locked' | summarize RenamedCount=count() by DeviceName, bin(Timestamp, 5m) | where RenamedCount > 50",
      "DeviceProcessEvents | where FileName == 'ransomware.exe'",
      "SecurityAlert | where AlertName contains 'ransomware'",
      "DeviceRegistryEvents | where RegistryKey contains 'encryption'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Ransomware Detection via File System Telemetry",
      "analysis": [
        "Option A is CORRECT: DeviceFileEvents with ActionType 'FileRenamed' captures file rename operations. Ransomware typically renames files rapidly (hundreds per minute) with a specific extension. Summarizing by 5-minute bins and filtering for counts > 50 identifies the high-velocity rename pattern characteristic of file encryption.",
        "Option B is INCORRECT: Searching for 'ransomware.exe' is naive — real ransomware uses obfuscated names, legitimate process names, or fileless techniques. Attackers never name their malware 'ransomware.exe'.",
        "Option C is INCORRECT: SecurityAlert would show alerts that have already been generated by detection engines. This is reactive, not proactive hunting. The analyst needs to search raw telemetry to find activity that may not have triggered an alert yet.",
        "Option D is INCORRECT: DeviceRegistryEvents tracks registry changes. While ransomware may modify registry keys (e.g., disabling shadow copies), the primary indicator of file encryption is the mass file rename/modify activity in DeviceFileEvents."
      ],
      "codeSnippet": "// KQL: Comprehensive ransomware file activity detection\\nDeviceFileEvents\\n| where Timestamp > ago(2h)\\n| where ActionType in (\\\"FileRenamed\\\", \\\"FileModified\\\")\\n| where FileName endswith \\\".locked\\\" or\\n    FileName endswith \\\".encrypted\\\" or\\n    FileName endswith \\\".crypto\\\"\\n| summarize\\n    FileCount = count(),\\n    Devices = dcount(DeviceName),\\n    FirstSeen = min(Timestamp),\\n    LastSeen = max(Timestamp)\\n    by InitiatingProcessFileName, bin(Timestamp, 5m)\\n| where FileCount > 100",
      "socTip": "Establish a baseline for normal file rename rates per device. Most workstations rename fewer than 20 files per 5-minute window during normal operations. Anything above 100 renames in 5 minutes with a consistent new extension is a strong ransomware indicator.",
      "docRef": "Microsoft Learn: DeviceFileEvents table"
    }
  },
  {
    "id": "xdr-032",
    "topic": "Defender for Cloud Apps — session policies",
    "scenario": "Litware allows contractors to access corporate SharePoint from unmanaged personal devices. The security team wants to allow read-only access to files from unmanaged devices but block downloads and copy/paste operations. They need to implement Conditional Access App Control.",
    "question": "Which combination of configurations achieves this requirement?",
    "options": [
      "Create an Azure AD Conditional Access policy requiring compliant devices for all SharePoint access",
      "Configure a Conditional Access policy with 'Use Conditional Access App Control' session control, then create a session policy in Defender for Cloud Apps that blocks file downloads and restricts clipboard operations for sessions from unmanaged devices",
      "Disable external sharing in SharePoint admin center",
      "Create a DLP policy that blocks all file downloads from SharePoint"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Conditional Access App Control and Session Policies",
      "analysis": [
        "Option A is INCORRECT: Requiring compliant devices would block contractors entirely since their personal devices are unmanaged and won't meet compliance requirements. The goal is to allow limited access, not block access completely.",
        "Option B is CORRECT: This is the standard implementation pattern: (1) Azure AD Conditional Access policy routes sessions from unmanaged devices through Defender for Cloud Apps proxy, (2) Session policies in Defender for Cloud Apps enforce granular controls like blocking downloads, preventing clipboard operations, and adding watermarks — all while allowing read-only browsing access.",
        "Option C is INCORRECT: Disabling external sharing prevents sharing with external users, but contractors with organizational accounts (guest accounts) would still have direct access. This doesn't address download/clipboard control for unmanaged devices.",
        "Option D is INCORRECT: A DLP policy blocks downloads based on content classification (sensitive data labels), not device management status. The requirement is to block downloads based on device compliance state (managed vs unmanaged), which requires Conditional Access App Control."
      ],
      "codeSnippet": "// Session policy pseudocode in MCAS:\\n// Policy: Block Downloads from Unmanaged Devices\\n// Filter: Device = Unmanaged\\n// App: SharePoint Online\\n// Action: Block file download\\n// Action: Block clipboard (cut/copy/paste)\\n// Notification: \\\"Downloads are restricted on\\n//   unmanaged devices. Use a corporate device\\n//   for full access.\\\"",
      "socTip": "Enable session recording for Conditional Access App Control sessions from unmanaged devices. This creates an audit trail of all file access activity, even for read-only browsing, which is critical for data exfiltration investigation.",
      "docRef": "Microsoft Learn: Protect apps with Conditional Access App Control"
    }
  },
  {
    "id": "xdr-033",
    "topic": "Multi-tenant management in Microsoft Defender XDR",
    "scenario": "Contoso is a Managed Security Service Provider (MSSP) managing security for 15 client tenants. The SOC team needs to monitor incidents, run Advanced Hunting queries, and manage alerts across all 15 tenants from a single pane of glass.",
    "question": "Which feature enables multi-tenant management in Microsoft Defender XDR?",
    "options": [
      "Create a single shared Microsoft Entra ID tenant and merge all 15 tenants into it",
      "Use multi-tenant management in Microsoft Defender XDR, which allows MSSP analysts to view and manage incidents, alerts, and Advanced Hunting data across multiple tenants through a unified portal",
      "Set up 15 separate browser tabs, one for each tenant's Defender XDR portal",
      "Configure Azure Lighthouse for delegated access and use Azure Security Center instead of Defender XDR"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Multi-Tenant Management for MSSPs",
      "analysis": [
        "Option A is INCORRECT: Merging tenants is not feasible for an MSSP — each client must maintain their own independent tenant for data sovereignty and compliance. Tenant merging would violate data isolation requirements.",
        "Option B is CORRECT: Microsoft Defender XDR supports multi-tenant management where MSSP analysts can access multiple client tenants through GDAP (Granular Delegated Admin Privileges). The multi-tenant view provides a unified incident queue, cross-tenant Advanced Hunting, and centralized alert management without switching between tenants.",
        "Option C is INCORRECT: Managing 15 separate browser sessions is operationally inefficient, doesn't allow cross-tenant correlation, and doesn't scale. The multi-tenant management feature was specifically built to solve this problem.",
        "Option D is INCORRECT: Azure Lighthouse provides delegated resource management for Azure resources, not Microsoft 365 security. Defender for Cloud (not Security Center, which was renamed) covers Azure workloads, but Defender XDR covers Microsoft 365 workloads (email, endpoint, identity, cloud apps)."
      ],
      "codeSnippet": "// Cross-tenant Advanced Hunting is available\\n// in the multi-tenant view. Queries run against\\n// all selected tenants simultaneously.\\n// Example: Find high-severity incidents across tenants\\nSecurityIncident\\n| where Severity == \\\"High\\\"\\n| where Status == \\\"Active\\\"\\n| project TenantId, IncidentNumber, Title\\n| order by TimeGenerated desc",
      "socTip": "When onboarding MSSP clients, use GDAP with time-limited, least-privilege roles instead of DAP (Delegated Admin Privileges). GDAP allows scoping to specific security roles without granting Global Admin access to client tenants.",
      "docRef": "Microsoft Learn: Multi-tenant management in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-034",
    "topic": "Advanced Hunting — DeviceRegistryEvents table",
    "scenario": "Fabrikam's SOC detects that a suspicious script is modifying Windows registry keys associated with persistence mechanisms (Run/RunOnce keys). The analyst needs to identify all registry modifications that establish persistence across the organization.",
    "question": "Which KQL query identifies registry-based persistence modifications?",
    "options": [
      "DeviceRegistryEvents | where Timestamp > ago(7d) | where ActionType == 'RegistryValueSet' | where RegistryKey has_any ('Run', 'RunOnce', 'CurrentVersion\\\\Run') | where InitiatingProcessFileName !in~ ('explorer.exe', 'msiexec.exe', 'setup.exe') | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName",
      "DeviceProcessEvents | where ProcessCommandLine contains 'reg add'",
      "DeviceEvents | where ActionType == 'RegistryModification'",
      "SecurityAlert | where Category == 'Persistence'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Registry Persistence Detection via Advanced Hunting",
      "analysis": [
        "Option A is CORRECT: DeviceRegistryEvents with ActionType 'RegistryValueSet' captures all registry write operations. Filtering for Run/RunOnce keys targets the most common persistence mechanisms. Excluding known legitimate processes (explorer.exe for user logins, msiexec.exe for installations) reduces false positives while catching suspicious persistence attempts.",
        "Option B is INCORRECT: Searching DeviceProcessEvents for 'reg add' commands only catches persistence set via the reg.exe command-line tool. Many malware variants modify the registry directly through Windows APIs without using reg.exe, which would be missed by this query.",
        "Option C is INCORRECT: DeviceEvents does not have a 'RegistryModification' ActionType. Registry-specific events are tracked in the dedicated DeviceRegistryEvents table with specific action types like 'RegistryValueSet', 'RegistryKeyCreated', and 'RegistryValueDeleted'.",
        "Option D is INCORRECT: SecurityAlert shows alerts already generated by detection engines. Proactive hunting in DeviceRegistryEvents can find persistence that hasn't yet triggered an alert, catching stealthier techniques that evade built-in detections."
      ],
      "codeSnippet": "// KQL: Comprehensive persistence detection\\nDeviceRegistryEvents\\n| where Timestamp > ago(7d)\\n| where ActionType == \\\"RegistryValueSet\\\"\\n| where RegistryKey has_any (\\n    \\\"CurrentVersion\\\\\\\\Run\\\",\\n    \\\"CurrentVersion\\\\\\\\RunOnce\\\",\\n    \\\"Winlogon\\\\\\\\Shell\\\",\\n    \\\"Winlogon\\\\\\\\Userinit\\\",\\n    \\\"CurrentVersion\\\\\\\\Explorer\\\\\\\\Shell Folders\\\")\\n| project Timestamp, DeviceName, RegistryKey,\\n    RegistryValueName, RegistryValueData,\\n    InitiatingProcessFileName,\\n    InitiatingProcessCommandLine",
      "socTip": "Monitor Run keys for entries pointing to unusual locations: AppData, Temp, Public folders, or direct URLs. Legitimate software typically installs to Program Files and registers persistence through MSI, not direct registry writes from scripts.",
      "docRef": "Microsoft Learn: DeviceRegistryEvents table"
    }
  },
  {
    "id": "xdr-035",
    "topic": "Evidence and response tab in incidents",
    "scenario": "A Northwind Traders analyst is reviewing a multi-alert incident in Microsoft Defender XDR. The incident involves a compromised user account, three affected devices, two malicious files, and suspicious network connections. The analyst needs to take targeted response actions against specific entities.",
    "question": "Where can the analyst find all affected entities and take response actions within the incident?",
    "options": [
      "The Alert queue page, which lists all alerts separately",
      "The Evidence and Response tab in the incident details, which consolidates all entities (users, devices, files, IPs, mailboxes) with available response actions for each entity type",
      "The Microsoft 365 admin center user management page",
      "The Azure portal resource health dashboard"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Evidence and Response Tab in Incident Details",
      "analysis": [
        "Option A is INCORRECT: The Alert queue shows individual alerts but doesn't consolidate all entities from a multi-alert incident. Each alert only shows its own evidence. The Evidence and Response tab aggregates entities across ALL alerts in the incident.",
        "Option B is CORRECT: The Evidence and Response tab in incident details provides a unified view of all impacted entities across all correlated alerts. It categorizes entities by type (users, devices, files, IPs, mailboxes) and provides context-specific response actions: disable user, isolate device, quarantine file, block IP/URL.",
        "Option C is INCORRECT: The M365 admin center manages user licenses and basic account settings. Security response actions (disable account due to compromise, force password reset, revoke sessions) should be taken through the Defender XDR incident workflow, not the admin center.",
        "Option D is INCORRECT: Azure portal resource health monitors Azure service health and resource availability. It does not provide security investigation or response capabilities for Microsoft 365 workloads."
      ],
      "codeSnippet": "// KQL: Get all evidence entities from an incident\\nAlertEvidence\\n| where Timestamp > ago(7d)\\n| where AlertId in (\\n    (AlertInfo | where AttackTechniques has \\\"T1566\\\"\\n    | project AlertId)\\n)\\n| summarize Entities=make_set(EntityType),\\n    Devices=make_set(DeviceName),\\n    Users=make_set(AccountUpn)\\n    by AlertId",
      "socTip": "In the Evidence and Response tab, check the 'Verdict' column — Defender XDR marks entities as 'Malicious', 'Suspicious', or 'Clean'. Prioritize response actions on entities marked Malicious first.",
      "docRef": "Microsoft Learn: Manage incidents in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-036",
    "topic": "MITRE ATT&CK mapping in incidents",
    "scenario": "Adatum's SOC manager requires all incident reports to include MITRE ATT&CK technique mapping for compliance with their threat intelligence framework. The analyst investigating a multi-stage attack needs to identify which ATT&CK techniques were observed.",
    "question": "How does Microsoft Defender XDR provide MITRE ATT&CK technique information?",
    "options": [
      "Analysts must manually research and tag each incident with the appropriate MITRE ATT&CK techniques",
      "Defender XDR automatically maps alerts to MITRE ATT&CK techniques and tactics, displaying them in the incident details and alert descriptions",
      "MITRE ATT&CK mapping is only available through a third-party integration plugin",
      "ATT&CK mapping requires exporting data to the MITRE ATT&CK Navigator tool"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Automatic MITRE ATT&CK Mapping in Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Manual tagging would be time-consuming and error-prone. Defender XDR's detection rules are pre-mapped to ATT&CK techniques by Microsoft's security research team, so mapping is automatic when alerts fire.",
        "Option B is CORRECT: Microsoft Defender XDR automatically maps each alert to one or more MITRE ATT&CK techniques and tactics. This mapping appears in the alert description, the incident summary, and can be queried in Advanced Hunting (AttackTechniques column in AlertInfo). The incident overview shows the full attack chain mapped to ATT&CK stages.",
        "Option C is INCORRECT: ATT&CK mapping is a built-in native feature of Microsoft Defender XDR. No third-party plugin is required. Microsoft maintains the mapping as part of their detection rule development process.",
        "Option D is INCORRECT: While you CAN export data to ATT&CK Navigator for visualization, the mapping data is natively available within Defender XDR. The Navigator is an optional enhancement, not a requirement."
      ],
      "codeSnippet": "// KQL: Analyze ATT&CK techniques in your environment\\nAlertInfo\\n| where Timestamp > ago(30d)\\n| where isnotempty(AttackTechniques)\\n| mv-expand AttackTechniques to typeof(string)\\n| summarize AlertCount=count(),\\n    Incidents=dcount(AlertId)\\n    by AttackTechniques\\n| order by AlertCount desc\\n| take 20",
      "socTip": "Use ATT&CK technique frequency analysis to identify gaps in your security coverage. If you see many T1566 (Phishing) alerts but no T1059 (Command and Scripting) alerts, your endpoint detection may need tuning.",
      "docRef": "Microsoft Learn: MITRE ATT&CK in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-037",
    "topic": "Defender for Identity — honeytoken accounts",
    "scenario": "Litware's Active Directory team creates several honeytoken (decoy) accounts designed to detect reconnaissance activity. These accounts have no legitimate use — any authentication attempt against them indicates an attacker enumerating the directory. The security team wants Microsoft Defender for Identity to alert on any activity involving these accounts.",
    "question": "How should the team configure Defender for Identity to monitor honeytoken accounts?",
    "options": [
      "Create custom Advanced Hunting queries that check for logon events against the honeytoken accounts daily",
      "Tag the accounts as honeytoken entities in the Microsoft Defender for Identity portal settings, which automatically generates high-severity alerts when any activity (authentication, LDAP queries, enumeration) involves these accounts",
      "Disable the honeytoken accounts in Active Directory and monitor the account lockout logs",
      "Configure a Group Policy Object (GPO) to audit logon failures on the honeytoken accounts"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Honeytoken Accounts in Microsoft Defender for Identity",
      "analysis": [
        "Option A is INCORRECT: Manual hunting queries only run on schedule and rely on an analyst remembering to check. Honeytoken detection should be real-time and automatic — any activity against a honeytoken is immediately suspicious and warrants an instant alert.",
        "Option B is CORRECT: Defender for Identity has a built-in honeytoken feature. You tag specific accounts in the Defender for Identity entity tags settings. When any authentication, LDAP query, or enumeration activity touches a honeytoken account, Defender for Identity immediately generates a high-confidence alert. This is one of the highest-fidelity detections available because legitimate users never interact with honeytoken accounts.",
        "Option C is INCORRECT: Disabling the accounts prevents authentication-based detection. A better approach is to leave the accounts enabled with complex passwords — this allows Defender for Identity to detect both authentication attempts and reconnaissance queries (LDAP enumeration) against the accounts.",
        "Option D is INCORRECT: GPO audit policies generate Windows Event Viewer entries but don't trigger real-time alerts in the security operations workflow. Defender for Identity honeytoken tagging integrates directly with the incident queue and can trigger automated investigation."
      ],
      "codeSnippet": "// KQL: Monitor all honeytoken activity\\nIdentityLogonEvents\\n| where Timestamp > ago(30d)\\n| where AccountUpn in (\\\"honeytrap1@litware.com\\\",\\n    \\\"svc_trap@litware.com\\\")\\n| project Timestamp, AccountUpn,\\n    LogonType, Application,\\n    IPAddress, DeviceName\\n| order by Timestamp desc",
      "socTip": "Create honeytoken accounts with names that look like high-value targets: 'svc_backup', 'admin_sql', 'svc_azure'. Attackers performing enumeration are attracted to service accounts and admin accounts, making these effective lures.",
      "docRef": "Microsoft Learn: Configure honeytoken accounts in Microsoft Defender for Identity"
    }
  },
  {
    "id": "xdr-038",
    "topic": "Advanced Hunting — cross-table joins",
    "scenario": "A Contoso SOC analyst needs to correlate email delivery with subsequent endpoint activity. A phishing email was delivered containing a URL — the analyst wants to find which recipients clicked the URL AND what processes were launched on their devices within 30 minutes of the click.",
    "question": "Which Advanced Hunting approach correctly correlates email clicks with endpoint process activity?",
    "options": [
      "Query EmailEvents and DeviceProcessEvents separately, then manually compare the results in Excel",
      "Use a KQL join between UrlClickEvents and DeviceProcessEvents, joining on the user's account name and using a time window to correlate clicks with subsequent process execution within 30 minutes",
      "Query only DeviceProcessEvents and search for browser process names like 'chrome.exe'",
      "Use the union operator to combine EmailEvents and DeviceProcessEvents into a single table"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Cross-Table KQL Joins for Email-to-Endpoint Correlation",
      "analysis": [
        "Option A is INCORRECT: Manual Excel comparison loses the analytical power of KQL, cannot enforce time-window correlation, and doesn't scale. KQL join operations perform this correlation automatically at query time.",
        "Option B is CORRECT: Joining UrlClickEvents (which records when users click URLs in emails) with DeviceProcessEvents on the user account, with a time-based filter (process timestamp within 30 minutes after click), reveals the exact causal chain from phishing click to endpoint compromise. This is a powerful cross-domain correlation technique.",
        "Option C is INCORRECT: Searching for browser processes (chrome.exe, msedge.exe) on all devices would return millions of results without any connection to the specific phishing campaign. The correlation between the email click and the endpoint activity is what makes this investigation meaningful.",
        "Option D is INCORRECT: The union operator appends rows from different tables into one result set but doesn't correlate related events. You need a join to match rows based on shared entities (user account) and time proximity."
      ],
      "codeSnippet": "// KQL: Email click to endpoint correlation\\nUrlClickEvents\\n| where Timestamp > ago(7d)\\n| where ActionType == \\\"ClickAllowed\\\"\\n| project ClickTime=Timestamp, AccountUpn, Url\\n| join kind=inner (\\n    DeviceProcessEvents\\n    | where Timestamp > ago(7d)\\n    | project ProcessTime=Timestamp,\\n        AccountName, DeviceName,\\n        FileName, ProcessCommandLine\\n) on $left.AccountUpn == $right.AccountName\\n| where ProcessTime between\\n    (ClickTime .. ClickTime + 30m)\\n| project ClickTime, ProcessTime, AccountUpn,\\n    Url, DeviceName, FileName, ProcessCommandLine",
      "socTip": "When correlating email-to-endpoint, focus on processes launched within 5-30 minutes of the click. Key indicators: PowerShell or cmd.exe spawning from browser processes, DLL side-loading, or executable downloads to Temp/Downloads folders.",
      "docRef": "Microsoft Learn: Advanced hunting query best practices"
    }
  },
  {
    "id": "xdr-039",
    "topic": "Defender for Cloud Apps — anomaly detection policies",
    "scenario": "Fabrikam's Defender for Cloud Apps has detected an 'Impossible travel' anomaly for a user account. The user logged into Microsoft 365 from New York at 10:00 AM and from Tokyo at 10:15 AM — a physical impossibility. The SOC analyst needs to investigate whether this is a legitimate false positive (VPN) or a genuine compromise.",
    "question": "What additional context should the analyst check to determine if this is a true compromise?",
    "options": [
      "Check only the user's email inbox for suspicious forwarding rules",
      "Review the sign-in details for both locations: check the IP addresses against known VPN/proxy services, verify the user agent strings for consistency, check for MFA satisfaction on both sign-ins, and correlate with the user's known travel schedule",
      "Immediately disable the user's account without further investigation",
      "Ignore the alert because impossible travel detections are always false positives from VPNs"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Impossible Travel Investigation Workflow",
      "analysis": [
        "Option A is INCORRECT: While checking for suspicious email forwarding rules is part of a compromised account investigation, it should not be the ONLY check. The analyst needs to first determine whether the impossible travel is a true positive or a VPN-related false positive.",
        "Option B is CORRECT: A thorough investigation checks: (1) IP reputation — corporate VPNs and known proxy IPs cause legitimate impossible travel, (2) User agent consistency — if both sessions use the same browser version, it may be VPN traffic, (3) MFA status — if MFA was satisfied on both sign-ins, the attacker may have an MFA-approved session, (4) User confirmation — check if the user is actually traveling or using a VPN.",
        "Option C is INCORRECT: Immediately disabling the account without investigation would disrupt a legitimate user if this is a VPN-caused false positive. Investigation should determine the validity before taking disruptive response actions.",
        "Option D is INCORRECT: While VPNs do cause many impossible travel false positives, they are NOT always false positives. Actual account compromises also trigger impossible travel alerts. Each alert requires investigation to determine its validity."
      ],
      "codeSnippet": "// KQL: Investigate impossible travel sign-ins\\nAADSignInEventsBeta\\n| where Timestamp > ago(24h)\\n| where AccountUpn == \\\"user@fabrikam.com\\\"\\n| project Timestamp, IPAddress, Country,\\n    City, Application, UserAgent,\\n    AuthenticationRequirement,\\n    ConditionalAccessStatus\\n| order by Timestamp asc",
      "socTip": "Create a 'Known VPN IPs' watchlist in your SIEM. When investigating impossible travel, first check if either IP is in the VPN list. If so, it's likely a false positive. Add IP ranges for corporate VPNs, cloud infrastructure, and developer proxies.",
      "docRef": "Microsoft Learn: Anomaly detection policies in Defender for Cloud Apps"
    }
  },
  {
    "id": "xdr-040",
    "topic": "Quarantine management",
    "scenario": "A Northwind Traders analyst discovers that Defender for Office 365 quarantined 200 emails from a legitimate bulk sender that employees need for business operations. The emails were quarantined due to a high confidence phishing verdict. The analyst needs to release the legitimate emails and prevent future quarantine.",
    "question": "What is the MOST efficient way to release all 200 emails and prevent recurrence?",
    "options": [
      "Release each email individually from the quarantine page, one at a time",
      "Use bulk release in the quarantine management page to release all 200 emails simultaneously, then add the sender to the Tenant Allow/Block List as an allow entry to prevent future quarantine",
      "Ask the sender to resend all 200 emails after you whitelist them",
      "Disable the anti-phishing policy entirely to prevent any emails from being quarantined"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Quarantine Bulk Management and Tenant Allow/Block List",
      "analysis": [
        "Option A is INCORRECT: Releasing 200 emails individually is extremely time-consuming and inefficient. The quarantine management page supports bulk selection and release operations specifically for scenarios like this.",
        "Option B is CORRECT: Quarantine management supports bulk operations — select all 200 emails using filters (by sender, subject, or date range) and release them in one action. Adding the sender to the Tenant Allow/Block List with an 'Allow' entry prevents future quarantine. Submit the emails as false positives via the Submissions portal so Microsoft can update their models.",
        "Option C is INCORRECT: Asking the sender to resend 200 emails is impractical and doesn't solve the root cause. The same emails would likely be quarantined again without an allow list entry.",
        "Option D is INCORRECT: Disabling the anti-phishing policy would expose the entire organization to phishing attacks. The correct approach is to create a specific allow entry for the legitimate sender while keeping protection active for all other emails."
      ],
      "codeSnippet": "// PowerShell: Bulk release quarantined emails\\n// Find quarantined emails from the sender\\n$quarantined = Get-QuarantineMessage \\n    -SenderAddress \\\"newsletter@legitsender.com\\\" \\n    -StartDate (Get-Date).AddDays(-7)\\n\\n// Release all matching emails\\n$quarantined | Release-QuarantineMessage \\n    -ReleaseToAll \\n    -AllowSender",
      "socTip": "When bulk releasing quarantined emails, always use the '-AllowSender' flag (in PowerShell) or check 'Allow sender' (in the portal) to simultaneously create a Tenant Allow/Block List entry. This prevents the same emails from being re-quarantined.",
      "docRef": "Microsoft Learn: Manage quarantined messages and files"
    }
  },
  {
    "id": "xdr-041",
    "topic": "Advanced Hunting — schema reference and table relationships",
    "scenario": "A new SOC analyst at Adatum is learning Advanced Hunting in Microsoft Defender XDR. The analyst is confused about which tables to query for different types of security data and how tables relate to each other through common columns.",
    "question": "Which statement correctly describes the Advanced Hunting schema?",
    "options": [
      "All security data is stored in a single unified table called 'SecurityEvents'",
      "The schema consists of specialized tables organized by data domain — DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents for endpoint data; EmailEvents, EmailAttachmentInfo, EmailUrlInfo for email data; IdentityLogonEvents, IdentityQueryEvents for identity data; and CloudAppEvents for SaaS app data. Tables are related through common columns like DeviceId, AccountUpn, and NetworkMessageId",
      "Advanced Hunting only supports querying one table at a time and does not allow joins",
      "The schema is identical to Microsoft Sentinel's table schema"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Advanced Hunting Schema Architecture",
      "analysis": [
        "Option A is INCORRECT: There is no single 'SecurityEvents' table. The schema is deliberately normalized into specialized tables to optimize query performance and organize data logically by security domain (endpoint, email, identity, cloud apps).",
        "Option B is CORRECT: The Advanced Hunting schema follows a domain-organized structure with common linking columns. Endpoint tables use DeviceId and DeviceName. Email tables use NetworkMessageId. Identity tables use AccountUpn. This design enables cross-domain joins — you can correlate an email (EmailEvents) with a device (DeviceProcessEvents) through the user (AccountUpn).",
        "Option C is INCORRECT: Advanced Hunting fully supports KQL join, union, and lookup operators. Cross-table queries are fundamental to XDR investigation — correlating email delivery with endpoint execution with identity compromise.",
        "Option D is INCORRECT: While some table names overlap (SecurityIncident, SecurityAlert), the schemas are different. Defender XDR Advanced Hunting tables (DeviceProcessEvents, EmailEvents) have different columns and data formats than the corresponding Sentinel tables."
      ],
      "codeSnippet": "// Key linking columns across tables:\\n// DeviceId → links all Device* tables\\n// NetworkMessageId → links all Email* tables\\n// AccountUpn/AccountName → links identity data\\n//\\n// Example: Schema exploration query\\nDeviceProcessEvents\\n| getschema\\n| project ColumnName, DataType\\n| order by ColumnName asc",
      "socTip": "Bookmark the Advanced Hunting schema reference page. When building cross-table queries, always check the common columns first — joining on the wrong column produces incorrect or empty results.",
      "docRef": "Microsoft Learn: Understand the Advanced Hunting schema"
    }
  },
  {
    "id": "xdr-042",
    "topic": "Alert classification and determination",
    "scenario": "After investigating a multi-alert incident in Microsoft Defender XDR, a Contoso analyst determines that the alerts were triggered by a legitimate penetration testing engagement authorized by the CISO. The analyst needs to close the incident with the correct classification.",
    "question": "What classification should the analyst assign to this incident?",
    "options": [
      "True Positive — the alerts correctly detected suspicious activity",
      "True Positive — Informational, expected activity: the alerts are correct detections of real activity, but the activity is authorized and expected (penetration test)",
      "False Positive — the detection logic is faulty and should be disabled",
      "Not set — leave the classification empty and close the incident"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Alert Classification in Microsoft Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Classifying as 'True Positive' without the 'Informational, expected activity' determination implies the activity was genuinely malicious and required remediation. This would skew SOC metrics and make it appear that a real attack occurred.",
        "Option B is CORRECT: 'True Positive — Informational, expected activity' is the correct classification for authorized activities like penetration tests, red team exercises, and authorized vulnerability scans. It acknowledges that the detections worked correctly (not false positives) while documenting that the activity was sanctioned. This maintains accurate SOC metrics.",
        "Option C is INCORRECT: The detections are NOT false positives — they correctly identified suspicious behavior. A false positive classification would imply the detection logic is wrong and might lead to tuning or suppression, which would weaken detection of real penetration attacks.",
        "Option D is INCORRECT: Leaving classification empty provides no value for SOC metrics, trend analysis, or detection tuning. Microsoft recommends always classifying resolved incidents to maintain data quality for reporting."
      ],
      "codeSnippet": "// KQL: Alert classification distribution analysis\\nSecurityIncident\\n| where TimeGenerated > ago(90d)\\n| where Status == \\\"Resolved\\\"\\n| summarize IncidentCount=count() by Classification\\n| render piechart",
      "socTip": "Before authorized pen tests begin, create alert suppression rules for the test IP ranges and timeframe. After the test, remove the suppression rules. This reduces noise during the test while maintaining detection capability afterward.",
      "docRef": "Microsoft Learn: Classify incidents in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-043",
    "topic": "Email security — anti-spam policies",
    "scenario": "Litware Inc. employees report that legitimate marketing emails from business partners are being sent to their Junk Email folder. The SOC team reviews the anti-spam policy and finds that the outbound spam filter confidence level (SCL) is set to the most aggressive setting.",
    "question": "What is the BEST approach to resolve this without compromising security?",
    "options": [
      "Disable the anti-spam policy entirely for all users",
      "Create a specific anti-spam policy for the marketing team with a less aggressive SCL threshold, and add trusted partner domains to the allowed sender list within that policy",
      "Set the global anti-spam SCL threshold to the lowest possible value for all users",
      "Configure the partner's email server to add 'X-MS-Exchange-Organization-SCL: -1' to outbound email headers"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Anti-Spam Policy Customization",
      "analysis": [
        "Option A is INCORRECT: Disabling anti-spam protection exposes all users to spam and phishing. Never disable security controls globally to fix a targeted issue.",
        "Option B is CORRECT: Creating a targeted anti-spam policy for the marketing team allows adjusting the SCL threshold for users who need to receive partner marketing emails without affecting the security posture of other departments. Adding trusted partner domains to the allowed sender list ensures their emails bypass spam filtering.",
        "Option C is INCORRECT: Lowering the global SCL threshold for all users increases spam risk organization-wide. The adjustment should be targeted to the affected users only, following the principle of least privilege.",
        "Option D is INCORRECT: You cannot control the outbound email headers of external partners' mail servers. Even if you could, this would bypass your organization's security scanning, which is a significant risk if the partner's email infrastructure is ever compromised."
      ],
      "codeSnippet": "// PowerShell: Create targeted anti-spam policy\\nNew-HostedContentFilterPolicy \\n    -Name \\\"Marketing-Partners\\\" \\n    -SpamAction MoveToJmf \\n    -HighConfidenceSpamAction Quarantine \\n    -BulkThreshold 7\\n\\nNew-HostedContentFilterRule \\n    -Name \\\"Marketing-Partners-Rule\\\" \\n    -HostedContentFilterPolicy \\\"Marketing-Partners\\\" \\n    -SentToMemberOf \\\"Marketing-Team\\\"",
      "socTip": "Review anti-spam policy hit rates monthly. If false positive rates exceed 2%, your SCL threshold may be too aggressive. Use the Email Entity page to check why specific emails were marked as spam.",
      "docRef": "Microsoft Learn: Configure anti-spam policies"
    }
  },
  {
    "id": "xdr-044",
    "topic": "Investigation priority score",
    "scenario": "Fabrikam's SOC has 50 active incidents in the queue. The SOC manager needs to determine which incidents pose the highest risk and should be investigated first. Each incident has an investigation priority score assigned by Microsoft Defender XDR.",
    "question": "What factors contribute to the investigation priority score?",
    "options": [
      "Only the number of alerts in the incident",
      "A combination of alert severity, the number of affected entities (users, devices, mailboxes), correlation with known threat intelligence, and whether automated investigation has identified confirmed threats",
      "The alphabetical order of the incident title",
      "The time zone of the SOC analyst assigned to the incident"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Investigation Priority Scoring in Microsoft Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Alert count alone is insufficient for prioritization. An incident with 1 high-severity alert targeting a domain admin account is far more critical than an incident with 10 informational alerts on a test machine.",
        "Option B is CORRECT: The investigation priority score considers multiple signals: individual alert severities, the sensitivity and criticality of affected entities (e.g., executives, domain controllers, sensitive data stores), correlation with known threat actor TTPs from Microsoft Threat Intelligence, and findings from automated investigations. This multi-factor approach provides a nuanced risk assessment.",
        "Option C is INCORRECT: Incident titles have no bearing on priority scoring. The title is a descriptive label derived from the most prominent alert, not a prioritization factor.",
        "Option D is INCORRECT: SOC analyst time zones are irrelevant to threat severity. Investigation priority is based entirely on the threat characteristics, not operational factors like analyst location."
      ],
      "codeSnippet": "// KQL: Prioritize incidents by score and impact\\nSecurityIncident\\n| where Status == \\\"Active\\\"\\n| extend EntityCount = array_length(\\n    todynamic(AdditionalData).alertCount)\\n| project IncidentNumber, Title, Severity,\\n    Classification, Owner, EntityCount\\n| order by Severity desc, EntityCount desc",
      "socTip": "Use the incident queue sorting by 'Investigation priority' column rather than severity alone. A medium-severity incident with a high investigation priority score may be more urgent than a high-severity incident with a low score.",
      "docRef": "Microsoft Learn: Incident prioritization in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-045",
    "topic": "Advanced Hunting — DeviceLogonEvents table",
    "scenario": "Northwind Traders suspects that an attacker has obtained valid credentials and is using them for remote access. The SOC analyst needs to identify unusual remote logon patterns — specifically, accounts logging into devices they have never accessed before.",
    "question": "Which KQL query identifies first-time remote logon relationships?",
    "options": [
      "DeviceLogonEvents | where Timestamp > ago(24h) | where LogonType == 'RemoteInteractive' | where ActionType == 'LogonSuccess' | join kind=leftanti (DeviceLogonEvents | where Timestamp between(ago(90d) .. ago(24h)) | where LogonType == 'RemoteInteractive' | where ActionType == 'LogonSuccess' | distinct AccountName, DeviceName) on AccountName, DeviceName | project Timestamp, DeviceName, AccountName, RemoteIP",
      "DeviceLogonEvents | where LogonType == 'Interactive' | summarize count() by AccountName",
      "SigninLogs | where ResultType == 0 | where AppDisplayName == 'Remote Desktop'",
      "DeviceNetworkEvents | where RemotePort == 3389"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "First-Time Logon Detection Using Anti-Join Pattern",
      "analysis": [
        "Option A is CORRECT: This query uses the leftanti join pattern — it takes remote interactive logons from the last 24 hours and removes any account-device pairs that were seen in the previous 90 days. The remaining results are genuinely first-time remote logons, which are highly suspicious during an active investigation.",
        "Option B is INCORRECT: Counting all interactive logons by account shows total logon volume but doesn't identify first-time relationships. It doesn't compare recent activity against historical baselines.",
        "Option C is INCORRECT: SigninLogs tracks Azure AD cloud authentication, not on-premises Remote Desktop Protocol (RDP) sessions. RDP logons to domain-joined devices are captured by DeviceLogonEvents through the Defender for Endpoint sensor.",
        "Option D is INCORRECT: DeviceNetworkEvents showing port 3389 connections indicates RDP network traffic but doesn't provide authentication context (which user, success/failure, logon type). DeviceLogonEvents provides the complete authentication event with user and device context."
      ],
      "codeSnippet": "// KQL: First-time RDP logon detection\\nlet lookback = 90d;\\nlet detection = 1d;\\nlet historical = DeviceLogonEvents\\n    | where Timestamp between(ago(lookback) .. ago(detection))\\n    | where LogonType == \\\"RemoteInteractive\\\"\\n    | where ActionType == \\\"LogonSuccess\\\"\\n    | distinct AccountName, DeviceName;\\nDeviceLogonEvents\\n| where Timestamp > ago(detection)\\n| where LogonType == \\\"RemoteInteractive\\\"\\n| where ActionType == \\\"LogonSuccess\\\"\\n| join kind=leftanti historical\\n    on AccountName, DeviceName\\n| project Timestamp, DeviceName, AccountName,\\n    RemoteIP, RemoteDeviceName",
      "socTip": "First-time logon detection is one of the most powerful hunting techniques. Establish a 90-day baseline and alert on any new account-device pair. Legitimate new relationships (new employees, device refreshes) can be verified quickly.",
      "docRef": "Microsoft Learn: DeviceLogonEvents table"
    }
  },
  {
    "id": "xdr-046",
    "topic": "Microsoft Defender for Identity — security assessments",
    "scenario": "Adatum Corporation's Active Directory infrastructure has several legacy configurations that create security vulnerabilities. The security team wants to use Microsoft Defender for Identity to identify and prioritize these AD security risks.",
    "question": "Which Defender for Identity feature provides proactive AD security configuration recommendations?",
    "options": [
      "The Advanced Hunting queries against IdentityLogonEvents",
      "Identity Security Posture Assessments, which continuously evaluate AD configurations and provide prioritized recommendations to fix security weaknesses like unsecured Kerberos delegation, dormant accounts, and cleartext password storage",
      "The Microsoft Sentinel UEBA (User and Entity Behavior Analytics) module",
      "The Active Directory Users and Computers MMC snap-in"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Identity Security Posture Assessments in Defender for Identity",
      "analysis": [
        "Option A is INCORRECT: Advanced Hunting queries against IdentityLogonEvents detect active threats and anomalies. They don't assess passive AD configuration weaknesses like unsecured delegation or dormant accounts.",
        "Option B is CORRECT: Identity Security Posture Assessments in Defender for Identity automatically evaluate AD configurations against security best practices. Assessments include: entities exposing credentials in cleartext, dormant entities in sensitive groups, unsecured Kerberos delegation, weak cipher usage, unmonitored domain controllers, and more. Each assessment includes remediation steps.",
        "Option C is INCORRECT: Sentinel UEBA provides behavioral analytics for anomaly detection on user and entity activities. It doesn't assess AD infrastructure configuration. UEBA detects unusual behavior patterns, not static configuration weaknesses.",
        "Option D is INCORRECT: Active Directory Users and Computers is a management tool for viewing and modifying AD objects. It doesn't provide security assessment functionality or prioritized remediation recommendations."
      ],
      "codeSnippet": "// These assessments are accessed in the portal:\\n// Microsoft Defender XDR > Identities >\\n//   Security posture > Assessments\\n//\\n// Key assessments to monitor:\\n// - Unsecured SID History attributes\\n// - Unresolved weak cipher usage\\n// - Dormant entities in sensitive groups\\n// - Clear text password exposure\\n// - Unsecured Kerberos delegation",
      "socTip": "Prioritize assessments related to Kerberos delegation and cleartext passwords. These are the most commonly exploited AD weaknesses. Fix unconstrained delegation first — it allows any compromised service to impersonate any user in the domain.",
      "docRef": "Microsoft Learn: Microsoft Defender for Identity security posture assessments"
    }
  },
  {
    "id": "xdr-047",
    "topic": "Data loss prevention in Microsoft Teams via Defender for Cloud Apps",
    "scenario": "Litware Inc. needs to prevent employees from sharing files containing credit card numbers through Microsoft Teams chats and channels. The security team wants to implement real-time DLP controls that block the message before it reaches other participants.",
    "question": "Which approach implements real-time DLP in Microsoft Teams?",
    "options": [
      "Configure a Microsoft Purview DLP policy with Microsoft Teams as a location, which inspects messages in near-real-time and blocks messages containing sensitive data patterns like credit card numbers",
      "Create a Teams messaging policy in the Teams admin center to disable file sharing",
      "Monitor Teams activity logs and manually delete messages containing credit card numbers after they are sent",
      "Block all external sharing in SharePoint since Teams uses SharePoint for file storage"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Policy for Microsoft Teams",
      "analysis": [
        "Option A is CORRECT: Microsoft Purview DLP policies with Teams as a designated location inspect chat messages and channel posts in near-real-time. When a message matches a sensitive information type (like credit card patterns), the policy can block the message, show a policy tip to the user, or allow with override. This is the native, Microsoft-supported approach.",
        "Option B is INCORRECT: Disabling file sharing in Teams messaging policies is overly restrictive and doesn't address the core requirement — detecting credit card numbers in message text. Users could still type credit card numbers in chat messages even if file sharing is disabled.",
        "Option C is INCORRECT: Post-hoc manual deletion means the sensitive data was already visible to other chat participants. Real-time DLP prevents the data from being shared in the first place, which is far more effective for data protection.",
        "Option D is INCORRECT: Blocking external sharing in SharePoint addresses file sharing with external users but doesn't prevent internal sharing of credit card numbers in Teams messages. The requirement is about content inspection, not sharing scope."
      ],
      "codeSnippet": "// DLP policy configuration (conceptual):\\n// Location: Microsoft Teams\\n// Condition: Content contains credit card number\\n// Sensitive info type: Credit Card Number\\n// Instance count: 1 or more\\n// Action: Block content\\n// User notification: Policy tip explaining why\\n//   the message was blocked\\n// Admin alert: High severity",
      "socTip": "When creating DLP policies for Teams, start in 'Test with policy tips' mode for 2 weeks before enforcing. This shows users policy tips without blocking, allowing you to identify false positives and educate users before enforcement begins.",
      "docRef": "Microsoft Learn: DLP for Microsoft Teams"
    }
  },
  {
    "id": "xdr-048",
    "topic": "Automated investigation — evidence analysis",
    "scenario": "After AIR completes an automated investigation in Microsoft Defender XDR, the investigation report shows that it analyzed 45 entities, executed 12 investigation steps, and reached a verdict for each entity (Malicious, Suspicious, Clean, or No threats found). The SOC analyst reviews the investigation.",
    "question": "What should the analyst do with the automated investigation results?",
    "options": [
      "Accept all automated verdicts without review since AIR is always 100% accurate",
      "Review the investigation summary, validate key evidence (especially entities marked Suspicious), approve pending remediation actions for confirmed threats, and reject actions for false positives",
      "Delete the investigation report and start a manual investigation from scratch",
      "Forward the investigation report to Microsoft support for external validation before taking any action"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Reviewing Automated Investigation Reports",
      "analysis": [
        "Option A is INCORRECT: No automated system is 100% accurate. AIR is a powerful tool that accelerates investigation, but analyst oversight is essential, especially for entities marked 'Suspicious' where the automated verdict may require human judgment to confirm or overturn.",
        "Option B is CORRECT: The proper workflow is to review the AIR investigation summary, focusing on: (1) Entities marked 'Malicious' — approve remediation, (2) Entities marked 'Suspicious' — manually investigate further before deciding, (3) Entities marked 'Clean' — no action needed but verify if they're part of the attack chain, (4) Approve/reject pending actions in the Action Center based on your review.",
        "Option C is INCORRECT: Discarding the automated investigation wastes the analysis AIR already performed. AIR has already correlated alerts, analyzed entities, and identified remediation actions. Use this as a starting point, not something to discard.",
        "Option D is INCORRECT: Microsoft support does not validate individual investigation reports. AIR investigations are designed for analyst review within the organization. Only escalate to Microsoft if you believe there's a product defect."
      ],
      "codeSnippet": "// KQL: Review automated investigation outcomes\\nAlertInfo\\n| where Timestamp > ago(7d)\\n| where DetectionSource == \\\"Automated investigation\\\"\\n| join AlertEvidence on AlertId\\n| summarize by AlertId, Title,\\n    EvidenceRole, EntityType\\n| order by AlertId desc",
      "socTip": "Set up a daily workflow to review the Action Center Pending tab. Automated investigations can produce pending actions at any time. The faster you approve legitimate remediation, the shorter the attacker's dwell time.",
      "docRef": "Microsoft Learn: View the details and results of an automated investigation"
    }
  },
  {
    "id": "xdr-049",
    "topic": "Advanced Hunting — externaldata operator",
    "scenario": "Contoso's threat intelligence team maintains a daily-updated CSV file of IOC IP addresses hosted on an internal Azure Blob Storage. The SOC analyst wants to use this external IOC list in Advanced Hunting queries without manually copying the IPs.",
    "question": "Which Advanced Hunting feature allows querying external data sources?",
    "options": [
      "The 'import' statement that loads CSV files from the local file system",
      "The 'externaldata' operator, which allows KQL queries to reference external data sources (Azure Blob Storage, web URLs) as virtual tables that can be joined with Defender XDR data",
      "The 'lookup' function that queries Azure SQL databases directly",
      "The 'invoke' plugin that calls external REST APIs from within KQL queries"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "External Data Integration in Advanced Hunting",
      "analysis": [
        "Option A is INCORRECT: Advanced Hunting runs in the cloud — it cannot access local file systems on analyst workstations. There is no 'import' statement for local files.",
        "Option B is CORRECT: The 'externaldata' operator allows KQL queries to reference external data in CSV, JSON, or other formats from Azure Blob Storage or public URLs. The external data is loaded as a virtual table at query time, enabling joins with Defender XDR tables for IOC matching, threat intelligence correlation, and asset context enrichment.",
        "Option C is INCORRECT: There is no 'lookup' function in Advanced Hunting KQL that directly queries Azure SQL databases. The 'lookup' operator in KQL references other KQL tables, not external SQL databases.",
        "Option D is INCORRECT: Advanced Hunting KQL does not support calling external REST APIs. The 'invoke' operator exists for certain KQL plugins (like ML models in Azure Data Explorer) but is not available in the Defender XDR Advanced Hunting environment."
      ],
      "codeSnippet": "// KQL: Join external IOC list with network events\\nlet IOC_IPs = externaldata(IP:string)\\n    [@\\\"https://storage.blob.core.windows.net/\\n    iocs/malicious_ips.csv\\\"]\\n    with (format=\\\"csv\\\", ignoreFirstRecord=true);\\nDeviceNetworkEvents\\n| where Timestamp > ago(7d)\\n| where RemoteIP in (IOC_IPs)\\n| project Timestamp, DeviceName, RemoteIP,\\n    RemotePort, InitiatingProcessFileName",
      "socTip": "Use externaldata with Azure Blob Storage for large IOC lists (thousands of entries). For small lists (< 50 entries), use the 'let' statement with a dynamic array. The externaldata approach scales better and stays current as the IOC file is updated.",
      "docRef": "Microsoft Learn: externaldata operator in Advanced Hunting"
    }
  },
  {
    "id": "xdr-050",
    "topic": "Defender for Cloud Apps — connected apps",
    "scenario": "Fabrikam wants to extend Microsoft Defender for Cloud Apps monitoring to third-party SaaS applications used by the organization, including Salesforce and ServiceNow. The security team needs visibility into user activities, file sharing, and suspicious behavior within these apps.",
    "question": "How should the team connect third-party apps to Defender for Cloud Apps?",
    "options": [
      "Install a Defender for Cloud Apps agent on the Salesforce and ServiceNow servers",
      "Use API connectors in Defender for Cloud Apps to connect to Salesforce and ServiceNow through their respective APIs, enabling activity monitoring, file scanning, and governance actions",
      "Configure SAML SSO between Azure AD and the third-party apps — this automatically enables Defender for Cloud Apps monitoring",
      "Deploy a network proxy appliance that intercepts all traffic to Salesforce and ServiceNow"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "API Connectors in Microsoft Defender for Cloud Apps",
      "analysis": [
        "Option A is INCORRECT: Defender for Cloud Apps is a cloud-native CASB — it does not require agents installed on SaaS application servers. SaaS applications like Salesforce and ServiceNow are cloud-hosted and don't expose their servers for agent installation.",
        "Option B is CORRECT: API connectors provide deep integration with third-party SaaS apps through their built-in APIs. Once connected, Defender for Cloud Apps can monitor user activities, scan files for sensitive content, detect anomalous behavior, and perform governance actions (suspend user, revoke access, quarantine file). Each SaaS app has a specific connector with documented setup steps.",
        "Option C is INCORRECT: SAML SSO provides single sign-on authentication but does not enable security monitoring. SSO handles who can access the app, while Defender for Cloud Apps monitors what they do after authentication.",
        "Option D is INCORRECT: While Defender for Cloud Apps can use reverse proxy for real-time session control (Conditional Access App Control), the primary deep monitoring integration is through API connectors, not network proxies. API connectors provide historical and near-real-time activity monitoring without traffic interception."
      ],
      "codeSnippet": "// After connecting via API, query activity in KQL:\\nCloudAppEvents\\n| where Timestamp > ago(7d)\\n| where Application in (\\\"Salesforce\\\",\\n    \\\"ServiceNow\\\")\\n| summarize EventCount=count(),\\n    UniqueUsers=dcount(AccountDisplayName)\\n    by Application, ActionType\\n| order by EventCount desc",
      "socTip": "When connecting a new SaaS app, enable all available activity types in the connector settings. Start with monitoring-only (no governance actions) for 2 weeks to establish baseline behavior before creating anomaly detection or activity policies.",
      "docRef": "Microsoft Learn: Connect apps in Defender for Cloud Apps"
    }
  },
  {
    "id": "xdr-051",
    "topic": "Advanced Hunting — union operator for cross-domain queries",
    "scenario": "An Adatum SOC analyst needs to build a comprehensive view of all activities related to a specific user who is suspected of being compromised. The analyst needs to see the user's email activity, endpoint processes, cloud app access, and identity events in a single timeline.",
    "question": "Which KQL approach creates a unified user activity timeline across all domains?",
    "options": [
      "Run four separate queries and manually combine the results in a spreadsheet",
      "Use the 'union' operator to combine rows from EmailEvents, DeviceProcessEvents, CloudAppEvents, and IdentityLogonEvents, filtering all tables by the user's account, then sort by timestamp to create a chronological timeline",
      "Query only DeviceProcessEvents since it captures all user activity",
      "Use the 'join' operator to join all four tables simultaneously on a single common column"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Union Operator for Cross-Domain User Activity Timeline",
      "analysis": [
        "Option A is INCORRECT: Manual spreadsheet combination loses the interactive KQL capabilities (further filtering, summarization, pivoting) and is time-consuming. The union operator automates this in a single query.",
        "Option B is CORRECT: The union operator appends rows from multiple tables into a single result set. By projecting common columns (Timestamp, AccountName, ActionType) from each table and filtering for the target user, you create a chronological cross-domain timeline showing email, endpoint, cloud app, and identity activities in sequence.",
        "Option C is INCORRECT: DeviceProcessEvents only contains endpoint process execution data. It doesn't capture email delivery, cloud app access, or identity logon events. Each domain requires its specific table.",
        "Option D is INCORRECT: A single join across four tables would try to find rows that match across ALL tables simultaneously — most combinations would return empty results since a user's email event won't share a common key with their process event. Union appends all rows; join matches related rows."
      ],
      "codeSnippet": "// KQL: Cross-domain user activity timeline\\nlet targetUser = \\\"john@adatum.com\\\";\\nunion\\n    (EmailEvents\\n    | where RecipientEmailAddress == targetUser\\n    | project Timestamp, Source=\\\"Email\\\",\\n        Activity=strcat(\\\"Email: \\\", Subject)),\\n    (DeviceProcessEvents\\n    | where AccountUpn == targetUser\\n    | project Timestamp, Source=\\\"Endpoint\\\",\\n        Activity=strcat(\\\"Process: \\\", FileName)),\\n    (CloudAppEvents\\n    | where AccountDisplayName has targetUser\\n    | project Timestamp, Source=\\\"CloudApp\\\",\\n        Activity=strcat(\\\"App: \\\", ActionType)),\\n    (IdentityLogonEvents\\n    | where AccountUpn == targetUser\\n    | project Timestamp, Source=\\\"Identity\\\",\\n        Activity=strcat(\\\"Logon: \\\", LogonType))\\n| order by Timestamp asc",
      "socTip": "When building user activity timelines, extend the time range to 7 days before the suspected compromise date. This helps identify the initial access vector that may have occurred days before the visible malicious activity.",
      "docRef": "Microsoft Learn: union operator in KQL"
    }
  },
  {
    "id": "xdr-052",
    "topic": "Microsoft Defender for Office 365 — Safe Documents",
    "scenario": "Litware has Safe Documents enabled for Microsoft 365 Apps. An employee opens a Word document received via email, and it opens in Protected View. The employee clicks 'Enable Editing' and the document is automatically sent to the cloud for detonation analysis.",
    "question": "What happens if Safe Documents determines the file is malicious?",
    "options": [
      "The document is silently deleted from the user's computer without notification",
      "The user is shown a warning that the document has been identified as malicious, and they are blocked from exiting Protected View. They cannot edit the document, and an alert is generated for the SOC",
      "The document is allowed to open normally but with all macros disabled",
      "Safe Documents sends an email to the user's manager requesting approval to open the file"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Safe Documents — Protected View Cloud Verification",
      "analysis": [
        "Option A is INCORRECT: Safe Documents does not silently delete files. The user is informed about the malicious verdict and prevented from editing, but the file remains on disk for potential forensic analysis.",
        "Option B is CORRECT: When Safe Documents determines a file is malicious, the user sees a red warning banner in the document stating that the file has been identified as unsafe. The document remains in Protected View (read-only), and the 'Enable Editing' button is blocked. An alert is also generated in the Defender XDR portal for SOC investigation.",
        "Option C is INCORRECT: If the file is identified as malicious, it is NOT allowed to open normally — not even with macros disabled. The entire document remains in Protected View to prevent any potentially malicious content from executing.",
        "Option D is INCORRECT: Safe Documents does not involve management approval workflows. It is an automated security control that immediately blocks malicious content based on cloud detonation results."
      ],
      "codeSnippet": "// KQL: Track Safe Documents verdicts\\nDeviceEvents\\n| where Timestamp > ago(7d)\\n| where ActionType == \\\"SafeDocumentVerdict\\\"\\n| project Timestamp, DeviceName,\\n    FileName, FolderPath,\\n    AdditionalFields\\n| order by Timestamp desc",
      "socTip": "Safe Documents is most effective for files received from external sources. Ensure it's configured to also apply when users open documents from network shares and USB drives, not just email attachments.",
      "docRef": "Microsoft Learn: Safe Documents in Microsoft 365 Apps"
    }
  },
  {
    "id": "xdr-053",
    "topic": "Incident response — containment actions",
    "scenario": "During a confirmed ransomware incident at Contoso, the SOC analyst needs to take immediate containment actions on multiple affected devices. Three workstations and one server are confirmed compromised. The analyst has identified the ransomware process running on all four machines.",
    "question": "What is the recommended containment sequence?",
    "options": [
      "Shut down the network switch that connects the affected subnet",
      "Isolate all four devices from the network via Defender for Endpoint, then use automated investigation to stop the malicious processes, and finally check for any lateral movement to other devices",
      "Wait for the ransomware to complete encryption and then restore from backup",
      "Disconnect the internet connection for the entire building"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Ransomware Containment Workflow in Defender XDR",
      "analysis": [
        "Option A is INCORRECT: Shutting down a network switch is a physical infrastructure change that affects ALL devices on the subnet, including non-compromised ones. Defender for Endpoint device isolation provides targeted containment for specific devices without affecting the rest of the network.",
        "Option B is CORRECT: The recommended containment sequence is: (1) Network isolation — immediately cut C2 communication and prevent lateral movement, (2) Process termination — stop the ransomware process on isolated devices using Live Response or automated investigation, (3) Lateral movement check — use Advanced Hunting to identify if the ransomware has spread to other devices. This targeted approach contains the threat without disrupting the entire network.",
        "Option C is INCORRECT: Waiting for ransomware to complete is never acceptable. Every minute of delay results in more encrypted files and potentially more compromised devices. Immediate containment is critical to minimize impact.",
        "Option D is INCORRECT: Disconnecting the internet for the entire building is a disproportionate response that disrupts all business operations. Targeted device isolation through Defender for Endpoint achieves containment without affecting other systems."
      ],
      "codeSnippet": "// KQL: Check for ransomware lateral movement\\nDeviceNetworkEvents\\n| where Timestamp > ago(1h)\\n| where DeviceName in (\\\"WS01\\\", \\\"WS02\\\",\\n    \\\"WS03\\\", \\\"SRV01\\\")\\n| where RemotePort in (445, 139, 3389)\\n| summarize Connections=count(),\\n    TargetDevices=make_set(RemoteIP)\\n    by DeviceName\\n| order by Connections desc",
      "socTip": "During ransomware containment, isolate devices in priority order: (1) File servers and domain controllers first (highest impact), (2) Known compromised workstations, (3) Devices with suspicious connections to compromised machines. Check for SMB (445) and RDP (3389) connections from compromised devices to identify lateral movement.",
      "docRef": "Microsoft Learn: Respond to your first incident — ransomware"
    }
  },
  {
    "id": "xdr-054",
    "topic": "Advanced Hunting — render operator for data visualization",
    "scenario": "A Fabrikam SOC analyst has written a KQL query that shows the trend of phishing emails detected over the past 30 days. The analyst wants to visualize this data as a chart directly within Advanced Hunting to include in a monthly security report.",
    "question": "Which KQL operator produces a visual chart of the query results?",
    "options": [
      "| chart type=line by Timestamp",
      "| render timechart",
      "| visualize trend",
      "| display graph"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Data Visualization with the render Operator",
      "analysis": [
        "Option A is INCORRECT: '| chart type=line' is not valid KQL syntax. The correct operator for visualization is 'render' followed by the chart type.",
        "Option B is CORRECT: The 'render' operator in KQL produces interactive charts. Common chart types include: timechart (time-series line chart), barchart, piechart, columnchart, and scatterchart. For trending data with timestamps, 'render timechart' is ideal as it automatically uses the timestamp column for the x-axis.",
        "Option C is INCORRECT: 'visualize' is not a valid KQL operator. The correct operator is 'render'.",
        "Option D is INCORRECT: 'display' is not a valid KQL operator. Chart rendering in KQL is done exclusively through the 'render' operator."
      ],
      "codeSnippet": "// KQL: Phishing trend visualization\\nEmailEvents\\n| where Timestamp > ago(30d)\\n| where ThreatTypes has \\\"Phish\\\"\\n| summarize PhishingCount=count()\\n    by bin(Timestamp, 1d)\\n| render timechart\\n    with (title=\\\"Daily Phishing Detections\\\",\\n    xtitle=\\\"Date\\\", ytitle=\\\"Count\\\")",
      "socTip": "Use 'render piechart' for category distribution (e.g., alert severity breakdown) and 'render timechart' for trends (e.g., daily alert counts). Export the chart as an image for inclusion in executive security reports.",
      "docRef": "Microsoft Learn: render operator"
    }
  },
  {
    "id": "xdr-055",
    "topic": "Microsoft Defender for Identity — sensor deployment",
    "scenario": "Northwind Traders is deploying Microsoft Defender for Identity to monitor their on-premises Active Directory. The infrastructure team needs to install sensors on domain controllers to capture authentication events, LDAP queries, and DNS traffic.",
    "question": "Which component must be installed on the domain controllers for Defender for Identity?",
    "options": [
      "The Microsoft Monitoring Agent (MMA)",
      "The Microsoft Defender for Identity sensor, which is a lightweight software package installed directly on domain controllers that captures and analyzes AD traffic through port mirroring or network parsing",
      "The Azure AD Connect Health agent",
      "The Microsoft Defender for Endpoint sensor (MDE agent)"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Defender for Identity Sensor Architecture",
      "analysis": [
        "Option A is INCORRECT: The Microsoft Monitoring Agent (MMA) is used for Azure Monitor and Log Analytics data collection. It does not capture Active Directory authentication events, Kerberos traffic, or LDAP queries that Defender for Identity requires.",
        "Option B is CORRECT: The Defender for Identity sensor is installed directly on domain controllers (or standalone sensors on dedicated machines with port mirroring). It captures Windows event logs, network traffic on the domain controller (Kerberos, NTLM, LDAP, DNS), and sends this data to the Defender for Identity cloud service for analysis and detection.",
        "Option C is INCORRECT: Azure AD Connect Health monitors the health and performance of Azure AD Connect, AD FS, and AD DS. It is not a security detection sensor and doesn't analyze authentication traffic for threat detection.",
        "Option D is INCORRECT: The Defender for Endpoint sensor provides endpoint detection and response (EDR) for endpoints. While it can be installed on domain controllers for endpoint protection, it doesn't capture the AD-specific protocol traffic (Kerberos, NTLM, LDAP) that Defender for Identity specializes in."
      ],
      "codeSnippet": "// Defender for Identity sensor requirements:\\n// - Domain Controller or AD FS server\\n// - Windows Server 2016+ recommended\\n// - .NET Framework 4.7+\\n// - Minimum 6 GB RAM on the DC\\n// - Outbound HTTPS to *.atp.azure.com\\n//\\n// Installation: Run the sensor installer\\n// package from the Defender for Identity portal\\n// with the access key for your workspace.",
      "socTip": "Install sensors on ALL domain controllers — not just the primary one. Attackers may target secondary DCs that are less monitored. If a sensor is only on the primary DC, authentication events processed by secondary DCs will be invisible to Defender for Identity.",
      "docRef": "Microsoft Learn: Install the Microsoft Defender for Identity sensor"
    }
  },
  {
    "id": "xdr-056",
    "topic": "Advanced Hunting — summarize operator best practices",
    "scenario": "An Adatum SOC analyst is writing an Advanced Hunting query to analyze alert patterns. The analyst needs to count the number of alerts per category, identify the most common alert titles, and calculate the average number of affected entities per alert — all in a single query.",
    "question": "Which KQL approach produces all three analyses in a single query?",
    "options": [
      "Run three separate queries and compare the results manually",
      "Use the summarize operator with multiple aggregation functions: count() for alert count per category, make_set() for distinct alert titles, and avg() for average entity count — all grouped by the desired dimension",
      "Use the where operator three times with different filter conditions",
      "Use the extend operator to add calculated columns for each analysis"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Multi-Aggregation with the summarize Operator",
      "analysis": [
        "Option A is INCORRECT: Running three separate queries is inefficient and doesn't produce a unified view. The summarize operator can perform multiple aggregations simultaneously in a single query scan.",
        "Option B is CORRECT: The summarize operator supports multiple aggregation functions in a single statement: count(), dcount(), avg(), sum(), min(), max(), make_set(), make_list(), and more. Each function operates independently on its specified column while grouping by the same dimension. This is efficient because the data is scanned only once.",
        "Option C is INCORRECT: The where operator filters rows but doesn't aggregate or calculate statistics. Filtering alone cannot produce counts, averages, or distinct lists.",
        "Option D is INCORRECT: The extend operator adds calculated columns to each row but doesn't aggregate across rows. To get counts and averages across multiple rows, you need summarize."
      ],
      "codeSnippet": "// KQL: Multi-aggregation analysis example\\nAlertInfo\\n| where Timestamp > ago(30d)\\n| join AlertEvidence on AlertId\\n| summarize\\n    AlertCount = count(),\\n    UniqueAlertTitles = dcount(Title),\\n    TopTitles = make_set(Title, 5),\\n    AvgEntities = avg(toint(\\n        countof(tostring(EntityType), \\\",\\\") + 1)),\\n    Severities = make_set(Severity)\\n    by Category\\n| order by AlertCount desc",
      "socTip": "When using summarize with make_set(), always specify a max size parameter (e.g., make_set(Title, 10)) to limit the output size. Unbounded make_set() on large datasets can produce enormous arrays that slow down rendering.",
      "docRef": "Microsoft Learn: summarize operator in KQL"
    }
  },
  {
    "id": "xdr-057",
    "topic": "Unified security operations platform",
    "scenario": "Litware's CISO wants to consolidate the SOC's toolset. Currently, analysts switch between multiple portals: the Microsoft Defender portal for XDR alerts, the Azure portal for Sentinel, and the Microsoft 365 compliance center for DLP. The CISO asks about the unified security operations platform.",
    "question": "What does the unified security operations platform in Microsoft Defender XDR provide?",
    "options": [
      "A single mobile app that replaces all security portals",
      "An integrated experience within the Microsoft Defender portal that combines Defender XDR, Microsoft Sentinel SIEM, exposure management, and threat intelligence into one unified interface — eliminating the need to switch between portals",
      "An AI assistant that automatically resolves all security incidents",
      "A third-party SIEM integration framework that replaces Microsoft Sentinel"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Unified Security Operations Platform",
      "analysis": [
        "Option A is INCORRECT: The unified security operations platform is a web-based portal experience, not a mobile app. It consolidates web-based security tools into the Microsoft Defender portal.",
        "Option B is CORRECT: The unified security operations platform brings Microsoft Sentinel's SIEM capabilities directly into the Microsoft Defender portal. This means analysts can manage Sentinel workspaces, analytics rules, hunting queries, incidents, workbooks, and data connectors alongside Defender XDR features — all from security.microsoft.com without switching to the Azure portal.",
        "Option C is INCORRECT: While Microsoft Copilot for Security provides AI-assisted investigation, no system automatically resolves all incidents. The unified platform consolidates tools for analyst efficiency, not full automation.",
        "Option D is INCORRECT: The unified platform includes Microsoft Sentinel — it doesn't replace it with a third-party tool. Sentinel's full SIEM capabilities are integrated into the Defender portal."
      ],
      "codeSnippet": "// In the unified platform, Sentinel KQL\\n// tables are accessible alongside Defender tables:\\n// Sentinel tables:\\nSecurityEvent\\n| where EventID == 4625\\n| take 10\\n\\n// Defender XDR tables:\\nDeviceProcessEvents\\n| where FileName == \\\"mimikatz.exe\\\"\\n| take 10\\n\\n// Both accessible from the same hunting page",
      "socTip": "After connecting Sentinel to the unified platform, migrate your Sentinel hunting queries and analytics rules gradually. Test each rule in the new environment to ensure it works correctly before decommissioning the Azure portal Sentinel experience.",
      "docRef": "Microsoft Learn: Microsoft's unified security operations platform"
    }
  },
  {
    "id": "xdr-058",
    "topic": "Advanced Hunting — let statements and variables",
    "scenario": "A Contoso SOC analyst is building a complex hunting query that references the same list of suspicious file hashes in multiple places. The analyst wants to define the hash list once and reuse it throughout the query for maintainability.",
    "question": "Which KQL feature allows defining reusable variables in Advanced Hunting queries?",
    "options": [
      "The 'declare @variable' syntax from SQL",
      "The 'let' statement, which defines named variables (scalars, tables, or functions) that can be referenced throughout the query",
      "The 'var' keyword from JavaScript",
      "The 'set' command for session-level variables"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "KQL let Statements for Query Modularity",
      "analysis": [
        "Option A is INCORRECT: 'declare @variable' is T-SQL syntax used in SQL Server and Azure SQL Database. KQL (Kusto Query Language) has a different syntax and uses 'let' for variable declaration.",
        "Option B is CORRECT: The 'let' statement in KQL defines named expressions that can be scalars (single values like strings, numbers, time spans), tabular expressions (subqueries that return tables), or functions (reusable query fragments). They are defined before the main query and referenced by name throughout.",
        "Option C is INCORRECT: 'var' is JavaScript syntax. KQL is a distinct query language used in Azure Data Explorer, Microsoft Defender XDR, and Microsoft Sentinel. It does not use JavaScript syntax.",
        "Option D is INCORRECT: 'set' is used in some KQL contexts for client request properties (like query timeout), but it does not define reusable query variables. The 'let' statement is the correct mechanism."
      ],
      "codeSnippet": "// KQL: Using let for reusable variables\\nlet suspiciousHashes = dynamic([\\n    \\\"abc123def456...\\\",\\n    \\\"789ghi012jkl...\\\"\\n]);\\nlet lookbackPeriod = 7d;\\nlet targetDeviceGroup = \\\"Finance-Workstations\\\";\\n// Reuse variables in the main query:\\nDeviceFileEvents\\n| where Timestamp > ago(lookbackPeriod)\\n| where SHA256 in (suspiciousHashes)\\n| where DeviceGroup == targetDeviceGroup\\n| project Timestamp, DeviceName, FileName, SHA256",
      "socTip": "Use 'let' statements at the top of every hunting query to define time ranges, IOC lists, and device groups. This makes queries self-documenting and easy to update — changing a single 'let' statement updates all references throughout the query.",
      "docRef": "Microsoft Learn: let statement in KQL"
    }
  },
  {
    "id": "xdr-059",
    "topic": "Conditional Access integration with Defender XDR signals",
    "scenario": "Fabrikam wants their Azure AD Conditional Access policies to automatically react to risk signals detected by Microsoft Defender XDR. When a user's device is flagged as compromised by Defender for Endpoint, their Conditional Access policies should block access to sensitive applications until the device is remediated.",
    "question": "How should Fabrikam integrate Defender for Endpoint risk signals into Conditional Access?",
    "options": [
      "Manually update Conditional Access policies each time a device is compromised",
      "Configure a Conditional Access policy that requires device compliance, with Intune compliance policy referencing the Defender for Endpoint machine risk level — when a device risk level changes to High, compliance status changes to non-compliant, and Conditional Access blocks access",
      "Create an Azure Logic App that monitors Defender for Endpoint alerts and disables user accounts",
      "Deploy a custom Azure Function that queries the Defender for Endpoint API every hour and updates Conditional Access policies"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "Risk-Based Conditional Access with Defender for Endpoint",
      "analysis": [
        "Option A is INCORRECT: Manually updating Conditional Access policies is reactive, slow, and doesn't scale. The integration should be automatic and real-time through the compliance state signal.",
        "Option B is CORRECT: This is the standard integration pattern: (1) Defender for Endpoint calculates machine risk level based on detected threats, (2) Intune compliance policy checks machine risk level — if High, the device becomes non-compliant, (3) Conditional Access policy requires compliant devices — non-compliant devices are blocked from accessing sensitive apps. This chain is automatic and near-real-time.",
        "Option C is INCORRECT: Disabling user accounts is overly disruptive and punishes the user for a device-level issue. The correct approach blocks app access from the compromised device while allowing the user to access apps from other compliant devices.",
        "Option D is INCORRECT: Building a custom Azure Function is unnecessary when the native Defender for Endpoint → Intune → Conditional Access integration provides this functionality out of the box. Custom solutions add complexity and maintenance burden."
      ],
      "codeSnippet": "// Integration chain (configuration, not code):\\n// 1. Defender for Endpoint → Intune connector:\\n//    Enable in Defender portal > Settings >\\n//    Endpoints > Advanced features >\\n//    Microsoft Intune connection\\n//\\n// 2. Intune Compliance Policy:\\n//    Require machine risk level <= Medium\\n//\\n// 3. Conditional Access Policy:\\n//    Grant: Require compliant device\\n//    Block: Non-compliant devices",
      "socTip": "Set different Conditional Access policies for different app sensitivity levels. Low-risk apps may allow Medium device risk, while finance apps require No risk. This balances security with user productivity.",
      "docRef": "Microsoft Learn: Enforce compliance for Microsoft Defender for Endpoint with Conditional Access"
    }
  },
  {
    "id": "xdr-060",
    "topic": "Automatic attack disruption",
    "scenario": "Contoso enables automatic attack disruption in Defender XDR. A human-operated ransomware campaign is detected spanning email and endpoints.",
    "question": "What does automatic attack disruption do when a high-confidence multi-stage attack is identified?",
    "options": [
      "Automatically contains the attack by taking coordinated response actions across workloads (such as disabling user accounts, containing devices, and limiting further progression) based on high-confidence detections",
      "Only sends an email to the CISO without taking action",
      "Permanently deletes all user mailboxes involved",
      "Requires a 72-hour waiting period before any containment"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Automatic Attack Disruption in Defender XDR",
      "analysis": [
        "Option A is CORRECT: Automatic attack disruption takes coordinated containment actions across domains when high-confidence multi-stage attacks are detected.",
        "Option B is INCORRECT: It performs active containment, not notification-only.",
        "Option C is INCORRECT: Destructive mailbox deletion is not the disruption model.",
        "Option D is INCORRECT: Disruption is designed for rapid response."
      ],
      "codeSnippet": "// Settings > Endpoints/XDR advanced features\n// Automatic attack disruption = On",
      "socTip": "Review disruption actions in the Action Center after each event and document lessons learned.",
      "docRef": "Microsoft Learn: Automatic attack disruption"
    }
  },
  {
    "id": "xdr-061",
    "topic": "Deception capabilities",
    "scenario": "Fabrikam wants to plant decoy accounts and hosts to detect attackers probing the environment.",
    "question": "How can Microsoft Defender XDR help detect attackers through deception?",
    "options": [
      "Deploy deception capabilities (decoy accounts/devices/lures) so interaction with them generates high-fidelity alerts indicating attacker presence",
      "Deception is not available in Microsoft security products",
      "Only physical honeypots outside the cloud can be used",
      "Disable all monitoring to attract attackers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Deception in Microsoft Defender XDR",
      "analysis": [
        "Option A is CORRECT: Deception features plant authentic-looking decoys; any interaction is highly suspicious.",
        "Option B is INCORRECT: Deception capabilities exist in the Microsoft security stack.",
        "Option C is INCORRECT: Cloud-managed deception is supported.",
        "Option D is INCORRECT: Monitoring must remain enabled."
      ],
      "codeSnippet": "// Configure decoys via Defender portal deception settings",
      "socTip": "Treat any decoy interaction as high priority — true positives are common.",
      "docRef": "Microsoft Learn: Deception in Microsoft Defender XDR"
    }
  },
  {
    "id": "xdr-062",
    "topic": "Exposure management overview",
    "scenario": "Litware's CISO wants a continuous view of attack paths from internet-facing assets to critical assets.",
    "question": "What does Microsoft Security Exposure Management provide in the Defender portal?",
    "options": [
      "Continuous mapping of exposure, critical assets, and potential attack paths so teams can prioritize reductions in blast radius",
      "Only a static annual PDF risk report",
      "Only antivirus signature counts",
      "A replacement for all backup systems"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Security Exposure Management",
      "analysis": [
        "Option A is CORRECT: Exposure management continuously evaluates paths and critical asset exposure.",
        "Option B is INCORRECT: It is continuous, not annual-only.",
        "Option C is INCORRECT: Far broader than AV signatures.",
        "Option D is INCORRECT: Not a backup product."
      ],
      "codeSnippet": "// Exposure management > Attack paths / Critical assets",
      "socTip": "Start by tagging crown-jewel assets so path analysis prioritizes what matters most.",
      "docRef": "Microsoft Learn: Microsoft Security Exposure Management"
    }
  },
  {
    "id": "xdr-063",
    "topic": "Critical asset management",
    "scenario": "Adatum needs domain controllers and finance servers treated as critical for exposure scoring.",
    "question": "Why classify assets as critical in Exposure Management?",
    "options": [
      "Critical asset classification improves prioritization of attack paths and recommendations toward the most important systems",
      "It has no effect on prioritization",
      "It automatically patches servers without approval",
      "It deletes non-critical assets"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Critical Asset Classification",
      "analysis": [
        "Option A is CORRECT: Critical tags focus exposure analysis on high-value targets.",
        "Option B is INCORRECT: Classification drives prioritization.",
        "Option C is INCORRECT: Classification does not auto-patch.",
        "Option D is INCORRECT: Non-critical assets are not deleted."
      ],
      "codeSnippet": "// Exposure management > Critical assets inventory",
      "socTip": "Review critical asset tags quarterly with business owners.",
      "docRef": "Microsoft Learn: Critical assets in Exposure Management"
    }
  },
  {
    "id": "xdr-064",
    "topic": "Advanced Hunting — DeviceFileEvents",
    "scenario": "A hunter needs files created in the Temp folder with double extensions like invoice.pdf.exe.",
    "question": "Which table is primary for file creation and modification events on endpoints?",
    "options": [
      "DeviceFileEvents — file create/modify/delete/rename telemetry including paths and hashes",
      "EmailAttachmentInfo only",
      "IdentityDirectoryEvents only",
      "CloudAppEvents only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceFileEvents for File Activity",
      "analysis": [
        "Option A is CORRECT: DeviceFileEvents is the endpoint file activity table.",
        "Option B is INCORRECT: Email attachments are a different domain.",
        "Option C is INCORRECT: Directory changes, not endpoint files.",
        "Option D is INCORRECT: SaaS app events, not local files."
      ],
      "codeSnippet": "DeviceFileEvents\n| where FolderPath has 'Temp'\n| where FileName matches regex @'\\\\.pdf\\\\.exe$'",
      "socTip": "Combine file events with process events to see which process dropped the payload.",
      "docRef": "Microsoft Learn: DeviceFileEvents"
    }
  },
  {
    "id": "xdr-065",
    "topic": "Advanced Hunting — DeviceNetworkEvents",
    "scenario": "SOC needs devices that connected to a suspicious IP on port 4444.",
    "question": "Which table provides endpoint network connection telemetry for hunting?",
    "options": [
      "DeviceNetworkEvents — remote IP/port, protocol, initiating process, and connection direction",
      "EmailEvents",
      "DeviceInfo only without connections",
      "Secure Score API only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceNetworkEvents for Network Hunting",
      "analysis": [
        "Option A is CORRECT: DeviceNetworkEvents is the primary network connection table.",
        "Option B is INCORRECT: Email metadata, not host connections.",
        "Option C is INCORRECT: DeviceInfo lacks connection rows.",
        "Option D is INCORRECT: Posture API is not connection telemetry."
      ],
      "codeSnippet": "DeviceNetworkEvents\n| where RemoteIP == '203.0.113.10'\n| where RemotePort == 4444",
      "socTip": "Always project InitiatingProcessFileName to attribute the connection.",
      "docRef": "Microsoft Learn: DeviceNetworkEvents"
    }
  },
  {
    "id": "xdr-066",
    "topic": "Advanced Hunting — DeviceLogonEvents",
    "scenario": "Analysts investigate interactive and remote logons after credential theft.",
    "question": "Which Advanced Hunting table captures device logon activity including logon type?",
    "options": [
      "DeviceLogonEvents — success/failure logons with logon type, account, and device context",
      "EmailUrlInfo",
      "UrlClickEvents only",
      "CloudAppEvents only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceLogonEvents",
      "analysis": [
        "Option A is CORRECT: DeviceLogonEvents holds endpoint authentication/logon telemetry.",
        "Option B is INCORRECT: URL info from email.",
        "Option C is INCORRECT: Safe Links clicks.",
        "Option D is INCORRECT: Cloud app activity."
      ],
      "codeSnippet": "DeviceLogonEvents\n| where LogonType == 'RemoteInteractive'\n| where ActionType == 'LogonSuccess'",
      "socTip": "Hunt for first-time remote logons to sensitive servers.",
      "docRef": "Microsoft Learn: DeviceLogonEvents"
    }
  },
  {
    "id": "xdr-067",
    "topic": "Advanced Hunting — DeviceRegistryEvents",
    "scenario": "Persistence via Run key modifications is suspected.",
    "question": "Which table should be queried for registry modifications related to persistence?",
    "options": [
      "DeviceRegistryEvents — registry set/delete operations with key path and value data",
      "EmailEvents",
      "IdentityQueryEvents only",
      "DeviceInfo only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceRegistryEvents for Persistence Hunting",
      "analysis": [
        "Option A is CORRECT: Registry telemetry lives in DeviceRegistryEvents.",
        "Option B is INCORRECT: Email domain.",
        "Option C is INCORRECT: Identity directory queries.",
        "Option D is INCORRECT: Inventory, not registry changes."
      ],
      "codeSnippet": "DeviceRegistryEvents\n| where RegistryKey has 'CurrentVersion\\\\Run'",
      "socTip": "Correlate registry persistence with the process that wrote the value.",
      "docRef": "Microsoft Learn: DeviceRegistryEvents"
    }
  },
  {
    "id": "xdr-068",
    "topic": "Advanced Hunting — EmailUrlInfo",
    "scenario": "Analysts need URLs extracted from emails in a phishing campaign.",
    "question": "Which table stores URLs found in email messages for hunting?",
    "options": [
      "EmailUrlInfo — URLs extracted from messages, joinable to EmailEvents via NetworkMessageId",
      "DeviceProcessEvents",
      "DeviceNetworkEvents only",
      "IdentityLogonEvents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "EmailUrlInfo",
      "analysis": [
        "Option A is CORRECT: EmailUrlInfo holds URL entities from email.",
        "Option B is INCORRECT: Process table.",
        "Option C is INCORRECT: Endpoint network, not email URL parse.",
        "Option D is INCORRECT: Identity logons."
      ],
      "codeSnippet": "EmailUrlInfo\n| join EmailEvents on NetworkMessageId\n| where Url has 'login-'",
      "socTip": "Join UrlClickEvents to see who actually clicked.",
      "docRef": "Microsoft Learn: EmailUrlInfo"
    }
  },
  {
    "id": "xdr-069",
    "topic": "Advanced Hunting — UrlClickEvents",
    "scenario": "SOC must find users who clicked a malicious Safe Links URL.",
    "question": "Which table records user clicks on URLs protected by Safe Links?",
    "options": [
      "UrlClickEvents — click time, user, URL, and action (allowed/blocked)",
      "DeviceFileEvents",
      "AlertInfo only without clicks",
      "CloudAppEvents only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "UrlClickEvents",
      "analysis": [
        "Option A is CORRECT: UrlClickEvents is the Safe Links click telemetry table.",
        "Option B is INCORRECT: File events.",
        "Option C is INCORRECT: Alerts may reference clicks but the table is UrlClickEvents.",
        "Option D is INCORRECT: SaaS events."
      ],
      "codeSnippet": "UrlClickEvents\n| where ActionType == 'ClickBlocked'",
      "socTip": "Investigate IsClickedThrough == true as high-risk user behavior.",
      "docRef": "Microsoft Learn: UrlClickEvents"
    }
  },
  {
    "id": "xdr-070",
    "topic": "Advanced Hunting — CloudAppEvents",
    "scenario": "Unusual Mass download from SharePoint needs investigation.",
    "question": "Which table provides Microsoft 365 and connected cloud app activity for hunting?",
    "options": [
      "CloudAppEvents — activities in Exchange, SharePoint, Teams, and connected apps",
      "DeviceProcessEvents only",
      "EmailAttachmentInfo only",
      "DeviceInfo only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "CloudAppEvents",
      "analysis": [
        "Option A is CORRECT: CloudAppEvents covers cloud app user and admin activities.",
        "Option B is INCORRECT: Endpoint processes.",
        "Option C is INCORRECT: Attachment metadata.",
        "Option D is INCORRECT: Device inventory."
      ],
      "codeSnippet": "CloudAppEvents\n| where Application == 'Microsoft SharePoint Online'\n| where ActionType has 'Download'",
      "socTip": "Baseline normal download volumes before alerting on spikes.",
      "docRef": "Microsoft Learn: CloudAppEvents"
    }
  },
  {
    "id": "xdr-071",
    "topic": "Advanced Hunting — IdentityLogonEvents",
    "scenario": "Password spray against on-prem AD is suspected.",
    "question": "Which table is appropriate for on-premises and hybrid identity logon hunting with Defender for Identity signals?",
    "options": [
      "IdentityLogonEvents — authentication attempts including failures useful for spray detection",
      "EmailEvents",
      "DeviceFileEvents",
      "UrlClickEvents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IdentityLogonEvents",
      "analysis": [
        "Option A is CORRECT: IdentityLogonEvents captures identity authentication telemetry relevant to sprays.",
        "Option B is INCORRECT: Email.",
        "Option C is INCORRECT: Files.",
        "Option D is INCORRECT: URL clicks."
      ],
      "codeSnippet": "IdentityLogonEvents\n| where ActionType == 'LogonFailed'\n| summarize dcount(AccountUpn) by IPAddress",
      "socTip": "Look for one IP failing against many accounts in a short window.",
      "docRef": "Microsoft Learn: IdentityLogonEvents"
    }
  },
  {
    "id": "xdr-072",
    "topic": "Advanced Hunting — AlertInfo and AlertEvidence",
    "scenario": "An analyst wants all evidence entities linked to high-severity alerts.",
    "question": "How are alert metadata and evidence typically combined in Advanced Hunting?",
    "options": [
      "Join AlertInfo to AlertEvidence on AlertId to combine alert properties with related entities",
      "Alerts cannot be queried in Advanced Hunting",
      "Only export CSV from the UI",
      "Use EmailEvents for all alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AlertInfo + AlertEvidence Join",
      "analysis": [
        "Option A is CORRECT: Standard pattern joins AlertInfo and AlertEvidence on AlertId.",
        "Option B is INCORRECT: Alerts are queryable.",
        "Option C is INCORRECT: KQL is preferred for scale.",
        "Option D is INCORRECT: Wrong table."
      ],
      "codeSnippet": "AlertInfo\n| join AlertEvidence on AlertId\n| where Severity == 'High'",
      "socTip": "Project EntityType and EvidenceRole to understand each entity's part in the alert.",
      "docRef": "Microsoft Learn: AlertInfo and AlertEvidence"
    }
  },
  {
    "id": "xdr-073",
    "topic": "Incident assignment and status",
    "scenario": "Tier 1 takes ownership of an incident and begins work.",
    "question": "What status and assignment practice helps SOC coordination?",
    "options": [
      "Assign the incident to an owner and set status to In Progress so others know it is being worked",
      "Leave all incidents unassigned and Active forever",
      "Close incidents without classification",
      "Assign every incident to Global Administrator"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Ownership and Status",
      "analysis": [
        "Option A is CORRECT: Owner + In Progress prevents duplicate work.",
        "Option B is INCORRECT: Causes collision and missed SLAs.",
        "Option C is INCORRECT: Classification is required for metrics.",
        "Option D is INCORRECT: Violates least privilege."
      ],
      "codeSnippet": "// Incident queue > Assign to me > Status = In Progress",
      "socTip": "Define SLA timers per severity for assignment and containment.",
      "docRef": "Microsoft Learn: Manage incidents"
    }
  },
  {
    "id": "xdr-074",
    "topic": "Incident classification values",
    "scenario": "After investigation, an alert was confirmed malware.",
    "question": "Which classification is appropriate for a confirmed malicious incident?",
    "options": [
      "True positive — with determination such as multi-stage attack or malware depending on findings",
      "False positive when malware is confirmed",
      "Not set is preferred for confirmed attacks",
      "Informational only with no true positive option"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Classification",
      "analysis": [
        "Option A is CORRECT: Confirmed malicious activity is classified true positive with a suitable determination.",
        "Option B is INCORRECT: False positive means the detection was wrong.",
        "Option C is INCORRECT: Classification should be set.",
        "Option D is INCORRECT: True positive is available."
      ],
      "codeSnippet": "// Resolve > Classification: True positive",
      "socTip": "Consistent classification improves detection tuning and reporting.",
      "docRef": "Microsoft Learn: Classify incidents"
    }
  },
  {
    "id": "xdr-075",
    "topic": "Go hunt from entities",
    "scenario": "From an incident graph node for a device, the analyst wants a pre-scoped hunt.",
    "question": "What does 'Go hunt' from an entity provide?",
    "options": [
      "A pivot into Advanced Hunting with queries/context scoped to that entity to accelerate investigation",
      "A full tenant wipe",
      "Only a PDF export",
      "Disables the entity permanently"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Go Hunt Entity Pivot",
      "analysis": [
        "Option A is CORRECT: Go hunt jumps into hunting with entity context.",
        "Option B is INCORRECT: Not destructive.",
        "Option C is INCORRECT: Interactive hunting, not just PDF.",
        "Option D is INCORRECT: No permanent disable."
      ],
      "codeSnippet": "// Entity page > Go hunt",
      "socTip": "Use Go hunt after reviewing the timeline to deepen evidence.",
      "docRef": "Microsoft Learn: Investigate entities"
    }
  },
  {
    "id": "xdr-076",
    "topic": "Suppression rules vs tuning",
    "scenario": "A noisy but sometimes useful detection floods the queue from a scanner subnet.",
    "question": "What is the preferred way to reduce noise without losing detection elsewhere?",
    "options": [
      "Create a narrowly scoped alert suppression or tuning rule matching the scanner source while leaving the detection enabled globally",
      "Disable the detection organization-wide",
      "Ignore the queue permanently",
      "Delete the detector code from Microsoft cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Scoped Suppression/Tuning",
      "analysis": [
        "Option A is CORRECT: Narrow suppression preserves detection elsewhere.",
        "Option B is INCORRECT: Creates a blind spot.",
        "Option C is INCORRECT: Operational failure.",
        "Option D is INCORRECT: Not customer-controlled."
      ],
      "codeSnippet": "// Settings > Alert suppression / tuning rules",
      "socTip": "Review suppression rules quarterly for still-valid scope.",
      "docRef": "Microsoft Learn: Suppress alerts"
    }
  },
  {
    "id": "xdr-077",
    "topic": "Threat analytics mitigation tracking",
    "scenario": "A Threat Analytics report lists mitigations for a campaign.",
    "question": "How should SOC use the Mitigations tab?",
    "options": [
      "Track recommended mitigations, mark progress, and reduce exposure as controls are applied",
      "Ignore mitigations and only read the narrative",
      "Mitigations only apply to Azure VMs not M365",
      "Mitigations auto-complete without evidence"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Threat Analytics Mitigations",
      "analysis": [
        "Option A is CORRECT: Mitigation tracking drives exposure reduction.",
        "Option B is INCORRECT: Mitigations are actionable.",
        "Option C is INCORRECT: Applies across relevant workloads.",
        "Option D is INCORRECT: Progress requires real changes."
      ],
      "codeSnippet": "// Threat analytics > report > Mitigations",
      "socTip": "Assign each mitigation an owner and due date.",
      "docRef": "Microsoft Learn: Threat analytics"
    }
  },
  {
    "id": "xdr-078",
    "topic": "Secure Score in Defender portal",
    "scenario": "CISO asks for improvement actions visible in the security portal.",
    "question": "Where can recommended security improvement actions be reviewed alongside Defender workloads?",
    "options": [
      "Microsoft Secure Score in the Microsoft Defender portal, with actionable recommendations across identity, device, apps, and data",
      "Only in a printed binder",
      "Only in Azure Cost Management",
      "Secure Score is deprecated and removed"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Secure Score Recommendations",
      "analysis": [
        "Option A is CORRECT: Secure Score surfaces prioritized improvement actions in the portal.",
        "Option B is INCORRECT: Portal is live.",
        "Option C is INCORRECT: Wrong product.",
        "Option D is INCORRECT: Still active."
      ],
      "codeSnippet": "// Microsoft Defender portal > Secure Score",
      "socTip": "Focus on high-impact, low-effort points first for quick wins.",
      "docRef": "Microsoft Learn: Microsoft Secure Score"
    }
  },
  {
    "id": "xdr-079",
    "topic": "Advanced Hunting data retention",
    "scenario": "A hunt needs 60-day-old process data but queries return empty beyond expected retention.",
    "question": "What should analysts remember about Advanced Hunting retention?",
    "options": [
      "Advanced Hunting data is retained for a limited period (commonly around 30 days for many tables); older investigations may need exported evidence or longer-term SIEM retention",
      "Unlimited multi-year retention is guaranteed for all tables by default",
      "Data is deleted every hour",
      "Retention only applies to email tables"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Hunting Data Retention Limits",
      "analysis": [
        "Option A is CORRECT: Retention is finite; plan exports or Sentinel for long-term.",
        "Option B is INCORRECT: Not unlimited by default.",
        "Option C is INCORRECT: Not hourly wipe of all hunting data.",
        "Option D is INCORRECT: Applies across tables with product-specific details."
      ],
      "codeSnippet": "// Check retention docs; export critical evidence early",
      "socTip": "During major incidents, export key query results the same day.",
      "docRef": "Microsoft Learn: Advanced Hunting overview"
    }
  },
  {
    "id": "xdr-080",
    "topic": "Custom detection impacted entities",
    "scenario": "A custom detection fires but the incident graph lacks device linkage.",
    "question": "How do you ensure custom detections map entities correctly?",
    "options": [
      "Configure impacted entities mapping in the custom detection rule so alerts link to devices/users/files for graph and response",
      "Entity mapping is impossible for custom rules",
      "Only titles can be customized, never entities",
      "Entities are random"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Detection Entity Mapping",
      "analysis": [
        "Option A is CORRECT: Impacted entities configuration is required for proper linkage.",
        "Option B is INCORRECT: Mapping is supported.",
        "Option C is INCORRECT: Entity mapping exists.",
        "Option D is INCORRECT: Deterministic mapping."
      ],
      "codeSnippet": "// Custom detection > Impacted entities columns",
      "socTip": "Test a custom detection in a lab device group before org-wide enablement.",
      "docRef": "Microsoft Learn: Custom detection rules"
    }
  },
  {
    "id": "xdr-081",
    "topic": "Email ZAP",
    "scenario": "A delivered email is later found malicious.",
    "question": "What is Zero-hour Auto Purge (ZAP) in Defender for Office 365?",
    "options": [
      "A capability that retrospectively removes or moves malicious emails already delivered when a new verdict is reached",
      "A tool that permanently disables email for the tenant",
      "Only a marketing name for antivirus",
      "A network firewall feature"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Zero-hour Auto Purge (ZAP)",
      "analysis": [
        "Option A is CORRECT: ZAP remediates already-delivered mail on updated verdicts.",
        "Option B is INCORRECT: Not a tenant email kill switch.",
        "Option C is INCORRECT: Specific post-delivery remediation feature.",
        "Option D is INCORRECT: Email security feature."
      ],
      "codeSnippet": "// Threat Explorer shows ZAP actions on messages",
      "socTip": "Monitor ZAP success/failure for high-severity campaigns.",
      "docRef": "Microsoft Learn: Zero-hour auto purge"
    }
  },
  {
    "id": "xdr-082",
    "topic": "Threat Explorer campaign view",
    "scenario": "Hundreds of similar phish messages arrive in one hour.",
    "question": "How does Threat Explorer help analyze email campaigns?",
    "options": [
      "Filter and pivot on sender, URL, attachment hash, and view totals for recipients, clicks, and ZAP actions across the campaign",
      "Threat Explorer only shows one email at a time with no pivots",
      "It only works for internal mail",
      "It replaces the need for any incident queue"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Threat Explorer Campaign Analysis",
      "analysis": [
        "Option A is CORRECT: Explorer is built for campaign-scale email investigation.",
        "Option B is INCORRECT: Rich filtering and aggregates exist.",
        "Option C is INCORRECT: External threats are a primary use.",
        "Option D is INCORRECT: Complements incidents."
      ],
      "codeSnippet": "// Threat Explorer > Phish > filter sender/URL",
      "socTip": "Start from URL or attachment hash to find all related messages.",
      "docRef": "Microsoft Learn: Threat Explorer"
    }
  },
  {
    "id": "xdr-083",
    "topic": "User-reported message triage",
    "scenario": "Users click Report phishing in Outlook.",
    "question": "Where do user-reported messages typically land for SOC/admin review?",
    "options": [
      "User-reported messages portal / submissions experience for analysis, false positive/negative handling, and conversion into improved detections",
      "They are permanently deleted without review",
      "Only the user's manager receives them in personal email",
      "They go exclusively to the physical mailroom"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "User-Reported Message Handling",
      "analysis": [
        "Option A is CORRECT: Submissions/user-reported flows support admin review.",
        "Option B is INCORRECT: Review is intended.",
        "Option C is INCORRECT: Not the primary SOC path.",
        "Option D is INCORRECT: Digital workflow."
      ],
      "codeSnippet": "// Email & collaboration > User-reported settings / Submissions",
      "socTip": "Train users to report; tune allow/block based on submission outcomes.",
      "docRef": "Microsoft Learn: User reported messages"
    }
  },
  {
    "id": "xdr-084",
    "topic": "Advanced Hunting — materialize operator",
    "scenario": "A complex query reuses an expensive subquery multiple times and hits performance issues.",
    "question": "Which technique can improve performance when reusing intermediate results?",
    "options": [
      "Use let with materialize() to cache intermediate results for reuse within the query",
      "Remove all filters",
      "Always query with no time bound",
      "Duplicate the full table scan ten times intentionally"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "materialize for Query Performance",
      "analysis": [
        "Option A is CORRECT: materialize caches intermediate results to avoid repeated computation.",
        "Option B is INCORRECT: Filters usually improve performance.",
        "Option C is INCORRECT: Time bounds reduce scan size.",
        "Option D is INCORRECT: Worsens performance."
      ],
      "codeSnippet": "let base = materialize(DeviceProcessEvents | where Timestamp > ago(1d));\nbase | where FileName == 'cmd.exe'",
      "socTip": "Materialize only when the intermediate set is reused and relatively selective.",
      "docRef": "Microsoft Learn: materialize operator"
    }
  },
  {
    "id": "xdr-085",
    "topic": "Sentinel correlation with XDR",
    "scenario": "SOC uses both Defender XDR and Microsoft Sentinel.",
    "question": "How do Defender XDR and Sentinel typically work together?",
    "options": [
      "XDR provides correlated incidents and rich entity context; Sentinel adds multi-source SIEM correlation, SOAR, and long-term retention via connectors",
      "They cannot be used in the same tenant",
      "Sentinel replaces the need for any Defender sensors",
      "XDR automatically shuts down Sentinel"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "XDR + Sentinel Integration",
      "analysis": [
        "Option A is CORRECT: Complementary roles — deep Microsoft XDR plus broad SIEM/SOAR.",
        "Option B is INCORRECT: Common joint deployment.",
        "Option C is INCORRECT: Sensors remain essential.",
        "Option D is INCORRECT: No shutdown relationship."
      ],
      "codeSnippet": "// Sentinel data connector: Microsoft Defender XDR",
      "socTip": "Pick a system of record for ticketing to avoid dual-queue confusion.",
      "docRef": "Microsoft Learn: Connect Defender XDR to Sentinel"
    }
  },
  {
    "id": "xdr-086",
    "topic": "Advanced Hunting schema reference",
    "scenario": "A new analyst needs column names for DeviceNetworkEvents.",
    "question": "Where should the analyst look for official table and column definitions?",
    "options": [
      "Microsoft Learn Advanced Hunting schema reference and the portal schema browser / getschema in queries",
      "Random blogs only without documentation",
      "Only printed books from 2015",
      "Schema is secret and unavailable"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Schema Documentation",
      "analysis": [
        "Option A is CORRECT: Official schema reference and in-portal discovery.",
        "Option B is INCORRECT: Use official docs.",
        "Option C is INCORRECT: Cloud schema evolves.",
        "Option D is INCORRECT: Publicly documented."
      ],
      "codeSnippet": "DeviceNetworkEvents | getschema",
      "socTip": "Bookmark schema pages for the tables you hunt weekly.",
      "docRef": "Microsoft Learn: Advanced Hunting schema"
    }
  },
  {
    "id": "xdr-087",
    "topic": "Response actions audit trail",
    "scenario": "After isolating devices, compliance asks who approved actions.",
    "question": "Where is the history of response actions tracked?",
    "options": [
      "Unified Action Center history showing automated and manual actions with actors and timestamps",
      "Nowhere",
      "Only on a sticky note",
      "Only in personal email"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Action Center History",
      "analysis": [
        "Option A is CORRECT: Action Center records response actions for audit.",
        "Option B is INCORRECT: History exists.",
        "Option C is INCORRECT: Portal is authoritative.",
        "Option D is INCORRECT: Not the audit store."
      ],
      "codeSnippet": "// Actions > History tab",
      "socTip": "Export Action Center history for major incident postmortems.",
      "docRef": "Microsoft Learn: Action center"
    }
  },
  {
    "id": "xdr-088",
    "topic": "Device tags for investigation",
    "scenario": "SOC wants to mark crown-jewel servers during incidents.",
    "question": "How can devices be labeled for easier filtering and prioritization?",
    "options": [
      "Apply device tags (manual or automatic) and filter queues/hunts by tag",
      "Tags are not supported",
      "Only IP address color coding exists",
      "Tags delete the device"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Tags",
      "analysis": [
        "Option A is CORRECT: Tags support prioritization and filtering.",
        "Option B is INCORRECT: Supported feature.",
        "Option C is INCORRECT: Tags are first-class.",
        "Option D is INCORRECT: Non-destructive."
      ],
      "codeSnippet": "// Device page > Manage tags",
      "socTip": "Auto-tag based on naming or group rules for servers.",
      "docRef": "Microsoft Learn: Create and manage device tags"
    }
  },
  {
    "id": "xdr-089",
    "topic": "Advanced Hunting — parse and extract",
    "scenario": "Command lines contain base64 blobs that need decoding in KQL.",
    "question": "Which approach helps extract structured values from messy strings in KQL?",
    "options": [
      "Use parse, extract, or parse_json/parse_csv style functions depending on format to pull fields from strings",
      "KQL cannot parse strings",
      "Only Python outside the portal can parse",
      "Delete the rows instead of parsing"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "KQL Parsing Functions",
      "analysis": [
        "Option A is CORRECT: KQL provides multiple parsing helpers.",
        "Option B is INCORRECT: Parsing is core.",
        "Option C is INCORRECT: In-query parsing exists.",
        "Option D is INCORRECT: Lose evidence."
      ],
      "codeSnippet": "DeviceProcessEvents\n| extend b64 = extract('([A-Za-z0-9+/=]{20,})', 1, ProcessCommandLine)",
      "socTip": "Validate extractions on a sample before wide hunts.",
      "docRef": "Microsoft Learn: parse operator"
    }
  },
  {
    "id": "xdr-090",
    "topic": "Multi-workspace and MSSP scenarios",
    "scenario": "An MSSP manages multiple customer Defender XDR tenants.",
    "question": "What capability supports security operations across multiple tenants?",
    "options": [
      "Multi-tenant management / Microsoft 365 Lighthouse-style and GDAP/GDAP-aligned partner access patterns for MSSPs managing multiple customers",
      "MSSPs are prohibited from using Defender",
      "Only one customer per partner forever",
      "Customers must share Global Admin passwords"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Multi-Tenant SOC Operations",
      "analysis": [
        "Option A is CORRECT: Partner multi-tenant tools and GDAP support MSSP models.",
        "Option B is INCORRECT: Supported scenario.",
        "Option C is INCORRECT: Multi-customer is common.",
        "Option D is INCORRECT: Use GDAP least privilege."
      ],
      "codeSnippet": "// Partner Center GDAP + multi-tenant portal views",
      "socTip": "Never share standing Global Admin; use GDAP with time-bound roles.",
      "docRef": "Microsoft Learn: Multi-tenant management for Defender"
    }
  },
  {
    "id": "xdr-091",
    "topic": "Advanced Hunting API",
    "scenario": "Engineering wants to run hunting queries programmatically on a schedule.",
    "question": "How can Advanced Hunting be automated?",
    "options": [
      "Use the Advanced Hunting API (Microsoft Graph security) to submit KQL and retrieve results in scripts or SOAR",
      "Hunting is UI-only with no API",
      "Only FTP upload of KQL files",
      "API access requires disabling MFA for all users"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Advanced Hunting API",
      "analysis": [
        "Option A is CORRECT: Graph security advanced hunting API enables automation.",
        "Option B is INCORRECT: API exists.",
        "Option C is INCORRECT: Not the interface.",
        "Option D is INCORRECT: Use app permissions properly."
      ],
      "codeSnippet": "// POST /security/runHuntingQuery",
      "socTip": "Throttle scheduled API hunts to respect service limits.",
      "docRef": "Microsoft Learn: Advanced Hunting API"
    }
  },
  {
    "id": "xdr-092",
    "topic": "Evidence collection package timing",
    "scenario": "Before isolating a host, the analyst wants volatile evidence.",
    "question": "When is the best time to collect an investigation package?",
    "options": [
      "As early as practical while the device is still online to the sensor, before aggressive containment changes state too much",
      "Only after the disk is wiped",
      "Only after 30 days",
      "Packages cannot be collected remotely"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Early Evidence Collection",
      "analysis": [
        "Option A is CORRECT: Collect early while telemetry and remote actions remain available.",
        "Option B is INCORRECT: Too late.",
        "Option C is INCORRECT: Delay loses volatility.",
        "Option D is INCORRECT: Remote collection is supported."
      ],
      "codeSnippet": "// Device > Collect investigation package",
      "socTip": "Package first, then isolate, then deep remediate.",
      "docRef": "Microsoft Learn: Collect investigation package"
    }
  },
  {
    "id": "xdr-093",
    "topic": "Cross-product incident story",
    "scenario": "Email phish, endpoint malware, and risky sign-in appear related.",
    "question": "What is the value of a single XDR incident spanning those alerts?",
    "options": [
      "One correlated incident with shared graph and timeline tells the full attack story across domains for faster response",
      "Three disconnected tickets with no shared context",
      "Automatic public disclosure of the incident",
      "Deletion of all related logs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Product Incident Correlation Value",
      "analysis": [
        "Option A is CORRECT: Correlation is the core XDR benefit.",
        "Option B is INCORRECT: Defeats XDR purpose.",
        "Option C is INCORRECT: Not automatic disclosure.",
        "Option D is INCORRECT: Logs are retained per policy."
      ],
      "codeSnippet": "// Incidents > open correlated multi-alert incident",
      "socTip": "Brief leadership from the incident graph, not isolated alerts.",
      "docRef": "Microsoft Learn: Incidents overview"
    }
  },
  {
    "id": "xdr-094",
    "topic": "KQL bin for time series",
    "scenario": "Analyst needs failed logons per hour for the last day.",
    "question": "Which KQL pattern creates hourly buckets?",
    "options": [
      "summarize count() by bin(Timestamp, 1h)",
      "summarize count() by random()",
      "where Timestamp = 1h only once",
      "join without summarize"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "bin() Time Bucketing",
      "analysis": [
        "Option A is CORRECT: bin(Timestamp, 1h) groups into hourly windows.",
        "Option B is INCORRECT: Not meaningful.",
        "Option C is INCORRECT: Invalid pattern.",
        "Option D is INCORRECT: Incomplete for counts."
      ],
      "codeSnippet": "IdentityLogonEvents\n| where ActionType has 'Fail'\n| summarize c=count() by bin(Timestamp, 1h)",
      "socTip": "Use render timechart after bin for visual spikes.",
      "docRef": "Microsoft Learn: bin function"
    }
  },
  {
    "id": "xdr-095",
    "topic": "Device isolation vs containment exclusions",
    "scenario": "Isolated device must still reach a remediation server.",
    "question": "How can limited connectivity be preserved during isolation when required?",
    "options": [
      "Use selective isolation and/or isolation exclusions so critical management channels remain while other traffic is blocked",
      "Isolation always allows full internet for everyone",
      "Isolation cannot be released once set",
      "Exclusions disable the entire EDR sensor"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Selective Isolation and Exclusions",
      "analysis": [
        "Option A is CORRECT: Selective isolation/exclusions balance containment and manageability.",
        "Option B is INCORRECT: Default isolation is restrictive.",
        "Option C is INCORRECT: Isolation is releasable.",
        "Option D is INCORRECT: Sensor remains for allowed channels."
      ],
      "codeSnippet": "// Isolate device > selective / configure exclusions",
      "socTip": "Document exclusions; overly broad exclusions weaken containment.",
      "docRef": "Microsoft Learn: Isolate devices"
    }
  },
  {
    "id": "xdr-096",
    "topic": "Advanced Hunting — take and limit results",
    "scenario": "A broad query returns too many rows and times out in the UI.",
    "question": "What is a practical first step to constrain result size while developing a query?",
    "options": [
      "Add tighter time filters and use take/limit during development, then remove limits after validating logic",
      "Always export millions of rows first",
      "Disable Advanced Hunting",
      "Remove the project operator only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Query Result Control",
      "analysis": [
        "Option A is CORRECT: Narrow time and take samples while building.",
        "Option B is INCORRECT: Causes timeouts.",
        "Option C is INCORRECT: Not a fix.",
        "Option D is INCORRECT: Insufficient alone."
      ],
      "codeSnippet": "DeviceProcessEvents\n| where Timestamp > ago(1h)\n| take 100",
      "socTip": "Develop with 1h windows, then expand to 24h/7d.",
      "docRef": "Microsoft Learn: Advanced Hunting best practices"
    }
  },
  {
    "id": "xdr-097",
    "topic": "Role of ServiceSource in alerts",
    "scenario": "An analyst filters which product generated alerts inside a multi-product incident.",
    "question": "What does ServiceSource help identify?",
    "options": [
      "Which Microsoft security service produced the alert (Endpoint, Office 365, Identity, Cloud Apps, etc.)",
      "The physical street address of the SOC",
      "The user's salary band",
      "The DNS TTL of the portal"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ServiceSource Field",
      "analysis": [
        "Option A is CORRECT: ServiceSource attributes alerts to the generating service.",
        "Option B is INCORRECT: Unrelated.",
        "Option C is INCORRECT: Unrelated.",
        "Option D is INCORRECT: Unrelated."
      ],
      "codeSnippet": "AlertInfo | summarize count() by ServiceSource",
      "socTip": "Use ServiceSource breakdowns in weekly SOC metrics.",
      "docRef": "Microsoft Learn: AlertInfo"
    }
  },
  {
    "id": "xdr-098",
    "topic": "Advanced Hunting bookmarks in incidents",
    "scenario": "A hunter finds three suspicious devices and wants them attached to the incident.",
    "question": "How should findings be preserved into the incident workflow?",
    "options": [
      "Create hunting bookmarks for the result rows and link them to the incident for collaborative follow-up",
      "Take a photo of the screen only",
      "Email the KQL to a personal Gmail account",
      "Delete the query after running"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Hunting Bookmarks",
      "analysis": [
        "Option A is CORRECT: Bookmarks attach hunting evidence to incidents.",
        "Option B is INCORRECT: Loses interactivity.",
        "Option C is INCORRECT: Data handling risk.",
        "Option D is INCORRECT: Lose reproducibility."
      ],
      "codeSnippet": "// Hunting results > Bookmark > Link to incident",
      "socTip": "Bookmark names should include IOC or host for searchability.",
      "docRef": "Microsoft Learn: Hunting bookmarks"
    }
  },
  {
    "id": "xdr-099",
    "topic": "Merged incidents",
    "scenario": "Two incidents clearly describe the same attack chain.",
    "question": "What can analysts do to consolidate investigation work?",
    "options": [
      "Merge related incidents so evidence and alerts combine into a single investigation record",
      "Delete both and start a blank incident with no data",
      "Merge is impossible in Defender XDR",
      "Merging automatically pages the entire company"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Merge",
      "analysis": [
        "Option A is CORRECT: Merge consolidates related work.",
        "Option B is INCORRECT: Destroys context.",
        "Option C is INCORRECT: Merge is supported.",
        "Option D is INCORRECT: No mass page."
      ],
      "codeSnippet": "// Incident > Manage > Merge incidents",
      "socTip": "Merge only when entity overlap and timeline clearly match.",
      "docRef": "Microsoft Learn: Merge incidents"
    }
  },
  {
    "id": "xdr-100",
    "topic": "Final XDR triage checklist",
    "scenario": "A new Tier 1 asks for a simple daily XDR operating checklist.",
    "question": "Which daily triage sequence best reflects Defender XDR best practice?",
    "options": [
      "Review high-severity active incidents first, check Action Center pending actions, monitor Threat Analytics exposure, then run scheduled hunts for residual IOCs",
      "Close all incidents unread at 9 AM",
      "Only look at informational alerts",
      "Disable correlations every morning"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Daily XDR Triage Discipline",
      "analysis": [
        "Option A is CORRECT: Severity-first incidents, pending actions, exposure, then proactive hunts.",
        "Option B is INCORRECT: Dangerous.",
        "Option C is INCORRECT: Wrong priority.",
        "Option D is INCORRECT: Correlations are valuable."
      ],
      "codeSnippet": "// Queue by severity → Action Center → Threat analytics → Hunts",
      "socTip": "Time-box Tier 1 queue review and escalate stuck high-severity items within SLA.",
      "docRef": "Microsoft Learn: Prioritize incidents in Microsoft Defender XDR"
    }
  }
]

def build_questions():
    """Attach module/audioSummary; keep explicit id for tracking 001-100."""
    result = []
    for i, q in enumerate(QUESTIONS):
        qid = q.get("id") or f"xdr-{i+1:03d}"
        concept = q["explanation"]["concept"]
        correct_analysis = q["explanation"]["analysis"][q["correctIndex"]]
        audio = concept + ". " + (
            correct_analysis.split(": ", 1)[1][:200]
            if ": " in correct_analysis else correct_analysis[:200]
        )
        result.append({
            "id": qid,
            "module": "xdr",
            "topic": q["topic"],
            "scenario": q["scenario"],
            "question": q["question"],
            "options": q["options"],
            "correctIndex": q["correctIndex"],
            "audioSummary": audio,
            "explanation": q["explanation"],
        })
    return result

if __name__ == "__main__":
    questions = build_questions()
    output = "const XDR_QUESTIONS = " + json.dumps(questions, indent=2, ensure_ascii=False) + ";\n"
    with open("questions_xdr_v2.js", "w", encoding="utf-8") as f:
        f.write(output)

    stems = set(q["question"] for q in questions)
    scenarios = set(q["scenario"][:80] for q in questions)
    ids = [q["id"] for q in questions]
    ci_dist = {}
    for q in questions:
        ci_dist[q["correctIndex"]] = ci_dist.get(q["correctIndex"], 0) + 1

    print(f"[+] Generated {len(questions)} XDR questions -> questions_xdr_v2.js")
    print(f"    ID range: {ids[0]} .. {ids[-1]}")
    print(f"    Unique IDs: {len(set(ids))}/{len(questions)}")
    print(f"    Unique question stems: {len(stems)}/{len(questions)}")
    print(f"    Unique scenario prefixes: {len(scenarios)}/{len(questions)}")
    print(f"    correctIndex distribution: {ci_dist}")
    expected = [f"xdr-{i:03d}" for i in range(1, 101)]
    missing = [e for e in expected if e not in set(ids)]
    print(f"    Missing IDs: {missing if missing else 'none (complete 001-100)'}")
