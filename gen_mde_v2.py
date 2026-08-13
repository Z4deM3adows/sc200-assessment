"""
SC-200 Question Generator — Microsoft Defender for Endpoint Module (100 Questions)
Each question has a stable id (mde-001 .. mde-100) for easy tracking,
unique scenario, varied stem, 4 options, per-option explanations, and SOC tips.
"""
import json

QUESTIONS = [
  {
    "id": "mde-001",
    "topic": "Device onboarding methods",
    "scenario": "Contoso is deploying Microsoft Defender for Endpoint across 5,000 Windows 11 workstations managed by Microsoft Intune. The security architect needs the most scalable onboarding method that does not require manual local scripts on each device.",
    "question": "Which onboarding method is recommended for Intune-managed Windows devices?",
    "options": [
      "Deploy the onboarding package via Intune device configuration profile or endpoint security policy so devices enroll automatically without local scripts",
      "Manually run a local PowerShell onboarding script on every workstation",
      "Install a third-party agent that proxies telemetry to Defender for Endpoint",
      "Use Group Policy only, even though devices are Intune-managed and not domain-joined"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Scalable Onboarding for Managed Devices",
      "analysis": [
        "Option A is CORRECT: For Intune-managed devices the preferred method is an Intune configuration profile or endpoint security policy that deploys the onboarding package. Devices enroll automatically at scale.",
        "Option B is INCORRECT: Manual local scripts do not scale to thousands of devices and are error-prone.",
        "Option C is INCORRECT: Defender for Endpoint uses its own sensor (Sense); a third-party proxy agent is not the supported path.",
        "Option D is INCORRECT: Group Policy is appropriate for domain-joined devices not managed by Intune; it is not the primary method when Intune is already in use."
      ],
      "codeSnippet": "// Intune path:\n// Endpoint security > Microsoft Defender for Endpoint\n// or Devices > Configuration profiles > Templates\n// > Microsoft Defender for Endpoint onboarding",
      "socTip": "After bulk onboarding, monitor the Device inventory and Sensor health report for devices that remain 'Can be onboarded' or show connectivity issues.",
      "docRef": "Microsoft Learn: Onboard devices to Microsoft Defender for Endpoint"
    }
  },
  {
    "id": "mde-002",
    "topic": "Device groups and RBAC",
    "scenario": "Fabrikam’s global SOC wants Tier 1 analysts in Europe to see and act only on devices in the EU device group, while the global Tier 3 team needs full access. They use Microsoft Defender for Endpoint role-based access control.",
    "question": "How should device groups and roles be combined to enforce this segregation?",
    "options": [
      "Create device groups based on location tags or naming, then assign roles that are scoped to those device groups so Tier 1 users only receive alerts and can perform actions on their assigned group",
      "Give every analyst Global Administrator rights and rely on manual filtering",
      "Create separate Defender for Endpoint tenants for each region",
      "Disable RBAC and use network firewalls to block portal access by geography"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Groups + Role Scoping",
      "analysis": [
        "Option A is CORRECT: Device groups define the set of devices a role can see. Roles (Security Reader, Security Operator, etc.) can be assigned with a device-group scope so analysts only work within their perimeter.",
        "Option B is INCORRECT: Over-privileged access violates least privilege and increases risk of accidental or malicious actions.",
        "Option C is INCORRECT: Multiple tenants break cross-region visibility and XDR correlation; RBAC within one tenant is the designed solution.",
        "Option D is INCORRECT: Network controls cannot enforce feature-level or device-level RBAC inside the portal."
      ],
      "codeSnippet": "// Settings > Permissions > Roles\n// Create role → Assign users → Device groups\n// Settings > Permissions > Device groups\n// Create group with dynamic rules (e.g. DeviceName starts with EU-)",
      "socTip": "Use dynamic device-group rules based on tags or naming conventions so newly onboarded devices automatically land in the correct scope.",
      "docRef": "Microsoft Learn: Create and manage device groups"
    }
  },
  {
    "id": "mde-003",
    "topic": "Automation levels",
    "scenario": "Northwind Traders wants automated investigation and remediation on low-risk workstations but requires analyst approval before any action on domain controllers and executive laptops.",
    "question": "How are automation levels configured in Microsoft Defender for Endpoint?",
    "options": [
      "Assign different automation levels (Full – remediate threats automatically, Semi – require approval for certain actions, or None) to device groups so high-value assets stay under human control while standard devices are auto-remediated",
      "Automation is global only; every device must use the same level",
      "Automation levels are controlled exclusively by Microsoft and cannot be changed by the customer",
      "Automation only works for macOS and Linux devices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Per-Device-Group Automation Levels",
      "analysis": [
        "Option A is CORRECT: Automation level is set on device groups. Full automation remediates without approval; Semi requires approval for folder/file remediation; None disables automated remediation for that group.",
        "Option B is INCORRECT: Levels are assigned per device group, enabling differentiated treatment of servers vs. workstations.",
        "Option C is INCORRECT: Customers fully control automation levels in the portal settings.",
        "Option D is INCORRECT: Automation and AIR primarily target Windows; the configuration model is not limited to non-Windows platforms."
      ],
      "codeSnippet": "// Settings > Endpoints > Device groups\n// Edit group → Automation level:\n//   Full – remediate threats automatically\n//   Semi – require approval for core folders\n//   Semi – require approval for all folders\n//   None",
      "socTip": "Start servers and privileged devices at 'None' or 'Semi', then gradually move standard workstations to Full after validating remediation quality for 2–4 weeks.",
      "docRef": "Microsoft Learn: Automation levels in automated investigation"
    }
  },
  {
    "id": "mde-004",
    "topic": "Attack Surface Reduction (ASR) rules",
    "scenario": "Litware’s SOC observed ransomware using Office macros to launch PowerShell. They want to block this behavior without immediately breaking legitimate business processes.",
    "question": "What is the recommended deployment approach for a new ASR rule?",
    "options": [
      "Enable the rule in Audit mode first, review the ASR report and advanced-hunting events for false positives, add exclusions if needed, then switch the rule to Block mode",
      "Enable the rule in Block mode on all devices immediately",
      "ASR rules can only be configured in Warn mode and never block",
      "Disable Microsoft Defender Antivirus before enabling any ASR rule"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ASR Rule Modes – Audit then Block",
      "analysis": [
        "Option A is CORRECT: Audit mode logs detections without blocking. After reviewing the Attack surface reduction report and DeviceEvents, organizations add necessary exclusions and then move the rule to Block.",
        "Option B is INCORRECT: Immediate Block mode risks business disruption from false positives.",
        "Option C is INCORRECT: ASR rules support Audit, Warn, and Block modes.",
        "Option D is INCORRECT: Real-time protection and cloud-delivered protection must remain enabled for ASR rules to function correctly."
      ],
      "codeSnippet": "// Example rule GUID (Block Office from creating child processes):\n// D4F940AB-401B-4EFC-AADC-AD5F3C50688A\n// Intune / Configuration Manager / GPO\n// Mode: Audit → review → Block",
      "socTip": "Query advanced hunting: DeviceEvents | where ActionType startswith 'Asr' | where ActionType endswith 'Audited' to quantify impact before switching to Block.",
      "docRef": "Microsoft Learn: Attack surface reduction rules deployment guide"
    }
  },
  {
    "id": "mde-005",
    "topic": "Live Response",
    "scenario": "An Adatum analyst needs to collect a memory dump and list running processes on a compromised Windows 11 laptop without physically visiting the machine.",
    "question": "Which capability provides a remote interactive shell for forensic collection and remediation on an onboarded device?",
    "options": [
      "Live Response — a remote shell that supports basic and advanced commands (processes, file collection, script execution, isolation) for deep investigation and containment",
      "Only the Collect investigation package button, which cannot run interactive commands",
      "Remote Desktop Protocol (RDP) forced through a jump box",
      "PowerShell Remoting that bypasses Defender for Endpoint entirely"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Live Response Remote Shell",
      "analysis": [
        "Option A is CORRECT: Live Response opens a remote shell on the device. Analysts can run built-in commands, upload/download files, execute scripts from the Live Response library, and perform containment actions.",
        "Option B is INCORRECT: Investigation package is a one-click forensic snapshot; it is not an interactive shell.",
        "Option C is INCORRECT: RDP is not a Defender for Endpoint response action and may be blocked or unsafe on compromised hosts.",
        "Option D is INCORRECT: PowerShell Remoting is outside the MDE control plane and lacks the audit trail and permission model of Live Response."
      ],
      "codeSnippet": "// Common Live Response commands:\n// processes\n// fileinfo C:\\Users\\...\\malware.exe\n// getfile \"C:\\path\\file\"\n// run script.ps1\n// isolate / release",
      "socTip": "Grant 'Live response – advanced commands' only to senior analysts. Basic commands are sufficient for most Tier 1 collection tasks.",
      "docRef": "Microsoft Learn: Investigate entities on devices using live response"
    }
  },
  {
    "id": "mde-006",
    "topic": "Investigation package",
    "scenario": "A Contoso Tier 2 analyst wants a complete forensic snapshot of a device (process list, autoruns, network connections, event logs, etc.) without opening a Live Response session.",
    "question": "What does the 'Collect investigation package' action provide?",
    "options": [
      "A downloadable ZIP containing structured forensic data (processes, network connections, scheduled tasks, autoruns, event logs, installed programs, and more) collected from the device at the moment of the request",
      "Only the current antivirus quarantine folder",
      "A live streaming video of the user’s desktop",
      "Automatic submission of every file on the disk to Microsoft for analysis"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Investigation Package Collection",
      "analysis": [
        "Option A is CORRECT: The investigation package is a comprehensive forensic bundle that can be downloaded and analyzed offline. It includes process listings, network data, persistence mechanisms, and selected event logs.",
        "Option B is INCORRECT: The package is far broader than the quarantine folder.",
        "Option C is INCORRECT: No desktop streaming is performed.",
        "Option D is INCORRECT: Only selected forensic artifacts are collected; full-disk upload does not occur."
      ],
      "codeSnippet": "// Device page → Actions → Collect investigation package\n// Status tracked in Action center\n// Download ZIP when ready\n// Typical contents: Processes.csv, NetworkConnections.csv,\n//   Prefetch, Autoruns, Event logs, etc.",
      "socTip": "Collect the package early in an investigation before containment actions that might alter the state of the device.",
      "docRef": "Microsoft Learn: Collect investigation package from device"
    }
  },
  {
    "id": "mde-007",
    "topic": "Device isolation",
    "scenario": "During a ransomware outbreak at Fabrikam, an analyst needs to immediately cut a compromised workstation off the corporate network while still allowing it to communicate with the Defender for Endpoint service so remediation can continue.",
    "question": "What happens when a device is isolated in Microsoft Defender for Endpoint?",
    "options": [
      "All network traffic is blocked except connectivity required by the Defender for Endpoint sensor (and any configured isolation exclusions), preventing lateral movement and C2 while keeping the device manageable",
      "The device is powered off remotely",
      "Only outbound internet traffic is blocked; internal lateral movement remains possible",
      "The device is permanently wiped and must be re-imaged"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Network Isolation with Sensor Connectivity",
      "analysis": [
        "Option A is CORRECT: Isolation severs general network access while preserving the channels needed for the MDE sensor, Live Response, and remediation. Selective isolation and exclusions can keep critical services reachable.",
        "Option B is INCORRECT: Isolation does not power off the device.",
        "Option C is INCORRECT: Isolation blocks both external and internal traffic except allowed exceptions.",
        "Option D is INCORRECT: Isolation is reversible; the device is not wiped."
      ],
      "codeSnippet": "// Device page → Isolate device\n// Full isolation or Selective isolation\n// Isolation exclusions can be defined for critical services\n// Release isolation when investigation complete",
      "socTip": "After isolation, immediately start Live Response or collect an investigation package while the device is still online to the sensor.",
      "docRef": "Microsoft Learn: Take response actions on a device"
    }
  },
  {
    "id": "mde-008",
    "topic": "Automated Investigation and Response (AIR)",
    "scenario": "Northwind Traders has enabled Full automation on the 'Workstations' device group. A malware alert fires on several machines.",
    "question": "What does Automated Investigation and Response (AIR) do when Full automation is configured?",
    "options": [
      "AIR automatically investigates the alert scope, collects evidence, determines verdict, and remediates (quarantine files, stop processes, etc.) without waiting for analyst approval on devices in that group",
      "AIR only creates a ticket in ServiceNow and waits for a human",
      "AIR disables the network adapter permanently",
      "AIR requires a separate Azure Logic Apps subscription to function"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AIR with Full Automation",
      "analysis": [
        "Option A is CORRECT: Under Full automation, AIR runs investigation playbooks, reaches a verdict, and applies remediation actions automatically on devices belonging to groups with that automation level.",
        "Option B is INCORRECT: AIR performs actual investigation and remediation inside Defender for Endpoint; ticketing is optional via integration.",
        "Option C is INCORRECT: AIR does not permanently disable hardware.",
        "Option D is INCORRECT: AIR is a native MDE capability; Logic Apps can complement it but are not required."
      ],
      "codeSnippet": "// Automation level = Full on device group\n// Alert → AIR playbook starts\n// Evidence collection → Verdict → Remediation\n// Progress visible in Action center and incident graph",
      "socTip": "Review the Action center daily for devices where AIR failed or required additional approval; those often indicate edge cases that need policy tuning.",
      "docRef": "Microsoft Learn: Automated investigation and response"
    }
  },
  {
    "id": "mde-009",
    "topic": "EDR in block mode",
    "scenario": "Contoso runs a third-party antivirus as the primary AV. Microsoft Defender Antivirus is therefore in passive mode, but the SOC still wants Defender for Endpoint to block malicious artifacts discovered post-breach.",
    "question": "Which feature allows Defender for Endpoint to block and remediate threats even when Microsoft Defender Antivirus is in passive mode?",
    "options": [
      "EDR in block mode — post-breach protection that can block malicious files and processes identified by EDR behavioral detections even when the antivirus component is passive",
      "Tamper Protection only",
      "Network Protection only",
      "Controlled Folder Access only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "EDR in Block Mode",
      "analysis": [
        "Option A is CORRECT: EDR in block mode provides behavioral blocking and remediation for threats detected by the EDR sensor, independent of the primary antivirus product being active.",
        "Option B is INCORRECT: Tamper Protection prevents unauthorized changes to Defender settings; it is not the post-breach blocking engine.",
        "Option C is INCORRECT: Network Protection blocks outbound connections to malicious sites; it is complementary but not the same feature.",
        "Option D is INCORRECT: Controlled Folder Access protects specific folders from unauthorized changes; it does not replace EDR block mode."
      ],
      "codeSnippet": "// Settings > Endpoints > Advanced features\n// Turn on 'Endpoint detection and response in block mode'\n// Works alongside third-party AV when MDAV is passive",
      "socTip": "Enable EDR in block mode whenever a non-Microsoft AV is primary. Validate with a controlled test file after enabling.",
      "docRef": "Microsoft Learn: EDR in block mode"
    }
  },
  {
    "id": "mde-010",
    "topic": "Advanced hunting tables",
    "scenario": "A junior analyst at Litware needs to hunt for processes that created suspicious scheduled tasks in the last 7 days. The analyst is unsure which Advanced Hunting table contains this data.",
    "question": "Which Advanced Hunting table is the primary source for process creation and related process activity events?",
    "options": [
      "DeviceProcessEvents — contains process creation, command-line, parent-child relationships, and integrity level data ideal for hunting malicious process activity",
      "DeviceNetworkEvents only",
      "IdentityLogonEvents only",
      "EmailEvents only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceProcessEvents for Process Hunting",
      "analysis": [
        "Option A is CORRECT: DeviceProcessEvents is the core table for process-related telemetry (creation, command lines, parent process, SHA256, etc.).",
        "Option B is INCORRECT: DeviceNetworkEvents covers network connections, not process creation.",
        "Option C is INCORRECT: IdentityLogonEvents is for authentication events.",
        "Option D is INCORRECT: EmailEvents belongs to Defender for Office 365."
      ],
      "codeSnippet": "DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where ProcessCommandLine has_any ('schtasks','/create')\n| project Timestamp, DeviceName, InitiatingProcessFileName,\n          FileName, ProcessCommandLine",
      "socTip": "Always join DeviceProcessEvents with DeviceInfo or DeviceNetworkEvents when you need device context or network destinations in the same hunt.",
      "docRef": "Microsoft Learn: Advanced hunting reference – DeviceProcessEvents"
    }
  },
  {
    "id": "mde-011",
    "topic": "Custom indicators",
    "scenario": "Fabrikam’s threat intelligence team receives a list of malicious SHA256 hashes and C2 domains from a trusted partner. They want Defender for Endpoint to block these indicators across all onboarded devices.",
    "question": "How are custom threat indicators enforced in Microsoft Defender for Endpoint?",
    "options": [
      "Create indicators of compromise (file hash, IP, URL/domain, or certificate) in the portal or via API, set the action to Alert and Block (or Allow), and scope them to device groups; the sensor enforces the policy",
      "Indicators can only generate alerts; they never block",
      "Indicators must be imported exclusively through Microsoft Sentinel",
      "Indicators are limited to Windows 10 version 1607 and earlier"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Indicators of Compromise",
      "analysis": [
        "Option A is CORRECT: The Indicators page (or API) accepts file hashes, IPs, URLs/domains, and certificates. Actions include Allow, Audit, Warn, Block execution, or Block and remediate. Scope can be organization-wide or limited to device groups.",
        "Option B is INCORRECT: Block actions are fully supported for supported indicator types and platforms.",
        "Option C is INCORRECT: Indicators are native to Defender for Endpoint; Sentinel integration is optional.",
        "Option D is INCORRECT: Modern Windows, macOS, and Linux sensors support indicators."
      ],
      "codeSnippet": "// Settings > Endpoints > Indicators\n// Add item → File hash / IP / URL / Certificate\n// Action: Alert and block\n// Scope: All devices or selected groups\n// Expiration date optional",
      "socTip": "Set an expiration date on temporary IoCs so the indicator list does not grow indefinitely and create management overhead.",
      "docRef": "Microsoft Learn: Manage indicators"
    }
  },
  {
    "id": "mde-012",
    "topic": "Threat and Vulnerability Management (TVM)",
    "scenario": "Adatum’s CISO asks the SOC for a prioritized list of devices that are exposed to a newly published critical CVE affecting a common browser extension.",
    "question": "How does Microsoft Defender Vulnerability Management help prioritize remediation?",
    "options": [
      "TVM continuously discovers software inventory and vulnerabilities, calculates exposure score and risk based on threat intelligence, and surfaces prioritized recommendations with affected device counts and remediation actions",
      "TVM only lists CVEs without any prioritization or device mapping",
      "TVM requires a separate non-Microsoft vulnerability scanner to function",
      "TVM data is only available 30 days after a CVE is published"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Threat-Aware Vulnerability Prioritization",
      "analysis": [
        "Option A is CORRECT: Defender Vulnerability Management combines software inventory, vulnerability data, and threat intelligence to produce risk-based recommendations, exposure scores, and device-level impact.",
        "Option B is INCORRECT: Prioritization and device mapping are core capabilities.",
        "Option C is INCORRECT: Inventory and assessment are performed by the MDE sensor; no third-party scanner is required for basic TVM.",
        "Option D is INCORRECT: New CVEs appear rapidly once Microsoft’s threat intelligence and vendor data are updated."
      ],
      "codeSnippet": "// Vulnerability management > Recommendations\n// Filter by CVE or software name\n// View exposure score, affected devices, remediation options\n// Create exception or ticket integration as needed",
      "socTip": "Use the 'Weaknesses' and 'Security recommendations' blades together: weaknesses show the raw CVE, recommendations give the actionable fix ordered by risk.",
      "docRef": "Microsoft Learn: Defender Vulnerability Management"
    }
  },
  {
    "id": "mde-013",
    "topic": "Device timeline",
    "scenario": "A Contoso analyst opens a high-severity incident involving lateral movement. The analyst needs a chronological view of every significant event on the primary compromised device.",
    "question": "What does the Device timeline provide during an investigation?",
    "options": [
      "A chronological, filterable view of alerts, events, and activities (process launches, network connections, file modifications, logons, etc.) on a single device, enabling reconstruction of the attack sequence",
      "Only the last 24 hours of antivirus scan results",
      "A static PDF report that cannot be filtered",
      "Only Microsoft 365 audit log entries for the device"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Timeline for Attack Reconstruction",
      "analysis": [
        "Option A is CORRECT: The timeline aggregates alerts and telemetry into a time-ordered view that can be filtered by event type, allowing analysts to follow the attacker’s steps on that device.",
        "Option B is INCORRECT: The timeline covers far more than AV scans and retains data according to the configured retention period.",
        "Option C is INCORRECT: The timeline is interactive and filterable inside the portal.",
        "Option D is INCORRECT: Device timeline is built from MDE sensor data, not solely from the unified audit log."
      ],
      "codeSnippet": "// Device page → Timeline tab\n// Filter by: Alerts, Events, Time range\n// Pivot to related entities (files, IPs, users)\n// Export or share findings as needed",
      "socTip": "When timeline volume is high, filter to 'Alerts' first, then expand the time window around the first alert to discover the initial access vector.",
      "docRef": "Microsoft Learn: Investigate devices in the Microsoft Defender portal"
    }
  },
  {
    "id": "mde-014",
    "topic": "Evidence and entity investigation",
    "scenario": "During an investigation, a Northwind analyst pivots from an alert to a suspicious file hash. The analyst needs to know how many devices in the organization have seen that file and whether it is considered malicious.",
    "question": "What information does entity investigation for a file provide?",
    "options": [
      "File prevalence (devices that observed it), first/last seen timestamps, verdict from Microsoft threat intelligence, related alerts/incidents, process execution context, and available response actions such as stop-and-quarantine or deep analysis",
      "Only the file size and MIME type",
      "Only the original author’s email address",
      "A complete disassembly of the binary with no reputation data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "File Entity Investigation",
      "analysis": [
        "Option A is CORRECT: The file entity page consolidates prevalence, reputation, related alerts, process tree context, and one-click response actions.",
        "Option B is INCORRECT: Far richer telemetry and intelligence are available.",
        "Option C is INCORRECT: Author information is not the focus of the entity page.",
        "Option D is INCORRECT: Deep analysis can be requested, but the primary view emphasizes reputation, prevalence, and response."
      ],
      "codeSnippet": "// From alert or Advanced Hunting → click file hash\n// Entity page shows:\n// - Prevalence, First/Last seen\n// - Verdict / Threat family\n// - Related incidents & alerts\n// - Actions: Stop and quarantine, Deep analysis, Add indicator",
      "socTip": "Always check prevalence before mass-blocking a hash; a high-prevalence legitimate binary that was later dual-used can cause widespread disruption if blocked carelessly.",
      "docRef": "Microsoft Learn: Investigate entities"
    }
  },
  {
    "id": "mde-015",
    "topic": "Network protection and web protection",
    "scenario": "Litware wants to prevent devices from reaching known malicious websites and from initiating connections to phishing domains, even when users try to bypass browser settings.",
    "question": "Which Defender for Endpoint capability blocks outbound connections to malicious or untrusted destinations at the network layer?",
    "options": [
      "Network protection (and web content filtering) — blocks connections to low-reputation or explicitly blocked URLs/IPs using the Windows Filtering Platform, independent of the browser",
      "Only SmartScreen inside Edge",
      "Only Windows Firewall with no cloud intelligence",
      "Only email Safe Links"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Network Protection / Web Protection",
      "analysis": [
        "Option A is CORRECT: Network protection uses the Windows Filtering Platform and cloud reputation to block malicious destinations for any process. Web content filtering adds category-based controls.",
        "Option B is INCORRECT: Browser SmartScreen is limited to Edge/IE; Network protection covers all processes.",
        "Option C is INCORRECT: Classic Windows Firewall lacks the cloud-delivered reputation feed used by Network protection.",
        "Option D is INCORRECT: Safe Links is an email/time-of-click protection, not an endpoint network filter."
      ],
      "codeSnippet": "// Endpoint security policy or Intune:\n// Network protection → Enable\n// Web content filtering → categories (Adult, High bandwidth, etc.)\n// Custom indicators can also feed Network protection",
      "socTip": "Enable Network protection in Audit mode first, review the report, then switch to Block to avoid breaking line-of-business apps that talk to unusual domains.",
      "docRef": "Microsoft Learn: Network protection"
    }
  },
  {
    "id": "mde-016",
    "topic": "Controlled Folder Access",
    "scenario": "After a ransomware incident, Contoso wants to prevent untrusted processes from modifying files in user document folders and other critical locations.",
    "question": "What does Controlled Folder Access protect?",
    "options": [
      "It protects designated folders (Documents, Pictures, custom paths) from unauthorized modification by untrusted applications, blocking ransomware-style encryption attempts while allowing known good apps",
      "It encrypts the entire disk with BitLocker",
      "It only protects the Windows system directory",
      "It disables all USB storage devices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Controlled Folder Access (CFA)",
      "analysis": [
        "Option A is CORRECT: CFA maintains a list of protected folders and only permits authorized applications to write to them, stopping many ransomware families from encrypting user data.",
        "Option B is INCORRECT: BitLocker is full-volume encryption; CFA is an access-control feature.",
        "Option C is INCORRECT: Default protected folders include user profile locations; system directories are handled by other protections.",
        "Option D is INCORRECT: USB control is a separate Device Control capability."
      ],
      "codeSnippet": "// Attack surface reduction / Endpoint security:\n// Controlled folder access = Enabled\n// Protected folders: default + custom paths\n// Allowed applications: add line-of-business apps that need write access",
      "socTip": "Review the Controlled folder access report regularly; legitimate apps that are blocked should be added to the allowed list rather than disabling CFA entirely.",
      "docRef": "Microsoft Learn: Controlled folder access"
    }
  },
  {
    "id": "mde-017",
    "topic": "Tamper Protection",
    "scenario": "An attacker who obtained local admin rights on a Fabrikam workstation attempts to disable real-time protection and exclude a malware folder via registry and PowerShell.",
    "question": "How does Tamper Protection help in this scenario?",
    "options": [
      "Tamper Protection prevents unauthorized changes to key Microsoft Defender Antivirus and Defender for Endpoint security settings, even by local administrators, when the setting is managed from the cloud",
      "Tamper Protection only logs the change but never blocks it",
      "Tamper Protection encrypts the hard drive",
      "Tamper Protection is only available on Windows Server"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Tamper Protection",
      "analysis": [
        "Option A is CORRECT: When Tamper Protection is enabled and the device is cloud-managed, critical security settings cannot be turned off or altered by local admins or malware using the usual management interfaces.",
        "Option B is INCORRECT: The feature actively blocks the change, not merely logs it.",
        "Option C is INCORRECT: Disk encryption is BitLocker.",
        "Option D is INCORRECT: Tamper Protection is available on supported Windows clients and servers."
      ],
      "codeSnippet": "// Settings > Endpoints > Advanced features\n// Tamper protection = On\n// Or via Intune endpoint security policy\n// Changes attempted locally are blocked and may generate alerts",
      "socTip": "Confirm Tamper Protection is On for all high-value and executive devices; it is one of the simplest high-impact hardening settings.",
      "docRef": "Microsoft Learn: Protect security settings with tamper protection"
    }
  },
  {
    "id": "mde-018",
    "topic": "Custom detection rules",
    "scenario": "Northwind’s hunting team repeatedly finds a living-off-the-land technique that does not generate a built-in alert. They want a persistent detection that creates an alert and optionally an incident whenever the pattern appears.",
    "question": "How can the team turn a successful Advanced Hunting query into an ongoing detection?",
    "options": [
      "Create a custom detection rule from the hunting query, define the alert title, severity, impacted entities, and frequency; the rule then runs continuously and raises alerts/incidents when matches occur",
      "Custom detections are not supported; only Microsoft-provided alerts exist",
      "The query must be rewritten in SQL and run against Azure SQL",
      "Custom detections can only run once and then expire"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Detection Rules",
      "analysis": [
        "Option A is CORRECT: From Advanced Hunting you can save a query as a custom detection rule, set schedule and alert details, and map entities so the resulting alerts participate in incident correlation.",
        "Option B is INCORRECT: Custom detections are a first-class capability of Defender XDR / MDE.",
        "Option C is INCORRECT: Custom detections use KQL against the Advanced Hunting schema.",
        "Option D is INCORRECT: Rules run on the defined schedule until disabled or deleted."
      ],
      "codeSnippet": "// Advanced Hunting → query → Create detection rule\n// Alert title, Description, Severity\n// Frequency: every 1h / 3h / 12h / 24h\n// Impacted entities: Device, User, Mailbox, etc.\n// Actions: Isolate device, Run AV scan, etc. (optional)",
      "socTip": "Keep the look-back window and frequency realistic so the rule does not consume excessive resources or generate duplicate alerts for the same activity.",
      "docRef": "Microsoft Learn: Custom detections in Microsoft Defender XDR"
    }
  },
  {
    "id": "mde-019",
    "topic": "Alert suppression and tuning",
    "scenario": "A noisy third-party backup agent repeatedly triggers a low-fidelity alert on every server at Litware, drowning out real threats.",
    "question": "What is the recommended way to reduce this noise while still retaining the ability to detect true positives?",
    "options": [
      "Create an alert suppression rule (or use alert tuning) that matches the specific process, path, or command line of the backup agent so those alerts are hidden or resolved automatically, while leaving the underlying detection enabled for other processes",
      "Turn off the entire detection rule globally",
      "Uninstall Defender for Endpoint from all servers",
      "Ignore the alerts and never open the portal"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Suppression / Tuning",
      "analysis": [
        "Option A is CORRECT: Suppression or tuning rules can be scoped tightly (file name, path, command line, device group) so only the known-benign activity is silenced.",
        "Option B is INCORRECT: Disabling the whole detection removes protection against real threats that use the same technique.",
        "Option C is INCORRECT: Removing the sensor eliminates all endpoint visibility.",
        "Option D is INCORRECT: Ignoring alerts defeats the purpose of the SOC."
      ],
      "codeSnippet": "// From an alert → Create suppression rule\n// Or Settings > Rules > Alert suppression\n// Conditions: File name, Path, SHA256, Device group\n// Action: Hide alert / Resolve alert",
      "socTip": "Document every suppression rule with an owner and review date; stale suppressions are a common source of detection gaps.",
      "docRef": "Microsoft Learn: Suppress alerts and tune detections"
    }
  },
  {
    "id": "mde-020",
    "topic": "Advanced features configuration",
    "scenario": "Contoso’s security architect is hardening the Defender for Endpoint tenant and needs to enable several post-breach and investigation capabilities.",
    "question": "Where are features such as Live Response, EDR in block mode, automated investigation, and tamper protection turned on?",
    "options": [
      "In the Microsoft Defender portal under Settings > Endpoints > Advanced features (or the corresponding Intune / configuration profiles for some settings)",
      "Only via local registry edits on every device",
      "Only inside the Azure portal under Microsoft Entra ID",
      "These features cannot be configured by customers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Advanced Features Toggle Panel",
      "analysis": [
        "Option A is CORRECT: The Advanced features page centralizes tenant-level switches for Live Response, EDR in block mode, automated investigation, tamper protection, and many other capabilities.",
        "Option B is INCORRECT: Local registry changes are not the supported management path and may be blocked by Tamper Protection.",
        "Option C is INCORRECT: Entra ID controls identity; endpoint advanced features live in the Defender portal.",
        "Option D is INCORRECT: Customers fully control these settings."
      ],
      "codeSnippet": "// security.microsoft.com\n// Settings > Endpoints > Advanced features\n// Toggle: Live Response, EDR in block mode,\n//   Automated investigation, Tamper protection, etc.",
      "socTip": "After enabling a new advanced feature, validate it on a pilot device group before rolling out organization-wide.",
      "docRef": "Microsoft Learn: Configure advanced features"
    }
  },
  {
    "id": "mde-021",
    "topic": "Data retention",
    "scenario": "Adatum’s compliance team requires that endpoint investigation data remain available for at least 180 days for regulatory reasons.",
    "question": "How is data retention managed for Microsoft Defender for Endpoint?",
    "options": [
      "Data retention for Advanced Hunting and related telemetry is configurable (default periods apply; longer retention may require additional licensing or settings), while alert and incident data follow the service’s published retention windows",
      "All data is deleted after 7 days with no option to extend",
      "Retention is controlled only by the Windows Event Log size on each device",
      "Defender for Endpoint never stores any historical data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Endpoint Data Retention",
      "analysis": [
        "Option A is CORRECT: MDE provides configurable or license-dependent retention for hunting data and fixed service retention for alerts/incidents. Organizations should verify current published limits against compliance needs.",
        "Option B is INCORRECT: Default retention is longer than 7 days for most data types.",
        "Option C is INCORRECT: Cloud-stored telemetry retention is independent of local event-log size.",
        "Option D is INCORRECT: Historical data is retained according to the service configuration."
      ],
      "codeSnippet": "// Check current retention in portal documentation\n// Advanced Hunting data typically 30 days (extendable)\n// Alerts / incidents follow Defender XDR retention\n// Export critical investigations if longer archival is required",
      "socTip": "For investigations that must be kept beyond service retention, export the investigation package and key Advanced Hunting results to long-term storage.",
      "docRef": "Microsoft Learn: Data retention in Microsoft Defender for Endpoint"
    }
  },
  {
    "id": "mde-022",
    "topic": "Sensor health and onboarding status",
    "scenario": "After a bulk Intune deployment, Fabrikam’s SOC notices that several hundred devices still show as 'Can be onboarded' or have impaired sensor health.",
    "question": "Where can administrators identify devices with onboarding or sensor-health problems?",
    "options": [
      "The Device inventory and the Sensor health / Device health reports in the Microsoft Defender portal, which show onboarding status, last seen time, and health issues",
      "Only the Windows Event Viewer on each individual device",
      "Only the Microsoft 365 admin center Users list",
      "Sensor health cannot be monitored centrally"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Centralized Sensor Health Monitoring",
      "analysis": [
        "Option A is CORRECT: Device inventory and dedicated health reports surface onboarding state, communication status, and common misconfigurations so administrators can remediate at scale.",
        "Option B is INCORRECT: Local event logs are useful for deep troubleshooting but do not provide fleet-wide visibility.",
        "Option C is INCORRECT: The M365 admin center does not surface MDE sensor health.",
        "Option D is INCORRECT: Central monitoring is a core capability."
      ],
      "codeSnippet": "// Devices > Device inventory\n// Filter: Onboarding status = Can be onboarded / Impaired\n// Reports > Device health / Sensor health\n// Export list for remediation via Intune or scripts",
      "socTip": "Create a weekly automated export of devices with 'Impaired communications' and feed it to the endpoint engineering team for remediation.",
      "docRef": "Microsoft Learn: Device inventory and sensor health"
    }
  },
  {
    "id": "mde-023",
    "topic": "Response actions overview",
    "scenario": "A Tier 1 analyst at Northwind needs a quick reference of the primary response actions available on a device page.",
    "question": "Which set of actions can an analyst with appropriate permissions perform directly from a device page?",
    "options": [
      "Isolate device, Collect investigation package, Initiate Live Response, Run antivirus scan, Restrict app execution, Stop and quarantine file, Manage tags, and Initiate automated investigation",
      "Only send an email to the device owner",
      "Only reboot the device",
      "Only delete the device from Active Directory"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Response Actions",
      "analysis": [
        "Option A is CORRECT: The device page action bar exposes the full set of containment, investigation, and remediation actions (subject to role permissions and plan).",
        "Option B is INCORRECT: Notification is possible via other channels but is not the primary response action set.",
        "Option C is INCORRECT: Reboot is not a primary listed response action.",
        "Option D is INCORRECT: AD object deletion is outside the MDE portal."
      ],
      "codeSnippet": "// Device page action bar:\n// - Isolate / Release\n// - Collect investigation package\n// - Live response\n// - Run AV scan\n// - Restrict app execution\n// - Action center (history)",
      "socTip": "Always check the Action center after issuing a response action; failures (e.g., device offline) appear there and need follow-up.",
      "docRef": "Microsoft Learn: Take response actions on a device"
    }
  },
  {
    "id": "mde-024",
    "topic": "Automatic attack disruption",
    "scenario": "Litware has enabled automatic attack disruption. A multi-stage ransomware attack is detected with high confidence.",
    "question": "What does automatic attack disruption do?",
    "options": [
      "It automatically contains the attack in near real time by actions such as isolating compromised devices and disabling compromised user accounts, limiting lateral movement before human intervention",
      "It only sends an email notification to the SOC",
      "It automatically pays any ransom demand",
      "It only works for email-borne threats"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Automatic Attack Disruption",
      "analysis": [
        "Option A is CORRECT: Automatic attack disruption uses high-confidence correlation to contain active attacks (device isolation, account disablement, etc.) with minimal human delay.",
        "Option B is INCORRECT: It performs containment actions, not merely notification.",
        "Option C is INCORRECT: Ransom payment is never automated.",
        "Option D is INCORRECT: It targets multi-stage attacks across endpoints and identities."
      ],
      "codeSnippet": "// Settings > Endpoints / XDR > Automatic attack disruption\n// Enable for supported scenarios\n// Review contained devices/accounts in incidents\n// Release isolation when safe",
      "socTip": "Treat automatic disruption events as high priority: verify the containment was appropriate and complete the investigation while the attacker is locked out.",
      "docRef": "Microsoft Learn: Automatic attack disruption"
    }
  },
  {
    "id": "mde-025",
    "topic": "Platform support",
    "scenario": "Contoso has a mixed estate of Windows 11, Windows Server 2022, macOS, and Linux servers. The CISO asks which platforms can be onboarded to Microsoft Defender for Endpoint.",
    "question": "Which statement correctly describes platform support?",
    "options": [
      "Defender for Endpoint supports Windows client and server, macOS, and Linux with varying feature parity; core EDR, vulnerability management, and many response actions are available across these platforms",
      "Only Windows 10/11 clients are supported",
      "Only Azure Virtual Machines are supported",
      "macOS and Linux require a completely separate non-Microsoft product"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Multi-Platform Endpoint Support",
      "analysis": [
        "Option A is CORRECT: MDE provides sensors and capabilities for Windows, macOS, and Linux. Feature sets differ (e.g., some ASR rules are Windows-only), but core detection, hunting, and response exist across platforms.",
        "Option B is INCORRECT: Servers and non-Windows platforms are supported.",
        "Option C is INCORRECT: On-premises and non-Azure devices are fully supported.",
        "Option D is INCORRECT: Official Microsoft sensors exist for macOS and Linux."
      ],
      "codeSnippet": "// Onboarding packages available for:\n// Windows 10/11, Windows Server,\n// macOS, Linux distributions\n// Check supported capabilities matrix for feature parity",
      "socTip": "Maintain a capability matrix for your environment so analysts know which response actions (e.g., Live Response advanced commands) are available on each OS.",
      "docRef": "Microsoft Learn: Supported capabilities by platform"
    }
  },
  {
    "id": "mde-026",
    "topic": "Microsoft Defender Antivirus integration",
    "scenario": "Fabrikam wants to understand the relationship between Microsoft Defender Antivirus and the broader Defender for Endpoint EDR capabilities.",
    "question": "How do Microsoft Defender Antivirus and Defender for Endpoint work together?",
    "options": [
      "Defender Antivirus provides next-generation protection (real-time scanning, cloud protection, behavior monitoring) while the EDR sensor provides detection, investigation, and response; together they form a unified endpoint protection platform",
      "They are completely independent products that cannot share data",
      "Defender Antivirus must be uninstalled for EDR to function",
      "EDR replaces antivirus entirely and no scanning occurs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified AV + EDR Platform",
      "analysis": [
        "Option A is CORRECT: MDAV supplies pre-breach protection; the Sense EDR sensor supplies post-breach detection and response. Telemetry from both enriches incidents and hunting.",
        "Option B is INCORRECT: They share a common platform and data model.",
        "Option C is INCORRECT: MDAV can run in active or passive mode alongside EDR.",
        "Option D is INCORRECT: Antivirus scanning remains a critical prevention layer."
      ],
      "codeSnippet": "// Active mode: MDAV is primary AV + EDR\n// Passive mode: third-party AV primary, MDAV passive,\n//   EDR in block mode still protects",
      "socTip": "Even when a third-party AV is primary, keep cloud-delivered protection and EDR in block mode enabled for defense-in-depth.",
      "docRef": "Microsoft Learn: Microsoft Defender Antivirus in Defender for Endpoint"
    }
  },
  {
    "id": "mde-027",
    "topic": "Passive mode",
    "scenario": "Northwind runs CrowdStrike as the primary antivirus. They still want Microsoft Defender for Endpoint EDR telemetry and the ability to block post-breach artifacts.",
    "question": "What is the correct configuration when a third-party antivirus is primary?",
    "options": [
      "Set Microsoft Defender Antivirus to passive mode and enable EDR in block mode so the EDR sensor continues to detect and can block malicious artifacts without conflicting with the third-party AV",
      "Uninstall the Microsoft Defender Antivirus components completely",
      "Disable the EDR sensor",
      "Run both antivirus products in active mode with no coordination"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Passive Mode + EDR in Block Mode",
      "analysis": [
        "Option A is CORRECT: Passive mode prevents MDAV from performing active real-time protection (avoiding dual-AV conflicts) while the EDR sensor and EDR in block mode continue to provide detection and post-breach blocking.",
        "Option B is INCORRECT: Uninstalling removes valuable telemetry and cloud-protection capabilities.",
        "Option C is INCORRECT: The EDR sensor is required for Defender for Endpoint value.",
        "Option D is INCORRECT: Dual active AV frequently causes performance and detection conflicts."
      ],
      "codeSnippet": "// Set MDAV to passive (Intune / GPO / local)\n// Advanced features → EDR in block mode = On\n// Verify with Get-MpComputerStatus (AMRunningMode)",
      "socTip": "After switching to passive mode, confirm that EDR in block mode is enabled and that cloud-delivered protection remains on for the best residual protection.",
      "docRef": "Microsoft Learn: Microsoft Defender Antivirus compatibility"
    }
  },
  {
    "id": "mde-028",
    "topic": "Custom data collection",
    "scenario": "Adatum’s advanced hunting team needs additional telemetry that is not collected by default (specific registry keys or file events) for a custom detection use case.",
    "question": "How can organizations collect additional endpoint telemetry beyond the default set?",
    "options": [
      "Configure custom data collection rules that instruct the sensor to gather specified file, registry, or other events so they become available in Advanced Hunting",
      "Custom data collection is impossible; only Microsoft-defined events exist",
      "Install a separate SIEM agent on every device",
      "Custom data can only be collected via manual Live Response sessions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Data Collection",
      "analysis": [
        "Option A is CORRECT: Custom data collection rules extend the sensor’s collection scope so additional events appear in Advanced Hunting tables for hunting and custom detections.",
        "Option B is INCORRECT: Custom collection is a supported advanced capability.",
        "Option C is INCORRECT: A separate agent is not required for MDE custom collection.",
        "Option D is INCORRECT: Live Response is interactive and not suitable for continuous fleet-wide collection."
      ],
      "codeSnippet": "// Settings > Endpoints > Custom data collection\n// Define rules for file / registry / etc.\n// Events appear in Advanced Hunting after deployment",
      "socTip": "Keep custom collection rules tightly scoped; over-collection increases data volume and cost if you stream to Sentinel or other SIEMs.",
      "docRef": "Microsoft Learn: Custom data collection"
    }
  },
  {
    "id": "mde-029",
    "topic": "Device discovery",
    "scenario": "Contoso wants to find unmanaged devices on the corporate network that are not yet onboarded to Defender for Endpoint so they can be brought under protection.",
    "question": "How does Defender for Endpoint help identify unmanaged devices?",
    "options": [
      "Device discovery uses onboarded devices as sensors to detect unmanaged endpoints on the network, surfacing them in the Device inventory with onboarding recommendations",
      "Unmanaged devices cannot be discovered; only manually entered assets appear",
      "Discovery requires a separate network TAP and SPAN port",
      "Discovery only works for Azure Arc-enabled servers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Endpoint and Network Device Discovery",
      "analysis": [
        "Option A is CORRECT: Onboarded devices observe network traffic and identify other devices, populating the inventory with unmanaged assets that can then be targeted for onboarding.",
        "Option B is INCORRECT: Discovery is designed precisely to find unknown devices.",
        "Option C is INCORRECT: No dedicated network hardware is required; onboarded endpoints act as sensors.",
        "Option D is INCORRECT: Discovery works for a broad range of network-connected devices, not only Arc-enabled servers."
      ],
      "codeSnippet": "// Settings > Device discovery\n// Standard or Basic discovery\n// Devices > Device inventory → filter Unmanaged\n// Onboard discovered devices via appropriate method",
      "socTip": "Review the unmanaged device list weekly and feed high-value or high-risk devices into the onboarding pipeline first.",
      "docRef": "Microsoft Learn: Device discovery"
    }
  },
  {
    "id": "mde-030",
    "topic": "Microsoft Secure Score for Devices",
    "scenario": "Northwind’s CISO wants a measurable way to track improvement of endpoint security configuration over time.",
    "question": "What does Microsoft Secure Score for Devices provide?",
    "options": [
      "A numerical score and improvement actions based on the configuration state of onboarded devices (ASR rules, AV settings, firewall, etc.), allowing organizations to track posture progress",
      "Only a count of open incidents",
      "A credit-score style rating of individual users",
      "A mandatory public ranking of the organization"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Secure Score for Devices",
      "analysis": [
        "Option A is CORRECT: Secure Score for Devices evaluates configuration baselines and presents prioritized improvement actions with potential score impact.",
        "Option B is INCORRECT: Incident count is separate from configuration posture scoring.",
        "Option C is INCORRECT: The score is device/configuration focused, not a user credit score.",
        "Option D is INCORRECT: Scores are private to the tenant."
      ],
      "codeSnippet": "// Microsoft Secure Score > Devices\n// View current score, improvement actions\n// Filter by category (Device, Application, etc.)\n// Track progress over time",
      "socTip": "Pick the top 5 improvement actions each month and assign owners; small consistent gains compound into a strong posture.",
      "docRef": "Microsoft Learn: Microsoft Secure Score for Devices"
    }
  },
  {
    "id": "mde-031",
    "topic": "Restrict app execution",
    "scenario": "An analyst determines that a compromised device is running multiple untrusted binaries but does not yet want full network isolation.",
    "question": "What does the 'Restrict app execution' response action do?",
    "options": [
      "It restricts the device so that only files signed by a Microsoft-issued certificate can execute, limiting the attacker’s ability to run arbitrary malware while investigation continues",
      "It uninstalls all applications from the device",
      "It only blocks web browsers",
      "It permanently bricks the device"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Restrict App Execution",
      "analysis": [
        "Option A is CORRECT: Restrict app execution puts the device into a mode where only Microsoft-signed binaries are allowed to run, reducing attacker freedom without full isolation.",
        "Option B is INCORRECT: Existing applications are not uninstalled.",
        "Option C is INCORRECT: The restriction applies broadly to unsigned/untrusted code, not only browsers.",
        "Option D is INCORRECT: The action is reversible."
      ],
      "codeSnippet": "// Device page → Restrict app execution\n// Device runs only Microsoft-signed code\n// Reverse the action when investigation complete",
      "socTip": "Use Restrict app execution as an intermediate containment step when full isolation would disrupt critical business functions that rely on network connectivity.",
      "docRef": "Microsoft Learn: Restrict app execution"
    }
  },
  {
    "id": "mde-032",
    "topic": "Stop and quarantine file",
    "scenario": "A malicious executable is identified on several devices. The analyst wants to stop any running instances and prevent future execution.",
    "question": "What does the 'Stop and quarantine file' action accomplish?",
    "options": [
      "It terminates running processes associated with the file, quarantines the file on the device, and can add a corresponding indicator to prevent future execution across the organization",
      "It only deletes the file from one device and does nothing else",
      "It sends the file to the user’s Recycle Bin",
      "It requires physical access to the device"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Stop and Quarantine File",
      "analysis": [
        "Option A is CORRECT: The action stops processes, quarantines the file, and can be paired with an indicator for organization-wide blocking.",
        "Option B is INCORRECT: The action is broader than a single-device delete.",
        "Option C is INCORRECT: Quarantine is a protected store, not the Recycle Bin.",
        "Option D is INCORRECT: The action is performed remotely through the portal or API."
      ],
      "codeSnippet": "// File entity or alert → Stop and quarantine\n// Optional: Add indicator (Block)\n// Verify in Action center",
      "socTip": "After quarantining, search Advanced Hunting for the hash across the entire estate to confirm no residual copies remain.",
      "docRef": "Microsoft Learn: Respond to file threats"
    }
  },
  {
    "id": "mde-033",
    "topic": "Deep analysis",
    "scenario": "An analyst has a suspicious file that is not yet classified. They want Microsoft to detonate it in a sandbox and return a detailed behavior report.",
    "question": "What does submitting a file for deep analysis provide?",
    "options": [
      "The file is executed in a Microsoft sandbox; a report of observed behaviors, network contacts, dropped files, and a verdict is returned to the portal for the analyst",
      "Deep analysis only checks the file hash against VirusTotal",
      "Deep analysis immediately deletes the file from all devices",
      "Deep analysis is only available for Office documents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Deep Analysis Sandbox Detonation",
      "analysis": [
        "Option A is CORRECT: Deep analysis detonates the sample in a controlled environment and returns rich behavioral telemetry and a verdict.",
        "Option B is INCORRECT: It performs actual detonation, not merely a hash lookup.",
        "Option C is INCORRECT: Submission for analysis does not automatically remediate the file on devices.",
        "Option D is INCORRECT: Many file types including PE executables are supported."
      ],
      "codeSnippet": "// File entity → Deep analysis\n// Wait for report (minutes)\n// Review behaviors, IOCs, verdict\n// Take response actions based on results",
      "socTip": "Use deep analysis results to extract additional IOCs (domains, IPs, child files) and hunt for them across the environment.",
      "docRef": "Microsoft Learn: Deep analysis"
    }
  },
  {
    "id": "mde-034",
    "topic": "Role-based access control (RBAC) roles",
    "scenario": "Litware wants Tier 1 analysts to view devices and alerts and perform basic response actions, but not manage security settings or device groups.",
    "question": "Which built-in role is most appropriate for Tier 1 SOC analysts?",
    "options": [
      "Security Operator (or a custom role with similar permissions) — can view data and take response actions but cannot change portal configuration or manage roles",
      "Global Administrator",
      "Security Reader only (view-only, no response actions)",
      "User Administrator"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "MDE / Defender XDR RBAC Roles",
      "analysis": [
        "Option A is CORRECT: Security Operator provides the typical Tier 1/2 balance of investigation and response without configuration rights. Custom roles can refine this further.",
        "Option B is INCORRECT: Global Administrator is far too privileged.",
        "Option C is INCORRECT: Security Reader cannot perform response actions needed by Tier 1.",
        "Option D is INCORRECT: User Administrator is an Entra ID role, not an MDE security role."
      ],
      "codeSnippet": "// Settings > Permissions > Roles\n// Built-in: Security Admin, Security Operator,\n//   Security Reader, etc.\n// Or create custom role with selected permissions\n// Assign to Azure AD groups + device group scope",
      "socTip": "Prefer Azure AD groups over individual user assignments so joiners/leavers are handled automatically.",
      "docRef": "Microsoft Learn: Create and manage roles for role-based access control"
    }
  },
  {
    "id": "mde-035",
    "topic": "Action center",
    "scenario": "An analyst issued several isolation and investigation-package requests. Some succeeded, some are pending, and one failed because the device was offline.",
    "question": "Where can the analyst track the status of all response actions?",
    "options": [
      "The Action center in the Microsoft Defender portal, which lists pending, completed, and failed actions with timestamps and details",
      "Only the Windows Event Log on the target device",
      "Only an email that is sent once per day",
      "Action status cannot be tracked"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Action Center Tracking",
      "analysis": [
        "Option A is CORRECT: The Action center is the central queue for all manual and automated response actions, their status, and any error details.",
        "Option B is INCORRECT: Local logs do not provide the fleet-wide action history.",
        "Option C is INCORRECT: Email is not the primary tracking mechanism.",
        "Option D is INCORRECT: Tracking is fully supported."
      ],
      "codeSnippet": "// Actions > Action center\n// Filter by status, action type, device\n// Investigate failed actions (device offline, permissions, etc.)",
      "socTip": "Check the Action center at the start of each shift for failed actions that need retry once devices come back online.",
      "docRef": "Microsoft Learn: Action center"
    }
  },
  {
    "id": "mde-036",
    "topic": "Web content filtering",
    "scenario": "Contoso wants to block access to adult and high-bandwidth streaming categories on corporate devices while still allowing business sites.",
    "question": "Which feature provides category-based web filtering on endpoints?",
    "options": [
      "Web content filtering (part of web protection) — blocks or audits access to predefined categories such as Adult content, High bandwidth, Legal liability, etc., using Network protection",
      "Only Microsoft Edge browser settings",
      "Only Windows Firewall rules with manual IP lists",
      "Only DNS sinkholing configured on domain controllers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Web Content Filtering Categories",
      "analysis": [
        "Option A is CORRECT: Web content filtering uses Network protection and Microsoft’s category database to enforce policy independently of the browser.",
        "Option B is INCORRECT: Browser settings alone do not cover non-Edge processes.",
        "Option C is INCORRECT: Manual firewall rules do not scale or use category intelligence.",
        "Option D is INCORRECT: DNS sinkholing is a different technique and not the MDE feature."
      ],
      "codeSnippet": "// Endpoint security policy:\n// Web protection → Web content filtering\n// Select categories to Block or Audit\n// Review Web content filtering report",
      "socTip": "Start categories in Audit mode for two weeks to measure business impact before switching to Block.",
      "docRef": "Microsoft Learn: Web content filtering"
    }
  },
  {
    "id": "mde-037",
    "topic": "Device tags",
    "scenario": "Fabrikam wants to label devices that belong to the Finance department so they can be filtered in hunting queries, device groups, and reports.",
    "question": "How are device tags used in Microsoft Defender for Endpoint?",
    "options": [
      "Tags are labels applied manually or via API/dynamic rules that can be used for filtering in the portal, defining device groups, and scoping hunting or automation",
      "Tags permanently change the device hostname",
      "Tags are only visible to Microsoft support",
      "Tags delete the device after 30 days"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Tags for Organization and Scoping",
      "analysis": [
        "Option A is CORRECT: Tags provide flexible metadata for grouping, filtering, and automation without altering the device itself.",
        "Option B is INCORRECT: Hostname remains unchanged.",
        "Option C is INCORRECT: Tags are visible and usable by the customer.",
        "Option D is INCORRECT: Tags have no automatic deletion side-effect."
      ],
      "codeSnippet": "// Device page → Manage tags\n// Or bulk via API / onboarding script\n// Use in device group rules: Tag = Finance\n// Filter inventory and hunting by tag",
      "socTip": "Establish a tagging standard (Department, Criticality, Location) early; consistent tags make device groups and RBAC far easier to maintain.",
      "docRef": "Microsoft Learn: Create and manage device tags"
    }
  },
  {
    "id": "mde-038",
    "topic": "Advanced hunting – DeviceNetworkEvents",
    "scenario": "An analyst needs to find all devices that established outbound connections to a specific suspicious IP in the last 48 hours.",
    "question": "Which Advanced Hunting table should be queried for network connection events?",
    "options": [
      "DeviceNetworkEvents — contains outbound and inbound connection telemetry including remote IP, port, protocol, initiating process, and action taken",
      "DeviceProcessEvents only",
      "DeviceRegistryEvents only",
      "CloudAppEvents only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceNetworkEvents Table",
      "analysis": [
        "Option A is CORRECT: DeviceNetworkEvents is the primary table for network connection data from the endpoint sensor.",
        "Option B is INCORRECT: Process events do not contain remote IP/port details.",
        "Option C is INCORRECT: Registry events are unrelated to network connections.",
        "Option D is INCORRECT: CloudAppEvents is for cloud application activity."
      ],
      "codeSnippet": "DeviceNetworkEvents\n| where Timestamp > ago(48h)\n| where RemoteIP == '203.0.113.50'\n| project Timestamp, DeviceName, InitiatingProcessFileName,\n          RemoteIP, RemotePort, ActionType",
      "socTip": "Join DeviceNetworkEvents with DeviceInfo to enrich results with OS version, device group, and onboarding status.",
      "docRef": "Microsoft Learn: DeviceNetworkEvents"
    }
  },
  {
    "id": "mde-039",
    "topic": "Advanced hunting – DeviceLogonEvents",
    "scenario": "A hunting hypothesis suggests an attacker is using pass-the-hash. The analyst wants to examine interactive and network logons on endpoints.",
    "question": "Which table provides endpoint logon activity for hunting?",
    "options": [
      "DeviceLogonEvents — records logon type, account, success/failure, protocol, and related process information for endpoint authentication events",
      "IdentityLogonEvents is the only logon table and only covers cloud identities",
      "EmailEvents",
      "DeviceFileEvents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceLogonEvents for Endpoint Authentication",
      "analysis": [
        "Option A is CORRECT: DeviceLogonEvents captures logon telemetry generated by the endpoint sensor, useful for detecting lateral movement and credential abuse.",
        "Option B is INCORRECT: IdentityLogonEvents covers identity provider / Entra ID style events; DeviceLogonEvents is the endpoint counterpart.",
        "Option C is INCORRECT: EmailEvents is unrelated.",
        "Option D is INCORRECT: File events do not contain logon data."
      ],
      "codeSnippet": "DeviceLogonEvents\n| where Timestamp > ago(7d)\n| where LogonType == 'Network' or ActionType == 'LogonFailed'\n| summarize count() by AccountName, DeviceName, RemoteIP",
      "socTip": "Correlate DeviceLogonEvents with IdentityLogonEvents when investigating hybrid identity attacks that span on-premises and cloud.",
      "docRef": "Microsoft Learn: DeviceLogonEvents"
    }
  },
  {
    "id": "mde-040",
    "topic": "ASR rule – Block credential stealing",
    "scenario": "Contoso wants to prevent tools such as Mimikatz from accessing LSASS memory to steal credentials.",
    "question": "Which ASR rule is specifically designed to block credential theft from LSASS?",
    "options": [
      "Block credential stealing from the Windows local security authority subsystem (LSASS) — prevents processes from accessing LSASS memory in ways commonly used by credential dumpers",
      "Block executable content from email client and webmail",
      "Block Office applications from creating executable content",
      "Block process creations originating from PSExec and WMI commands"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ASR Rule – Protect LSASS",
      "analysis": [
        "Option A is CORRECT: This standard-protection ASR rule targets the common technique of reading LSASS memory for credentials.",
        "Option B is INCORRECT: That rule focuses on email-borne executables.",
        "Option C is INCORRECT: That rule prevents Office from writing executables.",
        "Option D is INCORRECT: That rule targets lateral-movement tools, not LSASS access."
      ],
      "codeSnippet": "// ASR rule GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2\n// Name: Block credential stealing from LSASS\n// Deploy via Intune / GPO / Configuration Manager\n// Start in Audit, then Block",
      "socTip": "This rule is part of the recommended standard protection set; enable it early after validating with Audit mode.",
      "docRef": "Microsoft Learn: ASR rules reference"
    }
  },
  {
    "id": "mde-041",
    "topic": "Onboarding via Group Policy",
    "scenario": "Contoso has domain-joined Windows devices that are not yet in Intune. The security team needs a scalable onboarding method.",
    "question": "How can domain-joined devices be onboarded using Group Policy?",
    "options": [
      "Create a GPO that deploys the Defender for Endpoint onboarding package (script or configuration) so domain-joined devices enroll automatically at next policy refresh",
      "Manually run the onboarding script on each device",
      "Onboarding via GPO is not supported",
      "Only Azure AD joined devices can be onboarded"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "GPO-Based Onboarding",
      "analysis": [
        "Option A is CORRECT: Microsoft provides Group Policy templates and scripts to onboard domain-joined devices at scale.",
        "Option B is INCORRECT: Manual execution does not scale.",
        "Option C is INCORRECT: GPO onboarding is fully supported.",
        "Option D is INCORRECT: Domain-joined devices are a primary onboarding scenario."
      ],
      "codeSnippet": "// Download onboarding package from portal\n// Create GPO → Computer Configuration\n// Deploy script or scheduled task",
      "socTip": "Combine GPO onboarding with a device group that targets domain-joined machines for faster visibility.",
      "docRef": "Microsoft Learn: Onboard Windows devices using Group Policy"
    }
  },
  {
    "id": "mde-042",
    "topic": "Live Response library",
    "scenario": "The SOC at Fabrikam frequently runs the same forensic PowerShell scripts during Live Response sessions.",
    "question": "How can commonly used scripts be managed for Live Response?",
    "options": [
      "Upload scripts and files to the Live Response library so any authorized analyst can run them during a session without re-uploading each time",
      "Scripts can only be typed interactively each session",
      "The library only supports .exe files",
      "Library management requires a separate Azure subscription"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Live Response Library Management",
      "analysis": [
        "Option A is CORRECT: The library provides centralized storage and versioning of scripts and files for use in Live Response.",
        "Option B is INCORRECT: Re-typing is inefficient; the library solves this.",
        "Option C is INCORRECT: Scripts (PowerShell, etc.) are supported.",
        "Option D is INCORRECT: Library management is part of the Defender portal."
      ],
      "codeSnippet": "// Live response → Library\n// Upload script.ps1\n// During session: run script.ps1",
      "socTip": "Store approved forensic and remediation scripts in the library and restrict upload permissions to senior engineers.",
      "docRef": "Microsoft Learn: Live response library"
    }
  },
  {
    "id": "mde-043",
    "topic": "Selective isolation",
    "scenario": "A critical application server is compromised but must keep limited connectivity for business continuity while the SOC investigates.",
    "question": "What is selective isolation?",
    "options": [
      "Isolation that blocks most network traffic while allowing defined exclusions or Microsoft 365 / security service connectivity so essential functions can continue",
      "Isolation that only blocks USB devices",
      "Isolation that shuts down the server",
      "Isolation that only applies to mobile devices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Selective Network Isolation",
      "analysis": [
        "Option A is CORRECT: Selective isolation and isolation exclusions let organizations maintain critical connectivity while still containing the threat.",
        "Option B is INCORRECT: USB control is a separate feature.",
        "Option C is INCORRECT: Isolation does not power off the device.",
        "Option D is INCORRECT: Isolation applies to supported Windows (and some other) platforms."
      ],
      "codeSnippet": "// Isolate device → Selective\n// Configure isolation exclusions if needed\n// Release when investigation complete",
      "socTip": "Pre-define isolation exclusions for critical management and backup subnets so selective isolation can be applied quickly.",
      "docRef": "Microsoft Learn: Device isolation"
    }
  },
  {
    "id": "mde-044",
    "topic": "Automated investigation verdicts",
    "scenario": "AIR completes an investigation and assigns a verdict to the threat.",
    "question": "What are the possible verdicts from an automated investigation?",
    "options": [
      "Threats are classified with verdicts such as Malicious, Suspicious, or No threats found, guiding whether remediation actions are applied",
      "Verdicts are only 'Yes' or 'No'",
      "AIR never produces a verdict",
      "Verdicts are only visible to Microsoft engineers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AIR Verdicts",
      "analysis": [
        "Option A is CORRECT: AIR reaches a verdict that drives remediation decisions under the configured automation level.",
        "Option B is INCORRECT: More nuanced verdicts are provided.",
        "Option C is INCORRECT: Verdict generation is central to AIR.",
        "Option D is INCORRECT: Verdicts are visible to the customer in the portal."
      ],
      "codeSnippet": "// Incident / Investigation → Verdict\n// Malicious → remediate\n// Suspicious → may require approval\n// Clean → no action",
      "socTip": "Review 'Suspicious' verdicts regularly; they often highlight gray-area activity that needs tuning or hunting.",
      "docRef": "Microsoft Learn: Automated investigation"
    }
  },
  {
    "id": "mde-045",
    "topic": "Indicators – file hash",
    "scenario": "Threat intel provides a SHA256 of a new malware family. The SOC wants to prevent execution organization-wide.",
    "question": "What action should be set on a file-hash indicator to prevent execution?",
    "options": [
      "Alert and block (or Block and remediate) so the sensor prevents the file from running and can quarantine it",
      "Allow only",
      "Audit only with no blocking",
      "Indicators cannot block file execution"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Blocking File Hash Indicators",
      "analysis": [
        "Option A is CORRECT: File indicators support block actions that stop execution on onboarded devices.",
        "Option B is INCORRECT: Allow would permit the file.",
        "Option C is INCORRECT: Audit does not prevent execution.",
        "Option D is INCORRECT: Blocking is a core capability."
      ],
      "codeSnippet": "// Indicators → Add item → File hash\n// Action: Alert and block\n// Scope: All devices or groups",
      "socTip": "Prefer SHA256 over MD5/SHA1 for indicators; collisions and older hash weaknesses make stronger hashes safer.",
      "docRef": "Microsoft Learn: Create indicators for files"
    }
  },
  {
    "id": "mde-046",
    "topic": "Indicators – IP and URL",
    "scenario": "A C2 domain and its resolving IP are identified. The SOC wants to block both.",
    "question": "Can IP addresses and URLs/domains be blocked via indicators?",
    "options": [
      "Yes — network indicators for IPs and URLs/domains can be set to Alert and block, preventing connections from onboarded devices",
      "No — only file hashes can be indicators",
      "Only URLs can be blocked, not IPs",
      "Indicators only work for certificates"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Network Indicators",
      "analysis": [
        "Option A is CORRECT: IP and URL/domain indicators support block actions enforced by the sensor and Network protection.",
        "Option B is INCORRECT: Multiple indicator types exist.",
        "Option C is INCORRECT: Both IPs and URLs are supported.",
        "Option D is INCORRECT: Certificates are an additional type, not the only one."
      ],
      "codeSnippet": "// Indicators → IP address / URL\n// Action: Alert and block\n// Expiration recommended for temporary C2s",
      "socTip": "Set expiration dates on tactical network indicators so they do not permanently block infrastructure that may be reassigned.",
      "docRef": "Microsoft Learn: Create indicators for IPs and URLs"
    }
  },
  {
    "id": "mde-047",
    "topic": "Vulnerability management – software inventory",
    "scenario": "Adatum needs an accurate list of installed applications and versions across all onboarded devices for a compliance audit.",
    "question": "How does Defender for Endpoint provide software inventory?",
    "options": [
      "The sensor continuously discovers installed software and versions, available in the Software inventory blade and via Advanced Hunting tables",
      "Software inventory requires a separate SCCM-only scan",
      "Inventory is only updated once per year",
      "Inventory is limited to Microsoft products"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Continuous Software Inventory",
      "analysis": [
        "Option A is CORRECT: TVM maintains near-real-time software inventory from sensor data.",
        "Option B is INCORRECT: No separate SCCM scan is required for basic inventory.",
        "Option C is INCORRECT: Inventory is continuously updated.",
        "Option D is INCORRECT: Third-party software is included."
      ],
      "codeSnippet": "// Vulnerability management → Inventories → Software\n// Or Advanced Hunting: DeviceTvmSoftwareInventory",
      "socTip": "Export software inventory monthly for compliance evidence and to track shadow IT applications.",
      "docRef": "Microsoft Learn: Software inventory"
    }
  },
  {
    "id": "mde-048",
    "topic": "Exposure score",
    "scenario": "The CISO asks how exposed the organization is to a specific vulnerability.",
    "question": "What does the exposure score represent in Defender Vulnerability Management?",
    "options": [
      "A calculated metric reflecting how exposed the organization is to a given vulnerability or recommendation, based on affected devices, criticality, and threat context",
      "A random number with no meaning",
      "Only the number of CVEs published that week",
      "A score visible only to Microsoft"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Exposure Score",
      "analysis": [
        "Option A is CORRECT: Exposure score helps prioritize which weaknesses matter most in the current environment.",
        "Option B is INCORRECT: The score is data-driven.",
        "Option C is INCORRECT: It is environment-specific, not a global CVE count.",
        "Option D is INCORRECT: Customers see and act on the score."
      ],
      "codeSnippet": "// Vulnerability management → Dashboard\n// Exposure score trends\n// Drill into recommendations",
      "socTip": "Track exposure score weekly; a rising score often indicates new unpatched software or newly onboarded vulnerable devices.",
      "docRef": "Microsoft Learn: Exposure score"
    }
  },
  {
    "id": "mde-049",
    "topic": "Security recommendations",
    "scenario": "A recommendation appears to enable a missing ASR rule on 200 devices.",
    "question": "What can an administrator do from a security recommendation?",
    "options": [
      "Review affected devices, create a remediation request or ticket, apply exceptions, and track completion status",
      "Only delete the recommendation",
      "Recommendations cannot be acted upon",
      "Only email the recommendation to users"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Actionable Security Recommendations",
      "analysis": [
        "Option A is CORRECT: Recommendations are actionable—remediate, exception, or track.",
        "Option B is INCORRECT: Deleting does not fix the underlying issue.",
        "Option C is INCORRECT: Recommendations are designed for action.",
        "Option D is INCORRECT: Email alone is insufficient."
      ],
      "codeSnippet": "// Recommendations → Open item\n// Remediate / Exception / Ticket integration",
      "socTip": "Integrate recommendations with your ITSM tool so remediation work is tracked alongside other change tickets.",
      "docRef": "Microsoft Learn: Security recommendations"
    }
  },
  {
    "id": "mde-050",
    "topic": "Advanced hunting – DeviceFileEvents",
    "scenario": "An analyst wants to find all file creation events in the Downloads folder that have a low prevalence hash.",
    "question": "Which table contains file creation, modification, and deletion events?",
    "options": [
      "DeviceFileEvents — records file system activity including path, hash, initiating process, and action type",
      "DeviceProcessEvents only",
      "DeviceNetworkEvents only",
      "IdentityInfo only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceFileEvents Table",
      "analysis": [
        "Option A is CORRECT: DeviceFileEvents is the primary table for file-system telemetry.",
        "Option B is INCORRECT: Process events do not contain full file-path and hash details for all file operations.",
        "Option C is INCORRECT: Network events are separate.",
        "Option D is INCORRECT: IdentityInfo is not an event table for files."
      ],
      "codeSnippet": "DeviceFileEvents\n| where FolderPath has 'Downloads'\n| where ActionType == 'FileCreated'\n| where Timestamp > ago(1d)",
      "socTip": "Combine DeviceFileEvents with prevalence data or indicators to surface newly dropped low-prevalence executables.",
      "docRef": "Microsoft Learn: DeviceFileEvents"
    }
  },
  {
    "id": "mde-051",
    "topic": "Advanced hunting – DeviceRegistryEvents",
    "scenario": "A hunter is looking for persistence via Run key modifications.",
    "question": "Which table records registry modifications relevant to persistence hunting?",
    "options": [
      "DeviceRegistryEvents — contains registry key and value changes, including Run keys and other persistence locations",
      "DeviceNetworkEvents",
      "EmailAttachmentInfo",
      "CloudAppEvents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DeviceRegistryEvents for Persistence",
      "analysis": [
        "Option A is CORRECT: Registry telemetry is essential for detecting many persistence techniques.",
        "Option B is INCORRECT: Network events do not capture registry changes.",
        "Option C is INCORRECT: Email attachment info is unrelated.",
        "Option D is INCORRECT: Cloud app events are separate."
      ],
      "codeSnippet": "DeviceRegistryEvents\n| where RegistryKey has 'CurrentVersion\\\\Run'\n| where ActionType == 'RegistryValueSet'",
      "socTip": "Baseline legitimate Run-key entries in your environment so hunting queries can focus on anomalies.",
      "docRef": "Microsoft Learn: DeviceRegistryEvents"
    }
  },
  {
    "id": "mde-052",
    "topic": "Alert classification",
    "scenario": "After investigating an alert, the analyst determines it was a true positive that was successfully remediated.",
    "question": "How should the alert be classified?",
    "options": [
      "Set the classification to True positive and the determination to an appropriate value (e.g., Multistage attack, Malware) to improve future tuning and reporting",
      "Leave it unclassified forever",
      "Classify it as False positive even though it was real",
      "Delete the alert from the portal"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Classification and Determination",
      "analysis": [
        "Option A is CORRECT: Proper classification feeds analytics, tuning, and SOC metrics.",
        "Option B is INCORRECT: Unclassified alerts reduce the value of reporting.",
        "Option C is INCORRECT: False positive is incorrect for a real attack.",
        "Option D is INCORRECT: Deletion is not the normal workflow; classification is."
      ],
      "codeSnippet": "// Alert → Manage alert\n// Classification: True positive / False positive / Informational\n// Determination: select matching category",
      "socTip": "Make classification a mandatory step in the Tier 1 runbook; it directly improves detection quality over time.",
      "docRef": "Microsoft Learn: Classify alerts"
    }
  },
  {
    "id": "mde-053",
    "topic": "Incident graph",
    "scenario": "A complex incident spans multiple devices, users, and file artifacts.",
    "question": "What primary view does the Defender for Endpoint incident graph provide when analyzing multi-device alerts?",
    "options": [
      "Relationships between alerts, devices, users, files, and other entities involved in the incident, helping analysts understand attack scope and progression",
      "Only a list of CVEs",
      "Only email headers",
      "A network topology of the entire company"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Graph Visualization",
      "analysis": [
        "Option A is CORRECT: The graph shows entity relationships and attack paths within the incident.",
        "Option B is INCORRECT: CVE lists belong to vulnerability management.",
        "Option C is INCORRECT: Email headers are part of email entity views.",
        "Option D is INCORRECT: It is scoped to the incident, not the whole network."
      ],
      "codeSnippet": "// Incident → Graph tab\n// Expand entities, view alerts, pivot to timeline",
      "socTip": "Use the graph early to identify the 'patient zero' device and any lateral movement paths.",
      "docRef": "Microsoft Learn: Investigate incidents"
    }
  },
  {
    "id": "mde-054",
    "topic": "Microsoft Threat Experts / Endpoint Attack Notifications",
    "scenario": "Contoso has a premium managed hunting engagement and receives a targeted notification about a human adversary in the environment.",
    "question": "What are Endpoint Attack Notifications (or Microsoft Threat Experts targeted notifications)?",
    "options": [
      "Proactive, human-driven or advanced hunting notifications that alert the customer to high-severity, targeted activity observed in their endpoint data",
      "Automated marketing emails",
      "Only generic threat intelligence blogs",
      "Notifications that automatically wipe all devices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Managed Hunting Notifications",
      "analysis": [
        "Option A is CORRECT: These notifications surface critical, often human-operated activity that may not have generated a standard alert.",
        "Option B is INCORRECT: They are security operational notifications.",
        "Option C is INCORRECT: They are specific to the customer’s environment.",
        "Option D is INCORRECT: No automatic wipe occurs."
      ],
      "codeSnippet": "// Notifications appear in portal / email\n// Investigate immediately\n// Engage support if needed",
      "socTip": "Treat targeted attack notifications as P1 incidents; the adversary is often still active.",
      "docRef": "Microsoft Learn: Endpoint Attack Notifications"
    }
  },
  {
    "id": "mde-055",
    "topic": "Device control",
    "scenario": "Litware wants to block unauthorized USB storage devices while still allowing approved encrypted drives.",
    "question": "Which capability enforces USB and peripheral control policies?",
    "options": [
      "Device control — policies that allow, block, or audit removable storage and other peripherals based on device properties and approval lists",
      "Only BitLocker",
      "Only Network protection",
      "Only ASR rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device Control for Removable Media",
      "analysis": [
        "Option A is CORRECT: Device control policies manage removable storage and peripherals.",
        "Option B is INCORRECT: BitLocker encrypts drives but does not alone enforce insertion policy.",
        "Option C is INCORRECT: Network protection is for network destinations.",
        "Option D is INCORRECT: ASR rules target software behaviors, not USB insertion."
      ],
      "codeSnippet": "// Endpoint security → Device control\n// Policy: Block removable storage except approved IDs",
      "socTip": "Maintain an approved USB vendor/product ID list and review exceptions quarterly.",
      "docRef": "Microsoft Learn: Device control"
    }
  },
  {
    "id": "mde-056",
    "topic": "Firewall integration",
    "scenario": "The SOC wants Defender for Endpoint to report on Windows Firewall events and enforce rules.",
    "question": "How does Defender for Endpoint interact with the Windows Firewall?",
    "options": [
      "Defender for Endpoint can manage and report on firewall policies, surface firewall events in hunting, and integrate firewall status into device security posture",
      "Firewall management is completely separate and invisible to MDE",
      "MDE disables the Windows Firewall permanently",
      "Firewall logs are only available on domain controllers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Firewall Visibility and Management",
      "analysis": [
        "Option A is CORRECT: Firewall status and events are part of the endpoint security posture and hunting data.",
        "Option B is INCORRECT: Integration exists.",
        "Option C is INCORRECT: Firewall remains under policy control.",
        "Option D is INCORRECT: Client and server firewall events are collected."
      ],
      "codeSnippet": "// Endpoint security → Firewall policies\n// Advanced Hunting: DeviceEvents (firewall related)\n// Secure Score includes firewall posture",
      "socTip": "Ensure firewall policies are deployed via the same management channel (Intune/GPO) that manages other MDE settings for consistency.",
      "docRef": "Microsoft Learn: Firewall in Defender for Endpoint"
    }
  },
  {
    "id": "mde-057",
    "topic": "Onboarding status – Can be onboarded",
    "scenario": "Device discovery found servers that show status 'Can be onboarded'.",
    "question": "What does the 'Can be onboarded' status mean?",
    "options": [
      "The device has been discovered on the network but does not yet have the Defender for Endpoint sensor installed or fully onboarded",
      "The device is fully protected and healthy",
      "The device has been isolated",
      "The device is running an unsupported OS and can never be onboarded"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Onboarding Status Values",
      "analysis": [
        "Option A is CORRECT: 'Can be onboarded' indicates discovery without completed onboarding.",
        "Option B is INCORRECT: That would be an onboarded healthy state.",
        "Option C is INCORRECT: Isolation is a response action, not an onboarding status.",
        "Option D is INCORRECT: Many discovered devices are supported and simply need onboarding."
      ],
      "codeSnippet": "// Device inventory → filter Onboarding status\n// Can be onboarded → plan deployment\n// Onboarded → monitor health",
      "socTip": "Prioritize onboarding of servers and high-value assets that appear as 'Can be onboarded'.",
      "docRef": "Microsoft Learn: Device inventory"
    }
  },
  {
    "id": "mde-058",
    "topic": "Sense service",
    "scenario": "An analyst troubleshooting a device that is not reporting checks local services.",
    "question": "What is the primary Windows service name for the Defender for Endpoint sensor?",
    "options": [
      "Sense (Microsoft Defender for Endpoint Service) — the core EDR sensor service that must be running for telemetry and response",
      "WinDefend only",
      "wuauserv",
      "Spooler"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sense Sensor Service",
      "analysis": [
        "Option A is CORRECT: The Sense service is the EDR sensor. WinDefend is the antivirus service.",
        "Option B is INCORRECT: WinDefend is MDAV, not the full EDR sensor.",
        "Option C is INCORRECT: Windows Update service.",
        "Option D is INCORRECT: Print spooler."
      ],
      "codeSnippet": "// Get-Service Sense\n// sc query Sense\n// Event logs: Microsoft-Windows-SENSE/Operational",
      "socTip": "When a device stops reporting, verify Sense is running and check the SENSE operational log for connectivity errors.",
      "docRef": "Microsoft Learn: Troubleshoot onboarding issues"
    }
  },
  {
    "id": "mde-059",
    "topic": "Cloud-delivered protection",
    "scenario": "A new malware variant is seen in the wild. Contoso wants the fastest possible protection updates.",
    "question": "What does cloud-delivered protection provide?",
    "options": [
      "Near-real-time reputation and model updates from Microsoft’s cloud so the endpoint can block emerging threats faster than traditional signature updates alone",
      "Only monthly signature updates",
      "A replacement for the need for any local scanning",
      "Protection that only works when the device is offline"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud-Delivered Protection",
      "analysis": [
        "Option A is CORRECT: Cloud protection supplies rapid reputation and ML model decisions.",
        "Option B is INCORRECT: Cloud updates are far more frequent.",
        "Option C is INCORRECT: Local scanning remains important.",
        "Option D is INCORRECT: Cloud protection requires connectivity."
      ],
      "codeSnippet": "// Ensure cloud-delivered protection is enabled\n// MAPS / cloud block level settings\n// Critical for ASR and next-gen protection",
      "socTip": "Never disable cloud-delivered protection in production; it is one of the highest-value settings for emerging threats.",
      "docRef": "Microsoft Learn: Cloud-delivered protection"
    }
  },
  {
    "id": "mde-060",
    "topic": "Block at first sight",
    "scenario": "The security team wants unknown executables to be checked against the cloud before they are allowed to run.",
    "question": "What is Block at first sight?",
    "options": [
      "A cloud-powered feature that can block previously unseen executables while a reputation query is performed, preventing execution of new malware",
      "A feature that blocks the first user who logs on each day",
      "A firewall rule that blocks port 445",
      "A setting that only applies to Office macros"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Block at First Sight",
      "analysis": [
        "Option A is CORRECT: BAFS queries the cloud for new files and can block them pending analysis.",
        "Option B is INCORRECT: Unrelated to logons.",
        "Option C is INCORRECT: Not a simple port block.",
        "Option D is INCORRECT: It targets executables more broadly."
      ],
      "codeSnippet": "// Cloud-delivered protection + BAFS enabled\n// Sample submission optional but recommended",
      "socTip": "Enable sample submission together with BAFS so Microsoft can improve detection of the blocked samples.",
      "docRef": "Microsoft Learn: Block at first sight"
    }
  },
  {
    "id": "mde-061",
    "topic": "Advanced features – preview features",
    "scenario": "Contoso wants to test upcoming Defender for Endpoint capabilities before general availability.",
    "question": "How can preview features be enabled?",
    "options": [
      "Turn on preview features in the Microsoft Defender portal settings so the tenant receives early access to new capabilities",
      "Preview features are automatically enabled for all tenants",
      "Preview features require a separate paid SKU with no portal toggle",
      "Preview features can only be enabled by Microsoft support on request"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Preview Features Toggle",
      "analysis": [
        "Option A is CORRECT: A portal setting enables preview features for the tenant.",
        "Option B is INCORRECT: They are opt-in.",
        "Option C is INCORRECT: Preview access is controlled by the toggle, not a separate SKU in most cases.",
        "Option D is INCORRECT: Customers can self-enable."
      ],
      "codeSnippet": "// Settings → Preview features\n// Enable → review new capabilities\n// Disable if issues arise",
      "socTip": "Enable preview features in a pilot device group first; some previews can change behavior significantly.",
      "docRef": "Microsoft Learn: Preview features"
    }
  },
  {
    "id": "mde-062",
    "topic": "Remediation actions history",
    "scenario": "An auditor asks for a history of all isolation and quarantine actions taken in the last quarter.",
    "question": "Where is the history of remediation and response actions retained?",
    "options": [
      "The Action center and related investigation/incident records retain history of actions, status, and initiating account for audit and review",
      "Actions are discarded after 24 hours with no history",
      "History is only stored on each endpoint locally",
      "History is only available via Microsoft support request"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Action History and Auditability",
      "analysis": [
        "Option A is CORRECT: Action center and incident data provide the audit trail of response actions.",
        "Option B is INCORRECT: History is retained longer.",
        "Option C is INCORRECT: Central cloud history is the primary source.",
        "Option D is INCORRECT: Customers have self-service access."
      ],
      "codeSnippet": "// Action center → filter by date and action type\n// Export for audit evidence",
      "socTip": "Export Action center data periodically if your retention or SIEM requirements exceed the portal’s native window.",
      "docRef": "Microsoft Learn: Action center"
    }
  },
  {
    "id": "mde-063",
    "topic": "Device isolation – release",
    "scenario": "Investigation of an isolated device is complete and the threat has been removed.",
    "question": "How is a device released from isolation?",
    "options": [
      "From the device page or Action center, choose Release from isolation; network connectivity is restored while the sensor connection is maintained throughout",
      "The device automatically releases after exactly 1 hour with no option to control it",
      "Only a local admin can release isolation by rebooting",
      "Isolation can never be released"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Releasing Isolation",
      "analysis": [
        "Option A is CORRECT: Release is an explicit portal/API action that restores normal network access.",
        "Option B is INCORRECT: Timing is under operator control (though automatic disruption may be time-limited).",
        "Option C is INCORRECT: Release is performed from the cloud console.",
        "Option D is INCORRECT: Isolation is reversible."
      ],
      "codeSnippet": "// Device page → Release from isolation\n// Confirm in Action center",
      "socTip": "Document the reason for release in the incident notes so the timeline of containment is clear for post-incident review.",
      "docRef": "Microsoft Learn: Isolate devices"
    }
  },
  {
    "id": "mde-064",
    "topic": "Live Response – basic vs advanced commands",
    "scenario": "A Tier 1 analyst has permission to run basic Live Response commands but not advanced ones.",
    "question": "What is the difference between basic and advanced Live Response commands?",
    "options": [
      "Basic commands cover common investigation tasks (directory listing, process list, file info); advanced commands include actions such as running scripts, collecting full packages, and more powerful remediation",
      "There is no difference",
      "Basic commands can wipe the disk; advanced cannot",
      "Advanced commands are only for macOS"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Live Response Permission Tiers",
      "analysis": [
        "Option A is CORRECT: Role permissions distinguish basic investigative commands from advanced/scripting and stronger remediation commands.",
        "Option B is INCORRECT: The distinction is intentional for least privilege.",
        "Option C is INCORRECT: Neither tier is designed for destructive disk wipe as a standard command.",
        "Option D is INCORRECT: The model applies across supported platforms."
      ],
      "codeSnippet": "// Roles → Live response permissions\n// Basic vs Advanced commands\n// Assign Advanced only to senior responders",
      "socTip": "Keep advanced Live Response rights limited; use the library so Tier 1 can still run approved scripts under supervision.",
      "docRef": "Microsoft Learn: Live response commands"
    }
  },
  {
    "id": "mde-065",
    "topic": "Investigation package contents",
    "scenario": "An analyst downloads an investigation package and needs to know what artifacts are typically included.",
    "question": "Which artifacts are commonly found in an investigation package?",
    "options": [
      "Process lists, network connections, autoruns, scheduled tasks, installed programs, selected event logs, and other forensic data useful for offline analysis",
      "Only the pagefile",
      "Only browser history",
      "Only the SAM database"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Investigation Package Artifacts",
      "analysis": [
        "Option A is CORRECT: The package is a broad forensic snapshot designed for offline investigation.",
        "Option B is INCORRECT: Far more than pagefile is collected.",
        "Option C is INCORRECT: Browser history may appear in some collections but is not the sole content.",
        "Option D is INCORRECT: Sensitive credential stores are not the focus of the standard package."
      ],
      "codeSnippet": "// Download ZIP → extract\n// Review Processes.csv, NetworkConnections.csv,\n//   Autoruns, Prefetch, Event logs, etc.",
      "socTip": "Keep a local analysis VM ready with timelines and parsing tools so investigation packages can be reviewed quickly.",
      "docRef": "Microsoft Learn: Investigation package"
    }
  },
  {
    "id": "mde-066",
    "topic": "EDR block mode vs active AV",
    "scenario": "A device is running Microsoft Defender Antivirus in active mode and EDR in block mode is also enabled.",
    "question": "Is there a conflict between active MDAV and EDR in block mode?",
    "options": [
      "No — when MDAV is active, EDR in block mode still adds behavioral post-breach blocking; they complement each other",
      "Yes — one must be disabled",
      "EDR in block mode only works with third-party AV",
      "Active MDAV disables all EDR capabilities"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Complementary Protection Layers",
      "analysis": [
        "Option A is CORRECT: Active AV and EDR in block mode work together for defense in depth.",
        "Option B is INCORRECT: No requirement to disable either.",
        "Option C is INCORRECT: EDR in block mode is especially valuable with third-party AV but also works with active MDAV.",
        "Option D is INCORRECT: EDR continues to function."
      ],
      "codeSnippet": "// Both can be On simultaneously\n// Active MDAV + EDR block mode = strongest posture",
      "socTip": "Leave both enabled unless a specific compatibility issue is documented for a line-of-business application.",
      "docRef": "Microsoft Learn: EDR in block mode"
    }
  },
  {
    "id": "mde-067",
    "topic": "Custom detection – entity mapping",
    "scenario": "A custom detection rule fires but the resulting alert does not link to the correct device or user entities.",
    "question": "Why is entity mapping important in custom detection rules?",
    "options": [
      "Correct entity mapping allows the alert to participate in incident correlation, appear on device/user pages, and enable entity-based response actions",
      "Entity mapping is optional and has no effect",
      "Entity mapping only works for email alerts",
      "Entity mapping deletes the matched events"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Entity Mapping in Custom Detections",
      "analysis": [
        "Option A is CORRECT: Mapping query columns to entities (Device, User, etc.) is what connects the alert into the broader XDR graph.",
        "Option B is INCORRECT: Mapping is critical for usability.",
        "Option C is INCORRECT: It applies to endpoint and other detections.",
        "Option D is INCORRECT: Mapping does not delete data."
      ],
      "codeSnippet": "// Create detection rule → Entities\n// Map DeviceName → Device\n// Map AccountName → User\n// etc.",
      "socTip": "Always test a custom detection with a known-positive sample and verify the alert shows the expected entities before enabling broadly.",
      "docRef": "Microsoft Learn: Custom detections"
    }
  },
  {
    "id": "mde-068",
    "topic": "Alert tuning vs suppression",
    "scenario": "The SOC needs to permanently hide a specific false-positive pattern without turning off the underlying detection.",
    "question": "What is the difference between alert tuning and suppression in practice?",
    "options": [
      "Both can reduce noise; suppression rules hide or auto-resolve matching alerts, while broader tuning may adjust detection logic or thresholds depending on the product context — the goal is scoped noise reduction without disabling protection",
      "They are identical in every product",
      "Tuning always disables the detection globally",
      "Suppression requires a support ticket for every alert"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Noise Reduction Techniques",
      "analysis": [
        "Option A is CORRECT: Scoped suppression/tuning preserves the detection for true positives while silencing known benign patterns.",
        "Option B is INCORRECT: Terminology and exact behavior can vary, but the intent is noise reduction.",
        "Option C is INCORRECT: Good tuning is scoped, not global disable.",
        "Option D is INCORRECT: Customers create suppression rules directly."
      ],
      "codeSnippet": "// Alert → Create suppression rule\n// Scope tightly (path, hash, device group)\n// Review rules quarterly",
      "socTip": "Name suppression rules with a ticket number and owner so they can be revisited when the underlying software changes.",
      "docRef": "Microsoft Learn: Suppress alerts"
    }
  },
  {
    "id": "mde-069",
    "topic": "Device groups – dynamic rules",
    "scenario": "Northwind wants a device group that automatically includes every device whose name starts with 'FIN-'.",
    "question": "How can device groups stay up to date as new devices are onboarded?",
    "options": [
      "Use dynamic membership rules based on device name, tags, domain, OS, or other properties so new matching devices join the group automatically",
      "Manually add every new device forever",
      "Dynamic rules are not supported",
      "Only Azure AD groups can be used"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Dynamic Device Group Membership",
      "analysis": [
        "Option A is CORRECT: Dynamic rules keep groups current without manual maintenance.",
        "Option B is INCORRECT: Manual membership does not scale.",
        "Option C is INCORRECT: Dynamic rules are supported.",
        "Option D is INCORRECT: MDE device groups have their own rule engine (and can also integrate with other constructs)."
      ],
      "codeSnippet": "// Device groups → Create\n// Rule: Device name starts with FIN-\n// Or Tag equals Finance",
      "socTip": "Prefer tags + dynamic rules over hostname prefixes when possible; tags are more flexible when devices are renamed.",
      "docRef": "Microsoft Learn: Device groups"
    }
  },
  {
    "id": "mde-070",
    "topic": "RBAC – device group scoping",
    "scenario": "A regional SOC should only see devices in their geography.",
    "question": "How is visibility limited to a subset of devices?",
    "options": [
      "Assign the role with a device-group scope so the user only sees alerts, devices, and actions for devices in that group",
      "RBAC cannot limit device visibility",
      "Only network firewalls can limit visibility",
      "Each region needs a separate Microsoft 365 tenant"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Scoped Role Assignments",
      "analysis": [
        "Option A is CORRECT: Device-group scoping on roles enforces least-privilege visibility.",
        "Option B is INCORRECT: Scoping is a core RBAC feature.",
        "Option C is INCORRECT: Network controls do not filter portal data.",
        "Option D is INCORRECT: Single-tenant RBAC is the intended design."
      ],
      "codeSnippet": "// Roles → Assign → select device groups\n// User only sees scoped devices",
      "socTip": "Combine geographic device groups with regional Azure AD groups for clean joiners/movers/leavers handling.",
      "docRef": "Microsoft Learn: RBAC device groups"
    }
  },
  {
    "id": "mde-071",
    "topic": "Automated investigation – approval",
    "scenario": "A device group is set to Semi – require approval for all folders. AIR wants to quarantine a file.",
    "question": "What happens under a 'require approval' automation level?",
    "options": [
      "AIR completes the investigation and proposes remediation actions, but an analyst must approve before the actions are executed on the device",
      "AIR never investigates",
      "AIR automatically remediates without any record",
      "Approval is only required for email alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Semi-Automation Approval Gate",
      "analysis": [
        "Option A is CORRECT: Semi levels pause at remediation for human approval while still performing investigation.",
        "Option B is INCORRECT: Investigation still runs.",
        "Option C is INCORRECT: Remediation waits for approval.",
        "Option D is INCORRECT: The gate applies to endpoint remediation actions."
      ],
      "codeSnippet": "// Action center → Pending approval\n// Review → Approve or Reject",
      "socTip": "Set a SLA for pending approvals so semi-automated remediation does not stall for days.",
      "docRef": "Microsoft Learn: Automation levels"
    }
  },
  {
    "id": "mde-072",
    "topic": "Threat analytics",
    "scenario": "A new threat analytics report appears about a widespread phishing campaign that drops a specific payload.",
    "question": "How can Threat analytics help the SOC?",
    "options": [
      "Threat analytics provides expert reports on active threats, including impact in your environment, affected devices, and recommended defender actions and hunting queries",
      "It only lists general news headlines",
      "It automatically patches all devices",
      "It is only available to Microsoft employees"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Threat Analytics Reports",
      "analysis": [
        "Option A is CORRECT: Reports combine global intelligence with tenant-specific impact and actionable guidance.",
        "Option B is INCORRECT: Reports are security-operational, not general news.",
        "Option C is INCORRECT: Remediation is guided, not automatic for every recommendation.",
        "Option D is INCORRECT: Customers access Threat analytics in the portal."
      ],
      "codeSnippet": "// Threat analytics → open report\n// View impacted devices\n// Run provided hunting queries\n// Apply recommended protections",
      "socTip": "When a high-impact report appears, immediately run the included hunting queries and check the 'Impacted assets' section for your tenant.",
      "docRef": "Microsoft Learn: Threat analytics"
    }
  },
  {
    "id": "mde-073",
    "topic": "Advanced hunting – time range",
    "scenario": "A hunter writes a query but receives a warning about the look-back period.",
    "question": "What should analysts keep in mind about Advanced Hunting time ranges?",
    "options": [
      "Queries are limited by the data retention period and practical performance limits; very long look-backs on large tables may timeout or be truncated — use efficient filters and appropriate time windows",
      "There is no limit; queries can scan years of data instantly",
      "Time range is fixed at 1 hour and cannot be changed",
      "Hunting only works on data from the last 15 minutes"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Hunting Time Window and Performance",
      "analysis": [
        "Option A is CORRECT: Retention and query performance constrain practical look-backs; efficient KQL is essential.",
        "Option B is INCORRECT: Retention and timeouts apply.",
        "Option C is INCORRECT: Analysts choose the time range within limits.",
        "Option D is INCORRECT: Multi-day hunting is supported within retention."
      ],
      "codeSnippet": "// Prefer:\n// | where Timestamp > ago(7d)\n// + early filters on DeviceName / ActionType\n// Avoid unbounded scans on large tables",
      "socTip": "For multi-week investigations, break hunts into smaller time chunks or summarize early to stay within limits.",
      "docRef": "Microsoft Learn: Advanced hunting overview"
    }
  },
  {
    "id": "mde-074",
    "topic": "Response – contain device (when available)",
    "scenario": "In some scenarios an analyst needs a containment option that is lighter or different from full isolation.",
    "question": "What is the general purpose of device containment / isolation family of actions?",
    "options": [
      "To limit an attacker’s ability to communicate or move laterally from a compromised device while preserving enough connectivity for investigation and remediation",
      "To permanently destroy the device hardware",
      "To only log the attacker without any blocking",
      "To uninstall the operating system"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Containment Actions Purpose",
      "analysis": [
        "Option A is CORRECT: Isolation and related containment actions aim to stop attacker control and spread while keeping the device manageable.",
        "Option B is INCORRECT: Hardware is not destroyed.",
        "Option C is INCORRECT: Containment actively limits connectivity.",
        "Option D is INCORRECT: OS remains intact."
      ],
      "codeSnippet": "// Isolate / Restrict app execution / etc.\n// Choose based on business impact and threat severity",
      "socTip": "Match containment strength to threat severity and business criticality of the device.",
      "docRef": "Microsoft Learn: Response actions"
    }
  },
  {
    "id": "mde-075",
    "topic": "Sensor health – impaired communications",
    "scenario": "Several devices show 'Impaired communications' in the health report.",
    "question": "What does impaired communications typically indicate?",
    "options": [
      "The device is onboarded but is having trouble reliably sending telemetry or receiving commands — often due to network proxy, firewall, or connectivity issues to Microsoft endpoints",
      "The device has been successfully isolated",
      "The device is not onboarded at all",
      "Impaired status means the device is healthy"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Impaired Sensor Communications",
      "analysis": [
        "Option A is CORRECT: Impaired communications points to connectivity or proxy problems between the sensor and the cloud service.",
        "Option B is INCORRECT: Isolation is a separate state.",
        "Option C is INCORRECT: Impaired usually means onboarded but unhealthy.",
        "Option D is INCORRECT: Impaired is a problem state."
      ],
      "codeSnippet": "// Check proxy settings, firewall allow-lists\n// Required URLs for Defender for Endpoint\n// SENSE operational log",
      "socTip": "Maintain an allow-list of required Microsoft Defender for Endpoint URLs/IPs on all egress proxies and firewalls.",
      "docRef": "Microsoft Learn: Connectivity requirements"
    }
  },
  {
    "id": "mde-076",
    "topic": "Plan 1 vs Plan 2",
    "scenario": "A smaller organization is evaluating Defender for Endpoint licensing.",
    "question": "What is a key difference between Defender for Endpoint Plan 1 and Plan 2?",
    "options": [
      "Plan 2 includes the full EDR, automated investigation, advanced hunting, and threat & vulnerability management capabilities, while Plan 1 focuses more on prevention and basic response",
      "Plan 1 includes everything and Plan 2 is a downgrade",
      "There is no difference",
      "Plan 2 only supports Linux"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "MDE Plan Capabilities",
      "analysis": [
        "Option A is CORRECT: Plan 2 is the full SOC-oriented SKU with EDR, AIR, hunting, and TVM; Plan 1 is lighter.",
        "Option B is INCORRECT: Plan 2 is the higher capability plan.",
        "Option C is INCORRECT: Feature differences are significant.",
        "Option D is INCORRECT: Both plans support multiple platforms with different feature sets."
      ],
      "codeSnippet": "// Evaluate required capabilities:\n// Advanced hunting, AIR, TVM → Plan 2\n// Core prevention + some response → Plan 1 may suffice",
      "socTip": "Map your SC-200 / SOC use cases to the capability matrix before choosing a plan; hunting and AIR almost always need Plan 2.",
      "docRef": "Microsoft Learn: Defender for Endpoint plans"
    }
  },
  {
    "id": "mde-077",
    "topic": "Onboarding – local script",
    "scenario": "A few standalone kiosk machines cannot be reached by Intune or GPO.",
    "question": "How can individual devices be onboarded when centralized deployment is unavailable?",
    "options": [
      "Download the appropriate onboarding package from the portal and run the local script or package on each device with administrative rights",
      "Onboarding is impossible without Intune",
      "Only Microsoft can onboard devices remotely without a package",
      "Kiosk devices are unsupported"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Local Onboarding Package",
      "analysis": [
        "Option A is CORRECT: The portal provides downloadable packages/scripts for manual onboarding when automated channels are unavailable.",
        "Option B is INCORRECT: Manual onboarding is supported.",
        "Option C is INCORRECT: Customers run the package.",
        "Option D is INCORRECT: Many kiosk configurations are supported."
      ],
      "codeSnippet": "// Portal → Onboarding → Local script\n// Run as admin on the device\n// Verify in Device inventory",
      "socTip": "After manual onboarding, immediately apply the same hardening baseline (ASR, Tamper Protection, etc.) used for managed devices.",
      "docRef": "Microsoft Learn: Onboard devices using local script"
    }
  },
  {
    "id": "mde-078",
    "topic": "Advanced hunting – summarize and joins",
    "scenario": "A hunter needs a count of distinct devices that contacted a malicious domain, enriched with OS information.",
    "question": "Which KQL pattern is commonly used for this type of hunt?",
    "options": [
      "Filter DeviceNetworkEvents for the domain, summarize by DeviceId/DeviceName, then join to DeviceInfo for OS and other device properties",
      "Export everything to Excel and count manually",
      "Only use the portal UI filters with no KQL",
      "Hunting cannot join tables"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "KQL Summarize and Join Patterns",
      "analysis": [
        "Option A is CORRECT: Filter → summarize → join is a standard efficient pattern for prevalence and enrichment.",
        "Option B is INCORRECT: Manual Excel work does not scale.",
        "Option C is INCORRECT: Complex hunts require KQL.",
        "Option D is INCORRECT: Joins are fully supported."
      ],
      "codeSnippet": "DeviceNetworkEvents\n| where RemoteUrl has 'malicious.example'\n| summarize Devices=dcount(DeviceId) by DeviceName\n| join kind=inner DeviceInfo on DeviceName",
      "socTip": "Project only needed columns before large joins to improve query performance and readability.",
      "docRef": "Microsoft Learn: Advanced hunting query best practices"
    }
  },
  {
    "id": "mde-079",
    "topic": "File prevalence",
    "scenario": "An unknown executable appears on one executive laptop. The analyst checks the file entity page.",
    "question": "What does low prevalence indicate about a file?",
    "options": [
      "The file has been seen on few or no other devices in the organization (and possibly globally), which can be a signal of targeted or new malware — but prevalence alone is not proof of malice",
      "The file is guaranteed safe",
      "The file is guaranteed malicious",
      "Prevalence is not shown in the portal"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "File Prevalence Signal",
      "analysis": [
        "Option A is CORRECT: Low prevalence is a useful hunting and investigation signal but must be combined with reputation, behavior, and context.",
        "Option B is INCORRECT: Low prevalence does not equal safe.",
        "Option C is INCORRECT: Low prevalence does not equal malicious by itself.",
        "Option D is INCORRECT: Prevalence is a standard entity field."
      ],
      "codeSnippet": "// File entity → Prevalence\n// First/Last seen\n// Org and global stats when available",
      "socTip": "Treat low-prevalence executables on high-value devices as high priority for deep analysis and process-tree review.",
      "docRef": "Microsoft Learn: Investigate files"
    }
  },
  {
    "id": "mde-080",
    "topic": "Process tree / process explorer",
    "scenario": "An alert shows a suspicious process. The analyst needs to see parent and child processes.",
    "question": "How can process ancestry be investigated?",
    "options": [
      "From the alert or process entity, open the process tree / process details to view parent-child relationships, command lines, and related network or file activity",
      "Process ancestry is never available",
      "Only the child process is shown without parents",
      "Process trees are only available for macOS"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Process Tree Investigation",
      "analysis": [
        "Option A is CORRECT: Process trees are a core investigation visualization for understanding how malware was launched.",
        "Option B is INCORRECT: Ancestry is available.",
        "Option C is INCORRECT: Parent context is shown.",
        "Option D is INCORRECT: Windows process trees are a primary use case."
      ],
      "codeSnippet": "// Alert → Process → View process tree\n// Or Advanced Hunting with InitiatingProcess* columns",
      "socTip": "Always walk the process tree up to the initial user-launched or scheduled process to find the true entry point.",
      "docRef": "Microsoft Learn: Investigate processes"
    }
  },
  {
    "id": "mde-081",
    "topic": "Network protection audit mode",
    "scenario": "Before enforcing Network protection in block mode, the SOC wants visibility into what would have been blocked.",
    "question": "How can impact be assessed before enforcing Network protection?",
    "options": [
      "Enable Network protection in Audit mode, review the resulting events and reports, then switch to Block after validating false-positive rates",
      "There is no audit mode; it must be block or off",
      "Audit mode only works for email",
      "Audit mode requires a separate product"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Network Protection Audit Mode",
      "analysis": [
        "Option A is CORRECT: Audit mode provides the same detection telemetry without blocking, enabling safe validation.",
        "Option B is INCORRECT: Audit mode exists.",
        "Option C is INCORRECT: It applies to endpoint network protection.",
        "Option D is INCORRECT: It is part of Defender for Endpoint."
      ],
      "codeSnippet": "// Policy → Network protection = Audit\n// Review reports / DeviceEvents\n// Switch to Block when ready",
      "socTip": "Run Network protection in Audit for at least one full business cycle (including month-end processes) before enforcing Block.",
      "docRef": "Microsoft Learn: Network protection"
    }
  },
  {
    "id": "mde-082",
    "topic": "ASR exclusions",
    "scenario": "After enabling an ASR rule in Block mode, a line-of-business application is blocked.",
    "question": "How should legitimate applications be allowed while keeping the ASR rule active?",
    "options": [
      "Add a scoped exclusion for the specific application path or certificate so the rule continues to protect against real threats while permitting the business app",
      "Disable the ASR rule entirely for the whole organization",
      "Uninstall Defender for Endpoint",
      "Add a global allow for all executables"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Scoped ASR Exclusions",
      "analysis": [
        "Option A is CORRECT: Exclusions should be as narrow as possible (path, hash, or publisher) so protection remains effective.",
        "Option B is INCORRECT: Disabling the rule removes protection for everyone.",
        "Option C is INCORRECT: Uninstalling eliminates endpoint security.",
        "Option D is INCORRECT: Global allows defeat the purpose of ASR."
      ],
      "codeSnippet": "// ASR policy → Exclusions\n// Add path or file\n// Prefer publisher/certificate exclusions when possible",
      "socTip": "Document every ASR exclusion with business owner and review date; treat exclusions as technical debt.",
      "docRef": "Microsoft Learn: ASR exclusions"
    }
  },
  {
    "id": "mde-083",
    "topic": "Microsoft Defender portal URL",
    "scenario": "A new analyst asks where to access Microsoft Defender for Endpoint.",
    "question": "What is the primary portal URL for Microsoft Defender for Endpoint / Defender XDR?",
    "options": [
      "https://security.microsoft.com — the unified Microsoft Defender portal",
      "https://portal.azure.com only",
      "https://outlook.office.com",
      "https://aka.ms/defender is the only permanent URL and never changes"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified Defender Portal",
      "analysis": [
        "Option A is CORRECT: security.microsoft.com is the current unified portal for Defender XDR workloads including Endpoint.",
        "Option B is INCORRECT: Azure portal is for Azure resources; some settings overlap but the SOC lives in security.microsoft.com.",
        "Option C is INCORRECT: Outlook is email.",
        "Option D is INCORRECT: aka.ms links are shortcuts; the primary portal is security.microsoft.com."
      ],
      "codeSnippet": "// https://security.microsoft.com\n// Endpoints, Incidents, Hunting, Actions, Settings",
      "socTip": "Bookmark security.microsoft.com and ensure Conditional Access policies allow SOC analysts to reach it from expected locations.",
      "docRef": "Microsoft Learn: Microsoft Defender portal"
    }
  },
  {
    "id": "mde-084",
    "topic": "Integration with Microsoft Sentinel",
    "scenario": "Northwind streams Defender for Endpoint alerts and advanced hunting data into Microsoft Sentinel.",
    "question": "How does Defender for Endpoint typically integrate with Microsoft Sentinel?",
    "options": [
      "Via the Microsoft Defender XDR / Defender for Endpoint data connector that ingests alerts, incidents, and optionally advanced hunting data into the Sentinel workspace for correlation and SOAR",
      "There is no integration path",
      "Only via manual CSV export every day",
      "Integration requires disabling the Defender portal"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "MDE to Sentinel Data Connector",
      "analysis": [
        "Option A is CORRECT: Official connectors bring MDE signals into Sentinel for cross-product correlation and automation.",
        "Option B is INCORRECT: Integration is first-class.",
        "Option C is INCORRECT: Continuous connectors replace manual export.",
        "Option D is INCORRECT: Portal and Sentinel work together."
      ],
      "codeSnippet": "// Sentinel → Data connectors\n// Microsoft Defender for Endpoint / XDR\n// Configure incident / alert ingestion",
      "socTip": "Decide whether to bi-directionally sync incidents; many SOCs prefer Sentinel as the system of record for ticketing while keeping deep endpoint investigation in the Defender portal.",
      "docRef": "Microsoft Learn: Connect Defender for Endpoint to Sentinel"
    }
  },
  {
    "id": "mde-085",
    "topic": "Hunt for living-off-the-land binaries",
    "scenario": "The SOC wants to detect suspicious use of certutil or bitsadmin for payload download.",
    "question": "Which approach is effective for hunting LOLBin abuse?",
    "options": [
      "Query DeviceProcessEvents for known LOLBin file names with suspicious command-line patterns (download, decode, long encoded strings) and low-prevalence parent processes",
      "LOLBins cannot be detected because they are legitimate Microsoft binaries",
      "Only network indicators can detect LOLBin use",
      "Hunting for LOLBins requires a third-party EDR"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "LOLBin Hunting with Process Events",
      "analysis": [
        "Option A is CORRECT: Command-line aware process telemetry is the primary way to detect malicious use of legitimate binaries.",
        "Option B is INCORRECT: Behavioral patterns distinguish abuse from legitimate use.",
        "Option C is INCORRECT: Process command lines are often more reliable than network alone.",
        "Option D is INCORRECT: MDE Advanced Hunting is sufficient."
      ],
      "codeSnippet": "DeviceProcessEvents\n| where FileName in ('certutil.exe','bitsadmin.exe')\n| where ProcessCommandLine has_any ('urlcache','transfer','http')",
      "socTip": "Maintain a living list of LOLBins and suspicious arguments relevant to your environment; update it when new techniques appear in Threat analytics.",
      "docRef": "Microsoft Learn: Hunt for threats with advanced hunting"
    }
  },
  {
    "id": "mde-086",
    "topic": "Exploit protection",
    "scenario": "Contoso wants to apply mitigations such as Data Execution Prevention and Address Space Layout Randomization more strictly for high-risk applications.",
    "question": "What does Exploit protection provide in Defender for Endpoint?",
    "options": [
      "System- and application-level mitigations (DEP, ASLR, CFG, etc.) that can be configured via policy to reduce the success rate of memory corruption exploits",
      "Only a firewall rule set",
      "Only antivirus signature updates",
      "A replacement for all ASR rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Exploit Protection Mitigations",
      "analysis": [
        "Option A is CORRECT: Exploit protection applies OS and per-app mitigations that harden against common exploit techniques.",
        "Option B is INCORRECT: It is not limited to firewall rules.",
        "Option C is INCORRECT: Signature updates are separate.",
        "Option D is INCORRECT: Exploit protection complements ASR, it does not replace it."
      ],
      "codeSnippet": "// Endpoint security → Exploit protection\n// System settings + Program settings",
      "socTip": "Start with recommended defaults, then add per-app mitigations for frequently targeted browsers and Office apps.",
      "docRef": "Microsoft Learn: Exploit protection"
    }
  },
  {
    "id": "mde-087",
    "topic": "Application control WDAC",
    "scenario": "A high-security business unit requires that only approved applications can run on their workstations.",
    "question": "How can application allow-listing be approached with Microsoft endpoint security?",
    "options": [
      "Use Windows Defender Application Control (WDAC) or AppLocker policies, managed alongside Defender for Endpoint, to enforce which binaries are allowed to execute",
      "Application control is impossible on Windows",
      "Only Network protection can block applications",
      "Only disabling the internet prevents unapproved apps"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Application Control with WDAC",
      "analysis": [
        "Option A is CORRECT: WDAC/AppLocker provide strong application control that works with the broader Defender stack.",
        "Option B is INCORRECT: Windows has mature application control technology.",
        "Option C is INCORRECT: Network protection does not replace code integrity policies.",
        "Option D is INCORRECT: Offline execution would still be possible without code integrity."
      ],
      "codeSnippet": "// WDAC policy design → deploy via Intune/GPO\n// Audit mode first, then enforced",
      "socTip": "Always deploy application control in Audit mode and review block events before enforcing.",
      "docRef": "Microsoft Learn: Windows Defender Application Control"
    }
  },
  {
    "id": "mde-088",
    "topic": "Memory scanning and fileless",
    "scenario": "An attacker injects shellcode into a legitimate process. The SOC wants assurance that in-memory threats can still be detected.",
    "question": "How does Microsoft Defender Antivirus help with in-memory threats?",
    "options": [
      "Behavior monitoring, AMSI integration, and memory scanning engines help detect malicious code running in memory even when it never touches disk",
      "In-memory threats are completely undetectable",
      "Only network indicators can detect memory injection",
      "Memory scanning requires a reboot after every scan"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "In-Memory Threat Detection",
      "analysis": [
        "Option A is CORRECT: Multiple engines including behavior monitoring and AMSI target fileless and in-memory techniques.",
        "Option B is INCORRECT: Modern AV/EDR is designed for fileless threats.",
        "Option C is INCORRECT: Endpoint behavior is often the primary signal.",
        "Option D is INCORRECT: Scans do not require reboot for memory inspection."
      ],
      "codeSnippet": "// Real-time protection + behavior monitoring On\n// Cloud-delivered protection On",
      "socTip": "Ensure real-time protection and behavior monitoring remain enabled; they are critical for fileless attack detection.",
      "docRef": "Microsoft Learn: Next-generation protection"
    }
  },
  {
    "id": "mde-089",
    "topic": "AMSI integration",
    "scenario": "Malicious PowerShell is heavily obfuscated. The SOC relies on script content inspection.",
    "question": "What is the Antimalware Scan Interface (AMSI) role in Defender?",
    "options": [
      "AMSI allows script hosts (PowerShell, Office VBA, etc.) to submit content for scanning by Defender before or during execution, improving detection of obfuscated scripts",
      "AMSI only scans downloaded EXE files",
      "AMSI is a network protocol",
      "AMSI replaces the need for ASR rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AMSI for Script Scanning",
      "analysis": [
        "Option A is CORRECT: AMSI bridges script engines and the antimalware engine for content-based detection.",
        "Option B is INCORRECT: AMSI is particularly valuable for scripts.",
        "Option C is INCORRECT: It is an interface, not a network protocol.",
        "Option D is INCORRECT: AMSI and ASR are complementary."
      ],
      "codeSnippet": "// PowerShell + AMSI\n// Office macro AMSI",
      "socTip": "If script-based attacks increase, verify AMSI is not being bypassed and consider ASR rules that block obfuscated scripts.",
      "docRef": "Microsoft Learn: AMSI"
    }
  },
  {
    "id": "mde-090",
    "topic": "Sample submission",
    "scenario": "Cloud protection blocks a new file but Microsoft needs the sample to improve detection.",
    "question": "What does automatic sample submission do?",
    "options": [
      "It can send suspicious or unknown samples to Microsoft for analysis (with privacy controls), improving cloud protection for all customers",
      "It uploads the entire hard drive nightly",
      "It only submits Office documents",
      "Sample submission cannot be controlled by the customer"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Sample Submission",
      "analysis": [
        "Option A is CORRECT: Controlled sample submission feeds Microsoft’s analysis pipeline while respecting privacy settings.",
        "Option B is INCORRECT: Only selected samples are considered.",
        "Option C is INCORRECT: Multiple file types can be submitted.",
        "Option D is INCORRECT: Customers configure submission levels."
      ],
      "codeSnippet": "// Cloud-delivered protection settings\n// Automatic sample submission options",
      "socTip": "Prefer sending safe samples at minimum so cloud protection improves without sharing clearly sensitive files.",
      "docRef": "Microsoft Learn: Cloud protection and sample submission"
    }
  },
  {
    "id": "mde-091",
    "topic": "Device health reports",
    "scenario": "The endpoint engineering team wants a broad view of AV signature age, sensor versions, and configuration issues.",
    "question": "Where can a consolidated device health overview be found?",
    "options": [
      "Device health and sensor health reports in the Microsoft Defender portal, plus per-device health details on the device page",
      "Only in Azure Monitor workbooks with no portal view",
      "Only by emailing every device owner",
      "Health data is not available to customers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Device and Sensor Health Reports",
      "analysis": [
        "Option A is CORRECT: Portal reports and device pages surface health, configuration, and communication status.",
        "Option B is INCORRECT: Native portal reports exist.",
        "Option C is INCORRECT: Central reports replace manual outreach.",
        "Option D is INCORRECT: Health data is customer-visible."
      ],
      "codeSnippet": "// Reports → Device health / Sensor health",
      "socTip": "Create a recurring export of devices with outdated signatures or impaired sensors for the endpoint ops team.",
      "docRef": "Microsoft Learn: Device health"
    }
  },
  {
    "id": "mde-092",
    "topic": "Alert prioritization",
    "scenario": "A new analyst is learning how to prioritize the alert queue.",
    "question": "What factors typically influence how analysts prioritize Defender for Endpoint alerts?",
    "options": [
      "Severity (High/Medium/Low/Informational), category (malware, ransomware, lateral movement, etc.), confidence, affected assets, and whether the alert is part of a multi-stage incident",
      "Only the alphabetical order of alert titles",
      "Only the time of day the alert fired",
      "Severity is random and should be ignored"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Prioritization Factors",
      "analysis": [
        "Option A is CORRECT: Severity, category, asset criticality, and incident context drive triage order.",
        "Option B is INCORRECT: Title sort is not a security prioritization method.",
        "Option C is INCORRECT: Time alone is insufficient.",
        "Option D is INCORRECT: Severity is meaningful."
      ],
      "codeSnippet": "// Incidents queue sorted by severity\n// High + active attacks first",
      "socTip": "Define a written triage SLA: High within 15 minutes, Medium within 2 hours, etc., and measure compliance.",
      "docRef": "Microsoft Learn: Investigate alerts"
    }
  },
  {
    "id": "mde-093",
    "topic": "Multi-stage incident correlation",
    "scenario": "Several related alerts on different devices are automatically grouped.",
    "question": "How does Defender XDR help with multi-stage attacks?",
    "options": [
      "Related alerts are correlated into incidents with a shared graph, timeline, and consolidated investigation context so analysts see the full attack story",
      "Each alert is permanently isolated with no correlation",
      "Correlation only works for email alerts",
      "Correlation requires a custom Sentinel rule for every case"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Incident Correlation Across Alerts",
      "analysis": [
        "Option A is CORRECT: Automatic correlation into incidents is a core XDR value for multi-stage attacks.",
        "Option B is INCORRECT: Correlation is intentional.",
        "Option C is INCORRECT: Endpoint, identity, email, and other signals correlate.",
        "Option D is INCORRECT: Native correlation exists in Defender XDR."
      ],
      "codeSnippet": "// Incidents → Graph, Timeline, Alerts tab",
      "socTip": "Always open the parent incident rather than working alerts in isolation when correlation has already grouped them.",
      "docRef": "Microsoft Learn: Incidents in Defender XDR"
    }
  },
  {
    "id": "mde-094",
    "topic": "Browser activity evidence",
    "scenario": "During Live Response or package analysis, an analyst needs to understand web activity on a compromised host.",
    "question": "How can browser-related evidence be obtained from an endpoint?",
    "options": [
      "Investigation packages and Live Response can collect relevant artifacts; Advanced Hunting and timeline may also show network destinations and process activity related to browsers",
      "Browser history is never available through Defender for Endpoint",
      "Only the user’s email can reveal browsing",
      "Browser evidence requires a physical disk image every time"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Browser and Web Activity Evidence",
      "analysis": [
        "Option A is CORRECT: Packages, Live Response, network events, and process command lines provide web-activity context.",
        "Option B is INCORRECT: Multiple telemetry sources cover web activity.",
        "Option C is INCORRECT: Email is not the primary source for endpoint browsing.",
        "Option D is INCORRECT: Full disk imaging is not required for every investigation."
      ],
      "codeSnippet": "// Investigation package + DeviceNetworkEvents",
      "socTip": "Correlate browser process network connections with URL indicators to reconstruct the user’s click path.",
      "docRef": "Microsoft Learn: Investigate devices"
    }
  },
  {
    "id": "mde-095",
    "topic": "Configuration role separation",
    "scenario": "Only a small group should be able to change ASR rules, advanced features, and automation levels.",
    "question": "Which role capability should be restricted to security architects / senior admins?",
    "options": [
      "Permissions to manage security settings, device groups, and advanced features — typically Security Administrator or a custom role with configuration rights, not granted to Tier 1 analysts",
      "Every analyst should have full configuration rights",
      "Configuration rights cannot be restricted",
      "Only Global Reader can change settings"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Separation of Configuration and Operations",
      "analysis": [
        "Option A is CORRECT: Least privilege means Tier 1 responds; a smaller group configures.",
        "Option B is INCORRECT: Violates least privilege.",
        "Option C is INCORRECT: RBAC supports restriction.",
        "Option D is INCORRECT: Global Reader is view-oriented."
      ],
      "codeSnippet": "// Roles → Security Administrator for config\n// Security Operator for response",
      "socTip": "Require change tickets for any modification to ASR, automation levels, or advanced features.",
      "docRef": "Microsoft Learn: RBAC roles"
    }
  },
  {
    "id": "mde-096",
    "topic": "ASR audit report",
    "scenario": "After deploying several ASR rules in Audit mode, the SOC wants to see which rules would have blocked activity.",
    "question": "Where can ASR audit events be reviewed at scale?",
    "options": [
      "The Attack surface reduction report and Advanced Hunting queries on DeviceEvents where ActionType starts with Asr and ends with Audited",
      "ASR audit data is only on each device’s local disk with no central view",
      "ASR has no audit capability",
      "Only Microsoft support can see ASR events"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ASR Reporting and Hunting",
      "analysis": [
        "Option A is CORRECT: Central reports and hunting provide fleet-wide ASR visibility.",
        "Option B is INCORRECT: Events are available centrally.",
        "Option C is INCORRECT: Audit mode exists specifically for this.",
        "Option D is INCORRECT: Customers have full access."
      ],
      "codeSnippet": "DeviceEvents\n| where ActionType startswith 'Asr'\n| where ActionType endswith 'Audited'",
      "socTip": "Group ASR audit events by rule and process name to identify the top false-positive candidates before switching to Block.",
      "docRef": "Microsoft Learn: ASR report"
    }
  },
  {
    "id": "mde-097",
    "topic": "Quick vs full AV scan",
    "scenario": "After isolating a device, an analyst wants to run an antivirus scan as part of remediation.",
    "question": "What is the difference between a quick scan and a full scan initiated from Defender for Endpoint?",
    "options": [
      "A quick scan checks common malware locations and running processes; a full scan examines more of the file system and is more thorough but takes longer",
      "There is no difference",
      "A full scan only checks the Recycle Bin",
      "Scans can only be started locally on the device"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AV Scan Types from Response Actions",
      "analysis": [
        "Option A is CORRECT: Quick vs full trade speed for thoroughness; both can be triggered remotely.",
        "Option B is INCORRECT: Scope differs.",
        "Option C is INCORRECT: Full scan covers far more than Recycle Bin.",
        "Option D is INCORRECT: Portal/API can initiate scans."
      ],
      "codeSnippet": "// Device page → Run antivirus scan\n// Quick or Full",
      "socTip": "Use quick scan for rapid post-containment checks; schedule full scans when time permits or when deep cleaning is required.",
      "docRef": "Microsoft Learn: Run antivirus scan"
    }
  },
  {
    "id": "mde-098",
    "topic": "Indicator expiration",
    "scenario": "A temporary C2 IP from a threat report should not block traffic forever.",
    "question": "Why set an expiration on indicators?",
    "options": [
      "Expiration automatically removes the indicator after a defined period so temporary IoCs do not permanently block infrastructure that may later be reassigned or become benign",
      "Indicators can never expire",
      "Expiration only works for certificates",
      "Expiration disables the entire indicator feature"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Time-Bounded Indicators",
      "analysis": [
        "Option A is CORRECT: Expiration keeps the indicator list relevant and avoids long-term false blocks.",
        "Option B is INCORRECT: Expiration is supported.",
        "Option C is INCORRECT: Expiration applies to multiple indicator types.",
        "Option D is INCORRECT: Only the specific indicator expires."
      ],
      "codeSnippet": "// Add indicator → set Expiration date",
      "socTip": "Default tactical network indicators to 30–90 days unless the IoC is known to be permanently malicious.",
      "docRef": "Microsoft Learn: Manage indicators"
    }
  },
  {
    "id": "mde-099",
    "topic": "Unified cross-domain incidents",
    "scenario": "The SOC uses both Defender for Endpoint and Defender for Office 365.",
    "question": "How does the unified incident experience help cross-domain investigations?",
    "options": [
      "Incidents can include alerts from multiple Defender workloads (endpoint, email, identity, cloud apps) in one correlated incident with a shared graph and investigation timeline",
      "Each product has a completely separate incident system with no correlation",
      "Unification only works for Azure resources",
      "Cross-domain incidents require manual CSV merges"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Domain XDR Incidents",
      "analysis": [
        "Option A is CORRECT: Defender XDR correlates alerts across domains into unified incidents.",
        "Option B is INCORRECT: Correlation is a primary XDR benefit.",
        "Option C is INCORRECT: It covers M365 and endpoint workloads extensively.",
        "Option D is INCORRECT: Correlation is automatic."
      ],
      "codeSnippet": "// Incidents queue shows multi-product alerts",
      "socTip": "When an email alert and an endpoint alert share a user or file hash, investigate them as one incident rather than two tickets.",
      "docRef": "Microsoft Learn: Incidents in Microsoft Defender XDR"
    }
  },
  {
    "id": "mde-100",
    "topic": "Post-incident continuous improvement",
    "scenario": "After a major endpoint incident, the SOC wants to reduce the chance of recurrence.",
    "question": "Which MDE capabilities support continuous improvement after an incident?",
    "options": [
      "Threat analytics recommendations, Secure Score improvement actions, ASR and hardening gaps identified during investigation, custom detections built from hunting queries, and vulnerability remediation from TVM",
      "No improvement is possible after an incident",
      "Only re-imaging every device prevents recurrence",
      "Improvement requires switching to a different EDR vendor"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Post-Incident Hardening Loop",
      "analysis": [
        "Option A is CORRECT: MDE provides multiple feedback loops—posture, detections, vulnerabilities, and analytics—to harden after incidents.",
        "Option B is INCORRECT: Continuous improvement is a core SOC practice supported by the product.",
        "Option C is INCORRECT: Re-imaging is sometimes needed but is not the only control.",
        "Option D is INCORRECT: Improvement is achievable within the Microsoft stack."
      ],
      "codeSnippet": "// After incident: custom detection, TVM, ASR, Secure Score",
      "socTip": "Include a mandatory detection and posture improvement section in every major incident report.",
      "docRef": "Microsoft Learn: Improve security posture"
    }
  }
]

def build_questions():
    """Attach module/audioSummary; keep explicit id for tracking 001-100."""
    result = []
    for i, q in enumerate(QUESTIONS):
        qid = q.get("id") or f"mde-{i+1:03d}"
        concept = q["explanation"]["concept"]
        correct_analysis = q["explanation"]["analysis"][q["correctIndex"]]
        audio = concept + ". " + (
            correct_analysis.split(": ", 1)[1][:200]
            if ": " in correct_analysis else correct_analysis[:200]
        )
        result.append({
            "id": qid,
            "module": "mde",
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
    output = "const MDE_QUESTIONS = " + json.dumps(questions, indent=2, ensure_ascii=False) + ";\n"
    with open("questions_mde_v2.js", "w", encoding="utf-8") as f:
        f.write(output)

    stems = set(q["question"] for q in questions)
    scenarios = set(q["scenario"][:80] for q in questions)
    ids = [q["id"] for q in questions]
    ci_dist = {}
    for q in questions:
        ci_dist[q["correctIndex"]] = ci_dist.get(q["correctIndex"], 0) + 1

    print(f"[+] Generated {len(questions)} MDE questions -> questions_mde_v2.js")
    print(f"    ID range: {ids[0]} .. {ids[-1]}")
    print(f"    Unique IDs: {len(set(ids))}/{len(questions)}")
    print(f"    Unique question stems: {len(stems)}/{len(questions)}")
    print(f"    Unique scenario prefixes: {len(scenarios)}/{len(questions)}")
    print(f"    correctIndex distribution: {ci_dist}")
    expected = [f"mde-{i:03d}" for i in range(1, 101)]
    missing = [e for e in expected if e not in set(ids)]
    print(f"    Missing IDs: {missing if missing else 'none (complete 001-100)'}")
