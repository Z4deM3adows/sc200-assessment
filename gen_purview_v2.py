"""
SC-200 Question Generator — Microsoft Purview Module (100 Questions)
Each question has a stable id (purview-001 .. purview-100) for easy tracking,
unique scenario, varied stem, 4 options, per-option explanations, and SOC tips.
"""
import json

QUESTIONS = [
  {
    "id": "purview-001",
    "topic": "Sensitivity label basics",
    "scenario": "Contoso's compliance team wants to classify documents and emails so that Confidential files are automatically encrypted and Public files have no restrictions.",
    "question": "What is the primary purpose of Microsoft Purview sensitivity labels?",
    "options": [
      "To classify and protect content by applying encryption, watermarks, access restrictions, and visual markings based on the sensitivity of the data",
      "To scan endpoints for malware signatures",
      "To manage user licensing assignments in Microsoft 365",
      "To configure network firewall rules for Azure virtual networks"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Labels Fundamentals",
      "analysis": [
        "Option A is CORRECT: Sensitivity labels classify content (documents, emails, Teams meetings, containers) and can enforce protection actions like encryption, watermarks, headers/footers, and access restrictions based on the label's sensitivity level.",
        "Option B is INCORRECT: Malware scanning is handled by Defender for Endpoint/Office, not Purview sensitivity labels.",
        "Option C is INCORRECT: License assignment is managed in the Microsoft 365 admin center or Entra ID, not through sensitivity labels.",
        "Option D is INCORRECT: Network firewall configuration is an Azure networking function, unrelated to data classification."
      ],
      "codeSnippet": "// Example label hierarchy:\n// Public -> no protection\n// General -> internal use banner\n// Confidential -> encryption + watermark\n// Highly Confidential -> encryption + restricted access + DLP trigger",
      "socTip": "When investigating a DLP alert, always check which sensitivity label was applied to the content — it often explains why a policy triggered.",
      "docRef": "Microsoft Learn: Learn about sensitivity labels"
    }
  },
  {
    "id": "purview-002",
    "topic": "Label publishing vs auto-labeling",
    "scenario": "Fabrikam's admin has created sensitivity labels but users report they don't see any labels in Outlook or Word. A colleague mentions the labels were only created, not made available.",
    "question": "What step is missing that would make the labels appear for end users?",
    "options": [
      "The labels must be published via a label policy, which assigns them to specific users or groups and controls default settings and required justification prompts",
      "Labels automatically apply to all tenant users once created, so this indicates a licensing issue",
      "The user's device needs a firmware update",
      "The Global Administrator must manually email each user their label list"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Label Policies and Publishing",
      "analysis": [
        "Option A is CORRECT: Creating a sensitivity label only defines it — a label policy must be published to specific users/groups before those labels appear in Office apps, along with settings like default label and justification requirements for downgrading.",
        "Option B is INCORRECT: Labels are not automatically available tenant-wide; publishing via policy is required regardless of licensing.",
        "Option C is INCORRECT: Firmware is unrelated to Microsoft 365 label visibility.",
        "Option D is INCORRECT: There's no manual email distribution step; publishing handles rollout centrally."
      ],
      "codeSnippet": "// PowerShell (Security & Compliance):\n// New-LabelPolicy -Name \"Global-Policy\" -Labels \"Confidential\",\"Public\"\n// Set-LabelPolicy -Identity \"Global-Policy\" -AddLabels \"HighlyConfidential\"",
      "socTip": "If a user reports missing labels, check label policy scoping first — it's the most common root cause before escalating to licensing.",
      "docRef": "Microsoft Learn: Publish sensitivity labels"
    }
  },
  {
    "id": "purview-003",
    "topic": "Trainable classifiers",
    "scenario": "Adatum's legal team wants Purview to automatically identify contracts and resumes across SharePoint without relying on keyword matching, since document wording varies widely.",
    "question": "What Purview capability is best suited for identifying documents by category based on example samples rather than exact keywords?",
    "options": [
      "Trainable classifiers, which use machine learning trained on sample documents to recognize categories of content like contracts, resumes, or source code",
      "Exact Data Match (EDM) classifiers",
      "Regular expression (regex) sensitive info types only",
      "Keyword dictionaries applied through transport rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Trainable Classifiers",
      "analysis": [
        "Option A is CORRECT: Trainable classifiers use ML models trained on seed content (positive and negative samples) to recognize document categories that are hard to define with patterns, such as resumes, contracts, or source code.",
        "Option B is INCORRECT: EDM is used for matching exact structured data like customer records against a database, not general document categories.",
        "Option C is INCORRECT: Regex-based sensitive info types match specific patterns (like SSNs), not broad conceptual categories.",
        "Option D is INCORRECT: Keyword dictionaries in transport rules are static lists, not adaptive ML classification."
      ],
      "codeSnippet": "// Building a trainable classifier:\n// 1. Provide 50-500 seed (positive) samples\n// 2. Provide negative samples for contrast\n// 3. Test and validate classifier accuracy\n// 4. Publish and use in DLP/retention/auto-labeling policies",
      "socTip": "Trainable classifiers take time to train and validate — recommend a 2-4 week pilot period before relying on them for auto-labeling at scale.",
      "docRef": "Microsoft Learn: Trainable classifiers overview"
    }
  },
  {
    "id": "purview-004",
    "topic": "Sensitive information types",
    "scenario": "Litware's compliance officer needs a DLP policy to detect credit card numbers in outgoing emails. The officer asks what built-in Purview feature can recognize this pattern without custom development.",
    "question": "What Purview feature recognizes patterns like credit card numbers using built-in pattern definitions and checksum validation?",
    "options": [
      "Sensitive information types (SITs), which use pattern matching, keyword proximity, and checksums (like the Luhn algorithm for credit cards) to detect sensitive data",
      "Communication Compliance policies",
      "Records Management retention labels",
      "Data Lifecycle Management adaptive scopes"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitive Information Types (SITs)",
      "analysis": [
        "Option A is CORRECT: SITs are pattern-based definitions (regex, checksum validation, keyword proximity, confidence levels) built into Purview to detect data like credit card numbers, SSNs, and passport numbers. Credit card SITs specifically use the Luhn checksum.",
        "Option B is INCORRECT: Communication Compliance monitors for policy violations in communications, not pattern-based data detection.",
        "Option C is INCORRECT: Retention labels govern how long content is kept, unrelated to pattern recognition.",
        "Option D is INCORRECT: Adaptive scopes dynamically target policies to users/sites based on attributes, not content pattern detection."
      ],
      "codeSnippet": "// Built-in SIT example: Credit Card Number\n// Pattern: 13-19 digit sequences\n// Validation: Luhn algorithm checksum\n// Confidence: High/Medium/Low based on proximity keywords\n//   (e.g., \"card\", \"exp date\" nearby increases confidence)",
      "socTip": "When tuning DLP false positives, check the SIT's confidence level being used — switching from Low to High confidence often reduces noise significantly.",
      "docRef": "Microsoft Learn: Sensitive information type entity definitions"
    }
  },
  {
    "id": "purview-005",
    "topic": "DLP policy locations",
    "scenario": "Northwind Traders wants a single DLP policy to protect sensitive data whether it's shared via Exchange email, SharePoint sites, Teams chats, or copied to a USB drive from a managed Windows device.",
    "question": "Which set of locations can a single Microsoft Purview DLP policy span?",
    "options": [
      "Exchange Online, SharePoint Online, OneDrive, Teams chat/channel messages, Devices (endpoint DLP), Microsoft Defender for Cloud Apps, on-premises repositories, Power BI, and Fabric/Copilot experiences",
      "Only Exchange Online mailboxes",
      "Only on-premises file shares connected via VPN",
      "Only third-party cloud storage apps not owned by Microsoft"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified DLP Policy Scope",
      "analysis": [
        "Option A is CORRECT: Purview DLP is a unified policy engine that can span Exchange, SharePoint, OneDrive, Teams, Windows/macOS endpoint devices, Defender for Cloud Apps (for third-party SaaS), on-premises repositories via the scanner, Power BI, and Fabric/Copilot.",
        "Option B is INCORRECT: While Exchange is one supported location, limiting to it alone understates DLP's unified multi-location scope.",
        "Option C is INCORRECT: On-premises support exists but isn't the sole scope — cloud locations are core to DLP.",
        "Option D is INCORRECT: DLP protects Microsoft-owned locations directly and extends to third-party apps only through Defender for Cloud Apps integration, not exclusively third-party apps."
      ],
      "codeSnippet": "// DLP policy location toggles (compliance portal):\n// [x] Exchange email\n// [x] SharePoint sites\n// [x] OneDrive accounts\n// [x] Teams chat and channel messages\n// [x] Devices\n// [x] Power BI workspaces",
      "socTip": "When scoping a new DLP policy, start narrow (one location, pilot group) and expand — broad first-day rollouts generate alert fatigue.",
      "docRef": "Microsoft Learn: Learn about data loss prevention"
    }
  },
  {
    "id": "purview-006",
    "topic": "DLP policy actions",
    "scenario": "Tailspin Toys' SOC receives a DLP alert showing a user attempted to email a file containing 50 credit card numbers to an external recipient. The policy blocked the email but the SOC wants to understand available response actions.",
    "question": "Which of the following is a valid DLP policy action when a rule condition is matched?",
    "options": [
      "Restrict access or encrypt the content, show a policy tip to the user, block sharing with people outside the organization, send incident reports to admins, and optionally require a business justification override",
      "Automatically terminate the user's Active Directory account",
      "Physically disable the user's network switch port",
      "Delete the user's entire mailbox without notification"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Policy Actions",
      "analysis": [
        "Option A is CORRECT: DLP supports graduated actions: restricting access/encrypting content, showing policy tips (educating users in real time), blocking external sharing, generating incident reports to admins, and allowing users to override with justification (if configured).",
        "Option B is INCORRECT: DLP does not disable AD accounts; that requires separate identity governance action, not a native DLP response.",
        "Option C is INCORRECT: DLP is a data-layer control, not a network infrastructure control — it cannot disable switch ports.",
        "Option D is INCORRECT: DLP never deletes mailboxes; its actions are protective/preventive, not destructive."
      ],
      "codeSnippet": "// DLP rule action example (policy tip + block):\n// Condition: Content contains Credit Card Number (>=10 instances)\n// Action: Block access to content, notify user via policy tip,\n//         send incident report to compliance@tailspintoys.com",
      "socTip": "Enable policy tips first in 'test with notifications' mode before moving to full enforcement — this measures real-world impact before blocking business workflows.",
      "docRef": "Microsoft Learn: DLP policy actions reference"
    }
  },
  {
    "id": "purview-007",
    "topic": "DLP policy modes",
    "scenario": "Woodgrove Bank's compliance team is rolling out a new DLP policy but is concerned about disrupting business operations if the rules are too aggressive on day one.",
    "question": "What DLP policy mode allows admins to see what would have happened without actually blocking or restricting content?",
    "options": [
      "Test mode (with or without notifications), which evaluates policy matches and generates reports/alerts without enforcing blocking actions",
      "Enforce mode, which is the only mode available in Purview DLP",
      "Audit-only mode, which is exclusive to Microsoft Sentinel",
      "Preview mode, which requires a separate E5 add-on license"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Simulation and Test Modes",
      "analysis": [
        "Option A is CORRECT: DLP policies can run in 'Test it out first' mode — either silently (no notifications) or with policy tips shown to users — so admins can validate rule accuracy and impact before turning on enforcement.",
        "Option B is INCORRECT: Enforce mode exists but is not the only mode; test modes are explicitly designed for staged rollout.",
        "Option C is INCORRECT: Audit-only evaluation is native to Purview DLP, not exclusive to Sentinel.",
        "Option D is INCORRECT: Test mode is a standard DLP policy setting included with DLP licensing, not a separate paid add-on."
      ],
      "codeSnippet": "// Policy rollout stages:\n// 1. Test without notifications (silent baseline)\n// 2. Test with notifications (policy tips shown)\n// 3. Turn on enforcement (block/restrict actions active)",
      "socTip": "Run new DLP policies in test mode for at least 2 weeks and review the incident report volume before enabling enforcement — this avoids blocking legitimate business processes.",
      "docRef": "Microsoft Learn: Design a DLP policy"
    }
  },
  {
    "id": "purview-008",
    "topic": "Endpoint DLP",
    "scenario": "Trey Research's SOC wants to prevent employees from copying files containing source code to USB drives on company-managed laptops, even when the laptop is offline.",
    "question": "What Purview capability enforces DLP rules on activities like USB copy, cloud sync, and printing directly on Windows/macOS devices?",
    "options": [
      "Endpoint DLP, which extends DLP policies to onboarded Windows 10/11 and macOS devices to monitor and restrict activities like USB copy, network share copy, cloud upload, printing, and clipboard actions",
      "Microsoft Defender for Identity",
      "Azure Information Protection scanner",
      "Conditional Access App Control"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Endpoint DLP",
      "analysis": [
        "Option A is CORRECT: Endpoint DLP requires devices to be onboarded (via Defender for Endpoint or the standalone onboarding package) and then enforces DLP policies on local activities — USB copy, print, clipboard, cloud sync app uploads, and network share copy — even without network connectivity for locally cached policies.",
        "Option B is INCORRECT: Defender for Identity focuses on identity-based lateral movement detection, not endpoint file activity DLP.",
        "Option C is INCORRECT: The AIP scanner discovers and labels on-premises file shares; it does not enforce endpoint device activity restrictions.",
        "Option D is INCORRECT: Conditional Access App Control governs session-based cloud app access controls, not local device file operations."
      ],
      "codeSnippet": "// Endpoint DLP activities monitored:\n// - Copy to USB removable media\n// - Copy to network share\n// - Print\n// - Copy/paste (clipboard)\n// - Upload to cloud service domain\n// - Copy to Bluetooth device",
      "socTip": "Verify device onboarding status in the Purview compliance portal's 'Device onboarding' page before troubleshooting why endpoint DLP isn't triggering on a given machine.",
      "docRef": "Microsoft Learn: Learn about Endpoint data loss prevention"
    }
  },
  {
    "id": "purview-009",
    "topic": "Exact Data Match",
    "scenario": "Relecloud's compliance team wants DLP to flag only actual customer account numbers from their production database, not any random-looking numeric string that resembles an account number format.",
    "question": "Which Purview classification method matches content against actual structured values from a source-of-truth database rather than pattern-only detection?",
    "options": [
      "Exact Data Match (EDM), which hashes and matches content against specific values uploaded from a structured data source like a customer database",
      "Trainable classifiers",
      "Fingerprinting of unstructured documents only",
      "Named entity recognition without a reference dataset"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Exact Data Match (EDM)",
      "analysis": [
        "Option A is CORRECT: EDM uploads a hashed, salted version of actual sensitive data (like real account numbers) as a reference table, so DLP only flags exact matches against real records rather than any string that merely fits a pattern — reducing false positives significantly.",
        "Option B is INCORRECT: Trainable classifiers identify document categories using ML, not exact structured value matching.",
        "Option C is INCORRECT: Document fingerprinting matches whole document templates (like a specific form), not individual structured data values.",
        "Option D is INCORRECT: Named entity recognition without a reference dataset can't guarantee matches are real records — that's precisely the gap EDM closes."
      ],
      "codeSnippet": "// EDM setup steps:\n// 1. Define schema (e.g., AccountNumber, CustomerName)\n// 2. Export data, hash/salt via EDM upload tool\n// 3. Upload hashed data (never raw data) to Microsoft 365\n// 4. Create custom SIT referencing the EDM schema",
      "socTip": "EDM dramatically cuts DLP false positives for structured data like account or employee ID numbers — recommend it whenever a customer complains about noisy pattern-based alerts.",
      "docRef": "Microsoft Learn: Exact Data Match based sensitive information types"
    }
  },
  {
    "id": "purview-010",
    "topic": "Insider Risk Management overview",
    "scenario": "Proseware's HR department flags an employee who submitted resignation and is now behaving unusually with company data. The security team wants visibility into risky user activity leading up to departure.",
    "question": "What is the primary purpose of Microsoft Purview Insider Risk Management?",
    "options": [
      "To identify, investigate, and act on risky user activities such as data exfiltration, IP theft, or policy violations by correlating signals across Microsoft 365 into risk scores and alerts",
      "To scan external websites for phishing indicators",
      "To manage firewall rules between on-premises and cloud networks",
      "To automatically fire employees flagged by any policy violation"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Insider Risk Management (IRM) Overview",
      "analysis": [
        "Option A is CORRECT: IRM correlates signals (file downloads, exfiltration attempts, communication patterns, HR triggers like resignation) into risk scores, generating alerts for analysts to investigate potential insider threats such as data theft or policy violations.",
        "Option B is INCORRECT: External phishing detection is handled by Defender for Office 365, not IRM, which is focused on internal user risk.",
        "Option C is INCORRECT: Firewall rule management is a networking function unrelated to insider risk analytics.",
        "Option D is INCORRECT: IRM never takes automated HR action like termination — it surfaces risk for human investigators and HR/legal to act on through their own processes."
      ],
      "codeSnippet": "// IRM policy triggers example:\n// - HR connector event: \"Resignation submitted\"\n// - + File download to USB in the 14 days after trigger\n// - + Cumulative exfiltration volume threshold\n// -> Elevated risk score -> Alert generated for analyst review",
      "socTip": "IRM investigations are highly sensitive — coordinate with HR/Legal before taking any action, since findings often involve pending termination or legal proceedings.",
      "docRef": "Microsoft Learn: Learn about insider risk management"
    }
  },
  {
    "id": "purview-011",
    "topic": "IRM pseudonymization",
    "scenario": "Wingtip Toys' privacy officer is concerned that Insider Risk Management investigators might see employees' real names during early-stage triage, which could bias investigations or violate works council agreements.",
    "question": "What privacy control does Insider Risk Management offer to protect user identities during initial case review?",
    "options": [
      "Pseudonymization, which displays user names as anonymized aliases (like a generic ID) until a case reaches a stage where a role with appropriate permissions un-masks the identity",
      "Automatic deletion of all case data after 24 hours",
      "Mandatory two-factor authentication for HR staff only",
      "Disabling all IRM policies for employees represented by a works council"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Pseudonymization",
      "analysis": [
        "Option A is CORRECT: IRM supports pseudonymized display of usernames during alert triage, protecting privacy until a permitted role (with the 'unmask' RBAC permission) reveals the actual identity — often required for GDPR or works council compliance in EU operations.",
        "Option B is INCORRECT: Case data retention is configurable but is not tied specifically to a 24-hour auto-delete privacy feature.",
        "Option C is INCORRECT: MFA is an identity security control unrelated to IRM's name-masking privacy feature.",
        "Option D is INCORRECT: IRM doesn't need to be disabled for works-council-covered employees; pseudonymization is the built-in mechanism to satisfy those requirements while keeping monitoring active."
      ],
      "codeSnippet": "// RBAC roles relevant to pseudonymization:\n// - Insider Risk Management Analysts: see pseudonymized names\n// - Insider Risk Management Investigators: can unmask names\n// Settings > Privacy > \"Show anonymized versions of usernames\"",
      "socTip": "When deploying IRM in EU regions, enable pseudonymization by default and document the unmask approval workflow — this is often a legal/compliance prerequisite, not optional.",
      "docRef": "Microsoft Learn: Insider risk management settings - privacy"
    }
  },
  {
    "id": "purview-012",
    "topic": "IRM HR connector",
    "scenario": "Northwind Traders wants Insider Risk Management to automatically increase monitoring on employees who have just resigned, without manually flagging each departure.",
    "question": "What Purview feature ingests HR system events like resignations or terminations to automatically trigger elevated insider risk monitoring?",
    "options": [
      "The HR connector, which imports employee status change events (resignation, termination date) from an HR system via a scheduled CSV/API feed into IRM policies",
      "Microsoft Entra ID Connect",
      "Defender for Cloud Apps HR API",
      "Communication Compliance's HR flagging rule"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "HR Connector for Insider Risk",
      "analysis": [
        "Option A is CORRECT: The HR connector lets organizations feed structured HR data (like termination dates, resignation dates, job level changes) into IRM so policies can automatically trigger elevated monitoring during high-risk windows such as departure.",
        "Option B is INCORRECT: Entra ID Connect synchronizes identity objects between on-premises AD and Entra ID; it does not carry HR status change events into IRM.",
        "Option C is INCORRECT: Defender for Cloud Apps does not provide an HR connector; that capability is specific to Purview IRM.",
        "Option D is INCORRECT: Communication Compliance monitors communications for policy violations; it has no HR flagging connector."
      ],
      "codeSnippet": "// HR connector data flow:\n// HR system export (CSV) -> SFTP/API upload\n// -> IRM HR connector mapping (EmployeeID, EventType, EventDate)\n// -> Policy indicator: \"Resignation date\" -> monitoring window opens",
      "socTip": "Validate HR connector data freshness weekly — a stale feed means departing employees may not get elevated monitoring during their actual final two weeks.",
      "docRef": "Microsoft Learn: Import data with the HR connector"
    }
  },
  {
    "id": "purview-013",
    "topic": "Insider risk policy templates",
    "scenario": "Litware's compliance team is new to Insider Risk Management and wants to start with a pre-built policy for detecting data theft by departing employees rather than building indicators from scratch.",
    "question": "What does Microsoft Purview provide to help organizations quickly deploy common insider risk scenarios?",
    "options": [
      "Built-in policy templates such as 'Data theft by departing users,' 'Data leaks,' 'Security policy violations,' and 'Risky browsing usage,' each pre-configured with relevant indicators",
      "Only fully custom policies with no starting templates",
      "A single one-size-fits-all policy that cannot be scoped by scenario",
      "Templates that only work with third-party SIEM integration"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Policy Templates",
      "analysis": [
        "Option A is CORRECT: Purview provides several built-in templates mapped to common scenarios (departing employee data theft, general data leaks, security policy violations, risky browsing, patient data misuse in healthcare, etc.), each pre-loaded with relevant indicators to accelerate deployment.",
        "Option B is INCORRECT: While custom policies are supported, templates exist specifically to reduce the need to build everything from scratch.",
        "Option C is INCORRECT: IRM explicitly supports multiple scoped policies for different scenarios rather than a single generic policy.",
        "Option D is INCORRECT: Templates work natively within Purview IRM and don't require SIEM integration to function."
      ],
      "codeSnippet": "// Common IRM templates:\n// - Data theft by departing users\n// - Data leaks by priority users\n// - Security policy violations (DLP-related)\n// - Risky browsing usage\n// - Patient data misuse (healthcare)",
      "socTip": "Start with the 'Data theft by departing users' template — it typically has the highest signal-to-noise ratio for a first IRM deployment.",
      "docRef": "Microsoft Learn: Insider risk management policy templates"
    }
  },
  {
    "id": "purview-014",
    "topic": "IRM sequence detection",
    "scenario": "Fabrikam's IRM analyst notices an alert was generated not because of a single large download, but because of a chain of activities: a file was downloaded, renamed, then uploaded to a personal cloud storage account within a short window.",
    "question": "What Insider Risk Management capability correlates a chain of related activities occurring close together in time into a single higher-confidence risk indicator?",
    "options": [
      "Sequence detection, which identifies patterns of related risky activities occurring in a defined time window to increase confidence a deliberate exfiltration attempt occurred",
      "Communication Compliance keyword matching",
      "Retention label auto-apply",
      "Sensitivity label mandatory justification prompts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Sequence Detection",
      "analysis": [
        "Option A is CORRECT: Sequence detection in IRM links multiple related activities (e.g., download -> rename -> upload to personal storage) that occur within a short time window into a single sequence, raising confidence that the actions represent deliberate exfiltration rather than isolated, benign events.",
        "Option B is INCORRECT: Communication Compliance analyzes message content for policy violations, not multi-step file activity chains.",
        "Option C is INCORRECT: Retention labels govern content lifecycle, unrelated to behavioral sequence correlation.",
        "Option D is INCORRECT: Sensitivity label justification prompts capture a user's stated reason for downgrading a label, not a correlated activity sequence."
      ],
      "codeSnippet": "// Example sequence:\n// t=0: File 'financials.xlsx' downloaded\n// t+2min: File renamed to 'notes.xlsx'\n// t+5min: Uploaded to personal Dropbox\n// -> Sequence flagged: potential exfiltration pattern",
      "socTip": "When triaging IRM alerts, prioritize those flagged as sequences over single-indicator alerts — sequences have materially higher true-positive rates.",
      "docRef": "Microsoft Learn: Insider risk management activity sequence detection"
    }
  },
  {
    "id": "purview-015",
    "topic": "Priority user groups",
    "scenario": "Tailspin Toys wants Insider Risk Management to apply more sensitive monitoring thresholds to executives and R&D engineers who have access to trade secrets, without changing policies for the entire company.",
    "question": "What IRM feature allows admins to apply elevated monitoring specifically to a defined set of high-value employees?",
    "options": [
      "Priority user groups, which let admins designate specific users (executives, R&D staff, finance) for closer monitoring and lower alert thresholds within IRM policies",
      "Conditional Access named locations",
      "Sensitivity label auto-labeling scopes",
      "Compliance Manager improvement actions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Priority User Groups",
      "analysis": [
        "Option A is CORRECT: Priority user groups let admins flag specific individuals or departments (e.g., executives, engineers with IP access) so IRM policies apply tighter thresholds or added indicators specifically for them, without broadly changing organization-wide policy.",
        "Option B is INCORRECT: Named locations are a Conditional Access construct for network/IP-based access policies, unrelated to IRM user prioritization.",
        "Option C is INCORRECT: Auto-labeling scopes control which content sensitivity labels apply to, not which users get elevated IRM monitoring.",
        "Option D is INCORRECT: Compliance Manager improvement actions relate to compliance score remediation tasks, not IRM user prioritization."
      ],
      "codeSnippet": "// Priority user group example:\n// Group: \"R&D-TradeSecrets\"\n// Members: Engineering leads, patent team\n// Policy: Data theft by departing users\n// Effect: Lower indicator thresholds for this group only",
      "socTip": "Keep priority user group membership under periodic review with HR — stale membership (e.g., an executive who left) can silently reduce monitoring coverage.",
      "docRef": "Microsoft Learn: Insider risk management settings - priority user groups"
    }
  },
  {
    "id": "purview-016",
    "topic": "Communication Compliance overview",
    "scenario": "Woodgrove Bank's compliance department must detect potential insider trading language, harassment, and regulatory violations in employee emails and Teams chats, without reading every single message manually.",
    "question": "What Purview solution is designed to detect policy violations such as harassment, regulatory noncompliance, or conflicts of interest within internal and external communications?",
    "options": [
      "Communication Compliance, which uses classifiers and keyword conditions to detect potential violations in email, Teams, and third-party communications, then routes flagged messages to reviewers",
      "Insider Risk Management exclusively",
      "eDiscovery Premium hold notifications",
      "Records Management disposition reviews"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Communication Compliance Overview",
      "analysis": [
        "Option A is CORRECT: Communication Compliance scans communications (Exchange, Teams, Viva Engage, and third-party channels via connectors) using built-in classifiers (harassment, threat, adult content) or custom keyword/regex conditions, flagging matches for a reviewer to assess and act on.",
        "Option B is INCORRECT: IRM focuses on behavioral/activity-based risk indicators (like file exfiltration), not content-based communication scanning for language violations.",
        "Option C is INCORRECT: eDiscovery holds preserve content for legal cases; they don't proactively scan for policy violations in ongoing communications.",
        "Option D is INCORRECT: Records Management disposition review handles end-of-lifecycle content deletion/retention decisions, unrelated to communication content scanning."
      ],
      "codeSnippet": "// Communication Compliance policy example:\n// Classifier: \"Threat\" + \"Harassment\"\n// Scope: All Teams channels, Exchange mail\n// Reviewer group: HR-Compliance-Reviewers\n// Action on match: Route to review queue, tag for escalation",
      "socTip": "Coordinate Communication Compliance reviewer access carefully — reviewers see message content, so this role should be tightly scoped and audited.",
      "docRef": "Microsoft Learn: Learn about communication compliance"
    }
  },
  {
    "id": "purview-017",
    "topic": "Communication Compliance reviewer workflow",
    "scenario": "Litware's HR team is set up as reviewers for a Communication Compliance policy. An analyst asks what a reviewer actually sees and can do when a message is flagged.",
    "question": "When a message matches a Communication Compliance policy, what can an assigned reviewer typically do with the flagged item?",
    "options": [
      "View the flagged message content (with configurable text/attachment redaction options), tag it as resolved, escalate it to a specific reviewer group, or mark it as a false positive",
      "Automatically forward the message to law enforcement without further review",
      "Permanently delete the message from the sender's mailbox immediately",
      "Change the sender's Microsoft 365 license"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Communication Compliance Review Actions",
      "analysis": [
        "Option A is CORRECT: Reviewers can view flagged content (with optional redaction of attachments/certain content per policy configuration), resolve the item, escalate to another reviewer or group (e.g., Legal), or mark as not a violation to tune future results.",
        "Option B is INCORRECT: Communication Compliance does not automatically report to external law enforcement; any such escalation is a manual human/legal decision outside the tool.",
        "Option C is INCORRECT: Reviewers cannot delete the original message from a mailbox through Communication Compliance — it's a review and reporting tool, not a remediation/deletion tool.",
        "Option D is INCORRECT: License management is unrelated to communication review actions and is handled elsewhere."
      ],
      "codeSnippet": "// Reviewer actions:\n// - Resolve (no violation found)\n// - Escalate (send to another reviewer/group)\n// - Tag as violation type (e.g., \"Regulatory\")\n// - Send reminder notice to user (in some policy types)",
      "socTip": "Escalation paths should be pre-defined before policy go-live — reviewers stalling on ambiguous cases is a common early adoption issue.",
      "docRef": "Microsoft Learn: Investigate and remediate communication compliance alerts"
    }
  },
  {
    "id": "purview-018",
    "topic": "eDiscovery Standard vs Premium",
    "scenario": "Trey Research's legal team currently uses basic search-and-hold features but is evaluating whether they need advanced capabilities like custodian management, legal hold notifications, and TAR-based review for a large litigation case.",
    "question": "What distinguishes Microsoft Purview eDiscovery (Premium) from eDiscovery (Standard)?",
    "options": [
      "Premium adds case management with custodians, legal hold notifications, advanced analytics (near-duplicate detection, email threading, themes), and machine-learning-assisted review; Standard covers core search, hold, and export",
      "Standard includes AI-based document review, while Premium only supports keyword search",
      "Premium is only available for Azure resources, not Microsoft 365 data",
      "Standard requires a separate Microsoft Sentinel license, while Premium does not"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "eDiscovery Standard vs Premium",
      "analysis": [
        "Option A is CORRECT: eDiscovery Standard provides core case creation, content search, litigation hold, and export. Premium adds custodian management with hold notifications/acknowledgments, advanced analytics (near-duplicates, email threading, themes), and predictive coding/ML-assisted review for large-scale litigation.",
        "Option B is INCORRECT: This reverses the capabilities — ML-assisted review and analytics are Premium features, not Standard's.",
        "Option C is INCORRECT: Both Standard and Premium eDiscovery operate on Microsoft 365 content (Exchange, SharePoint, Teams, OneDrive), not Azure infrastructure resources.",
        "Option D is INCORRECT: Neither eDiscovery tier requires a Sentinel license; they are part of Microsoft 365/E5 compliance licensing."
      ],
      "codeSnippet": "// Feature comparison snapshot:\n// Standard: Search, Hold, Export, Case management (basic)\n// Premium: + Custodians, Hold notifications,\n//          + Near-duplicate/email threading,\n//          + Predictive coding, Review sets, Tagging",
      "socTip": "Confirm licensing (E5 Compliance or eDiscovery Premium add-on) before promising a legal team access to custodian hold notifications — it's a common licensing gap.",
      "docRef": "Microsoft Learn: eDiscovery solutions in Microsoft Purview"
    }
  },
  {
    "id": "purview-019",
    "topic": "Legal hold mechanics",
    "scenario": "Adatum's legal team places a litigation hold on an employee's mailbox as part of an eDiscovery case. The employee later tries to permanently delete several emails related to the case.",
    "question": "What happens to content when it is placed under a legal hold in Microsoft Purview eDiscovery?",
    "options": [
      "The content is preserved in its original form even if the user tries to delete or edit it — a hidden copy is retained so it can still be discovered and reviewed",
      "The content is immediately moved to a separate archive mailbox visible to the user",
      "The user's mailbox becomes completely read-only and unusable until the hold is lifted",
      "Only email subject lines are preserved; body content and attachments are excluded from hold"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Legal Hold Preservation",
      "analysis": [
        "Option A is CORRECT: When content is placed under hold (via eDiscovery case hold or litigation hold), Exchange/SharePoint preserves the original version even if a user edits or deletes it — the item is retained in a hidden/recoverable location so it remains discoverable.",
        "Option B is INCORRECT: Hold preservation happens transparently in the background; there's no separate archive mailbox the user can see specifically for hold purposes.",
        "Option C is INCORRECT: Users can generally continue working normally in a held mailbox — hold does not make the mailbox read-only.",
        "Option D is INCORRECT: Legal hold preserves full content including body and attachments, not just metadata like subject lines."
      ],
      "codeSnippet": "// Hold behavior:\n// User deletes email -> moved to Recoverable Items\n// (Purges subfolder) -> hold prevents permanent purge\n// -> content remains searchable via eDiscovery case",
      "socTip": "When a custodian reports 'missing' emails during a hold, check the Recoverable Items folder via eDiscovery search before assuming data loss occurred.",
      "docRef": "Microsoft Learn: Learn about eDiscovery holds"
    }
  },
  {
    "id": "purview-020",
    "topic": "eDiscovery search query syntax",
    "scenario": "Wingtip Toys' legal analyst needs to run an eDiscovery content search to find emails from a specific sender containing the word 'merger' sent within a specific date range.",
    "question": "What query approach does Microsoft Purview eDiscovery content search use to build precise search criteria like sender, keyword, and date range?",
    "options": [
      "KQL (Keyword Query Language) syntax, combining properties like from:, subject:, and date ranges with Boolean operators (AND, OR, NOT)",
      "SQL SELECT statements against the Exchange database directly",
      "Python regular expressions entered into the search bar",
      "A drag-and-drop visual designer with no text-based query option"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "eDiscovery Content Search Query Syntax",
      "analysis": [
        "Option A is CORRECT: eDiscovery content search uses KQL, allowing property-restricted searches (from:, subject:, sent:, size:) combined with Boolean operators and wildcards, giving precise control over search scope.",
        "Option B is INCORRECT: Direct SQL against the Exchange database is not exposed to admins; KQL is the supported abstraction layer.",
        "Option C is INCORRECT: Regex is not the native query language for eDiscovery content search; KQL is used instead, though some conditions support pattern-like refinement.",
        "Option D is INCORRECT: While a condition builder UI exists, it is built on top of KQL and an advanced text query option is also available — it isn't purely drag-and-drop only."
      ],
      "codeSnippet": "// KQL example:\n// from:\"jsmith@adatum.com\" AND subject:\"merger\"\n// AND (sent>=2026-01-01 AND sent<=2026-03-31)",
      "socTip": "Always run a scoping/estimate search before executing a full export — large date ranges without keyword refinement can return unmanageable result sets.",
      "docRef": "Microsoft Learn: Keyword queries and search conditions for eDiscovery"
    }
  },
  {
    "id": "purview-021",
    "topic": "Records Management overview",
    "scenario": "Relecloud's records officer needs certain contracts to be retained for exactly 7 years and then automatically deleted, with the deletion event requiring manager sign-off before it happens.",
    "question": "What Purview solution is designed for formal records declaration, retention period enforcement, and disposition review before final deletion?",
    "options": [
      "Records Management, which uses retention labels configured as 'records' to enforce retention periods, immutability, and a disposition review workflow before final deletion",
      "Communication Compliance disposition rules",
      "Insider Risk Management retention policies",
      "Sensitivity label encryption settings"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Records Management",
      "analysis": [
        "Option A is CORRECT: Records Management uses retention labels marked as 'Record' or 'Regulatory Record' to declare content as an official record, enforce a defined retention period (e.g., 7 years), and route eligible items to a disposition review stage where an authorized reviewer approves final deletion.",
        "Option B is INCORRECT: Communication Compliance handles message content review for policy violations, not formal records lifecycle management.",
        "Option C is INCORRECT: IRM focuses on user risk behavior, not records retention and disposition workflows.",
        "Option D is INCORRECT: Sensitivity labels handle protection/encryption, a separate concern from retention period enforcement and disposition review."
      ],
      "codeSnippet": "// Record label example:\n// Label: \"Contract-7yr\"\n// Retention: 7 years from label applied date\n// Record type: Record (content becomes read-only for edits)\n// Disposition: Require review by 'RecordsOfficers' group",
      "socTip": "Records marked as 'Record' typically cannot be relabeled or have content edited — validate this is intended before applying to actively-used documents.",
      "docRef": "Microsoft Learn: Learn about records management"
    }
  },
  {
    "id": "purview-022",
    "topic": "Retention label vs retention policy",
    "scenario": "Litware's compliance team is confused about whether to apply retention rules broadly to a whole SharePoint site or to specific individual documents that need different retention periods.",
    "question": "What is the key difference between a retention policy and a retention label in Microsoft Purview?",
    "options": [
      "A retention policy applies the same retention/deletion rule broadly across a location (site, mailbox), while a retention label applies granular, item-level rules that can differ per document and travel with the content",
      "Retention policies only work on emails; retention labels only work on Teams messages",
      "Retention labels are always temporary and expire after 30 days regardless of configuration",
      "There is no functional difference; they are two names for the same feature"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retention Policies vs Retention Labels",
      "analysis": [
        "Option A is CORRECT: Retention policies apply uniformly across a scoped location like a site or mailbox. Retention labels are applied at the item level (a specific document or email) and allow different content within the same location to have different retention behavior, and the label travels with the item if moved.",
        "Option B is INCORRECT: Both retention policies and labels can apply across Exchange, SharePoint, OneDrive, and Teams — they are not restricted to a single workload each.",
        "Option C is INCORRECT: Retention label duration is fully configurable (days to indefinite) and is not fixed at 30 days.",
        "Option D is INCORRECT: They are distinct mechanisms with different granularity and application methods, not interchangeable names for one feature."
      ],
      "codeSnippet": "// Retention policy (location-level):\n// Applies to: All mailboxes in \"Sales\" OU\n// Retain for: 3 years, then delete\n//\n// Retention label (item-level):\n// Applied to: Specific contract.docx\n// Retain for: 7 years, then trigger disposition review",
      "socTip": "When a user asks why one document in a site has different retention than the rest, check for an item-level retention label overriding the site-level policy.",
      "docRef": "Microsoft Learn: Retention policies and retention labels overview"
    }
  },
  {
    "id": "purview-023",
    "topic": "Disposition review",
    "scenario": "Contoso's records team has retention labels configured to trigger disposition review after the retention period expires, ensuring a human confirms deletion is appropriate rather than automatic purging.",
    "question": "What happens during the disposition review stage in Records Management?",
    "options": [
      "Content whose retention period has expired is routed to designated reviewers who can approve permanent deletion, extend retention, or relabel the content before any deletion occurs",
      "The content is immediately and irreversibly deleted with no human involvement",
      "The content is automatically relabeled as Public and shared organization-wide",
      "Disposition review only applies to Teams messages, not documents or emails"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Disposition Review Workflow",
      "analysis": [
        "Option A is CORRECT: When a retention label with disposition review enabled expires, matching content moves to a review stage where assigned reviewers evaluate it and choose to approve deletion, extend the retention period, or change the label — nothing is auto-deleted without this checkpoint.",
        "Option B is INCORRECT: The entire point of enabling disposition review is to prevent silent automatic deletion by requiring human sign-off.",
        "Option C is INCORRECT: Disposition review does not change sensitivity or sharing settings; it strictly governs retention/deletion decisions.",
        "Option D is INCORRECT: Disposition review can apply to documents, emails, and other supported content types wherever retention labels with that setting are applied — not exclusively Teams messages."
      ],
      "codeSnippet": "// Disposition review stages example:\n// Stage 1 reviewers: Records-Team\n// Stage 2 reviewers: Legal-Dept (multi-stage approval)\n// Outcome options: Delete, Extend retention, Relabel",
      "socTip": "Multi-stage disposition review (e.g., Records team then Legal) adds accountability for high-value records — recommend it for regulated industries.",
      "docRef": "Microsoft Learn: Disposition of content"
    }
  },
  {
    "id": "purview-024",
    "topic": "Data Lifecycle Management overview",
    "scenario": "Northwind Traders wants a simpler, organization-wide approach to automatically delete old Teams chat messages and stale SharePoint content without setting up a full formal records program.",
    "question": "What Purview solution focuses on broad retention and deletion of content across the organization for general data lifecycle hygiene, as opposed to formal records declaration?",
    "options": [
      "Data Lifecycle Management, which uses retention policies and non-record retention labels to automatically retain or delete content across Microsoft 365 workloads based on age or event triggers",
      "Insider Risk Management adaptive protection",
      "Communication Compliance escalation workflows",
      "Priva Privacy Risk Management"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data Lifecycle Management (DLM)",
      "analysis": [
        "Option A is CORRECT: Data Lifecycle Management is the broader retention/deletion toolset (retention policies, adaptive scopes, event-based retention, non-record labels) aimed at general content lifecycle hygiene across the tenant, distinct from the formal 'record' declaration workflow in Records Management.",
        "Option B is INCORRECT: Adaptive protection is an IRM/DLP feature that dynamically adjusts control strictness based on risk level, unrelated to content lifecycle retention/deletion.",
        "Option C is INCORRECT: Communication Compliance escalation handles reviewer workflows for flagged messages, not organization-wide retention scheduling.",
        "Option D is INCORRECT: Priva focuses on privacy risk management (like data subject requests and overexposed personal data), a separate Purview solution from lifecycle retention."
      ],
      "codeSnippet": "// DLM policy example:\n// Scope: All SharePoint sites (adaptive scope: Dept=Sales)\n// Rule: Delete content older than 5 years with no activity\n// Trigger type: Age-based (creation date)",
      "socTip": "Use adaptive scopes in DLM policies to dynamically include/exclude users or sites based on attributes (like department), avoiding manual list maintenance.",
      "docRef": "Microsoft Learn: Learn about Microsoft Purview Data Lifecycle Management"
    }
  },
  {
    "id": "purview-025",
    "topic": "Event-based retention",
    "scenario": "Tailspin Toys wants a retention label on employee contracts to start its retention clock only when an employee's last day of employment is recorded, not from the document's creation date.",
    "question": "What Purview feature allows a retention period to begin counting only after a defined business event occurs, rather than from content creation or labeling date?",
    "options": [
      "Event-based retention, which starts the retention clock when a defined event (such as 'employee last day' or 'contract expiration') is triggered instead of using a static creation date",
      "Adaptive scopes",
      "Trainable classifiers",
      "Sensitivity label auto-labeling policies"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Event-Based Retention",
      "analysis": [
        "Option A is CORRECT: Event-based retention lets admins define event types (e.g., employee departure, contract end date, product end-of-life) that, when triggered manually or via import, start the retention countdown for content tagged with an associated label — rather than counting from creation date.",
        "Option B is INCORRECT: Adaptive scopes dynamically define which users/sites/mailboxes a policy targets based on attribute queries, unrelated to triggering retention timing based on events.",
        "Option C is INCORRECT: Trainable classifiers identify content categories via ML; they don't control retention start timing.",
        "Option D is INCORRECT: Auto-labeling policies apply sensitivity or retention labels based on content matches, not specifically the event-triggered countdown mechanism."
      ],
      "codeSnippet": "// Event-based retention example:\n// Event type: \"Employment ends\"\n// Label: \"Employee-Record-Retain-7yr\"\n// Trigger: HR imports termination date via event or connector\n// -> Retention clock starts 7-year countdown from that date",
      "socTip": "Event-based retention requires someone (or a connector) to actually trigger the event — audit that the triggering process is reliable, or records will never begin their retention countdown.",
      "docRef": "Microsoft Learn: Event-driven retention"
    }
  },
  {
    "id": "purview-026",
    "topic": "Purview Audit (Standard) overview",
    "scenario": "Fabrikam's SOC needs to investigate whether a specific user accessed a SharePoint file last month. They check Purview Audit but aren't sure how far back the data goes with their current licensing.",
    "question": "By default, how long are audit logs retained for organizations with Microsoft Purview Audit (Standard)?",
    "options": [
      "180 days",
      "24 hours only",
      "10 years automatically for all tenants",
      "Audit logs are not retained; they must be exported in real time or lost"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Standard Retention",
      "analysis": [
        "Option A is CORRECT: Microsoft Purview Audit (Standard), included with most Microsoft 365 plans, retains audit log records for 180 days by default.",
        "Option B is INCORRECT: 24-hour retention would be far too short to be useful for investigations and does not reflect Audit Standard's actual retention window.",
        "Option C is INCORRECT: 10-year retention is a capability of Audit (Premium) with long-term retention add-ons/policies, not the Standard default.",
        "Option D is INCORRECT: Audit Standard does retain logs natively for the stated window; export is not required to prevent immediate loss within that period."
      ],
      "codeSnippet": "// Audit log retention comparison:\n// Audit (Standard): 180 days default\n// Audit (Premium): up to 1 year default, extendable\n//   to 10 years with audit log retention policies (add-on)",
      "socTip": "For investigations older than 180 days, confirm whether the tenant has Audit Premium and a long-term retention policy configured — otherwise the data may already be purged.",
      "docRef": "Microsoft Learn: Audit log retention policies"
    }
  },
  {
    "id": "purview-027",
    "topic": "Audit Premium capabilities",
    "scenario": "Woodgrove Bank's SOC is investigating a suspected mailbox compromise and needs to know exactly which emails an attacker accessed, searched, or forwarded — details not available in basic audit logs.",
    "question": "What additional audit capability does Microsoft Purview Audit (Premium) provide that is critical for investigating mailbox compromise scope?",
    "options": [
      "High-value crime-related events like MailItemsAccessed, Send, and SearchQueryInitiated, which help determine the exact scope of data an attacker accessed during a compromise",
      "Real-time SMS alerts to the CISO's personal phone",
      "Automatic password resets for compromised accounts",
      "Physical security camera footage correlation"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Premium Forensic Events",
      "analysis": [
        "Option A is CORRECT: Audit Premium captures additional high-value 'crime scene' events such as MailItemsAccessed (mail sync/access), Send, and SearchQueryInitiated, which are essential for scoping exactly what an attacker viewed, searched, or exfiltrated during a Business Email Compromise investigation.",
        "Option B is INCORRECT: Audit Premium is a logging capability, not an SMS alerting/notification system.",
        "Option C is INCORRECT: Password reset is an identity remediation action performed manually or via automated playbooks, not an Audit Premium logging feature.",
        "Option D is INCORRECT: Audit logs are entirely digital telemetry from Microsoft 365 services; they have no relationship to physical security camera systems."
      ],
      "codeSnippet": "// Key Audit Premium events for BEC investigations:\n// MailItemsAccessed - mail sync/read activity\n// Send - message sent via compromised mailbox\n// SearchQueryInitiated - what attacker searched for\n// New-InboxRule - malicious forwarding rule creation",
      "socTip": "During a suspected BEC, immediately pull MailItemsAccessed and New-InboxRule events — these two alone often reveal both the access scope and persistence mechanism.",
      "docRef": "Microsoft Learn: Audit (Premium) - Search for crime scene events"
    }
  },
  {
    "id": "purview-028",
    "topic": "Unified Audit Log search",
    "scenario": "Adatum's analyst needs to search across Exchange, SharePoint, Teams, and Entra ID sign-in activity in a single query rather than checking each service's logs separately.",
    "question": "What Purview feature provides a single, cross-workload search interface for user and admin activity across Microsoft 365?",
    "options": [
      "The Unified Audit Log (searchable via the Purview compliance portal or Search-UnifiedAuditLog PowerShell cmdlet), which aggregates activity from Exchange, SharePoint, OneDrive, Teams, Entra ID, and more",
      "Microsoft Defender for Cloud Apps Cloud Discovery dashboard",
      "Azure Monitor Log Analytics workspace exclusively",
      "Windows Event Viewer on each domain controller"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified Audit Log",
      "analysis": [
        "Option A is CORRECT: The Unified Audit Log centralizes activity records across most Microsoft 365 services into one searchable store, accessible through the compliance portal's Audit tool or the Search-UnifiedAuditLog PowerShell cmdlet for larger/scripted queries.",
        "Option B is INCORRECT: Cloud Discovery in Defender for Cloud Apps analyzes network traffic logs for shadow IT discovery, not native Microsoft 365 unified auditing.",
        "Option C is INCORRECT: Azure Monitor/Log Analytics can ingest audit data (e.g., via Sentinel connectors) but is not itself the native source of the Unified Audit Log.",
        "Option D is INCORRECT: Windows Event Viewer captures local/domain controller events, unrelated to cloud service activity logging."
      ],
      "codeSnippet": "// PowerShell example:\n// Search-UnifiedAuditLog -StartDate 2026-08-01 `\n//   -EndDate 2026-08-10 -UserIds jsmith@adatum.com `\n//   -Operations FileAccessed,FileDownloaded",
      "socTip": "For investigations needing more than the UI's 5,000-result cap, use Search-UnifiedAuditLog with pagination (-SessionCommand ReturnLargeSet) instead of the portal search.",
      "docRef": "Microsoft Learn: Search the audit log"
    }
  },
  {
    "id": "purview-029",
    "topic": "Compliance Manager score",
    "scenario": "Litware's compliance officer wants a single measurable indicator of how well the organization's Microsoft 365 configuration aligns with a chosen regulation, to report progress to the board.",
    "question": "What does the Compliance Manager score in Microsoft Purview represent?",
    "options": [
      "A weighted percentage score reflecting how many recommended improvement actions (technical, documentation, or assessment-based) an organization has completed against selected regulations/standards",
      "A count of active malware infections currently on the network",
      "The number of licensed users assigned E5 compliance SKUs",
      "A measure of network bandwidth utilization across the tenant"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Compliance Manager Score",
      "analysis": [
        "Option A is CORRECT: Compliance Manager assigns point values to improvement actions across technical configuration, documentation, and assessment categories; completing actions raises the overall percentage score, which reflects alignment maturity against chosen regulations like GDPR or ISO 27001.",
        "Option B is INCORRECT: Malware infection counts are a security operations metric from Defender products, unrelated to the Compliance Manager score.",
        "Option C is INCORRECT: License counts are an administrative/billing metric, not a compliance posture score.",
        "Option D is INCORRECT: Network bandwidth is an infrastructure performance metric, entirely unrelated to regulatory compliance scoring."
      ],
      "codeSnippet": "// Compliance Manager scoring breakdown:\n// Technical actions (e.g., enable MFA): up to 100 pts\n// Documentation actions (e.g., policy on file): up to 100 pts\n// Total tenant score = sum(completed action points) / max points",
      "socTip": "Prioritize 'technical' improvement actions over documentation ones first when time-constrained — they typically carry higher point weight and immediate security value.",
      "docRef": "Microsoft Learn: Microsoft Purview Compliance Manager"
    }
  },
  {
    "id": "purview-030",
    "topic": "Compliance Manager assessments",
    "scenario": "Trey Research's compliance team wants to track their readiness specifically against ISO 27001 and NIST 800-53, in addition to their existing Microsoft 365 Data Protection Baseline assessment.",
    "question": "How does Compliance Manager allow organizations to track alignment with multiple distinct regulations or standards simultaneously?",
    "options": [
      "By creating multiple assessments, each built from a regulation-specific template (like ISO 27001 or NIST 800-53), which can share improvement actions already completed elsewhere in the tenant",
      "Compliance Manager only supports one regulation per tenant at a time",
      "Each regulation requires a completely separate Microsoft 365 tenant",
      "Assessments must be manually recreated from scratch with no shared action credit between them"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Compliance Manager Assessments",
      "analysis": [
        "Option A is CORRECT: Organizations can add multiple assessments from a library of regulation/standard templates. Since many controls overlap (e.g., MFA enablement helps both ISO 27001 and NIST), completing an action in one assessment often automatically credits progress in overlapping assessments.",
        "Option B is INCORRECT: Compliance Manager explicitly supports tracking many simultaneous assessments against different regulations within a single tenant.",
        "Option C is INCORRECT: Separate tenants are not required; multiple assessments coexist within one tenant's Compliance Manager instance.",
        "Option D is INCORRECT: Shared improvement actions do carry credit across overlapping assessments rather than requiring duplicate manual work."
      ],
      "codeSnippet": "// Example assessments in one tenant:\n// - Data Protection Baseline (default)\n// - ISO/IEC 27001:2013\n// - NIST 800-53 Rev 5\n// Shared action: \"Enable MFA for all users\" credits all three",
      "socTip": "When multiple assessments are active, filter improvement actions by 'shared across assessments' to prioritize work with the broadest compliance impact.",
      "docRef": "Microsoft Learn: Create and manage assessments in Compliance Manager"
    }
  },
  {
    "id": "purview-031",
    "topic": "Purview integration with Copilot for Security",
    "scenario": "Northwind Traders' SOC analyst is using Copilot for Security embedded in the Purview portal to investigate why a DLP alert fired on a specific file share.",
    "question": "How does the embedded Copilot for Security experience in Purview typically assist an analyst investigating a DLP alert?",
    "options": [
      "It summarizes the alert context, explains which policy and rule matched, identifies the sensitive information types detected, and suggests likely next investigative or remediation steps in natural language",
      "It automatically deletes the offending file without analyst approval",
      "It disables the DLP policy that generated the alert to stop future noise",
      "It only works for Defender XDR incidents, not Purview alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security embedded in Purview",
      "analysis": [
        "Option A is CORRECT: Embedded Copilot in Purview can summarize a DLP alert in plain language — which policy/rule triggered, what sensitive info types were detected, involved users/locations — and suggest next steps, speeding up analyst triage.",
        "Option B is INCORRECT: Copilot provides guidance and summaries; it does not autonomously delete files or take irreversible remediation actions without analyst action.",
        "Option C is INCORRECT: Copilot assists investigation; disabling a policy is a deliberate admin action taken by a human, not an automatic Copilot behavior.",
        "Option D is INCORRECT: Copilot for Security has embedded experiences across multiple products including Purview, Defender XDR, Entra, and Intune — not limited to Defender XDR alone."
      ],
      "codeSnippet": "// Example embedded Copilot prompt in Purview:\n// \"Summarize this DLP alert and explain why it triggered\"\n// \"What sensitive info types were found in this incident?\"\n// \"What should I investigate next for this DLP match?\"",
      "socTip": "Use embedded Copilot summaries as a starting point for triage, but always verify sensitive info type matches manually before closing an alert as a false positive.",
      "docRef": "Microsoft Learn: Copilot for Security in Microsoft Purview"
    }
  },
  {
    "id": "purview-032",
    "topic": "Auto-labeling policies",
    "scenario": "Woodgrove Bank has thousands of existing SharePoint documents containing SSNs that were never manually labeled. The compliance team wants Purview to apply the correct sensitivity label retroactively without touching each file by hand.",
    "question": "What Purview capability automatically applies sensitivity or retention labels to existing and new content that matches defined conditions, without requiring end-user action?",
    "options": [
      "Auto-labeling policies, which scan content in Exchange, SharePoint, OneDrive, and Teams for matching conditions (like specific sensitive info types) and apply the configured label automatically",
      "Manual labeling only, since auto-labeling does not exist in Purview",
      "Conditional Access policies",
      "Endpoint DLP print restriction rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Auto-Labeling Policies",
      "analysis": [
        "Option A is CORRECT: Auto-labeling policies (service-side, not the client-side recommendation) continuously scan supported locations for content matching defined conditions and automatically apply the specified sensitivity or retention label, including to files that already exist in the environment.",
        "Option B is INCORRECT: Auto-labeling is a real, well-documented Purview capability distinct from manual client-side labeling.",
        "Option C is INCORRECT: Conditional Access governs authentication/access decisions, not content labeling.",
        "Option D is INCORRECT: Endpoint DLP print restrictions control device-level printing behavior, unrelated to automatic content labeling."
      ],
      "codeSnippet": "// Auto-labeling policy example:\n// Condition: Content contains U.S. SSN (High confidence)\n// Locations: SharePoint sites, OneDrive accounts\n// Action: Apply label \"Confidential - PII\"\n// Mode: Simulate first, then turn on",
      "socTip": "Always run auto-labeling in simulation mode first and review the match report — this catches unexpected false-positive labeling before it affects real business documents.",
      "docRef": "Microsoft Learn: Apply a sensitivity label automatically"
    }
  },
  {
    "id": "purview-033",
    "topic": "Client-side vs service-side auto-labeling",
    "scenario": "An Adatum analyst is confused about the difference between a label being auto-applied while a user is actively editing a Word document versus a label being applied to a file already sitting in SharePoint that no one has opened in months.",
    "question": "What is the distinction between client-side automatic labeling and service-side auto-labeling in Purview?",
    "options": [
      "Client-side labeling applies recommendations or automatic labels in real time as a user creates/edits content in an Office app; service-side auto-labeling runs as a background scan across content at rest in Exchange, SharePoint, OneDrive, and Teams",
      "Client-side labeling only works on mobile devices; service-side only works on desktops",
      "There is no such distinction — both terms describe an identical process",
      "Client-side labeling requires a third-party plugin; service-side is entirely a Microsoft-native feature only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Client-Side vs Service-Side Auto-Labeling",
      "analysis": [
        "Option A is CORRECT: Client-side auto-labeling/recommendation happens inside apps like Word or Outlook in real time as the user types or saves, prompting or applying a label. Service-side auto-labeling is a backend policy that periodically scans existing content across cloud locations and applies labels without user interaction.",
        "Option B is INCORRECT: Both mechanisms work across desktop and other supported platforms; the distinction is timing/location of enforcement, not device type.",
        "Option C is INCORRECT: They are functionally distinct mechanisms with different triggers (real-time editing vs. backend scan), not synonyms.",
        "Option D is INCORRECT: Both client-side and service-side auto-labeling are native Microsoft Purview capabilities; no third-party plugin is required for either."
      ],
      "codeSnippet": "// Client-side: triggers while editing in Word/Outlook\n// -> \"This looks like it contains PII, apply Confidential label?\"\n//\n// Service-side: scheduled backend scan\n// -> Scans SharePoint library nightly, labels matches found",
      "socTip": "For a backlog of thousands of unlabeled legacy documents, service-side auto-labeling is the right tool — client-side only catches content actively being edited.",
      "docRef": "Microsoft Learn: Apply a sensitivity label to content automatically"
    }
  },
  {
    "id": "purview-034",
    "topic": "Container labels for sites and groups",
    "scenario": "Tailspin Toys' compliance team wants an entire Microsoft Teams team and its associated SharePoint site to be marked Highly Confidential, restricting external guest access and site-wide sharing, rather than labeling individual files.",
    "question": "What kind of sensitivity label can be applied to Microsoft 365 Groups, Teams, and SharePoint sites (rather than individual documents) to control access at the container level?",
    "options": [
      "Container labels, which can enforce settings like privacy (private/public), external user access, and unmanaged device access at the site/group/team level",
      "File labels, which are the only type of sensitivity label Purview supports",
      "Retention labels applied to individual list items only",
      "DLP policy tips configured per document library"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Container (Site/Group/Team) Labels",
      "analysis": [
        "Option A is CORRECT: Container labels apply to Microsoft 365 Groups/Teams/SharePoint sites and can govern privacy settings, whether guests can be added, and whether unmanaged devices can access the site — operating at the container level rather than individual file level.",
        "Option B is INCORRECT: Purview explicitly supports both file/email labels and separate container labels for sites/groups/Teams — file labels are not the only type.",
        "Option C is INCORRECT: Retention labels govern content lifecycle for items, not access/privacy settings for an entire site or team container.",
        "Option D is INCORRECT: DLP policy tips are per-document/library data loss warnings, not the mechanism for controlling site-wide privacy or guest access."
      ],
      "codeSnippet": "// Container label example:\n// Label: \"Highly Confidential - Restricted Team\"\n// Privacy: Private (cannot be changed to Public)\n// External sharing: Guests not allowed\n// Unmanaged devices: Blocked from access",
      "socTip": "Container labels are set at Team/site creation and are harder to change later — advise project owners to select the correct label upfront rather than relabeling after content accumulates.",
      "docRef": "Microsoft Learn: Use sensitivity labels to protect content in Microsoft Teams, Microsoft 365 groups, and SharePoint sites"
    }
  },
  {
    "id": "purview-035",
    "topic": "DLP for Microsoft Teams chat",
    "scenario": "Relecloud's SOC wants to prevent employees from pasting customer credit card numbers into Teams chat messages, whether in 1:1 chats or channel conversations.",
    "question": "Can a Microsoft Purview DLP policy inspect and act on content typed directly into Teams chat and channel messages, not just file attachments?",
    "options": [
      "Yes — DLP for Teams supports scanning message text (not just attachments) and can block a message from being sent when it matches policy conditions like a credit card number",
      "No — DLP can only inspect files attached to a Teams message, never the message text itself",
      "No — Teams is entirely excluded from all Purview DLP capabilities",
      "Yes, but only for messages sent in private 1:1 chats, never in channels"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP for Microsoft Teams Chat and Channel Messages",
      "analysis": [
        "Option A is CORRECT: DLP policies scoped to the Teams location inspect actual message text typed into chats and channels (in addition to attachments) and can block the message from being sent, or restrict access, when conditions like a credit card number are matched.",
        "Option B is INCORRECT: Purview DLP explicitly can inspect the message body text itself, not just attached files.",
        "Option C is INCORRECT: Teams is a fully supported DLP location, not excluded.",
        "Option D is INCORRECT: DLP for Teams covers both private/group chats and channel messages, not just 1:1 chats."
      ],
      "codeSnippet": "// DLP Teams policy example:\n// Location: Teams chat and channel messages\n// Condition: Content contains Credit Card Number\n// Action: Block message from being sent,\n//         notify sender with policy tip explanation",
      "socTip": "When testing DLP for Teams, remember blocked messages show the sender an in-line policy tip rather than silently failing — coach users to read that tip before assuming a bug.",
      "docRef": "Microsoft Learn: Enable Endpoint DLP and DLP for Teams"
    }
  },
  {
    "id": "purview-036",
    "topic": "Information barriers",
    "scenario": "Woodgrove Bank must comply with financial regulations preventing its Investment Banking division from communicating or collaborating with the Research division to avoid conflicts of interest.",
    "question": "What Purview feature enforces communication and collaboration restrictions between specific groups of users to prevent conflicts of interest?",
    "options": [
      "Information barriers, which define policies preventing or restricting communication and content sharing between specified segments of users in Teams, SharePoint, and OneDrive",
      "Sensitivity label encryption",
      "Insider Risk Management priority groups",
      "Endpoint DLP device restrictions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Information Barriers",
      "analysis": [
        "Option A is CORRECT: Information barriers define user segments (e.g., 'Investment Banking' vs 'Research') and policies that block or restrict chat, calls, file sharing, and Teams/site membership between those segments, commonly used in finance for conflict-of-interest compliance.",
        "Option B is INCORRECT: Sensitivity label encryption restricts document access based on identity/rights, not organization-wide group-to-group communication segmentation.",
        "Option C is INCORRECT: IRM priority groups apply elevated monitoring, not hard communication blocking between departments.",
        "Option D is INCORRECT: Endpoint DLP restricts data movement actions on a device, not interpersonal communication between user segments."
      ],
      "codeSnippet": "// Information barrier policy example:\n// Segment A: \"Investment-Banking\" (department attribute)\n// Segment B: \"Research\"\n// Policy: Block communication between A and B\n// Applies to: Teams chat/calls, SharePoint site access",
      "socTip": "Information barrier segments rely on accurate user attributes (like department) in Entra ID — verify attribute hygiene before deploying, or segmentation will be incomplete.",
      "docRef": "Microsoft Learn: Learn about information barriers"
    }
  },
  {
    "id": "purview-037",
    "topic": "Adaptive protection",
    "scenario": "Litware wants DLP enforcement to automatically become stricter for a specific user the moment Insider Risk Management flags them as elevated risk, without an analyst manually reconfiguring policies each time.",
    "question": "What Purview capability dynamically adjusts DLP policy strictness for a user based on their current insider risk level?",
    "options": [
      "Adaptive protection, which integrates Insider Risk Management risk levels with DLP so that higher-risk users automatically get stricter DLP controls applied without manual policy changes",
      "Compliance Manager scoring automation",
      "Communication Compliance escalation rules",
      "Records Management disposition automation"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Adaptive Protection",
      "analysis": [
        "Option A is CORRECT: Adaptive protection links IRM risk scoring to DLP so that as a user's risk level changes (elevated, moderate, minor), DLP policies dynamically apply stricter or more lenient controls to that specific user automatically, reducing manual policy tuning.",
        "Option B is INCORRECT: Compliance Manager scoring tracks overall regulatory posture, unrelated to per-user dynamic DLP strictness.",
        "Option C is INCORRECT: Communication Compliance escalation routes flagged messages to reviewers; it doesn't adjust DLP enforcement strictness.",
        "Option D is INCORRECT: Disposition automation concerns records deletion/retention workflows, not dynamic per-user DLP control adjustment."
      ],
      "codeSnippet": "// Adaptive protection flow:\n// IRM flags UserX as \"Elevated\" risk\n// -> Adaptive protection auto-applies \"Strict DLP\" tier to UserX\n// -> Stricter thresholds/blocking apply automatically\n// -> Risk level drops -> stricter controls automatically relax",
      "socTip": "Adaptive protection reduces analyst workload but should still be reviewed periodically — validate that risk-level transitions are actually changing enforcement as expected.",
      "docRef": "Microsoft Learn: Learn about adaptive protection"
    }
  },
  {
    "id": "purview-038",
    "topic": "Data Security Posture Management (DSPM)",
    "scenario": "Fabrikam's new CISO wants a single dashboard showing overall data risk across the organization — including oversharing, unlabeled sensitive data, and risky user activity — before deciding where to focus the compliance team's efforts.",
    "question": "What Purview solution provides a consolidated, risk-prioritized view of an organization's overall data security posture across labeling, sharing, and activity signals?",
    "options": [
      "Data Security Posture Management (DSPM), which aggregates signals across Purview solutions to surface top data risks, recommend policies, and track risk reduction over time",
      "Microsoft Defender for Cloud Secure Score exclusively",
      "Entra ID Identity Secure Score",
      "Azure Policy compliance dashboard"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data Security Posture Management (DSPM)",
      "analysis": [
        "Option A is CORRECT: DSPM in Purview provides a unified dashboard highlighting top data risks (like oversharing, unlabeled sensitive data, risky AI/Copilot usage), recommends policies to reduce that risk, and tracks improvement over time — purpose-built for data-centric posture assessment.",
        "Option B is INCORRECT: Defender for Cloud Secure Score focuses on cloud infrastructure/workload security posture, not data-centric labeling/sharing risk specifically.",
        "Option C is INCORRECT: Identity Secure Score focuses on identity configuration hardening (MFA, Conditional Access), not data classification/sharing risk.",
        "Option D is INCORRECT: Azure Policy compliance dashboards track resource configuration compliance against Azure policies, unrelated to Purview's data risk signals."
      ],
      "codeSnippet": "// DSPM dashboard highlights example:\n// - 12,000 files overshared externally with sensitive data\n// - 4,500 files with sensitive data but no label applied\n// - 3 recommended policies to reduce oversharing risk",
      "socTip": "Use DSPM's recommended policy actions as a prioritized starting backlog for a new compliance program rather than building a rollout plan from scratch.",
      "docRef": "Microsoft Learn: Data Security Posture Management overview"
    }
  },
  {
    "id": "purview-039",
    "topic": "DSPM for AI",
    "scenario": "Northwind Traders has rolled out Microsoft 365 Copilot broadly and is concerned employees may inadvertently surface oversensitive or unlabeled data through Copilot prompts and responses.",
    "question": "What Purview capability specifically monitors and reports on data risks introduced by generative AI tools like Microsoft 365 Copilot?",
    "options": [
      "DSPM for AI, which reports on AI app usage, sensitive data referenced in AI interactions, and unethical/risky prompts, and helps apply policies to reduce oversharing through AI tools",
      "Endpoint DLP printer restriction policies",
      "Records Management disposition review for AI-generated content only",
      "eDiscovery Premium custodian communications"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DSPM for AI",
      "analysis": [
        "Option A is CORRECT: DSPM for AI extends data security posture management specifically to generative AI usage, showing which apps are used, what sensitive data appears in prompts/responses, flagging risky prompts, and recommending policies (like DLP for Copilot) to reduce oversharing through AI interactions.",
        "Option B is INCORRECT: Printer restriction is an unrelated Endpoint DLP device control, not an AI usage monitoring capability.",
        "Option C is INCORRECT: Records Management disposition review governs content lifecycle deletion decisions, not AI interaction monitoring.",
        "Option D is INCORRECT: eDiscovery custodian communications concern legal hold/case management, unrelated to ongoing AI usage risk reporting."
      ],
      "codeSnippet": "// DSPM for AI report highlights example:\n// - Top AI apps in use: Microsoft 365 Copilot, ChatGPT (browser)\n// - Sensitive data types surfaced in Copilot interactions\n// - Risky prompts detected (e.g., requesting restricted data)",
      "socTip": "Pair DSPM for AI findings with a DLP policy for Microsoft 365 Copilot to actually block oversensitive content from being surfaced in AI responses, not just report on it.",
      "docRef": "Microsoft Learn: Data security posture management for AI"
    }
  },
  {
    "id": "purview-040",
    "topic": "Priva overview",
    "scenario": "Litware's Data Protection Officer needs to identify where personal data is overexposed within the organization and manage subject rights requests (like a customer's right to be forgotten under GDPR).",
    "question": "What Purview-family solution focuses specifically on privacy risk management, including personal data overexposure and subject rights request automation?",
    "options": [
      "Microsoft Priva, which provides Privacy Risk Management to detect data overexposure/hoarding and Subject Rights Requests to automate discovery and fulfillment of individual data requests",
      "Insider Risk Management, which is the only tool for privacy-related requests",
      "eDiscovery Standard, used exclusively for GDPR-related legal holds",
      "Communication Compliance, used solely to fulfill subject rights requests"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Microsoft Priva",
      "analysis": [
        "Option A is CORRECT: Priva includes Privacy Risk Management (identifying data overexposure, hoarding, and transfers) and Subject Rights Requests (automating search, retrieval, redaction, and reporting for individual data requests under laws like GDPR/CCPA).",
        "Option B is INCORRECT: IRM addresses insider threat/behavioral risk, not privacy-specific overexposure detection or subject rights automation — that is Priva's dedicated purpose.",
        "Option C is INCORRECT: eDiscovery is a litigation/investigation search tool; while it can technically search content, Priva is purpose-built with workflow automation specifically for privacy subject requests.",
        "Option D is INCORRECT: Communication Compliance reviews message content for policy violations; it has no subject rights request fulfillment capability."
      ],
      "codeSnippet": "// Priva capabilities:\n// Privacy Risk Management:\n//   - Data overexposure alerts\n//   - Data hoarding/minimization insights\n//   - Data transfer policies (cross-border)\n// Subject Rights Requests:\n//   - Automated search across M365 for a named individual\n//   - Redaction and export workflow",
      "socTip": "When a DPO asks for help with a 'right to be forgotten' request, point them to Priva Subject Rights Requests rather than manually building eDiscovery searches — it's purpose-built for that workflow.",
      "docRef": "Microsoft Learn: Learn about Microsoft Priva"
    }
  },
  {
    "id": "purview-041",
    "topic": "Purview compliance portal RBAC",
    "scenario": "Trey Research wants its Communication Compliance reviewers to see flagged messages, but does not want those same reviewers to be able to configure DLP policies or view eDiscovery cases.",
    "question": "What Purview mechanism allows admins to grant scoped, role-specific access so users only see the compliance features and data relevant to their job function?",
    "options": [
      "Role-based access control (RBAC) using Microsoft Purview role groups (e.g., Communication Compliance Analysts, DLP Compliance Management, eDiscovery Manager) that scope permissions to specific solutions",
      "A single Global Administrator role that grants or denies all compliance features at once",
      "Sensitivity label justification prompts",
      "Conditional Access device compliance policies"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Role-Based Access Control",
      "analysis": [
        "Option A is CORRECT: Purview uses granular role groups (built-in or custom) mapped to specific solutions — e.g., Communication Compliance Analysts only see communication review data, while DLP Compliance Management manages DLP policies — enforcing least-privilege access across the compliance portal.",
        "Option B is INCORRECT: Global Administrator is an all-or-nothing tenant-wide role; Purview's RBAC model is specifically designed to avoid needing that broad a role for day-to-day compliance operations.",
        "Option C is INCORRECT: Justification prompts capture user reasons for label changes; they are unrelated to admin/reviewer access control.",
        "Option D is INCORRECT: Conditional Access device compliance evaluates device health for authentication decisions, not Purview feature-level permission scoping."
      ],
      "codeSnippet": "// Example Purview role groups:\n// - Communication Compliance Analysts: review-only, no DLP access\n// - DLP Compliance Management: manage/edit DLP policies\n// - eDiscovery Manager: manage cases and holds\n// - Compliance Data Administrator: broad, cross-solution admin",
      "socTip": "Audit Purview role group membership quarterly — overly broad membership (like everyone in 'Compliance Administrator') is a common finding in security reviews.",
      "docRef": "Microsoft Learn: Permissions in the Microsoft Purview portal"
    }
  },
  {
    "id": "purview-042",
    "topic": "Content Explorer and Activity Explorer",
    "scenario": "Adatum's compliance analyst wants to see, right now, exactly which documents in SharePoint currently carry a specific sensitivity label, as well as a historical log of label downgrade events by users over the past month.",
    "question": "Which two Purview tools respectively provide a real-time inventory of currently labeled content and a historical log of label-related user activity?",
    "options": [
      "Content Explorer (current-state inventory of labeled/classified content) and Activity Explorer (historical log of label application, changes, and removal events)",
      "Only Content Explorer exists; Activity Explorer is a Defender for Cloud Apps feature",
      "Only Activity Explorer exists; Content Explorer is part of Microsoft Sentinel",
      "Both tools show identical, interchangeable data with no functional distinction"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Content Explorer vs Activity Explorer",
      "analysis": [
        "Option A is CORRECT: Content Explorer shows a real-time snapshot of currently classified/labeled content across locations (what exists right now, by label and sensitive info type). Activity Explorer shows a historical timeline of label-related events, such as when labels were applied, changed, downgraded, or removed, and by whom.",
        "Option B is INCORRECT: Activity Explorer is a native Purview tool, not a Defender for Cloud Apps feature.",
        "Option C is INCORRECT: Content Explorer is native to Purview information protection, not a Microsoft Sentinel component.",
        "Option D is INCORRECT: The two tools serve distinct purposes — current inventory vs. historical activity — and are not interchangeable."
      ],
      "codeSnippet": "// Content Explorer: \"What is labeled Confidential right now?\"\n// Activity Explorer: \"Who downgraded a label from\n//                     Confidential to Public last week?\"",
      "socTip": "Use Content Explorer to scope a DLP/auto-labeling rollout (how much data exists) and Activity Explorer afterward to monitor whether users are bypassing or downgrading labels.",
      "docRef": "Microsoft Learn: Get started with content explorer and activity explorer"
    }
  },
  {
    "id": "purview-043",
    "topic": "DLP for Power BI and Fabric",
    "scenario": "Woodgrove Bank's analytics team publishes datasets in Power BI and Microsoft Fabric that sometimes contain customer PII. The compliance team wants sensitivity labeling and DLP enforcement to extend into these BI workloads, not just Office documents.",
    "question": "Does Microsoft Purview support sensitivity labeling and DLP enforcement for Power BI and Microsoft Fabric content?",
    "options": [
      "Yes — sensitivity labels can be applied to Power BI reports/datasets, and DLP policies can detect sensitive data and restrict actions like export within Power BI and Fabric",
      "No — Purview labeling and DLP are limited strictly to Office documents and email",
      "Only Fabric is supported; Power BI has no sensitivity labeling integration at all",
      "Yes, but only through a separate third-party connector, not natively"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Integration with Power BI and Fabric",
      "analysis": [
        "Option A is CORRECT: Purview sensitivity labels extend to Power BI reports, dashboards, and datasets, and DLP policies can be scoped to Fabric/Power BI to detect sensitive information and restrict actions like exporting to Excel or PDF.",
        "Option B is INCORRECT: Purview's protection scope has expanded well beyond Office documents/email to include Power BI, Fabric, Teams, and endpoint devices.",
        "Option C is INCORRECT: Power BI has native sensitivity label support (label inheritance from underlying data and manual application), not just Fabric.",
        "Option D is INCORRECT: This integration is native within Microsoft Purview and Power BI/Fabric admin settings — no third-party connector is required."
      ],
      "codeSnippet": "// Power BI sensitivity label flow:\n// Dataset with SQL source labeled \"Confidential\"\n// -> Label inherited by Power BI report/dashboard\n// -> DLP policy scans Power BI, restricts export of\n//    high-sensitivity reports to unmanaged devices",
      "socTip": "Enable sensitivity label inheritance from data sources in Power BI tenant settings — otherwise reports built on labeled data won't automatically carry the correct label.",
      "docRef": "Microsoft Learn: Sensitivity labels in Power BI"
    }
  },
  {
    "id": "purview-044",
    "topic": "Records Management file plan",
    "scenario": "Relecloud's records team manages hundreds of distinct record categories, each with different regulatory citations, retention periods, and departments responsible for them, and needs a structured way to organize this metadata.",
    "question": "What Purview Records Management feature provides a structured, hierarchical way to organize retention labels with metadata like regulatory citations, department, and business function?",
    "options": [
      "File plan, which lets admins organize retention labels into a structured hierarchy with metadata such as citation, department, category, and sub-category for large-scale records governance",
      "Content Explorer categories",
      "DLP policy templates",
      "Sensitivity label priority ordering"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "File Plan in Records Management",
      "analysis": [
        "Option A is CORRECT: The file plan is a structured taxonomy within Records Management that organizes retention labels with rich metadata (regulatory citation, business function, department, category/sub-category), making it manageable to govern hundreds or thousands of distinct record types at scale, and supports bulk import/export via CSV.",
        "Option B is INCORRECT: Content Explorer shows classified content inventory; it doesn't provide the structured label metadata taxonomy that a file plan does.",
        "Option C is INCORRECT: DLP policy templates are pre-built starting points for data loss prevention rules, unrelated to records taxonomy organization.",
        "Option D is INCORRECT: Sensitivity label priority ordering determines which label 'wins' when multiple could apply, not a records metadata organization structure."
      ],
      "codeSnippet": "// File plan CSV import columns example:\n// Name, Citation, Department, Category, SubCategory,\n// RetentionPeriod, RecordType, DispositionReviewers",
      "socTip": "For large records programs, use the file plan CSV bulk import rather than manually creating hundreds of labels one at a time in the UI — it's dramatically faster and less error-prone.",
      "docRef": "Microsoft Learn: File plan descriptors in Microsoft Purview"
    }
  },
  {
    "id": "purview-045",
    "topic": "eDiscovery export and load files",
    "scenario": "Trey Research's outside counsel needs the results of an eDiscovery Premium review set exported in a format their legal review platform (Relativity) can ingest, including document metadata and load files.",
    "question": "What does exporting results from Microsoft Purview eDiscovery Premium typically produce for use in external legal review platforms?",
    "options": [
      "A native file export accompanied by load files (such as a metadata report and a document map) formatted for ingestion into third-party review platforms like Relativity",
      "A single unstructured ZIP file with no metadata, requiring counsel to manually reconstruct context",
      "An automatic direct API push into Relativity requiring no export step at all",
      "Only a printed PDF report summarizing item counts, without the underlying documents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "eDiscovery Export and Load Files",
      "analysis": [
        "Option A is CORRECT: eDiscovery Premium export produces native files plus load files (e.g., a metadata/DAT file and document/image load file) structured so external review platforms like Relativity can import documents along with their associated metadata and family relationships.",
        "Option B is INCORRECT: Exports are structured specifically to preserve metadata and document relationships for downstream legal platforms, not dumped as unstructured files.",
        "Option C is INCORRECT: There's no native automatic API push directly into Relativity; an export step producing load files is required, which counsel then imports.",
        "Option D is INCORRECT: Exports include the actual underlying documents/files, not merely a summary PDF of item counts."
      ],
      "codeSnippet": "// Typical eDiscovery export contents:\n// /NATIVES/ (original files)\n// /TEXT/ (extracted text)\n// load_file.dat (metadata for review platform)\n// image_load_file.opt (if imaged/TIFF requested)",
      "socTip": "Confirm the outside counsel's review platform's exact load file format requirements (Concordance, Relativity, etc.) before running a large export — mismatched formats cause costly re-exports.",
      "docRef": "Microsoft Learn: Export case data from eDiscovery (Premium)"
    }
  },
  {
    "id": "purview-046",
    "topic": "Retention for Yammer/Viva Engage",
    "scenario": "Northwind Traders' compliance team wants retention and eDiscovery capabilities to also cover conversations happening in Viva Engage (formerly Yammer) communities, not just Exchange and SharePoint.",
    "question": "Are Microsoft Purview retention policies and eDiscovery search capabilities extended to Viva Engage (Yammer) community posts and messages?",
    "options": [
      "Yes — Viva Engage is a supported location for retention policies, eDiscovery content search, and Communication Compliance, allowing governance of community posts and messages",
      "No — Viva Engage content is entirely outside the scope of Purview compliance tools",
      "Yes, but only for private messages, never public community posts",
      "No — Viva Engage requires a completely separate compliance product from a third-party vendor"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Coverage of Viva Engage (Yammer)",
      "analysis": [
        "Option A is CORRECT: Viva Engage is a supported workload within Purview retention policies, eDiscovery content search, and Communication Compliance, allowing organizations to retain, search, and monitor community posts and native messages alongside other Microsoft 365 content.",
        "Option B is INCORRECT: Viva Engage content is explicitly within scope for multiple Purview compliance solutions, not excluded.",
        "Option C is INCORRECT: Both public community posts and private/native messages in Viva Engage can be covered by supported Purview solutions, not private messages exclusively.",
        "Option D is INCORRECT: Governance is handled natively within Microsoft Purview; no separate third-party compliance product is required for Viva Engage coverage."
      ],
      "codeSnippet": "// Purview locations supporting Viva Engage:\n// - Retention policies: Yammer community messages\n// - eDiscovery: Search Viva Engage native/community posts\n// - Communication Compliance: monitor community conversations",
      "socTip": "When scoping a retention policy to include Viva Engage, remember public community content behaves differently from native private messages — review location-specific scoping options carefully.",
      "docRef": "Microsoft Learn: Learn about retention for Viva Engage (Yammer)"
    }
  },
  {
    "id": "purview-047",
    "topic": "Bring your own key (BYOK) / HYOK",
    "scenario": "A highly regulated Woodgrove Bank division wants to encrypt its most sensitive sensitivity-labeled content using encryption keys stored entirely within their own on-premises HSM, outside Microsoft's control.",
    "question": "What Purview Information Protection option allows an organization to use encryption keys hosted entirely on their own infrastructure rather than Microsoft-managed keys?",
    "options": [
      "Hold Your Own Key (HYOK), which uses an on-premises Active Directory Rights Management Services (AD RMS) key that Microsoft never has access to, for the organization's most sensitive labels",
      "Bring Your Own Key (BYOK) is the only option, and it still stores a copy of the key in Microsoft's key vault by default",
      "Neither BYOK nor HYOK exist in Purview; all encryption keys are Microsoft-managed only",
      "Customer Lockbox, which replaces the need for any key management entirely"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Hold Your Own Key (HYOK)",
      "analysis": [
        "Option A is CORRECT: HYOK lets an organization use on-premises AD RMS to generate and manage keys entirely outside Microsoft's cloud, so Microsoft never has access to the key — used for extremely sensitive content requiring maximum key sovereignty, though it limits some cloud-native features like eDiscovery search on that content.",
        "Option B is INCORRECT: BYOK (customer key) does let organizations supply their own key material, and while it's stored in Azure Key Vault under customer control, it's a distinct option from HYOK, which keeps keys fully on-premises.",
        "Option C is INCORRECT: Both BYOK and HYOK are real, documented Purview/AIP key management options for organizations wanting more control than Microsoft-managed keys.",
        "Option D is INCORRECT: Customer Lockbox controls Microsoft support engineer access approval workflows; it does not replace encryption key management."
      ],
      "codeSnippet": "// Key management options tiered by control:\n// Microsoft-managed key (default) - least admin overhead\n// BYOK / Customer Key (Azure Key Vault, customer-controlled)\n// HYOK (on-prem AD RMS) - maximum sovereignty, feature trade-offs",
      "socTip": "Warn stakeholders before adopting HYOK: content protected with HYOK keys cannot be indexed by many cloud services (like eDiscovery search or DLP content inspection), which is a major operational trade-off.",
      "docRef": "Microsoft Learn: Hold your own key (HYOK) requirements"
    }
  },
  {
    "id": "purview-048",
    "topic": "Data classification and overshared content",
    "scenario": "Fabrikam's SOC is alerted that a folder containing thousands of files with financial data has been shared with 'Everyone' in the organization, far beyond the finance team who should have access.",
    "question": "What Purview capability specifically helps identify content that is overshared relative to how sensitive it is, so it can be remediated?",
    "options": [
      "Data Security Posture Management (DSPM) oversharing insights, which surface sensitive content shared broadly (e.g., 'Everyone' or org-wide links) so admins can right-size access",
      "Records Management disposition review",
      "Communication Compliance keyword scanning",
      "eDiscovery case holds"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Oversharing Detection via DSPM",
      "analysis": [
        "Option A is CORRECT: DSPM surfaces oversharing insights — sensitive files shared via 'Everyone' groups, org-wide links, or excessive external sharing — specifically to help admins identify and remediate access that's disproportionate to the content's sensitivity.",
        "Option B is INCORRECT: Disposition review concerns end-of-lifecycle deletion decisions for records, not access/sharing scope remediation.",
        "Option C is INCORRECT: Communication Compliance scans message content for policy violations like harassment, not file sharing permission scope.",
        "Option D is INCORRECT: eDiscovery holds preserve content for legal cases; they don't analyze or remediate oversharing risk."
      ],
      "codeSnippet": "// DSPM oversharing insight example:\n// \"2,300 files with financial data shared org-wide\"\n// Recommended action: Restrict 'Everyone' sharing links,\n//   apply sensitivity label with access restriction",
      "socTip": "Prioritize DSPM oversharing remediation on files with both high sensitivity AND broad sharing scope — that intersection represents the highest actual risk, not sensitivity alone.",
      "docRef": "Microsoft Learn: Data security posture management overview"
    }
  },
  {
    "id": "purview-049",
    "topic": "DLP incident reports and alerts",
    "scenario": "Litware's SOC manager wants DLP violations routed automatically to a specific distribution list and wants the severity of the incident to scale based on how many sensitive items were involved.",
    "question": "What DLP policy configuration allows admins to escalate severity and route notifications based on the volume or type of sensitive content matched?",
    "options": [
      "Rule conditions with instance count thresholds combined with configurable incident reports (recipients, severity level, additional details) per DLP rule",
      "A single fixed severity level applied identically to every DLP policy tenant-wide with no customization",
      "Manual severity tagging performed entirely by the SOC after each incident, since DLP cannot assign severity itself",
      "Severity is determined solely by Microsoft Defender for Cloud Apps and cannot be configured within DLP rules"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Rule Conditions, Thresholds, and Incident Reports",
      "analysis": [
        "Option A is CORRECT: DLP rules can use instance count thresholds (e.g., trigger only when 10+ SSNs are found) to differentiate low vs. high-risk matches, and each rule's incident report settings let admins configure severity level, specific recipients, and included details (like matched content) for notification routing.",
        "Option B is INCORRECT: Severity and recipient configuration are rule-specific and fully customizable, not a single fixed tenant-wide setting.",
        "Option C is INCORRECT: DLP can assign severity automatically based on rule configuration; manual post-hoc tagging isn't required for basic severity assignment.",
        "Option D is INCORRECT: DLP severity/incident report configuration is native to the Purview DLP rule itself, not dependent on Defender for Cloud Apps."
      ],
      "codeSnippet": "// DLP rule threshold example:\n// Low severity: 1-9 instances of SSN detected\n// High severity: 10+ instances of SSN detected\n// Incident report -> send to: soc-alerts@litware.com\n//   Include: Matched sensitive info type details",
      "socTip": "Tune instance-count thresholds based on real business patterns — a threshold of 1 for common SITs like phone numbers often produces excessive low-value alerts.",
      "docRef": "Microsoft Learn: Create and deploy a data loss prevention policy"
    }
  },
  {
    "id": "purview-050",
    "topic": "Sensitivity label scoped to specific apps",
    "scenario": "An Adatum admin wants a particular sensitivity label available for Word, Excel, and PowerPoint, but not shown as an option for Outlook emails, since it's a document-classification-only label.",
    "question": "Can a Microsoft Purview sensitivity label be scoped to appear only for specific content types like files, but not emails?",
    "options": [
      "Yes — when creating a label, admins choose scope options such as Items (files and emails), Files, Emails, Groups & sites, Meetings, or specific combinations to control where the label is available",
      "No — every sensitivity label is automatically available in every app and content type with no scoping option",
      "Yes, but only for PowerPoint specifically; scoping to other apps is not supported",
      "No — scoping requires a separate Azure Information Protection client that has been fully deprecated"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Label Scope Configuration",
      "analysis": [
        "Option A is CORRECT: When defining a label, admins select its scope (Items/Files, Emails, Meetings, Groups & sites, PowerBI, Schematized data assets) which controls where the label can be applied, letting a purely document-oriented label be excluded from Outlook, for example.",
        "Option B is INCORRECT: Label scope is explicitly configurable per label; it is not a blanket all-or-nothing availability.",
        "Option C is INCORRECT: Scoping applies broadly across all supported content types (files, emails, meetings, sites), not limited to PowerPoint specifically.",
        "Option D is INCORRECT: While the standalone AIP client has been retired in favor of built-in labeling, label scoping itself is a core, still-supported configuration option in the modern Purview labeling experience, unrelated to that deprecated client."
      ],
      "codeSnippet": "// Label scope options during creation:\n// [x] Files and other data assets\n// [ ] Emails\n// [ ] Meetings\n// [ ] Groups & sites\n// -> Label will NOT appear as an option in Outlook",
      "socTip": "Review label scope settings when users report a label 'missing' in a specific app — it's often intentionally scoped out rather than a policy publishing issue.",
      "docRef": "Microsoft Learn: Create and configure sensitivity labels"
    }
  },
  {
    "id": "purview-051",
    "topic": "Retention for Copilot interactions",
    "scenario": "Northwind Traders' legal team asks whether prompts and responses generated through Microsoft 365 Copilot are subject to the same retention and eDiscovery obligations as regular emails and documents.",
    "question": "Are Microsoft 365 Copilot prompts and AI-generated responses subject to Purview retention policies and eDiscovery search?",
    "options": [
      "Yes — Copilot interactions are stored and can be captured by retention policies and searched/held through eDiscovery, similar to other Microsoft 365 content types",
      "No — AI-generated content is explicitly exempt from all retention and eDiscovery obligations",
      "Yes, but only the user's prompts are retained; Copilot's generated responses are never stored",
      "No — Copilot interaction data is deleted immediately after each session and cannot be retained"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retention and eDiscovery for Copilot Interactions",
      "analysis": [
        "Option A is CORRECT: Microsoft 365 Copilot prompts and responses are stored (typically in the user's mailbox as a hidden interaction record) and are supported locations for retention policies and eDiscovery search/hold, treating them similarly to other compliance-relevant content.",
        "Option B is INCORRECT: AI-generated content is not exempt — Microsoft explicitly built retention and eDiscovery support for Copilot interactions given their potential business/legal relevance.",
        "Option C is INCORRECT: Both the prompt and the generated response are captured together as part of the interaction record, not just the prompt.",
        "Option D is INCORRECT: Copilot interaction data is not immediately deleted after a session; it persists and is subject to the same governance tools as other content, pending organizational retention configuration."
      ],
      "codeSnippet": "// Copilot interaction governance:\n// Location type: \"Microsoft 365 Copilot\" (retention/eDiscovery)\n// Retained content: User prompt + Copilot's generated response\n// Searchable via eDiscovery content search like other items",
      "socTip": "When scoping legal holds for cases involving AI usage, explicitly include the 'Microsoft 365 Copilot' location — it's easy to overlook alongside standard mailbox/site holds.",
      "docRef": "Microsoft Learn: Manage data and governance for Microsoft 365 Copilot"
    }
  },
  {
    "id": "purview-052",
    "topic": "Sensitivity label default settings for new content",
    "scenario": "Tailspin Toys' compliance officer wants any new document that is not manually labeled to automatically inherit a baseline 'General' sensitivity label rather than remaining unlabeled indefinitely.",
    "question": "What label policy setting ensures that content without an explicit label is automatically assigned a baseline label?",
    "options": [
      "Setting a default label within the label policy, which automatically applies to new documents and emails when the user doesn't choose one",
      "Auto-labeling policies only, since default labels cannot be configured through label policies",
      "Retention labels, which always take precedence over any sensitivity label default",
      "There is no mechanism to default-label unlabeled content in Purview"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Default Label in Label Policy",
      "analysis": [
        "Option A is CORRECT: A label policy can specify a default label that automatically applies to new/unlabeled content (documents and emails) so nothing remains classification-free by default, establishing a baseline like 'General' across the organization.",
        "Option B is INCORRECT: Default labeling is configured directly within the label policy itself, distinct from (and simpler than) condition-based auto-labeling policies.",
        "Option C is INCORRECT: Retention labels and sensitivity labels are separate systems; retention label precedence isn't relevant to sensitivity label defaulting behavior.",
        "Option D is INCORRECT: The default label setting in label policies is a well-documented, standard mechanism specifically for this scenario."
      ],
      "codeSnippet": "// Label policy setting:\n// Default label: \"General\"\n// Applies to: New emails and documents with no label chosen\n// Result: Nothing is left completely unclassified",
      "socTip": "Pair a sensible default label (like 'General') with mandatory labeling for high-risk apps — defaults alone don't stop a user from manually downgrading to Public.",
      "docRef": "Microsoft Learn: Configure a default label for a label policy"
    }
  },
  {
    "id": "purview-053",
    "topic": "DLP policy tips vs blocking",
    "scenario": "Woodgrove Bank's compliance team debates whether a new DLP rule should only warn users with an educational message or fully block the action, for a moderately sensitive data type.",
    "question": "What is the functional difference between a DLP 'policy tip' action and a 'block' action?",
    "options": [
      "A policy tip shows an informational or warning message to the user (optionally allowing override with justification) while still permitting the action, whereas block prevents the action from completing at all",
      "Policy tips and block actions are functionally identical and always occur together",
      "Policy tips can only be seen by admins, never by the end user who triggered them",
      "Block actions only apply to email; policy tips only apply to SharePoint"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Policy Tips vs Block Actions",
      "analysis": [
        "Option A is CORRECT: A policy tip is an in-context notification (in Outlook, Office apps, or Teams) informing the user their content matched a policy, which may allow them to proceed anyway (with or without providing justification) — whereas a block action actually prevents the send/share/save action from completing.",
        "Option B is INCORRECT: They are distinct action types that can be configured independently or together (e.g., show a tip, then block if the user doesn't provide justification).",
        "Option C is INCORRECT: Policy tips are specifically designed to be shown to the end user in real time as they work, not just to admins.",
        "Option D is INCORRECT: Both policy tips and block actions can apply across Exchange, SharePoint, OneDrive, Teams, and endpoint locations — neither is restricted to a single workload."
      ],
      "codeSnippet": "// Graduated DLP response example:\n// Low severity: Policy tip only (educate, allow override)\n// High severity: Policy tip + Block (no override allowed)\n// Rule can combine tip -> justification -> conditional block",
      "socTip": "Start new DLP rules with policy-tip-only actions for a trial period, then graduate to blocking once you've validated low false-positive rates and gathered user feedback.",
      "docRef": "Microsoft Learn: DLP policy tips reference"
    }
  },
  {
    "id": "purview-054",
    "topic": "Data Lifecycle Management vs Records Management licensing",
    "scenario": "Trey Research's procurement team is trying to determine what Microsoft 365 licensing tier is generally required to unlock the full Purview Data Lifecycle Management and Records Management capability set, including disposition review and event-based retention.",
    "question": "What licensing tier is generally required for full Data Lifecycle Management and Records Management capabilities in Microsoft Purview?",
    "options": [
      "Microsoft 365 E5 Compliance (or equivalent add-on SKUs), which unlocks advanced retention, disposition review, and event-based retention features beyond what's in lower base tiers",
      "Microsoft 365 E1 exclusively, with no upgrade needed for advanced records features",
      "Every capability is free and included in Microsoft 365 F1 with no additional licensing required",
      "These features require a completely separate non-Microsoft product regardless of tenant licensing"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Licensing Tiers",
      "analysis": [
        "Option A is CORRECT: While basic retention policies exist in lower/base plans, the advanced Records Management and Data Lifecycle Management capabilities — disposition review, event-based retention, file plan, and regulatory records — typically require Microsoft 365 E5 Compliance or standalone add-on licensing.",
        "Option B is INCORRECT: E1 provides only foundational capabilities; advanced records/retention features require the higher compliance tier.",
        "Option C is INCORRECT: F1 (frontline) licensing does not include the full advanced compliance feature set at no additional cost; premium capabilities require appropriate add-on licensing.",
        "Option D is INCORRECT: These are native Microsoft Purview capabilities licensed within the Microsoft 365 ecosystem, not a separate third-party product."
      ],
      "codeSnippet": "// Simplified licensing tiers (illustrative):\n// E3: Basic retention policies/labels\n// E5 Compliance: + Advanced records mgmt, disposition review,\n//                  event-based retention, file plan, DSPM",
      "socTip": "Before promising a client advanced records features like disposition review, confirm their actual license SKU in the admin center — E3-only tenants will hit feature gates.",
      "docRef": "Microsoft Learn: Microsoft Purview licensing"
    }
  },
  {
    "id": "purview-055",
    "topic": "DLP alert investigation workflow in Purview",
    "scenario": "A Fabrikam SOC analyst opens the DLP alert management dashboard after receiving a high-severity notification and needs to understand the standard triage workflow before deciding on remediation.",
    "question": "What is a standard triage step when investigating a DLP alert in the Purview compliance portal's DLP alerts dashboard?",
    "options": [
      "Review the alert details including matched policy/rule, sensitive info types detected, user and location involved, then assign the alert to an analyst and set its status (e.g., Active, Investigating, Resolved)",
      "Immediately suspend the user's Entra ID account before reviewing any alert details",
      "Close the alert automatically after 24 hours regardless of investigation status",
      "Forward the alert directly to the affected user for self-assessment without SOC review"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Alert Triage Workflow",
      "analysis": [
        "Option A is CORRECT: The DLP alerts dashboard provides matched policy/rule context, detected sensitive info types, involved user/location, and lets analysts assign ownership and update status (New, Active, Investigating, Resolved, Dismissed) as part of a standard structured triage process.",
        "Option B is INCORRECT: Account suspension is a drastic action that should follow, not precede, proper investigation of alert context — jumping straight to it risks unnecessary business disruption on a false positive.",
        "Option C is INCORRECT: Alerts don't auto-close on a fixed timer; they persist until an analyst actively resolves or dismisses them based on investigation findings.",
        "Option D is INCORRECT: DLP alerts are handled by SOC/compliance analysts as part of a controlled investigation process, not delegated to the flagged user for self-assessment."
      ],
      "codeSnippet": "// DLP alert dashboard fields:\n// Policy matched | Rule matched | Severity | Status\n// User | Location | Sensitive info types | Timestamp\n// Actions: Assign to analyst, Add comment, Change status",
      "socTip": "Always check whether an alert is part of a broader pattern (same user, multiple recent alerts) before treating it as an isolated one-off event — this is visible in the user's alert history within the dashboard.",
      "docRef": "Microsoft Learn: Investigate data loss prevention alerts"
    }
  },
  {
    "id": "purview-056",
    "topic": "Sensitivity label priority order",
    "scenario": "Litware has two sensitivity labels — 'Confidential' and 'Highly Confidential' — and a document currently labeled 'Confidential' is later matched by an auto-labeling condition for 'Highly Confidential.' The admin wants to know which label will win.",
    "question": "How does Microsoft Purview determine which sensitivity label applies when multiple labels could match the same content?",
    "options": [
      "Label priority order (position in the label list, with lower position number typically meaning higher sensitivity/priority) determines which label takes precedence when more than one could apply",
      "Purview always applies both labels simultaneously with no single winner",
      "The label applied first chronologically always wins regardless of configured priority",
      "Labels are chosen randomly when more than one condition matches"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Label Priority",
      "analysis": [
        "Option A is CORRECT: Labels have a defined priority order (their position in the label list, admin-configurable) which determines precedence — generally, a label listed lower in the list (higher sensitivity) takes priority over one listed higher up when multiple conditions could apply, such as in auto-labeling or upgrade scenarios.",
        "Option B is INCORRECT: A single document can only carry one sensitivity label at a time; two labels cannot apply simultaneously to the same item.",
        "Option C is INCORRECT: Priority is governed by the configured order in the label list, not simply which condition matched chronologically first.",
        "Option D is INCORRECT: Label selection in conflicts is deterministic based on configured priority, not random."
      ],
      "codeSnippet": "// Label list order (top to bottom = increasing priority):\n// 1. Public\n// 2. General\n// 3. Confidential\n// 4. Highly Confidential (highest priority)\n// -> If both Confidential and Highly Confidential conditions\n//    match, Highly Confidential applies",
      "socTip": "When designing label taxonomies, always order labels from least to most sensitive in the admin console — this list order silently controls conflict resolution behavior.",
      "docRef": "Microsoft Learn: Sensitivity label priority order"
    }
  },
  {
    "id": "purview-057",
    "topic": "Communication Compliance third-party connectors",
    "scenario": "Relecloud uses Bloomberg Message and a third-party trading chat platform in addition to Microsoft 365, and compliance wants those conversations monitored for regulatory violations alongside Teams and Exchange.",
    "question": "Can Communication Compliance monitor communications from certain non-Microsoft platforms in addition to Exchange and Teams?",
    "options": [
      "Yes — through supported third-party connectors, Communication Compliance can ingest and monitor communications from select non-Microsoft platforms alongside native Microsoft 365 channels",
      "No — Communication Compliance is strictly limited to Exchange and Teams with no extensibility whatsoever",
      "Yes, but only for read receipts, never actual message content",
      "No — third-party monitoring requires an entirely separate non-Microsoft compliance suite"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Communication Compliance Third-Party Connectors",
      "analysis": [
        "Option A is CORRECT: Communication Compliance supports connectors for select third-party communication platforms (in addition to native Exchange, Teams, and Viva Engage), letting organizations extend policy-based monitoring for regulatory or conduct violations to those external channels.",
        "Option B is INCORRECT: Third-party connector extensibility is an explicit, documented capability, not a limitation strictly to Microsoft-native channels.",
        "Option C is INCORRECT: Connectors ingest actual message content for classifier/keyword analysis, not merely read receipt metadata.",
        "Option D is INCORRECT: The integration happens within Purview Communication Compliance itself via connectors, not by adopting a wholly separate third-party compliance product."
      ],
      "codeSnippet": "// Communication Compliance connector concept:\n// Third-party platform -> data connector -> ingested into\n// Purview -> scanned by same classifiers/keyword policies\n// used for native Exchange/Teams content",
      "socTip": "Confirm connector data latency (some third-party feeds ingest on a delay, not real time) when setting SLA expectations for how quickly a violation will be flagged.",
      "docRef": "Microsoft Learn: Communication compliance third-party connectors"
    }
  },
  {
    "id": "purview-058",
    "topic": "Exporting and reporting DLP incidents to Sentinel",
    "scenario": "Northwind Traders' SOC wants Purview DLP alerts to appear alongside other security incidents in Microsoft Sentinel for unified correlation and incident response, rather than checking the compliance portal separately.",
    "question": "How can Microsoft Purview DLP alerts be surfaced within Microsoft Sentinel for centralized SOC monitoring?",
    "options": [
      "Through the Microsoft Purview (Information Protection/DLP) data connector in Microsoft Sentinel, which ingests DLP alert data as part of the broader Microsoft 365 security signal correlation",
      "DLP alerts cannot be surfaced in Sentinel under any circumstances",
      "Only by manually re-typing each DLP alert into a Sentinel incident by hand",
      "DLP alerts automatically appear in Sentinel without any connector configuration"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview DLP Integration with Microsoft Sentinel",
      "analysis": [
        "Option A is CORRECT: Microsoft Sentinel offers a Microsoft Purview data connector that ingests DLP (and related information protection) alert data, allowing SOC analysts to correlate DLP signals with other security telemetry (identity, endpoint, network) in unified incidents and analytics rules.",
        "Option B is INCORRECT: Surfacing DLP alerts in Sentinel is a supported, documented integration, not something categorically impossible.",
        "Option C is INCORRECT: The integration is automated via the data connector, not a manual re-entry process.",
        "Option D is INCORRECT: A connector must be explicitly configured/enabled in Sentinel; DLP data does not appear automatically with zero setup."
      ],
      "codeSnippet": "// Sentinel setup steps:\n// 1. Content hub -> install \"Microsoft Purview\" solution\n// 2. Enable Information Protection/DLP data connector\n// 3. DLP alerts flow into Sentinel as log data\n// 4. Build analytics rules/incidents correlating DLP + other signals",
      "socTip": "Once DLP data lands in Sentinel, build a correlation rule joining DLP alerts with IRM or sign-in risk signals for the same user — single-source alerts are often lower-confidence than correlated ones.",
      "docRef": "Microsoft Learn: Microsoft Purview data connector for Microsoft Sentinel"
    }
  },
  {
    "id": "purview-059",
    "topic": "Retention label immutability for records",
    "scenario": "Woodgrove Bank labels a financial document as a 'Record' for regulatory purposes. An employee later tries to edit the document's content directly in SharePoint.",
    "question": "What happens when a user tries to edit the content of a document that has been declared a formal 'Record' via a retention label?",
    "options": [
      "The document becomes read-only for content edits — users can typically still view, copy, or move it, but cannot alter or delete the underlying record content while it's under retention",
      "The document remains fully editable exactly as before, since 'Record' status only affects visual metadata display",
      "The document is automatically converted to a PDF format upon record declaration",
      "The document becomes completely inaccessible and hidden from all users, including admins"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Record Label Content Immutability",
      "analysis": [
        "Option A is CORRECT: Declaring content a 'Record' makes it immutable for content edits and deletion — users generally can't change the document body or delete it while under retention, though viewing, copying to a new file, or renaming may still be allowed depending on configuration.",
        "Option B is INCORRECT: Record status specifically enforces content immutability as a core compliance guarantee, not merely a cosmetic metadata tag.",
        "Option C is INCORRECT: Record declaration does not trigger an automatic file format conversion to PDF.",
        "Option D is INCORRECT: Records remain visible and accessible for viewing/reference by authorized users; they are not hidden entirely — immutability applies to edit/delete actions, not visibility."
      ],
      "codeSnippet": "// Record behavior once declared:\n// - Edit content: Blocked\n// - Delete: Blocked (unless disposition approved)\n// - Rename: May be blocked depending on settings\n// - View/copy: Typically still allowed",
      "socTip": "If a business team complains a 'record' document can't be edited, that's expected behavior by design — the correct fix is creating a new working copy, not removing the record label from the original.",
      "docRef": "Microsoft Learn: Restrict record content edits"
    }
  },
  {
    "id": "purview-060",
    "topic": "Insider Risk analytics (initial assessment)",
    "scenario": "Tailspin Toys wants to gauge potential insider risk exposure across the organization before committing to configuring and turning on full Insider Risk Management policies.",
    "question": "What Purview feature allows an organization to run a lightweight, policy-free assessment of potential insider risk indicators before fully deploying IRM policies?",
    "options": [
      "Insider risk analytics, which runs a one-time, aggregated, privacy-protective scan across the organization to estimate potential risk activity volume without any active policy or individual identification",
      "A live, fully configured IRM policy that must be activated first with no assessment option available",
      "DSPM for AI, which is required before any IRM feature becomes available",
      "Compliance Manager's regulatory assessment templates"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Insider Risk Analytics (Pre-Assessment)",
      "analysis": [
        "Option A is CORRECT: Insider risk analytics runs a preliminary, aggregate-level scan (without individual user identification or active policy enforcement) to help organizations understand potential risk activity volume across categories like data leaks or security violations, informing whether/how to configure full IRM policies.",
        "Option B is INCORRECT: Analytics is specifically designed as a no-policy-required, low-commitment first step, not a requirement to first activate a live policy.",
        "Option C is INCORRECT: DSPM for AI is a separate, unrelated capability focused on generative AI risk, not a prerequisite for IRM analytics.",
        "Option D is INCORRECT: Compliance Manager assessments track regulatory posture scoring, unrelated to the insider risk analytics pre-assessment feature."
      ],
      "codeSnippet": "// Insider risk analytics output (aggregated, anonymized):\n// \"Estimated X% of users had potential data leak indicators\n//  in the last 90 days\"\n// No individual names shown; used to justify policy investment",
      "socTip": "Use insider risk analytics results as supporting evidence when requesting budget/approval to formally deploy IRM policies — it quantifies risk before committing to full monitoring.",
      "docRef": "Microsoft Learn: Enable and configure insider risk analytics"
    }
  },
  {
    "id": "purview-061",
    "topic": "Data Lifecycle Management retention for Teams private channels",
    "scenario": "Adatum's compliance team applies a retention policy to standard Teams channels but later discovers content in a project's private channel does not appear to follow the same retention rule.",
    "question": "Why might content in a Microsoft Teams private channel not be governed by the same retention policy applied to the parent team's standard channels?",
    "options": [
      "Private channels have their own separate underlying SharePoint site and associated storage, so retention policies must explicitly include private channel messages/content as a distinct scope target",
      "Private channels are entirely exempt from all Purview governance by Microsoft design with no possible coverage",
      "Retention policies automatically cascade to private channels with no separate configuration ever needed",
      "Private channels only exist temporarily and are deleted automatically after 30 days, making retention irrelevant"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retention for Teams Private Channels",
      "analysis": [
        "Option A is CORRECT: Teams private channels have distinct underlying storage (their own SharePoint site for files, and messages stored differently than standard channels), so admins typically need to ensure retention policies are scoped to cover private channel messages specifically, rather than assuming standard channel policies automatically extend to them.",
        "Option B is INCORRECT: Private channels can be governed by Purview retention and other compliance tools; they are not categorically exempt, though scoping requires attention.",
        "Option C is INCORRECT: Because of their distinct architecture, automatic cascading isn't guaranteed — explicit scoping consideration is the practical reality that necessitates option A's answer.",
        "Option D is INCORRECT: Private channels are not automatically deleted after a fixed 30-day period; they persist based on normal Teams/SharePoint lifecycle, making retention entirely relevant."
      ],
      "codeSnippet": "// Retention scoping checklist for Teams:\n// [ ] Standard channel messages covered?\n// [ ] Private channel messages covered?\n// [ ] Chat (1:1 and group) covered?\n// [ ] Underlying private channel SharePoint site covered?",
      "socTip": "When a retention gap is reported for Teams content, always check whether private/shared channels were explicitly included in policy scope — this is one of the most common retention coverage gaps.",
      "docRef": "Microsoft Learn: Retention policies for Teams"
    }
  },
  {
    "id": "purview-062",
    "topic": "Purview unified portal navigation",
    "scenario": "A new Litware compliance hire is trying to find where DLP, Insider Risk Management, and eDiscovery are all managed, since they've heard these used to be spread across separate admin centers.",
    "question": "Where are Microsoft Purview's compliance solutions such as DLP, Insider Risk Management, eDiscovery, and Records Management primarily managed today?",
    "options": [
      "The unified Microsoft Purview portal, which consolidates data governance, risk, and compliance solutions into a single administrative experience",
      "Three entirely separate portals with no shared navigation, one for each solution",
      "Only through PowerShell, since no web-based portal exists for these solutions",
      "The Microsoft Defender portal exclusively, with no separate Purview-branded experience"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified Microsoft Purview Portal",
      "analysis": [
        "Option A is CORRECT: Microsoft consolidated compliance solutions (DLP, IRM, Communication Compliance, eDiscovery, Records Management, Audit, Compliance Manager, DSPM, Priva) into the unified Microsoft Purview portal, providing shared navigation and, in many cases, cross-solution data connections like DSPM insights feeding recommended DLP/label policies.",
        "Option B is INCORRECT: The modern experience specifically unifies these solutions rather than keeping them in three separate, disconnected portals.",
        "Option C is INCORRECT: A full web-based portal exists as the primary interface; PowerShell is available for automation/scripting but is not the only management path.",
        "Option D is INCORRECT: While there is cross-linking and some embedded experiences with Defender (like Copilot for Security), Purview retains its own dedicated portal for these compliance solutions rather than being folded entirely into Defender."
      ],
      "codeSnippet": "// Unified Purview portal structure (high level):\n// Home > Solutions:\n//   - Data Loss Prevention\n//   - Insider Risk Management\n//   - Communication Compliance\n//   - eDiscovery\n//   - Records Management / Data Lifecycle Management\n//   - Audit\n//   - Compliance Manager",
      "socTip": "Bookmark the unified Purview portal home page for new hires — it's the fastest way to get oriented across all these solutions instead of hunting for scattered legacy admin center links.",
      "docRef": "Microsoft Learn: Microsoft Purview portal overview"
    }
  },
  {
    "id": "purview-063",
    "topic": "Double Key Encryption",
    "scenario": "A Woodgrove Bank division handling government contracts must ensure that not even Microsoft can decrypt certain top-secret sensitivity-labeled documents under any circumstances, including legal compulsion.",
    "question": "What Purview encryption option requires two separate keys — one from Microsoft and one held entirely by the customer — so that neither party alone can decrypt the content?",
    "options": [
      "Double Key Encryption (DKE), which requires both a Microsoft-held key and a customer-held key (stored on customer infrastructure) to decrypt content, ensuring Microsoft alone can never access it",
      "Bring Your Own Key (BYOK), which stores a single customer key inside Microsoft's Azure Key Vault",
      "Standard AES-256 encryption applied automatically to every label with no key-splitting involved",
      "Hold Your Own Key (HYOK), which uses a single on-premises key with no Microsoft-side component"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Double Key Encryption (DKE)",
      "analysis": [
        "Option A is CORRECT: DKE splits decryption requirements across two keys — one managed by Microsoft in the cloud and one held entirely on the customer's own infrastructure — so content can never be decrypted by Microsoft alone, used for the most extreme confidentiality requirements.",
        "Option B is INCORRECT: BYOK/Customer Key uses a single customer-supplied key stored in Azure Key Vault, which Microsoft can still access operationally, unlike DKE's two-key requirement.",
        "Option C is INCORRECT: Standard encryption without DKE doesn't involve a customer-only key component; Microsoft retains sufficient access to decrypt under normal key management.",
        "Option D is INCORRECT: HYOK uses a single on-premises AD RMS key with no separate Microsoft-side key requirement — it differs structurally from DKE's two-key model."
      ],
      "codeSnippet": "// DKE decryption requirement:\n// Decrypt = Microsoft-held key AND Customer-held key\n// Customer key server hosted entirely on-premises\n// Neither key alone is sufficient to decrypt content",
      "socTip": "DKE trades strong confidentiality for reduced cloud functionality (e.g., no cloud-side content search/indexing) — confirm the business truly needs this before recommending it over standard encryption.",
      "docRef": "Microsoft Learn: Double Key Encryption for Microsoft Purview"
    }
  },
  {
    "id": "purview-064",
    "topic": "Label analytics and usage reporting",
    "scenario": "Fabrikam's compliance manager wants to know which departments are applying sensitivity labels consistently and which are mostly leaving documents unlabeled, to target training efforts.",
    "question": "What Purview reporting capability helps identify labeling adoption trends and gaps across the organization?",
    "options": [
      "Label analytics reports (within Activity Explorer and related usage reports) showing label application trends, most/least used labels, and adoption by location or user group",
      "Compliance Manager improvement action scoring",
      "eDiscovery case export logs",
      "Endpoint DLP device onboarding status"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Label Adoption Reporting",
      "analysis": [
        "Option A is CORRECT: Purview provides label usage and adoption reporting through Activity Explorer and related analytics, showing trends like most-applied labels, label changes, and gaps by location/department, useful for targeting training or policy adjustments.",
        "Option B is INCORRECT: Compliance Manager scoring tracks regulatory control implementation, not sensitivity label adoption specifically.",
        "Option C is INCORRECT: eDiscovery export logs track case export actions for legal purposes, unrelated to organization-wide labeling adoption trends.",
        "Option D is INCORRECT: Device onboarding status shows which endpoints have Endpoint DLP enabled, not label usage patterns."
      ],
      "codeSnippet": "// Label adoption report example:\n// \"Finance\": 92% of new documents labeled\n// \"Sales\": 34% of new documents labeled -> training gap flagged",
      "socTip": "Use low-adoption department data to prioritize targeted label training sessions rather than a blanket organization-wide campaign — it's a more efficient use of compliance team time.",
      "docRef": "Microsoft Learn: Get started with activity explorer"
    }
  },
  {
    "id": "purview-065",
    "topic": "IRM cumulative exfiltration detection",
    "scenario": "A Litware analyst notices no single file download from a user was large enough to trigger an alert, but the user downloaded small batches of sensitive files every day for three weeks, adding up to a significant volume.",
    "question": "What Insider Risk Management capability is designed to detect this kind of slow, incremental exfiltration pattern that would evade single-event thresholds?",
    "options": [
      "Cumulative exfiltration detection, which aggregates smaller activities over a rolling time window to identify a pattern that individually would stay under alerting thresholds",
      "Sensitivity label default settings",
      "DLP policy tips shown only once per user",
      "Compliance Manager scoring trend analysis"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cumulative Exfiltration Detection in IRM",
      "analysis": [
        "Option A is CORRECT: IRM can aggregate activity volume over a rolling window (days to weeks) so that many small, individually low-risk actions are correlated into a cumulative risk indicator, catching slow-drip exfiltration that a single-event threshold would miss.",
        "Option B is INCORRECT: Default label settings control baseline sensitivity classification, unrelated to behavioral volume aggregation over time.",
        "Option C is INCORRECT: DLP policy tips are user-facing educational notifications, not a mechanism for detecting cumulative behavioral patterns.",
        "Option D is INCORRECT: Compliance Manager scoring trends track regulatory posture over time, unrelated to individual user exfiltration behavior."
      ],
      "codeSnippet": "// Cumulative detection example:\n// Day 1-21: ~15 files/day downloaded (under daily threshold)\n// Rolling 21-day total: 315 files -> cumulative threshold breached\n// -> Alert generated despite no single-day trigger",
      "socTip": "When tuning IRM thresholds, review both daily and rolling cumulative thresholds together — relying on daily limits alone leaves a detectable gap for patient insider threats.",
      "docRef": "Microsoft Learn: Insider risk management settings - policy indicators"
    }
  },
  {
    "id": "purview-066",
    "topic": "eDiscovery review sets and tagging",
    "scenario": "Trey Research's legal reviewers need to mark thousands of documents in an eDiscovery Premium case as Responsive, Privileged, or Not Relevant, and apply redactions before producing them to opposing counsel.",
    "question": "What eDiscovery Premium feature lets reviewers apply consistent tags (Responsive, Privileged, etc.) and redactions to documents within a defined working collection pulled from search results?",
    "options": [
      "Review sets, which create a static, tagged working copy of search results where reviewers apply tags, redactions, and annotations without altering the underlying source data",
      "Content search exports, which cannot be tagged or annotated in any way",
      "Communication Compliance review queues, repurposed for legal tagging",
      "Records Management disposition stages"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "eDiscovery Review Sets",
      "analysis": [
        "Option A is CORRECT: A review set is a static copy of search results loaded into eDiscovery Premium's review interface, where legal reviewers can tag documents (Responsive, Privileged, Not Relevant), apply redactions, add notes, and organize by review batches — all without modifying the original source content.",
        "Option B is INCORRECT: Basic content search exports are for search/export, not an interactive tagging and redaction workspace; review sets specifically add that layer.",
        "Option C is INCORRECT: Communication Compliance review queues are built for policy violation triage by HR/compliance, a different workflow from formal legal document review and production.",
        "Option D is INCORRECT: Disposition stages govern records retention/deletion approval, unrelated to legal document tagging for litigation review."
      ],
      "codeSnippet": "// Review set workflow:\n// 1. Search -> add results to Review set\n// 2. Reviewers tag: Responsive / Privileged / Not Relevant\n// 3. Apply redactions to privileged content\n// 4. Export tagged, redacted set for production",
      "socTip": "Always work from a review set rather than re-running raw searches repeatedly — it gives reviewers a stable, taggable snapshot and preserves an audit trail of review decisions.",
      "docRef": "Microsoft Learn: Work with review sets in eDiscovery (Premium)"
    }
  },
  {
    "id": "purview-067",
    "topic": "Audit alert policies",
    "scenario": "Northwind Traders' SOC wants to be proactively notified the moment a specific high-risk activity — like a mass file download or an eDiscovery search performed by a non-authorized admin — occurs, rather than discovering it during a periodic audit log review.",
    "question": "What Purview capability generates near-real-time notifications when specific activities occur in the Unified Audit Log, rather than requiring manual log review?",
    "options": [
      "Audit alert policies, which monitor for specific activities (mass downloads, unusual eDiscovery searches, elevated permission changes) and trigger email notifications when matched",
      "Records Management disposition reviewer emails",
      "Sensitivity label default policy notifications",
      "Compliance Manager weekly digest emails"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Alert Policies",
      "analysis": [
        "Option A is CORRECT: Audit alert policies let admins define specific activities of interest (e.g., mass file downloads, malware campaigns, unusual eDiscovery search activity, permission elevation) and receive near-real-time email alerts when those activities are logged, avoiding reliance on manual periodic log review.",
        "Option B is INCORRECT: Disposition reviewer emails notify records reviewers about pending deletion decisions, unrelated to general audit activity alerting.",
        "Option C is INCORRECT: Sensitivity label policies don't generate proactive activity alerts about audit log events.",
        "Option D is INCORRECT: Compliance Manager digests summarize regulatory score changes, not specific real-time audit activity triggers."
      ],
      "codeSnippet": "// Audit alert policy example:\n// Activity: \"eDiscovery search performed\"\n// Condition: Performed by user NOT in \"Legal-Approved\" group\n// Action: Email alert to soc-alerts@northwindtraders.com",
      "socTip": "Prioritize alert policies for high-impact, low-frequency events (like permission escalation or unusual eDiscovery activity) — high-frequency events will generate alert fatigue if not carefully scoped.",
      "docRef": "Microsoft Learn: Create an audit log alert policy"
    }
  },
  {
    "id": "purview-068",
    "topic": "Regulatory records",
    "scenario": "Woodgrove Bank must comply with a regulation (like SEC 17a-4) requiring certain financial records to be stored in a non-erasable, non-rewritable format that cannot be altered even by administrators, for the full retention period.",
    "question": "What Purview record type provides the strictest level of immutability, preventing even administrators from shortening retention or deleting content before the period expires?",
    "options": [
      "Regulatory records, which apply the strictest lock-down — retention periods cannot be shortened, labels cannot be removed, and content cannot be deleted even by administrators until the period expires",
      "Standard records, which behave identically to regulatory records in every respect",
      "Draft labels, which have no retention enforcement at all",
      "Sensitivity labels configured with 'Highly Confidential' priority"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Regulatory Records",
      "analysis": [
        "Option A is CORRECT: Regulatory records are the strictest record type in Purview, designed for regulations requiring immutable, non-erasable storage (like SEC 17a-4) — once declared, even administrators cannot shorten the retention period, remove the label, or delete the content before expiration.",
        "Option B is INCORRECT: Standard 'Record' labels can, with appropriate permissions, have their retention period extended/shortened or be relabeled by an admin in some cases; regulatory records remove even that administrative flexibility.",
        "Option C is INCORRECT: Draft/non-record labels don't provide the strict immutability regulatory compliance frameworks like SEC 17a-4 require.",
        "Option D is INCORRECT: Sensitivity labels govern access/encryption, not retention immutability — they are a separate mechanism from record types entirely."
      ],
      "codeSnippet": "// Record type strictness (least to most restrictive):\n// Non-record retention label < Record < Regulatory Record\n// Regulatory Record: retention period is immutable,\n//   even Global Admins cannot delete before expiration",
      "socTip": "Regulatory records are effectively irreversible commitments — pilot the configuration carefully in a test label before applying it to production content, since mistakes cannot be undone via admin override.",
      "docRef": "Microsoft Learn: Declare records by using retention labels"
    }
  },
  {
    "id": "purview-069",
    "topic": "Compliance Manager improvement action ownership",
    "scenario": "Litware's Compliance Manager assessment shows 40 outstanding improvement actions, but nobody on the compliance team knows who is responsible for implementing each one across IT, HR, and Legal.",
    "question": "What Compliance Manager feature allows admins to assign specific improvement actions to individual owners and track implementation status?",
    "options": [
      "Action assignment and status tracking, which lets admins assign an improvement action to a specific user, set implementation status (Not started, In progress, Implemented, Tested), and add supporting evidence documentation",
      "Compliance Manager has no assignment capability; all actions must be tracked in an external spreadsheet",
      "Only Global Administrators can view improvement actions; no assignment to other roles is possible",
      "Improvement actions are automatically completed by Microsoft with no customer action required"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Compliance Manager Action Assignment",
      "analysis": [
        "Option A is CORRECT: Each improvement action in Compliance Manager can be assigned to a specific user/owner, tracked through implementation status stages, and supported with uploaded evidence documentation, enabling accountability across teams like IT, HR, and Legal.",
        "Option B is INCORRECT: Native assignment and tracking exists within the tool itself; an external spreadsheet is not required for basic ownership tracking.",
        "Option C is INCORRECT: Compliance Manager supports role-based access allowing various compliance team members (not just Global Admins) to view and manage relevant improvement actions.",
        "Option D is INCORRECT: The vast majority of improvement actions require actual customer-side configuration or documentation work; Microsoft does not auto-complete them."
      ],
      "codeSnippet": "// Improvement action fields:\n// Action: \"Enable MFA for all users\"\n// Assigned to: jsmith@litware.com\n// Status: In progress\n// Evidence: MFA_rollout_policy.pdf (attached)",
      "socTip": "Assign a due date convention (even though not native to every action type) in the action notes field — unassigned deadlines are the most common reason improvement actions stall indefinitely.",
      "docRef": "Microsoft Learn: Assign and manage improvement actions in Compliance Manager"
    }
  },
  {
    "id": "purview-070",
    "topic": "Priva data transfer policies",
    "scenario": "Adatum operates in the EU and US and must monitor when personal data belonging to EU residents is transferred to non-adequate countries, since this could violate GDPR cross-border transfer restrictions.",
    "question": "What Priva capability specifically monitors and flags personal data transfers across defined geographic or organizational boundaries?",
    "options": [
      "Data transfer policies in Priva Privacy Risk Management, which detect and alert on personal data moving across configured boundaries such as regions or departments",
      "DLP endpoint policies, which are the only tool capable of geographic data transfer monitoring",
      "eDiscovery Premium custodian communications tracking",
      "Records Management file plan citation fields"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Priva Data Transfer Policies",
      "analysis": [
        "Option A is CORRECT: Priva's Privacy Risk Management includes data transfer policies that detect when personal data is shared or moved across defined boundaries (e.g., between geographic regions or organizational units), alerting privacy teams to potential cross-border compliance risks like GDPR transfer restrictions.",
        "Option B is INCORRECT: While DLP can be configured for some geographic conditions, Priva's data transfer policies are the purpose-built privacy-specific tool for this scenario, distinct from general endpoint DLP.",
        "Option C is INCORRECT: eDiscovery custodian tracking concerns legal hold/case management, not ongoing privacy-focused cross-border transfer monitoring.",
        "Option D is INCORRECT: File plan citation fields are records metadata for retention labels, unrelated to personal data transfer detection."
      ],
      "codeSnippet": "// Priva data transfer policy example:\n// Boundary: EU region -> Non-EU region\n// Data type: Personal data (detected via SITs)\n// Alert: Notify privacy team of cross-border transfer event",
      "socTip": "Coordinate Priva data transfer alert configuration with Legal's list of 'adequate' countries under current GDPR guidance — the boundary definitions should reflect actual regulatory requirements, not just company org structure.",
      "docRef": "Microsoft Learn: Data transfer policies in Priva"
    }
  },
  {
    "id": "purview-071",
    "topic": "Priva subject rights request automation",
    "scenario": "Relecloud receives a GDPR data subject access request from a former customer asking what personal data the company holds about them across Exchange, SharePoint, and Teams.",
    "question": "How does Priva Subject Rights Requests help fulfill a data subject access request like this?",
    "options": [
      "It automates discovery of a named individual's personal data across supported Microsoft 365 locations, then provides a workflow to review, redact, and export the findings for the response",
      "It automatically emails the requester their data with zero admin review or redaction step",
      "It only works for financial data, not general personal data categories like names or addresses",
      "It requires manually searching each service one at a time with no automation support"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Priva Subject Rights Requests Automation",
      "analysis": [
        "Option A is CORRECT: Subject Rights Requests automates the discovery phase (searching for data associated with a named individual across Exchange, SharePoint, OneDrive, Teams) and provides a structured workflow for admins to review, redact sensitive/third-party content, and generate a report/export to fulfill the request.",
        "Option B is INCORRECT: The tool includes a mandatory review step before any data is released; it does not auto-send unreviewed personal data directly to the requester.",
        "Option C is INCORRECT: Subject Rights Requests searches broadly for personal data (names, contact info, and other personal identifiers), not solely financial data categories.",
        "Option D is INCORRECT: The core value of the tool is automating what would otherwise be a fully manual multi-service search, not requiring one-by-one manual searching."
      ],
      "codeSnippet": "// Subject Rights Request workflow:\n// 1. Create request for \"Jane Doe\"\n// 2. Automated search across M365 locations\n// 3. Reviewer redacts third-party/irrelevant content\n// 4. Generate report/export for formal response",
      "socTip": "Always route Subject Rights Request exports through the built-in review stage before sending to the requester — un-reviewed exports risk including other individuals' personal data mixed into shared documents.",
      "docRef": "Microsoft Learn: Subject rights requests in Priva"
    }
  },
  {
    "id": "purview-072",
    "topic": "Retention label version history behavior",
    "scenario": "Litware's records team wants to know what happens to a document's retention obligations when a user edits and saves a new version of a file that already has a retention label applied.",
    "question": "How does a retention label typically behave when a new version of a labeled document is saved?",
    "options": [
      "The retention label and its settings generally persist across versions, continuing to govern the document based on the original applicable retention configuration (e.g., from creation or label date), depending on policy settings",
      "The retention label is automatically removed every time a new version is saved, requiring manual relabeling",
      "A brand-new, separate retention clock starts from zero for every single version, unrelated to the original",
      "Only the very first version of a document is ever subject to retention; later versions are permanently exempt"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retention Labels Across Document Versions",
      "analysis": [
        "Option A is CORRECT: A retention label generally stays applied to a document across versions, continuing to enforce the configured retention behavior (such as retention counted from creation/label date), so simple editing and saving doesn't remove governance — though the exact retention start-date behavior depends on the label's specific configuration.",
        "Option B is INCORRECT: Retention labels are designed to persist through normal editing and version updates, not automatically strip off on every save.",
        "Option C is INCORRECT: Versioning does not reset the retention clock to zero for each version by default; that would undermine the label's compliance purpose.",
        "Option D is INCORRECT: All versions of a labeled document remain subject to the label's governance, not just the initial version."
      ],
      "codeSnippet": "// Retention label persistence example:\n// v1 labeled \"Contract-7yr\" on 2024-01-01\n// v2, v3 edited/saved later in 2026\n// -> Label remains applied; retention still tracks from\n//    the label's configured start point (e.g., 2024-01-01)",
      "socTip": "If a user asks whether editing a labeled document 'resets the clock,' the safe default answer is no — but always verify against the specific label's retention trigger configuration (creation date vs. labeled date vs. event-based) before confirming.",
      "docRef": "Microsoft Learn: Learn about retention for SharePoint and OneDrive"
    }
  },
  {
    "id": "purview-073",
    "topic": "Communication Compliance policy templates by scenario",
    "scenario": "Trey Research's compliance officer wants to deploy a policy specifically aimed at detecting potential conflicts of interest and insider trading language among finance staff, rather than building conditions from scratch.",
    "question": "What does Communication Compliance provide to accelerate deployment of scenario-specific monitoring like conflict of interest or regulatory compliance detection?",
    "options": [
      "Built-in policy templates (such as Conflict of interest, Regulatory compliance, Sensitive information type-based, and custom keyword policies) pre-configured with relevant classifiers and conditions for common scenarios",
      "A single generic policy template with no scenario-specific options at all",
      "Only fully manual policy creation, since no templates of any kind exist",
      "Templates that only monitor phone calls, not text-based chat or email"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Communication Compliance Policy Templates",
      "analysis": [
        "Option A is CORRECT: Communication Compliance offers pre-built policy templates for common scenarios — conflict of interest, regulatory compliance (like offensive language or financial regulations), sensitive info type sharing, and custom keyword-based policies — each pre-loaded with relevant classifiers/conditions to speed deployment.",
        "Option B is INCORRECT: Multiple distinct scenario-specific templates exist, not a single generic one-size-fits-all option.",
        "Option C is INCORRECT: Templates explicitly exist to reduce the need for fully manual policy construction from scratch.",
        "Option D is INCORRECT: Communication Compliance monitors text-based channels like email, Teams chat, and Viva Engage; it does not monitor voice phone calls."
      ],
      "codeSnippet": "// Communication Compliance template examples:\n// - Detect conflicts of interest\n// - Detect regulatory collusion / insider trading language\n// - Detect offensive language\n// - Detect sensitive info sharing (custom SIT-based)",
      "socTip": "Start with the 'Conflict of interest' template for finance-sector deployments — it typically includes relevant classifier language tuned for that exact scenario out of the box.",
      "docRef": "Microsoft Learn: Communication compliance policy templates"
    }
  },
  {
    "id": "purview-074",
    "topic": "DLP for third-party cloud apps via Defender for Cloud Apps",
    "scenario": "Northwind Traders' employees use a sanctioned but non-Microsoft SaaS app (like Box) to store files, and compliance wants Purview DLP-style detection to extend to that app as well.",
    "question": "How does Microsoft Purview extend DLP-style sensitive data detection to sanctioned third-party SaaS applications like Box or Google Workspace?",
    "options": [
      "Through integration with Microsoft Defender for Cloud Apps, which applies file policies leveraging Purview sensitive information types and DLP-like conditions to third-party cloud app data",
      "Purview DLP directly manages third-party SaaS apps with no other product involved at all",
      "Third-party SaaS DLP is entirely unsupported by any Microsoft product",
      "Only by exporting all Box data manually into SharePoint first"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Extension to Third-Party Apps via Defender for Cloud Apps",
      "analysis": [
        "Option A is CORRECT: Defender for Cloud Apps (a CASB) integrates with Purview to apply file policies referencing the same sensitive information types/classifiers used in native DLP, extending detection and control (like quarantine or access restriction) to sanctioned third-party SaaS apps such as Box or Google Workspace.",
        "Option B is INCORRECT: Native Purview DLP alone doesn't directly manage third-party SaaS apps; Defender for Cloud Apps is the integration layer that extends that coverage.",
        "Option C is INCORRECT: Third-party SaaS DLP-style coverage is explicitly supported through the Defender for Cloud Apps integration, not unsupported.",
        "Option D is INCORRECT: Manually migrating all third-party data into SharePoint is not a real or necessary requirement; the CASB integration works with data in place in the third-party app."
      ],
      "codeSnippet": "// Defender for Cloud Apps file policy example:\n// App: Box (sanctioned)\n// Condition: File contains SIT \"Credit Card Number\"\n// Action: Restrict access / quarantine file in Box",
      "socTip": "When a customer asks about DLP for non-Microsoft SaaS apps, clarify that Defender for Cloud Apps (not core Purview DLP alone) is the product doing the enforcement — this affects licensing conversations.",
      "docRef": "Microsoft Learn: Information protection in Microsoft Defender for Cloud Apps"
    }
  },
  {
    "id": "purview-075",
    "topic": "Insider risk investigation and case management",
    "scenario": "An IRM alert for a Fabrikam employee has been triaged and confirmed as a genuine concern. The analyst now needs to formally investigate, gather evidence, and potentially involve HR and Legal in a structured way.",
    "question": "What does Insider Risk Management provide once an alert is confirmed and needs formal, structured investigation?",
    "options": [
      "The ability to convert a confirmed alert into a case, which aggregates related activity, evidence, and allows collaboration with HR/Legal stakeholders through defined case management workflows",
      "Automatic termination of the employee's access with no further investigation options",
      "A public case summary automatically posted to the entire organization's intranet",
      "Immediate transfer of the investigation to an external law firm with no internal workflow"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Case Management",
      "analysis": [
        "Option A is CORRECT: A confirmed IRM alert can be escalated into a case, which consolidates related user activity and evidence into a structured investigation record, supports adding content (like eDiscovery-sourced evidence), and enables coordinated collaboration with stakeholders such as HR and Legal.",
        "Option B is INCORRECT: IRM surfaces evidence for human decision-makers; it doesn't automatically terminate access as part of case escalation.",
        "Option C is INCORRECT: IRM cases are strictly access-controlled and confidential, never automatically published organization-wide.",
        "Option D is INCORRECT: Cases stay within the organization's internal IRM/case management workflow; there's no automatic handoff to an external law firm."
      ],
      "codeSnippet": "// Alert-to-case workflow:\n// Alert confirmed by analyst -> \"Create case\"\n// Case aggregates: user activity timeline, related alerts,\n//   analyst notes, and optional linked eDiscovery evidence\n// Case team: Analyst + HR reviewer + Legal reviewer (scoped access)",
      "socTip": "When escalating to a case, immediately scope case team membership tightly (analyst, HR, Legal only) — case content is highly sensitive and over-broad access is a common audit finding.",
      "docRef": "Microsoft Learn: Insider risk management cases"
    }
  },
  {
    "id": "purview-076",
    "topic": "Compliance Manager control mapping across regulations",
    "scenario": "Litware implements a single technical control — enabling Conditional Access MFA — and wants to understand why their overall Compliance Manager score increased across three different regulatory assessments at once.",
    "question": "Why can a single implemented control affect an organization's compliance score across multiple different regulatory assessments simultaneously?",
    "options": [
      "Compliance Manager maps individual controls to multiple overlapping regulatory requirements, so one completed action can satisfy corresponding requirements in several assessments that share that control",
      "Compliance Manager only supports one assessment at a time, so this scenario is not actually possible",
      "Each assessment requires entirely separate, non-overlapping implementation work with no possible overlap",
      "The score increase is a display bug and does not reflect actual overlapping compliance credit"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Assessment Control Mapping",
      "analysis": [
        "Option A is CORRECT: Compliance Manager's control library maps individual improvement actions to the specific requirements of multiple regulations/standards they satisfy, so completing one action (like enabling MFA) can simultaneously credit progress across every assessment in the tenant that includes an equivalent requirement.",
        "Option B is INCORRECT: Multiple simultaneous assessments are explicitly supported, and this mapped-credit behavior is a real, intended feature across them.",
        "Option C is INCORRECT: While some requirements are unique per regulation, many core security controls do genuinely overlap across common frameworks like GDPR, ISO 27001, and NIST.",
        "Option D is INCORRECT: This is documented, intended cross-assessment credit behavior, not a display bug."
      ],
      "codeSnippet": "// Control mapping example:\n// Action: \"Enable Conditional Access MFA\"\n// Maps to: GDPR Art. 32, ISO 27001 A.9.4.2, NIST 800-53 IA-2\n// -> Completing once credits all three assessments' scores",
      "socTip": "When prioritizing improvement actions across multiple assessments, sort by the number of regulations/standards a single action maps to for the most efficient score improvement per unit of effort.",
      "docRef": "Microsoft Learn: Compliance Manager templates list"
    }
  },
  {
    "id": "purview-077",
    "topic": "Sensitivity labels for schematized data assets",
    "scenario": "Adatum's data governance team wants sensitivity labels to apply not just to files and emails but to structured database columns and tables registered in Microsoft Purview's data catalog.",
    "question": "Can Microsoft Purview sensitivity labels be applied to structured, schematized data assets like database columns, not just documents and emails?",
    "options": [
      "Yes — sensitivity labels can be scoped to and applied on schematized data assets (like SQL columns) registered in the Microsoft Purview unified catalog, in addition to files and emails",
      "No — sensitivity labels only ever apply to unstructured content like Word documents and email messages",
      "Yes, but only for Azure Synapse specifically, and no other structured data sources",
      "No — structured data governance uses a completely separate, unrelated product outside Purview entirely"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Labels for Schematized Data Assets",
      "analysis": [
        "Option A is CORRECT: The Purview label scope options include 'Schematized data assets,' allowing labels to be applied to structured data (like database columns/tables) registered in the Purview Data Map/unified catalog, extending classification beyond unstructured files and emails.",
        "Option B is INCORRECT: Label scoping explicitly supports structured/schematized data assets as a distinct scope category, not just unstructured content.",
        "Option C is INCORRECT: Schematized asset labeling isn't limited to Azure Synapse alone; it applies broadly to data sources registered in the Purview catalog.",
        "Option D is INCORRECT: Structured data governance and labeling are part of the same Microsoft Purview product family (Purview Data Map/unified catalog), not an unrelated separate product."
      ],
      "codeSnippet": "// Label scope for schematized assets:\n// [x] Schematized data assets\n// Applied to: SQL DB column \"CustomerSSN\"\n// -> Label \"Highly Confidential\" flows to catalog metadata",
      "socTip": "When a data governance team asks about labeling database columns, point them to the Purview unified catalog integration rather than assuming file/email labeling is the only option.",
      "docRef": "Microsoft Learn: Apply sensitivity labels to schematized data assets"
    }
  },
  {
    "id": "purview-078",
    "topic": "Audit search result limits and PowerShell pagination",
    "scenario": "Tailspin Toys' analyst runs an audit search through the Purview portal UI for a broad date range and notices results appear to be capped, missing potentially relevant later events.",
    "question": "Why might an analyst need to use PowerShell rather than the Purview portal UI when searching very large volumes of audit log data?",
    "options": [
      "The portal UI search returns a maximum of 5,000 results per search, while Search-UnifiedAuditLog with pagination parameters can retrieve significantly larger result sets",
      "The PowerShell cmdlet and the portal UI have an identical, unlimited results cap, so there is no practical difference",
      "Portal UI searches are limited to a maximum 24-hour date range, while PowerShell has no date range limitation at all",
      "PowerShell cannot search audit logs at all; only the UI can execute audit searches"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Search Result Limits",
      "analysis": [
        "Option A is CORRECT: The Purview portal's audit search UI caps results at 5,000 records per search, which can silently truncate results for high-volume queries; using Search-UnifiedAuditLog with -SessionCommand ReturnLargeSet and pagination allows retrieval of much larger result sets.",
        "Option B is INCORRECT: The two interfaces have materially different practical limits — the UI's cap is a real constraint that PowerShell's pagination approach overcomes.",
        "Option C is INCORRECT: The portal UI's limitation is on result count, not restricted to a 24-hour date range; wide date ranges are allowed but can hit the result cap.",
        "Option D is INCORRECT: PowerShell (Search-UnifiedAuditLog) is a fully supported and often preferred method for audit log searching, especially at scale."
      ],
      "codeSnippet": "// PowerShell pagination example:\n// Search-UnifiedAuditLog -StartDate ... -EndDate ... `\n//   -SessionId \"invA\" -SessionCommand ReturnLargeSet `\n//   -ResultSize 5000\n// Repeat call with same SessionId to get next page",
      "socTip": "For any investigation spanning more than a few days of high-activity logs, default to PowerShell with pagination from the start — discovering the 5,000-result cap mid-investigation wastes valuable time.",
      "docRef": "Microsoft Learn: Search-UnifiedAuditLog"
    }
  },
  {
    "id": "purview-079",
    "topic": "DLP policy scoping with adaptive scopes",
    "scenario": "Woodgrove Bank wants a DLP policy to automatically apply to any new SharePoint site created by the Finance department going forward, without an admin manually adding each new site to the policy.",
    "question": "What Purview feature allows a DLP or retention policy's scope to automatically update based on dynamic attributes like department, rather than a static, manually maintained list?",
    "options": [
      "Adaptive scopes, which use attribute-based queries (such as department = Finance) to dynamically include matching users, sites, or mailboxes as they are created or updated",
      "Static scopes, which are the only scoping method available and must be manually updated",
      "Sensitivity label default policy assignment",
      "Compliance Manager assessment scope filters"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Adaptive Scopes",
      "analysis": [
        "Option A is CORRECT: Adaptive scopes define policy targeting using dynamic attribute-based queries (e.g., department, location) so that as new sites, users, or mailboxes match the criteria, they are automatically included in the policy's scope without manual list maintenance.",
        "Option B is INCORRECT: Static scopes exist but require manual updates as the environment changes; adaptive scopes were specifically introduced to solve that maintenance burden.",
        "Option C is INCORRECT: Default label policy assignment relates to sensitivity labeling defaults, not dynamic DLP/retention scope targeting based on attributes.",
        "Option D is INCORRECT: Compliance Manager assessment scope filters relate to regulatory assessment configuration, unrelated to DLP/retention policy location targeting."
      ],
      "codeSnippet": "// Adaptive scope example:\n// Scope type: Sites\n// Query: Department equals \"Finance\"\n// -> New SharePoint sites tagged Department=Finance\n//    automatically join this DLP policy's scope",
      "socTip": "Adaptive scopes rely on accurate site/user attribute metadata — verify that attribute (like Department) is being reliably populated at site creation before depending on adaptive scopes for compliance coverage.",
      "docRef": "Microsoft Learn: Learn about adaptive scopes"
    }
  },
  {
    "id": "purview-080",
    "topic": "Purview data map and unified catalog",
    "scenario": "Trey Research's data governance team wants a centralized inventory of all their structured data sources — SQL databases, Azure Data Lake, Power BI datasets — with lineage tracking showing how data flows between systems.",
    "question": "What Purview capability provides an automated inventory, classification, and lineage map of an organization's structured and unstructured data estate across multiple sources?",
    "options": [
      "The Microsoft Purview Data Map (unified catalog), which scans, classifies, and catalogs data sources while tracking lineage showing how data moves and transforms across systems",
      "Communication Compliance connectors",
      "Endpoint DLP device inventory",
      "Compliance Manager control library"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Data Map / Unified Catalog",
      "analysis": [
        "Option A is CORRECT: The Purview Data Map (part of the unified data governance capabilities) scans registered data sources (SQL, Azure Data Lake, Power BI, and more), automatically classifies data, and builds a lineage map showing how data flows and transforms across systems for governance and discovery purposes.",
        "Option B is INCORRECT: Communication Compliance connectors ingest message content for policy monitoring, unrelated to structured data cataloging and lineage.",
        "Option C is INCORRECT: Endpoint DLP device inventory tracks onboarded devices for data loss prevention, not a data source catalog with lineage tracking.",
        "Option D is INCORRECT: The Compliance Manager control library maps regulatory controls to improvement actions, unrelated to data source cataloging."
      ],
      "codeSnippet": "// Data Map capabilities:\n// - Scan and register data sources (SQL, ADLS, Power BI, etc.)\n// - Auto-classify columns/tables using sensitive info types\n// - Lineage: Source DB -> ETL pipeline -> Data warehouse -> BI report",
      "socTip": "Recommend registering high-value data sources in the Data Map early in a governance program — lineage visibility becomes exponentially harder to reconstruct retroactively once pipelines multiply.",
      "docRef": "Microsoft Learn: What is Microsoft Purview Data Map?"
    }
  },
  {
    "id": "purview-081",
    "topic": "Communication Compliance and free/paid tier scope",
    "scenario": "Relecloud's admin sets up a Communication Compliance policy but wants to understand how broadly it can scan communications without triggering unexpected licensing shortfalls for the whole organization.",
    "question": "How does Communication Compliance licensing typically scope coverage across an organization's users?",
    "options": [
      "Licensing is generally required per user included in the scope of a Communication Compliance policy, so only properly licensed users' communications are monitored under that policy",
      "Communication Compliance is entirely free and requires no per-user licensing under any circumstance",
      "A single license covers the entire tenant with no per-user consideration whatsoever",
      "Licensing is based on the number of policies created, not the number of users covered"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Communication Compliance Licensing Scope",
      "analysis": [
        "Option A is CORRECT: Communication Compliance generally requires appropriate per-user licensing (such as E5 Compliance or standalone add-ons) for users whose communications are included in a policy's scope, so admins must ensure covered users are properly licensed.",
        "Option B is INCORRECT: Communication Compliance is a licensed premium compliance capability, not a free feature with no licensing requirement.",
        "Option C is INCORRECT: Coverage is tied to per-user licensing status of users in scope, not a single blanket tenant-wide license with no per-user dimension.",
        "Option D is INCORRECT: Licensing is centered on the users covered by policies, not simply the count of policies an admin creates."
      ],
      "codeSnippet": "// Licensing consideration checklist:\n// [ ] Are all users in policy scope licensed for\n//     Communication Compliance (e.g., E5 Compliance)?\n// [ ] Does policy scope exceed licensed user count?",
      "socTip": "Before broadly scoping a new Communication Compliance policy to 'All users,' verify licensing coverage first — under-licensed scope is a common compliance and cost-control gap.",
      "docRef": "Microsoft Learn: Microsoft Purview Communication Compliance licensing"
    }
  },
  {
    "id": "purview-082",
    "topic": "Insider risk indicators for physical security",
    "scenario": "Northwind Traders integrates its physical badge access system data into Insider Risk Management to detect situations where an employee badges into a secure facility at unusual hours shortly before a large data download occurs.",
    "question": "Does Insider Risk Management support incorporating non-Microsoft signals, such as physical badge access data, into its risk indicators?",
    "options": [
      "Yes — IRM supports importing certain third-party/physical security signals (like badge access data) via connectors to correlate with digital activity for richer risk indicators",
      "No — IRM can only ever use signals natively generated within Microsoft 365 services",
      "Yes, but only video surveillance footage is supported, not badge access logs",
      "No — physical security data integration requires an entirely separate, unrelated Microsoft product with no IRM connection"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Physical/Third-Party Signal Integration",
      "analysis": [
        "Option A is CORRECT: IRM supports importing certain third-party data, including physical access/badge system signals via supported connectors, allowing correlation between physical presence anomalies and digital activity for more comprehensive risk indicators.",
        "Option B is INCORRECT: While many indicators are native to Microsoft 365, IRM explicitly extends to support imported third-party signals like physical security data.",
        "Option C is INCORRECT: Badge access log data specifically is a supported signal type; the capability isn't limited to video surveillance alone (which generally isn't a natively supported IRM signal type).",
        "Option D is INCORRECT: This integration happens within IRM itself via data import/connectors, not through a completely separate, unconnected product."
      ],
      "codeSnippet": "// Physical signal correlation example:\n// Badge access: after-hours entry to R&D secure lab\n// + Digital: large file download 20 minutes later\n// -> Combined indicator raises risk score for that user",
      "socTip": "When proposing physical badge data integration, involve Facilities/Physical Security early — data format and refresh frequency from badge systems vary widely and need validation before IRM can use them reliably.",
      "docRef": "Microsoft Learn: Insider risk management browser signal detection and other indicators"
    }
  },
  {
    "id": "purview-083",
    "topic": "DLP false positive tuning with exceptions",
    "scenario": "A Fabrikam DLP policy correctly blocks credit card numbers in outgoing email, but it is now blocking the Finance team's routine, approved reconciliation reports sent to an external, sanctioned payment processor.",
    "question": "What DLP policy mechanism allows admins to exclude specific legitimate business scenarios from an otherwise broad rule, without disabling the rule entirely?",
    "options": [
      "Rule exceptions (such as excluding a specific sender group or a specific approved external domain) that carve out defined legitimate scenarios from an otherwise applicable DLP rule",
      "Deleting and recreating the entire DLP policy from scratch every time an exception is needed",
      "Disabling the whole policy tenant-wide whenever any false positive occurs",
      "There is no way to create exceptions; all matches must be treated identically"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP Rule Exceptions",
      "analysis": [
        "Option A is CORRECT: DLP rules support exceptions — such as excluding specific sender/recipient groups, approved external domains, or particular content conditions — allowing legitimate business workflows (like sending reconciliation data to an approved processor) to bypass an otherwise broad blocking rule.",
        "Option B is INCORRECT: Exceptions can be added to an existing rule without needing to delete and rebuild the entire policy from scratch.",
        "Option C is INCORRECT: Disabling the whole policy tenant-wide over one legitimate business exception is unnecessarily broad and defeats the purpose of the control for all other scenarios.",
        "Option D is INCORRECT: Purview DLP explicitly supports exception conditions as a core rule-building feature, precisely to handle scenarios like this one."
      ],
      "codeSnippet": "// DLP rule exception example:\n// Base condition: Content contains Credit Card Number\n// Exception: Recipient domain is \"approvedprocessor.com\"\n//            AND Sender is member of \"Finance-Reconciliation\"\n// -> Exempted traffic bypasses the block action",
      "socTip": "Document the business justification for every DLP exception you add — exceptions accumulate over time, and undocumented ones are a common audit finding and security gap.",
      "docRef": "Microsoft Learn: Create a DLP policy from a template"
    }
  },
  {
    "id": "purview-084",
    "topic": "eDiscovery Premium predictive coding",
    "scenario": "Litware's legal team has 500,000 documents in an eDiscovery Premium case and cannot manually review all of them within the litigation timeline. They want technology to help prioritize which documents are most likely relevant.",
    "question": "What eDiscovery Premium capability uses machine learning trained on reviewer decisions to rank and prioritize the likely relevance of remaining unreviewed documents?",
    "options": [
      "Predictive coding (technology-assisted review), which trains a model on a sample of reviewer-tagged documents and then scores/ranks the remaining population by likely relevance",
      "Content search wildcards, which only match exact keyword patterns with no relevance ranking",
      "Retention label auto-apply, which is unrelated to document relevance ranking",
      "Communication Compliance classifier training, repurposed for legal review"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Predictive Coding in eDiscovery Premium",
      "analysis": [
        "Option A is CORRECT: Predictive coding (technology-assisted review) trains a machine learning model on a reviewer-tagged sample set (relevant vs. not relevant), then applies that model to score and prioritize the remaining unreviewed document population, dramatically speeding up large-scale review.",
        "Option B is INCORRECT: Keyword wildcard search matches literal text patterns; it doesn't perform ML-based relevance ranking across an entire document population.",
        "Option C is INCORRECT: Retention label auto-apply concerns records lifecycle classification, unrelated to litigation review relevance scoring.",
        "Option D is INCORRECT: Communication Compliance classifiers are trained for policy violation detection in communications, a different system from eDiscovery's predictive coding model."
      ],
      "codeSnippet": "// Predictive coding workflow:\n// 1. Reviewers tag a statistically valid sample set\n// 2. Model trains on tagged Relevant/Not Relevant examples\n// 3. Model scores remaining 500,000 docs by relevance\n// 4. Reviewers prioritize highest-scored docs first",
      "socTip": "Validate predictive coding model accuracy with a defensible sampling/quality-control round before relying on it to exclude large batches of documents from manual review — this is often required to withstand legal challenge.",
      "docRef": "Microsoft Learn: Predictive coding workflow in eDiscovery Premium"
    }
  },
  {
    "id": "purview-085",
    "topic": "Purview and Microsoft 365 retention for third-party data via connectors",
    "scenario": "Woodgrove Bank uses Bloomberg Message data alongside Microsoft 365 and needs that third-party data included under the same retention and eDiscovery obligations as their Exchange mailboxes for regulatory recordkeeping.",
    "question": "How can non-Microsoft communication data, such as Bloomberg Message content, be brought under Purview's retention and eDiscovery governance?",
    "options": [
      "Through supported third-party data connectors that ingest the external data into Microsoft 365 (e.g., as items in a mailbox or dedicated store), making it subject to the same retention policies and eDiscovery search as native content",
      "It cannot be done; third-party communication platforms are permanently outside Purview's governance scope",
      "Only by physically printing all Bloomberg messages and manually filing them in SharePoint",
      "By purchasing an entirely separate compliance suite unrelated to Microsoft Purview"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Third-Party Data Connectors for Retention/eDiscovery",
      "analysis": [
        "Option A is CORRECT: Purview supports data connectors for various third-party platforms that import external communication content (like Bloomberg Message, Reuters, or other regulated communication tools) into Microsoft 365 storage, making it subject to the same retention policies and eDiscovery content search as native Exchange/Teams data.",
        "Option B is INCORRECT: Third-party data connectors specifically exist to bring such external content into Purview's governance scope, contradicting a categorical impossibility claim.",
        "Option C is INCORRECT: Manual printing and filing is neither necessary nor practical; connectors handle digital ingestion directly.",
        "Option D is INCORRECT: This capability is native to the Microsoft Purview connector ecosystem, not something requiring an entirely separate, unrelated compliance product."
      ],
      "codeSnippet": "// Third-party connector flow:\n// Bloomberg Message data -> data connector -> imported into\n// a dedicated Microsoft 365 mailbox/store -> now covered by:\n//   - Retention policies\n//   - eDiscovery content search and hold\n//   - Communication Compliance (if also scoped)",
      "socTip": "Confirm connector data latency and completeness with the vendor documentation before certifying regulatory recordkeeping compliance — gaps in ingested history are a common audit risk for financial services connectors.",
      "docRef": "Microsoft Learn: Third-party data connectors overview"
    }
  },
  {
    "id": "purview-086",
    "topic": "Sensitivity labels and PDF support",
    "scenario": "Adatum's compliance team wants sensitivity labels with encryption to apply consistently whether a document is a native Word file or has been exported to PDF, since customers often receive PDFs.",
    "question": "Can Microsoft Purview sensitivity labels, including encryption protection, be applied to and preserved in PDF files?",
    "options": [
      "Yes — sensitivity labels including encryption can be applied to PDF files, and the protection is preserved and enforced when opened in supported PDF readers (like Adobe Acrobat with the sensitivity label plugin, or Office apps)",
      "No — sensitivity labels only work on native Office file formats like .docx and .xlsx",
      "Yes, but only visual watermarks work on PDFs; encryption is never supported for that format",
      "No — PDF support requires a completely separate non-Microsoft encryption product"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sensitivity Labels for PDF Files",
      "analysis": [
        "Option A is CORRECT: Purview sensitivity labels, including encryption, extend to PDF files. When exporting from Office to PDF (or labeling a native PDF), the protection can be preserved and enforced by supported readers, such as Adobe Acrobat with Microsoft's sensitivity label integration or through Office/Purview clients.",
        "Option B is INCORRECT: PDF is an explicitly supported file format for sensitivity labeling and encryption, not limited to native Office formats only.",
        "Option C is INCORRECT: Full encryption protection (not just visual markings like watermarks) is supported for PDFs, not merely cosmetic markings.",
        "Option D is INCORRECT: PDF labeling/encryption is handled natively through Microsoft's Information Protection capabilities and supported partner integrations, not a wholly separate non-Microsoft product requirement."
      ],
      "codeSnippet": "// PDF label support:\n// Word doc labeled \"Confidential\" -> Export to PDF\n// -> Label + encryption preserved in the PDF\n// Opening PDF requires Adobe Acrobat (with sensitivity\n//   label add-in) or another supporting reader with rights",
      "socTip": "When a customer complains PDF protection 'isn't working,' first check whether the recipient's PDF reader actually supports Microsoft Information Protection — this is the most common root cause, not a Purview misconfiguration.",
      "docRef": "Microsoft Learn: Support for PDF in sensitivity labels"
    }
  },
  {
    "id": "purview-087",
    "topic": "Insider risk detection of browser-based exfiltration",
    "scenario": "Tailspin Toys' analyst suspects an employee is exfiltrating data by pasting sensitive content into a personal webmail account or an unsanctioned AI chatbot website through their browser, rather than using file downloads.",
    "question": "What signal source does Insider Risk Management use to detect potentially risky activity happening within a web browser, such as pasting content into unsanctioned websites?",
    "options": [
      "Browser signal detection (via Microsoft Edge or Purview browser extensions/integration with Defender for Cloud Apps), which can identify risky activity like uploads or pastes to unsanctioned or personal web destinations",
      "Only file server access logs, since IRM has no visibility into browser activity at all",
      "Physical badge access data exclusively",
      "Compliance Manager improvement action logs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "IRM Browser Signal Detection",
      "analysis": [
        "Option A is CORRECT: IRM can incorporate browser-based signals — such as through Microsoft Edge enterprise features or integration with Defender for Cloud Apps — to detect activities like uploading/pasting sensitive content into unsanctioned personal webmail, cloud storage, or AI chatbot sites.",
        "Option B is INCORRECT: IRM's visibility explicitly extends beyond file server logs to include browser-based activity signals for exactly this kind of scenario.",
        "Option C is INCORRECT: Badge access data is a separate, optional physical security signal type, not the mechanism used for browser-based exfiltration detection.",
        "Option D is INCORRECT: Compliance Manager logs relate to regulatory control implementation tracking, unrelated to real-time browser activity monitoring."
      ],
      "codeSnippet": "// Browser signal indicator example:\n// User pastes content matching sensitive info type\n// into an unsanctioned domain (e.g., personal webmail,\n// unapproved AI chatbot site) -> IRM indicator triggered",
      "socTip": "Browser signal detection typically requires Microsoft Edge (or supported integration) as the browser in use — confirm browser standardization across the organization before relying on this indicator for coverage.",
      "docRef": "Microsoft Learn: Insider risk management browser signal detection"
    }
  },
  {
    "id": "purview-088",
    "topic": "Compliance Manager assessment templates for industry regulations",
    "scenario": "A healthcare-focused Relecloud subsidiary needs to track HIPAA compliance readiness specifically, in addition to their general Microsoft 365 data protection baseline.",
    "question": "Does Compliance Manager provide industry-specific regulatory templates, such as one tailored to HIPAA, in addition to general baselines?",
    "options": [
      "Yes — Compliance Manager includes a library of pre-built assessment templates for numerous industry-specific regulations, including HIPAA, alongside general baselines like the Microsoft 365 Data Protection Baseline",
      "No — only one universal template exists for all industries and use cases",
      "Yes, but healthcare-specific templates require a separate, additional non-Microsoft licensing agreement",
      "No — HIPAA-specific tracking must be done entirely outside of Microsoft Purview using manual spreadsheets"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Compliance Manager Industry-Specific Templates",
      "analysis": [
        "Option A is CORRECT: Compliance Manager's template library includes numerous regulation- and industry-specific assessments (HIPAA, GDPR, PCI-DSS, FedRAMP, ISO standards, and more), in addition to Microsoft's general Data Protection Baseline, letting organizations track posture against the specific frameworks relevant to their industry.",
        "Option B is INCORRECT: A broad library of distinct templates exists rather than a single universal one covering every regulation identically.",
        "Option C is INCORRECT: These templates are included within standard Compliance Manager licensing (e.g., E5 Compliance); no separate non-Microsoft licensing agreement is required to access the HIPAA template itself.",
        "Option D is INCORRECT: HIPAA tracking is natively supported within Compliance Manager's assessment framework, not something requiring an entirely separate manual spreadsheet process."
      ],
      "codeSnippet": "// Compliance Manager template library examples:\n// - Data Protection Baseline (default)\n// - HIPAA HITECH\n// - GDPR\n// - PCI-DSS\n// - NIST 800-53, ISO 27001, FedRAMP, and more",
      "socTip": "When onboarding a regulated-industry client, add their industry-specific template (like HIPAA) alongside the default baseline on day one — retrofitting it later means losing historical score trend continuity for that framework.",
      "docRef": "Microsoft Learn: Microsoft Purview Compliance Manager templates list"
    }
  },
  {
    "id": "purview-089",
    "topic": "Retention policy conflict resolution (principles)",
    "scenario": "Woodgrove Bank has one retention policy set to delete content after 3 years and a separate retention label on the same document set to retain content for 7 years, creating a direct conflict for certain files.",
    "question": "What general principle does Microsoft Purview follow when a retention policy and a retention label produce conflicting instructions for the same content?",
    "options": [
      "Purview generally follows a preference order favoring retention over deletion, and more specific/longer retention over shorter, with explicit label-level settings typically taking precedence over broader policy-level settings in a conflict",
      "Purview always deletes the content immediately whenever any conflict is detected, regardless of other settings",
      "Purview ignores both conflicting settings entirely and applies no retention at all until the conflict is manually resolved",
      "Purview randomly selects one of the two conflicting settings to apply, with no deterministic rule"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retention Policy and Label Conflict Resolution Principles",
      "analysis": [
        "Option A is CORRECT: Purview's general conflict-resolution principles favor retaining content over deleting it, prefer longer retention periods over shorter ones, and generally give more specific settings (like an item-level retention label) precedence over broader location-level policies, to minimize the risk of premature data loss.",
        "Option B is INCORRECT: Immediate deletion on any conflict would risk destroying content that should be retained, which contradicts the retention-favoring design principle.",
        "Option C is INCORRECT: Purview does apply a deterministic resolution rather than defaulting to no retention at all pending manual intervention.",
        "Option D is INCORRECT: Conflict resolution follows documented, deterministic principles (retain over delete, longer over shorter, more specific over general) rather than random selection."
      ],
      "codeSnippet": "// Conflict resolution principles (general order):\n// 1. Retention wins over deletion\n// 2. Longer retention period wins over shorter\n// 3. Explicit/specific label settings can win over\n//    broader policy-level settings in certain conflicts",
      "socTip": "Don't assume the shortest retention period always applies in a conflict — always test conflicting scenarios in a sandbox site, since the actual resolution can retain content longer than either administrator expected.",
      "docRef": "Microsoft Learn: The principles of retention or how retention works"
    }
  },
  {
    "id": "purview-090",
    "topic": "Custom sensitive information types",
    "scenario": "Litware has an internal employee ID number format unique to their company (e.g., 'LTW-XXXXX-YY') that isn't covered by any built-in sensitive information type, and they need DLP to detect it.",
    "question": "What Purview capability allows an organization to define detection logic for a proprietary, company-specific data pattern not covered by built-in sensitive information types?",
    "options": [
      "Custom sensitive information types, which let admins define a new SIT using a regular expression pattern, supporting keywords, and confidence levels tailored to the organization's unique data format",
      "Only Microsoft can create new sensitive information types; customers cannot define their own",
      "Trainable classifiers are the only way to detect any custom pattern, and regex-based custom SITs do not exist",
      "Exact Data Match is the sole option, and pattern-only custom SITs are not supported"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Sensitive Information Types",
      "analysis": [
        "Option A is CORRECT: Admins can create custom SITs using regular expressions (and optionally supporting keywords/proximity) to detect proprietary formats — such as a company-specific employee ID pattern — giving DLP and auto-labeling policies the ability to recognize data not covered by built-in types.",
        "Option B is INCORRECT: Customers have full self-service capability to create custom SITs directly in the Purview compliance portal; it is not Microsoft-exclusive.",
        "Option C is INCORRECT: Regex-based custom SITs are a well-established, documented feature distinct from trainable classifiers, which serve a different (document-category) use case.",
        "Option D is INCORRECT: While EDM is one option for structured reference-data matching, simple regex-pattern custom SITs are also fully supported and commonly used for cases like this."
      ],
      "codeSnippet": "// Custom SIT definition example:\n// Name: Litware Employee ID\n// Pattern: LTW-\\d{5}-[A-Z]{2}\n// Supporting keyword: \"employee id\", \"emp id\" (nearby)\n// Confidence: High if keyword within 300 characters",
      "socTip": "Test new custom SITs against a representative sample of real and near-miss data before deploying broadly — overly loose regex patterns are a common source of DLP false positives.",
      "docRef": "Microsoft Learn: Create a custom sensitive information type"
    }
  },
  {
    "id": "purview-091",
    "topic": "eDiscovery custodian communications",
    "scenario": "Trey Research's legal team places 15 employees under litigation hold as case custodians and needs each of them formally notified of their preservation obligations, with acknowledgment tracked.",
    "question": "What eDiscovery Premium feature manages the process of notifying custodians of their hold obligations and tracking their acknowledgment?",
    "options": [
      "Custodian communications (hold notifications), which sends and tracks legal hold notices to designated custodians, including reminders and acknowledgment status",
      "Communication Compliance escalation notices, repurposed for legal holds",
      "Compliance Manager improvement action notifications",
      "Sensitivity label justification prompts sent to custodians"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "eDiscovery Premium Custodian Communications",
      "analysis": [
        "Option A is CORRECT: eDiscovery Premium's custodian management includes hold notifications — formal communications sent to designated custodians informing them of preservation obligations, with the ability to send reminders and track acknowledgment status for defensibility.",
        "Option B is INCORRECT: Communication Compliance escalation handles policy violation review routing, an entirely different workflow from formal legal hold notification and acknowledgment tracking.",
        "Option C is INCORRECT: Compliance Manager notifications relate to regulatory improvement action tracking, unrelated to legal custodian hold communications.",
        "Option D is INCORRECT: Sensitivity label justification prompts capture reasons for label downgrades during document editing, unrelated to legal hold notice delivery."
      ],
      "codeSnippet": "// Custodian communication workflow:\n// 1. Add custodian to case (e.g., jsmith@treyresearch.net)\n// 2. Send hold notice with case details and obligations\n// 3. Track: Sent / Acknowledged / Reminder sent\n// 4. Escalate if custodian hasn't acknowledged within SLA",
      "socTip": "Set a firm SLA (e.g., 5 business days) for custodian acknowledgment and configure automatic reminders — unacknowledged holds are a common point of legal defensibility challenge.",
      "docRef": "Microsoft Learn: Manage custodians and communications in eDiscovery (Premium)"
    }
  },
  {
    "id": "purview-092",
    "topic": "Purview and Microsoft 365 Multi-Geo considerations",
    "scenario": "Northwind Traders operates a Microsoft 365 Multi-Geo environment with users' data residing in different geographic regions (EU, APAC, NA), and the compliance team wants to understand how this affects Purview policy scoping.",
    "question": "What consideration is important when configuring Purview compliance policies (DLP, retention, eDiscovery) in a Microsoft 365 Multi-Geo tenant?",
    "options": [
      "Policies generally need appropriate scoping/awareness of data residency, since content resides in region-specific satellite locations, and some search/investigation workflows must account for where data actually lives",
      "Multi-Geo has no impact whatsoever on any Purview compliance solution or policy scoping",
      "Purview compliance solutions are entirely unavailable in Multi-Geo tenants and require a single-geo tenant only",
      "Data residency is automatically irrelevant because all Purview data is processed exclusively in the tenant's primary region regardless of Multi-Geo configuration"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Considerations in Multi-Geo Environments",
      "analysis": [
        "Option A is CORRECT: In Multi-Geo tenants, user/site data resides in different satellite geo-locations based on configured Preferred Data Location, so compliance admins must be aware of residency when scoping policies and running investigations (like eDiscovery search) to ensure appropriate coverage and compliance with regional data handling requirements.",
        "Option B is INCORRECT: Multi-Geo residency is a real, documented factor that affects how some compliance workflows and considerations are approached, not something with zero impact.",
        "Option C is INCORRECT: Purview compliance solutions are supported in Multi-Geo tenants; they are not restricted to single-geo tenants only.",
        "Option D is INCORRECT: Content in Multi-Geo tenants resides according to the configured Preferred Data Location per user/site, not automatically processed only in the primary region."
      ],
      "codeSnippet": "// Multi-Geo awareness checklist for compliance admins:\n// [ ] Confirm which satellite geo a custodian's mailbox resides in\n// [ ] Ensure eDiscovery search accounts for cross-geo content\n// [ ] Review regional regulatory requirements per geo location",
      "socTip": "When scoping an eDiscovery case in a Multi-Geo tenant, explicitly verify custodian data location rather than assuming a single search automatically captures all relevant regional data.",
      "docRef": "Microsoft Learn: Multi-Geo capabilities in Microsoft 365"
    }
  },
  {
    "id": "purview-093",
    "topic": "DLP policy for Copilot and generative AI",
    "scenario": "Woodgrove Bank has deployed Microsoft 365 Copilot and wants to ensure Copilot cannot surface highly sensitive labeled content (like 'Highly Confidential' financial reports) in its responses to users who technically have access but shouldn't see summarized excerpts via AI.",
    "question": "What Purview capability lets admins specifically restrict Microsoft 365 Copilot (and other AI apps) from processing or surfacing certain highly sensitive labeled content in its responses?",
    "options": [
      "A DLP policy scoped to Microsoft 365 Copilot (and other AI sites), which can restrict Copilot from processing content with specific sensitivity labels, even if the user has underlying file access",
      "Sensitivity labels alone are always sufficient with no DLP configuration needed for Copilot behavior",
      "Communication Compliance keyword policies, which are the only way to restrict Copilot's responses",
      "Records Management disposition review, which controls what Copilot can reference"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "DLP for Microsoft 365 Copilot",
      "analysis": [
        "Option A is CORRECT: DLP policies can be scoped specifically to Microsoft 365 Copilot (and other AI apps/sites) to restrict processing of content carrying certain sensitivity labels, adding a governance layer beyond standard file permissions to control what Copilot can surface in generated responses.",
        "Option B is INCORRECT: While sensitivity labels define classification, a DLP policy scoped to Copilot is the specific mechanism needed to actively restrict AI processing behavior based on those labels.",
        "Option C is INCORRECT: Communication Compliance handles message content review for policy violations; it doesn't govern what content Copilot can process or surface in its responses.",
        "Option D is INCORRECT: Disposition review concerns records retention/deletion decisions, unrelated to controlling what content generative AI tools can reference at query time."
      ],
      "codeSnippet": "// DLP for Copilot policy example:\n// Location: Microsoft 365 Copilot experiences\n// Condition: Content has sensitivity label \"Highly Confidential\"\n// Action: Prevent Copilot from including this content in responses",
      "socTip": "Deploy DLP for Copilot as a defense-in-depth layer on top of correct file permissions — don't rely on file-level access control alone to prevent oversensitive AI-generated summaries.",
      "docRef": "Microsoft Learn: Data loss prevention policies for Microsoft 365 Copilot"
    }
  },
  {
    "id": "purview-094",
    "topic": "Purview onboarding and licensing prerequisites",
    "scenario": "Fabrikam's IT admin is preparing to enable Purview compliance features for the first time and wants to confirm what baseline prerequisite must be in place before most solutions like DLP and retention can be configured.",
    "question": "What is a common prerequisite before deploying most Microsoft Purview compliance solutions in a tenant?",
    "options": [
      "Appropriate Microsoft 365 licensing (such as E3/E5 or relevant compliance add-ons) assigned to users/admins, along with the necessary admin roles granted in the Purview portal",
      "No licensing or role assignment is ever required; every Purview feature is available by default to anonymous users",
      "A fully configured on-premises Active Directory Rights Management Services server is mandatory for every Purview feature",
      "Every user must first individually opt in through a personal privacy consent banner before any policy can be created"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Prerequisites",
      "analysis": [
        "Option A is CORRECT: Deploying Purview solutions generally requires appropriate licensing for the specific capability (e.g., E5 Compliance for premium features) assigned to relevant users, plus the admin configuring policies needs suitable Purview role group membership (like Compliance Administrator or a solution-specific role).",
        "Option B is INCORRECT: Purview features require licensing and permissions; they are not available by default to anonymous or unlicensed users.",
        "Option C is INCORRECT: AD RMS is only required for specific scenarios like HYOK, not as a general prerequisite for most Purview solutions such as DLP or retention.",
        "Option D is INCORRECT: Purview policy creation doesn't require individual end-user consent banners; it's an administrative configuration function governed by admin roles and licensing."
      ],
      "codeSnippet": "// Basic onboarding checklist:\n// [ ] Confirm E3/E5 or add-on licensing for target users\n// [ ] Assign admin to appropriate Purview role group\n// [ ] Review data residency/region settings before policy creation",
      "socTip": "Always validate the admin's actual Purview role group membership before troubleshooting a 'feature not visible' report — insufficient permissions are a frequent root cause mistaken for a product bug.",
      "docRef": "Microsoft Learn: Microsoft Purview licensing and prerequisites"
    }
  },
  {
    "id": "purview-095",
    "topic": "Retention for deleted/departed users' mailboxes",
    "scenario": "Litware's HR department offboards an employee and deletes their Microsoft 365 account, but Legal later realizes that mailbox needed to be preserved for an ongoing investigation that started before the deletion.",
    "question": "What Purview mechanism should have been used before account deletion to ensure a departing or at-risk employee's mailbox content is preserved regardless of account status changes?",
    "options": [
      "Placing the mailbox on a retention hold or litigation hold (or applying a retention label/policy) before deletion, since holds preserve content independently of the underlying account's active status",
      "Nothing could have prevented data loss; deleted account data is always immediately and permanently unrecoverable",
      "Renaming the user's account instead of deleting it, which is the only supported preservation method",
      "Exporting the mailbox to a personal USB drive prior to deletion, since Purview has no relevant preservation feature"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Preserving Departing/At-Risk User Content",
      "analysis": [
        "Option A is CORRECT: Applying a hold (litigation hold, eDiscovery case hold, or retention policy/label) before account deletion ensures the mailbox content is preserved independently of account lifecycle actions, and Microsoft 365 also supports retaining a former user's mailbox content when a hold is in place at time of deletion.",
        "Option B is INCORRECT: With proper holds/retention configured beforehand, content is not automatically lost upon account deletion — that's precisely the protection holds provide.",
        "Option C is INCORRECT: Renaming an account is not the standard or necessary mechanism for content preservation; holds and retention policies are the purpose-built tools.",
        "Option D is INCORRECT: Manual USB export is not a recommended or necessary Purview-native approach; built-in hold/retention capabilities exist specifically to avoid this kind of manual workaround."
      ],
      "codeSnippet": "// Best practice offboarding checklist:\n// [ ] Check if user is under any active hold\n// [ ] Apply/confirm retention policy or label BEFORE deletion\n// [ ] Coordinate with Legal before deleting accounts\n//     involved in any pending or anticipated investigation",
      "socTip": "Build a standard HR-to-IT offboarding checkpoint requiring a Legal/Compliance sign-off before deleting any account — this single process gap is one of the most common causes of accidental spoliation.",
      "docRef": "Microsoft Learn: Learn about retention for inactive mailboxes"
    }
  },
  {
    "id": "purview-096",
    "topic": "Sensitivity label mandatory labeling enforcement",
    "scenario": "Fabrikam's compliance officer wants to prevent users from saving or sending any document or email without first applying a sensitivity label, rather than relying on a default label alone.",
    "question": "What label policy setting forces users to explicitly choose a sensitivity label before they can save a document or send an email?",
    "options": [
      "Mandatory labeling (require users to apply a label), which blocks saving/sending until the user actively selects a label rather than relying solely on a default",
      "Default labeling, which is functionally identical to mandatory labeling in every respect",
      "Auto-labeling recommendation only, which cannot be configured to be mandatory",
      "There is no setting to require label selection; it is always fully optional for end users"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Mandatory Labeling Enforcement",
      "analysis": [
        "Option A is CORRECT: The label policy setting 'Require users to apply a label' forces active label selection before a document can be saved or an email sent, going further than a default label by not letting users skip the decision entirely.",
        "Option B is INCORRECT: A default label auto-applies a baseline without requiring active user choice, whereas mandatory labeling specifically forces the user to make an explicit selection — they are distinct behaviors.",
        "Option C is INCORRECT: Client-side auto-labeling recommendations can prompt users, but the specific 'require a label' enforcement setting is a separate, configurable mandatory policy option, not merely a recommendation.",
        "Option D is INCORRECT: Purview explicitly provides a mandatory labeling enforcement setting; label application is not universally optional by design once this policy option is enabled."
      ],
      "codeSnippet": "// Label policy setting:\n// [x] Require users to apply a label to their\n//     emails and documents\n// Effect: Save/Send blocked until a label is chosen",
      "socTip": "Pilot mandatory labeling with a small group before tenant-wide rollout — it's one of the most disruptive-if-misconfigured settings and generates significant help desk volume if users aren't prepared.",
      "docRef": "Microsoft Learn: Require users to apply a label"
    }
  },
  {
    "id": "purview-097",
    "topic": "DLP for on-premises file shares (scanner)",
    "scenario": "Adatum still has a large on-premises file server with legacy sensitive documents that were never migrated to SharePoint, and compliance wants those files classified and covered by DLP as well.",
    "question": "What Purview component extends sensitivity label discovery, classification, and DLP-style protection to on-premises file shares and SharePoint Server?",
    "options": [
      "The Microsoft Purview Information Protection scanner, which crawls on-premises repositories to discover, classify, and optionally label or apply protection to files at rest",
      "Endpoint DLP, which only covers actively used Windows/macOS endpoint devices, not static file servers",
      "Communication Compliance connectors, repurposed for file share scanning",
      "eDiscovery Premium custodian collection tools"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Purview Information Protection Scanner",
      "analysis": [
        "Option A is CORRECT: The Information Protection scanner is a service that runs on-premises, crawling designated file shares and SharePoint Server repositories to discover sensitive content, apply classification/sensitivity labels, and optionally enforce protection — extending Purview's reach beyond cloud-only locations.",
        "Option B is INCORRECT: Endpoint DLP protects activity on managed endpoint devices in near real time; it is not the tool designed for bulk scanning of static on-premises file server repositories.",
        "Option C is INCORRECT: Communication Compliance connectors ingest message content for review, an unrelated capability to file share content discovery and labeling.",
        "Option D is INCORRECT: eDiscovery custodian collection focuses on gathering evidence for legal cases, not ongoing bulk classification/labeling of file shares."
      ],
      "codeSnippet": "// Scanner deployment basics:\n// 1. Install scanner on a Windows Server\n// 2. Configure repositories (UNC paths, SharePoint Server sites)\n// 3. Run in discovery mode first (no changes)\n// 4. Enable enforce mode to apply labels/protection",
      "socTip": "Always run the Information Protection scanner in discovery-only mode first against a large legacy file share — this reveals classification scope and volume before committing to enforcement, avoiding unexpected mass relabeling.",
      "docRef": "Microsoft Learn: Learn about the Microsoft Purview Information Protection scanner"
    }
  },
  {
    "id": "purview-098",
    "topic": "Insider risk management and adaptive protection tiers",
    "scenario": "Northwind Traders' security team wants to understand what actually changes for a user once Adaptive Protection classifies them at the 'Elevated' risk tier versus the 'Minor' risk tier.",
    "question": "What typically changes for a user as their Adaptive Protection risk tier increases from Minor to Elevated?",
    "options": [
      "Stricter DLP enforcement is automatically applied — for example, moving from policy-tip-only warnings at low risk to active blocking of sensitive data actions at elevated risk, without manual policy reconfiguration",
      "Nothing changes automatically; an administrator must always manually update DLP rules for each user individually regardless of risk tier",
      "The user's Microsoft 365 license is automatically downgraded to a lower tier",
      "The user is automatically and permanently removed from all security groups"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Adaptive Protection Risk Tiers",
      "analysis": [
        "Option A is CORRECT: As Adaptive Protection raises a user's risk tier (e.g., Minor to Moderate to Elevated), it automatically applies progressively stricter pre-configured DLP responses — such as escalating from policy-tip warnings to active blocking — without requiring an admin to manually edit DLP rules for that individual user.",
        "Option B is INCORRECT: The entire value proposition of Adaptive Protection is automatic dynamic adjustment tied to risk level, removing the need for manual per-user DLP reconfiguration.",
        "Option C is INCORRECT: Risk tier changes affect DLP enforcement strictness, not Microsoft 365 license assignment or tier.",
        "Option D is INCORRECT: Adaptive Protection does not remove users from security groups; it adjusts DLP policy enforcement behavior tied to that user's current risk classification."
      ],
      "codeSnippet": "// Adaptive protection tier -> DLP response example:\n// Minor risk: Policy tip only\n// Moderate risk: Policy tip + justification required\n// Elevated risk: Block action entirely, no override allowed",
      "socTip": "Review the specific DLP rule tiers mapped to each Adaptive Protection risk level during initial setup — the default mappings may be more or less aggressive than your organization's risk tolerance requires.",
      "docRef": "Microsoft Learn: Learn about adaptive protection"
    }
  },
  {
    "id": "purview-099",
    "topic": "Purview compliance portal search across solutions",
    "scenario": "Woodgrove Bank's compliance analyst wants a quick way to search for a specific user or keyword and see relevant results surfaced across multiple Purview solutions (like DLP alerts, IRM alerts, and audit records) rather than searching each solution's dashboard individually.",
    "question": "Does the unified Microsoft Purview portal provide any cross-solution search or correlation capability spanning multiple compliance solutions?",
    "options": [
      "Yes — the unified portal and related dashboards (like DSPM and eDiscovery) can surface related signals across solutions such as DLP, IRM, and audit data for a more holistic investigative view, though each solution also retains its own dedicated search/dashboard",
      "No — every solution's data is entirely siloed with absolutely zero possibility of cross-referencing any signals",
      "Only Microsoft support engineers can perform any type of cross-solution search; customers cannot",
      "Cross-solution search requires purchasing a completely separate, unrelated third-party SIEM product with no exceptions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Solution Visibility in the Purview Portal",
      "analysis": [
        "Option A is CORRECT: The unified Purview portal, along with capabilities like DSPM dashboards and Copilot for Security's embedded experience, is designed to surface and correlate signals across multiple compliance solutions (DLP, IRM, audit, etc.), giving analysts a more holistic view beyond a single solution's isolated dashboard — while each solution still has its own dedicated interface for deep dives.",
        "Option B is INCORRECT: The unified portal's explicit design goal is reducing the historical siloing between compliance solutions, not preserving total isolation.",
        "Option C is INCORRECT: Customers with appropriate roles and licensing can access cross-solution dashboards and correlated views themselves; this is not restricted to Microsoft support engineers only.",
        "Option D is INCORRECT: While Sentinel integration can add further correlation with broader security telemetry, meaningful cross-solution visibility within Purview itself does not require a separate third-party SIEM as a strict prerequisite."
      ],
      "codeSnippet": "// Example cross-solution visibility:\n// DSPM dashboard surfaces:\n//   \"User X: elevated IRM risk + recent DLP alerts +\n//    unusual audit activity\" in one consolidated view",
      "socTip": "Encourage analysts to check DSPM's top risks dashboard periodically as a cross-solution starting point, then pivot into the specific solution (DLP, IRM, Audit) for deep investigation of any flagged user.",
      "docRef": "Microsoft Learn: Data security posture management overview"
    }
  },
  {
    "id": "purview-100",
    "topic": "Purview audit log search for compliance investigations",
    "scenario": "Contoso's compliance investigator needs to determine which admin changed a DLP policy last week and whether a specific user accessed a labeled document.",
    "question": "Where should the investigator search for a historical record of admin configuration changes and user content activities in Microsoft 365?",
    "options": [
      "The Microsoft Purview audit log (unified audit log), which records admin and user activities across Microsoft 365 services including DLP policy changes, file access, and label application events",
      "Only the Windows Event Viewer on each user's laptop",
      "Only Azure Activity Log for resource manager operations",
      "There is no searchable audit trail for Purview activities"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified Audit Log for Compliance Investigations",
      "analysis": [
        "Option A is CORRECT: The Purview/Microsoft 365 unified audit log records admin configuration changes and user activities across workloads, supporting compliance investigations into who changed policies and who accessed content.",
        "Option B is INCORRECT: Local Event Viewer cannot provide tenant-wide Microsoft 365 compliance activity.",
        "Option C is INCORRECT: Azure Activity Log focuses on Azure resource operations, not M365 content and Purview policy activities.",
        "Option D is INCORRECT: A searchable unified audit log is a core compliance capability."
      ],
      "codeSnippet": "// Purview portal > Audit > Search\n// Activities: DLP rule match, Sensitivity label applied,\n//   Updated policy, File accessed\n// Date range + Users + File/Folder filters",
      "socTip": "Enable audit log retention appropriate to your regulatory requirements; default retention may be insufficient for long investigations.",
      "docRef": "Microsoft Learn: Search the audit log in the Microsoft Purview portal"
    }
  }
]

def build_questions():
    """Attach module/audioSummary; keep explicit id for tracking 001-100."""
    result = []
    for i, q in enumerate(QUESTIONS):
        qid = q.get("id") or f"purview-{i+1:03d}"
        concept = q["explanation"]["concept"]
        correct_analysis = q["explanation"]["analysis"][q["correctIndex"]]
        audio = concept + ". " + (
            correct_analysis.split(": ", 1)[1][:200]
            if ": " in correct_analysis else correct_analysis[:200]
        )
        result.append({
            "id": qid,
            "module": "purview",
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
    output = "const PURVIEW_QUESTIONS = " + json.dumps(questions, indent=2, ensure_ascii=False) + ";\n"
    with open("questions_purview_v2.js", "w", encoding="utf-8") as f:
        f.write(output)

    stems = set(q["question"] for q in questions)
    scenarios = set(q["scenario"][:80] for q in questions)
    ids = [q["id"] for q in questions]
    ci_dist = {}
    for q in questions:
        ci_dist[q["correctIndex"]] = ci_dist.get(q["correctIndex"], 0) + 1

    print(f"[+] Generated {len(questions)} Purview questions -> questions_purview_v2.js")
    print(f"    ID range: {ids[0]} .. {ids[-1]}")
    print(f"    Unique IDs: {len(set(ids))}/{len(questions)}")
    print(f"    Unique question stems: {len(stems)}/{len(questions)}")
    print(f"    Unique scenario prefixes: {len(scenarios)}/{len(questions)}")
    print(f"    correctIndex distribution: {ci_dist}")
    expected = [f"purview-{i:03d}" for i in range(1, 101)]
    missing = [e for e in expected if e not in set(ids)]
    print(f"    Missing IDs: {missing if missing else 'none (complete 001-100)'}")
