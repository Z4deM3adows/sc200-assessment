"""
SC-200 Question Generator — Microsoft Copilot for Security Module (100 Questions)
Each question has a stable id (copilot-001 .. copilot-100) for easy tracking,
unique scenario, varied stem, 4 options, per-option explanations, and SOC tips.
"""
import json

QUESTIONS = [
  {
    "id": "copilot-001",
    "topic": "Standalone vs embedded experience",
    "scenario": "Contoso's CISO wants SOC analysts to use Microsoft Copilot for Security. Some analysts prefer using it directly in a full-screen browser while others want to use it within the Defender XDR portal without switching contexts.",
    "question": "What are the two primary experiences for interacting with Microsoft Copilot for Security?",
    "options": [
      "The standalone experience (security.microsoft.com/copilot) providing a full-screen prompt interface, and the embedded experience integrated directly into Microsoft Defender XDR, Intune, Purview, and Entra ID portals",
      "A desktop application installed on Windows and a mobile app for iOS/Android",
      "A PowerShell module and a REST API endpoint",
      "A Microsoft Teams bot and an Outlook add-in"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security — Standalone and Embedded Experiences",
      "analysis": [
        "Option A is CORRECT: Copilot for Security offers two primary interaction modes: (1) Standalone at security.microsoft.com/copilot with a full prompt bar for free-form queries, and (2) Embedded within product portals (Defender XDR, Intune, Purview, Entra ID) where Copilot appears as contextual panels and buttons.",
        "Option B is INCORRECT: Copilot for Security is a cloud-based service accessed through web browsers. There is no installable desktop application or mobile app.",
        "Option C is INCORRECT: While Copilot for Security has API capabilities for automation, the primary analyst interaction modes are the standalone and embedded web experiences, not PowerShell modules.",
        "Option D is INCORRECT: Copilot for Security is not delivered through Teams bots or Outlook add-ins. It is accessed through the dedicated security portals."
      ],
      "codeSnippet": "// Standalone: security.microsoft.com/copilot\n// Embedded examples:\n//   Defender XDR: Incident summary panel\n//   Intune: Device troubleshooting\n//   Purview: DLP alert investigation\n//   Entra ID: Sign-in log analysis",
      "socTip": "Use the standalone experience for complex, multi-step investigations. Use embedded Copilot for quick contextual actions like incident summaries within the Defender portal.",
      "docRef": "Microsoft Learn: Microsoft Copilot for Security experiences"
    }
  },
  {
    "id": "copilot-002",
    "topic": "Security Compute Units (SCUs)",
    "scenario": "Fabrikam is budgeting for Microsoft Copilot for Security deployment. The finance team asks the SOC manager to explain how Copilot for Security is billed and what controls exist to manage costs.",
    "question": "How is Microsoft Copilot for Security billed?",
    "options": [
      "A flat monthly fee per user regardless of usage",
      "Through Security Compute Units (SCUs), which are provisioned capacity units billed hourly — organizations can increase or decrease SCU count to control costs and performance",
      "Per query — each prompt submitted to Copilot incurs a separate charge",
      "It is included free with all Microsoft 365 E5 licenses"
    ],
    "correctIndex": 1,
    "explanation": {
      "concept": "SCU-Based Billing Model",
      "analysis": [
        "Option A is INCORRECT: Copilot for Security does not use per-user licensing. It uses a consumption-based model with provisioned capacity units.",
        "Option B is CORRECT: SCUs are provisioned in Azure and billed hourly. Organizations set the number of SCUs (minimum 1) which determines the processing capacity. More SCUs = faster processing and more concurrent sessions. SCUs can be adjusted at any time to manage costs.",
        "Option C is INCORRECT: Billing is not per-query. SCUs provide pooled capacity that is consumed by all queries across the organization. Individual prompts are not billed separately.",
        "Option D is INCORRECT: Copilot for Security is NOT included in Microsoft 365 E5. It requires a separate Azure subscription with provisioned SCUs. M365 E5 provides the underlying data (Defender, Purview) that Copilot analyzes."
      ],
      "codeSnippet": "// SCU Management via Azure Portal:\n// 1. Navigate to Azure Portal > Copilot for Security\n// 2. Set SCU count (minimum: 1)\n// 3. Monitor usage in the Copilot dashboard\n// 4. Scale up/down based on demand",
      "socTip": "Start with 1-3 SCUs for a pilot team. Monitor the Usage dashboard to see actual consumption before scaling. SCUs can be changed at any time without downtime.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-003",
    "topic": "Promptbooks",
    "scenario": "Northwind Traders' SOC lead creates a sequence of 8 prompts that systematically investigate a compromised user account — from checking sign-in logs to reviewing email forwarding rules to assessing lateral movement. The lead wants to share this investigation workflow with all analysts.",
    "question": "Which Copilot for Security feature allows saving and sharing a reusable sequence of prompts?",
    "options": [
      "Promptbooks — reusable, sharable sequences of prompts that can accept input parameters and execute as a complete investigation workflow",
      "KQL saved queries in Advanced Hunting",
      "Power Automate playbooks triggered by Sentinel",
      "OneNote notebooks shared via SharePoint"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Promptbooks — Reusable Investigation Workflows",
      "analysis": [
        "Option A is CORRECT: Promptbooks are sequences of prompts saved in Copilot for Security. They can include input parameters (e.g., username, IP address), execute prompts in order, and build on previous responses. Organizations can create custom promptbooks and share them with the SOC team.",
        "Option B is INCORRECT: KQL saved queries are individual database queries, not multi-step investigation workflows with natural language prompts. They don't provide the conversational, AI-driven analysis that promptbooks offer.",
        "Option C is INCORRECT: Power Automate playbooks are automation workflows that execute actions (send email, block IP), not interactive AI investigation sequences. They operate differently from Copilot's natural language interface.",
        "Option D is INCORRECT: OneNote is a note-taking tool, not a security investigation automation platform. It cannot execute security prompts or analyze threat data."
      ],
      "codeSnippet": "// Example Promptbook: Compromised User Investigation\n// Input parameter: <username>\n// Step 1: Get recent sign-in activity for <username>\n// Step 2: Check for suspicious email forwarding rules\n// Step 3: List devices <username> has logged into\n// Step 4: Summarize any incidents involving <username>\n// Step 5: Recommend remediation actions",
      "socTip": "Create promptbooks for your top 5 most common investigation scenarios: compromised account, phishing email, malware detection, data exfiltration, and suspicious sign-in. This standardizes investigation quality across all analysts.",
      "docRef": "Microsoft Learn: Use promptbooks in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-004",
    "topic": "Incident summary capabilities",
    "scenario": "A Tier 1 analyst at Adatum opens a high-severity incident in Microsoft Defender XDR that contains 15 correlated alerts spanning email, endpoint, and identity. The analyst clicks the 'Summarize incident' button powered by Copilot for Security embedded in the portal.",
    "question": "What does the Copilot-generated incident summary provide?",
    "options": [
      "A natural language summary describing the attack timeline, affected assets, attack techniques used, scope of impact, and recommended next steps — synthesized from all 15 correlated alerts",
      "Only a count of the number of alerts and affected devices",
      "A raw JSON export of all alert metadata",
      "A link to the Microsoft Threat Intelligence blog about the attack technique"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Generated Incident Summaries",
      "analysis": [
        "Option A is CORRECT: Copilot's incident summary provides a comprehensive natural language narrative covering: what happened (attack chain), when it happened (timeline), who/what was affected (users, devices, mailboxes), how it happened (techniques), current status, and recommended investigation/remediation steps.",
        "Option B is INCORRECT: The summary goes far beyond counts. It synthesizes the relationships between alerts, explains the attack narrative, and provides actionable next steps in plain language.",
        "Option C is INCORRECT: Copilot generates human-readable summaries, not raw JSON exports. The value is in the AI's ability to synthesize complex multi-alert data into an understandable narrative.",
        "Option D is INCORRECT: While Copilot may reference threat intelligence, the incident summary is specific to YOUR incident — it's not a generic blog link. It analyzes the specific alerts, entities, and timeline in your environment."
      ],
      "codeSnippet": "// Embedded Copilot incident summary example:\n// \"This high-severity incident involves a phishing\n// email delivered to 3 users on Aug 10. User\n// john@contoso.com clicked the link, triggering\n// PowerShell execution on WORKSTATION-05.\n// The attacker established persistence via a\n// scheduled task and attempted lateral movement\n// to the domain controller DC01.\n// Recommended: Isolate WORKSTATION-05, reset\n// john@contoso.com credentials.\"",
      "socTip": "Use Copilot incident summaries for shift handoffs. Instead of writing manual notes, generate a summary at the end of your shift that the next analyst can read to immediately understand the investigation state.",
      "docRef": "Microsoft Learn: Summarize an incident with Copilot in Defender"
    }
  },
  {
    "id": "copilot-005",
    "topic": "Script analysis and reverse engineering",
    "scenario": "A Contoso SOC analyst finds a heavily obfuscated PowerShell script during an incident investigation. The script uses Base64 encoding, variable substitution, and string concatenation to hide its true intent. The analyst needs to understand what the script does without executing it.",
    "question": "How can the analyst use Copilot for Security to analyze the obfuscated script?",
    "options": [
      "Paste the script into Copilot's standalone prompt and ask 'Analyze this script' — Copilot will decode obfuscation layers, explain each function, identify malicious behaviors, and provide a plain-language summary of the script's purpose",
      "Upload the script to VirusTotal and check the detection ratio",
      "Run the script in a sandboxed virtual machine and observe the behavior",
      "Search for the script's SHA256 hash in threat intelligence databases"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Powered Script Analysis",
      "analysis": [
        "Option A is CORRECT: Copilot for Security can analyze scripts in multiple languages (PowerShell, Python, Bash, JavaScript, etc.). It decodes Base64 strings, resolves variable substitutions, explains the logic step-by-step, identifies malicious patterns (reverse shells, credential harvesting, persistence mechanisms), and provides a plain-language summary.",
        "Option B is INCORRECT: VirusTotal checks file hashes and runs AV scans but doesn't provide detailed code analysis or explain what specific lines of a script do. It's a detection tool, not a code analysis tool.",
        "Option C is INCORRECT: Running unknown scripts, even in a sandbox, carries risk and takes time. Copilot provides static analysis that's faster and doesn't require executing the potentially malicious code.",
        "Option D is INCORRECT: Hash-based lookups only work if the exact script has been seen before. Obfuscated scripts are often unique to each attack, making hash lookups ineffective. Copilot analyzes the code itself, not its hash."
      ],
      "codeSnippet": "// Example Copilot prompt for script analysis:\n// \"Analyze this PowerShell script, decode any\n// obfuscation, and explain what it does:\n// [paste script here]\"\n//\n// Copilot response includes:\n// 1. Decoded strings and variables\n// 2. Function-by-function explanation\n// 3. IOCs extracted (URLs, IPs, domains)\n// 4. MITRE ATT&CK technique mapping\n// 5. Severity assessment",
      "socTip": "When analyzing scripts with Copilot, follow up with 'Extract all IOCs from this script' to get a structured list of IP addresses, domains, URLs, file paths, and registry keys for further investigation.",
      "docRef": "Microsoft Learn: Analyze scripts with Copilot in Defender"
    }
  },
  {
    "id": "copilot-006",
    "topic": "Natural language to KQL translation",
    "scenario": "A junior SOC analyst at Fabrikam needs to hunt for devices that have connected to Tor exit nodes in the last 7 days. The analyst doesn't know KQL syntax well enough to write the query from scratch.",
    "question": "How can Copilot for Security help this analyst?",
    "options": [
      "The analyst types a natural language request like 'Find all devices that connected to known Tor exit node IPs in the last 7 days' and Copilot generates the corresponding KQL query for Advanced Hunting",
      "Copilot can only answer questions about Microsoft documentation, not generate queries",
      "The analyst must first learn KQL syntax before Copilot can assist",
      "Copilot generates SQL queries for Azure SQL databases, not KQL for Advanced Hunting"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Natural Language to KQL Query Generation",
      "analysis": [
        "Option A is CORRECT: Copilot for Security can translate natural language descriptions into valid KQL queries for Advanced Hunting. The analyst describes what they want to find, and Copilot generates the query with correct table names, column references, operators, and filters.",
        "Option B is INCORRECT: Copilot's capabilities extend far beyond documentation lookup. It can generate queries, analyze data, summarize incidents, decode scripts, and perform threat intelligence lookups.",
        "Option C is INCORRECT: Copilot is specifically designed to help analysts who may not be KQL experts. The natural language interface removes the syntax barrier, democratizing Advanced Hunting capabilities.",
        "Option D is INCORRECT: Copilot generates KQL (Kusto Query Language) queries for Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel, not SQL queries for relational databases."
      ],
      "codeSnippet": "// Analyst prompt: \"Find devices connecting to Tor\"\n// Copilot generates:\nDeviceNetworkEvents\n| where Timestamp > ago(7d)\n| where RemoteIP in (externaldata(IP:string)\n    [@\"https://check.torproject.org/exit-addresses\"]\n    with (format=\"txt\"))\n| summarize Connections=count() by DeviceName, RemoteIP\n| order by Connections desc",
      "socTip": "After Copilot generates a KQL query, always review it before running. Check the table name, column names, and filter logic. Copilot may occasionally use deprecated column names or incorrect operators.",
      "docRef": "Microsoft Learn: Generate KQL queries with Copilot in Defender"
    }
  },
  {
    "id": "copilot-007",
    "topic": "Custom plugins for Copilot",
    "scenario": "Litware Inc. uses a proprietary threat intelligence platform (TIP) that is not natively integrated with Microsoft Copilot for Security. The security engineering team wants Copilot to query their TIP when analysts ask about IOC reputation or threat actor profiles.",
    "question": "How can Litware extend Copilot for Security to integrate with their proprietary TIP?",
    "options": [
      "Create a custom plugin using an OpenAPI specification that defines the TIP's API endpoints, authentication, and response schema — Copilot will invoke the plugin when analysts ask relevant questions",
      "Replace the TIP with Microsoft Defender Threat Intelligence (MDTI) since Copilot only works with Microsoft products",
      "Export TIP data to a CSV file and upload it to Copilot monthly",
      "Install a browser extension that auto-copies TIP data into Copilot prompts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Plugins for Copilot for Security",
      "analysis": [
        "Option A is CORRECT: Copilot for Security supports custom plugins defined via OpenAPI (Swagger) specifications. You provide the API endpoint URLs, authentication method (API key, OAuth), and response schema. Copilot learns when to invoke the plugin based on analyst queries and presents the results inline.",
        "Option B is INCORRECT: Copilot is designed to be extensible through plugins — it's not limited to Microsoft-only data sources. Custom plugins allow integration with any third-party tool that has an API.",
        "Option C is INCORRECT: Static CSV uploads don't provide real-time threat intelligence. Custom plugins query the TIP API in real-time, ensuring analysts always get the latest IOC reputation data.",
        "Option D is INCORRECT: Browser extensions are not the supported integration method. Custom plugins provide a formal, secure, API-level integration that Copilot's orchestrator can invoke automatically."
      ],
      "codeSnippet": "// Custom plugin manifest (OpenAPI spec):\n// {\n//   \"openapi\": \"3.0.0\",\n//   \"info\": { \"title\": \"Litware TIP Plugin\" },\n//   \"paths\": {\n//     \"/api/ioc/{indicator}\": {\n//       \"get\": {\n//         \"summary\": \"Lookup IOC reputation\",\n//         \"parameters\": [...]\n//       }\n//     }\n//   }\n// }",
      "socTip": "When building custom plugins, include descriptive summaries for each API operation. Copilot uses these summaries to decide when to invoke your plugin — vague descriptions lead to missed invocations.",
      "docRef": "Microsoft Learn: Manage plugins in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-008",
    "topic": "Threat intelligence summarization",
    "scenario": "A Contoso analyst is investigating a threat actor group called 'Midnight Blizzard'. The analyst wants a quick overview of this group's known TTPs, targeted industries, and recent campaigns without reading multiple lengthy reports.",
    "question": "How does Copilot for Security help with threat intelligence research?",
    "options": [
      "Copilot synthesizes threat intelligence from Microsoft Defender Threat Intelligence (MDTI) and other sources to provide a natural language summary of threat actors, their TTPs, targeted sectors, and known IOCs",
      "Copilot only displays raw STIX/TAXII threat intelligence feeds without summarization",
      "Copilot redirects the analyst to external websites like MITRE ATT&CK for threat actor research",
      "Copilot cannot access threat intelligence data and requires manual research"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Threat Intelligence Summarization",
      "analysis": [
        "Option A is CORRECT: Copilot integrates with Microsoft Defender Threat Intelligence (MDTI) to provide comprehensive threat actor profiles. It summarizes known TTPs (MITRE ATT&CK mapping), targeted industries, geographic focus, recent campaigns, and associated IOCs in plain language.",
        "Option B is INCORRECT: Copilot does not dump raw STIX/TAXII data. It processes and summarizes threat intelligence into human-readable narratives that analysts can immediately act upon.",
        "Option C is INCORRECT: While MITRE ATT&CK is a valuable resource, Copilot provides the information directly within its interface using Microsoft's own threat intelligence. No external navigation is required.",
        "Option D is INCORRECT: Threat intelligence is a core capability of Copilot for Security. MDTI is one of the primary data sources that Copilot draws from when answering threat-related queries."
      ],
      "codeSnippet": "// Example Copilot prompt:\n// \"Tell me about the threat actor Midnight Blizzard\"\n//\n// Copilot response includes:\n// - Also known as: APT29, Cozy Bear, NOBELIUM\n// - Nation-state: Russia\n// - Primary targets: Government, diplomatic\n// - Key TTPs: Spear-phishing, token theft\n// - Recent activity: M365 tenant compromise\n// - Associated IOCs: domains, IPs, hashes",
      "socTip": "When investigating an incident, ask Copilot 'What threat actors are known to use [technique observed]?' to get attribution hypotheses based on the TTPs you've observed.",
      "docRef": "Microsoft Learn: Threat intelligence in Copilot for Security"
    }
  },
  {
    "id": "copilot-009",
    "topic": "Data sources and plugins architecture",
    "scenario": "Adatum's security architect is evaluating Copilot for Security and needs to understand which Microsoft security products feed data into Copilot. The architect wants to know if Copilot can access data from Defender XDR, Sentinel, Intune, Purview, and Entra ID simultaneously.",
    "question": "Which statement correctly describes Copilot for Security's data access architecture?",
    "options": [
      "Copilot accesses data through plugins — each Microsoft security product (Defender XDR, Sentinel, Intune, Purview, Entra ID) has its own plugin that Copilot invokes based on the analyst's query, allowing cross-product data access in a single session",
      "Copilot can only access data from one Microsoft product at a time and requires switching between modes",
      "Copilot stores a local copy of all security data and queries it offline",
      "Copilot only works with Microsoft Sentinel and requires all data to be ingested into Sentinel first"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Plugin-Based Data Architecture",
      "analysis": [
        "Option A is CORRECT: Copilot for Security uses a plugin architecture where each Microsoft product (and third-party integrations) is accessed through a dedicated plugin. The orchestrator automatically determines which plugins to invoke based on the analyst's query, enabling seamless cross-product investigation in a single conversation.",
        "Option B is INCORRECT: Copilot can access multiple products simultaneously in a single session. There is no mode switching. An analyst can ask about an Entra ID sign-in, a Defender XDR incident, and Intune device compliance in the same conversation.",
        "Option C is INCORRECT: Copilot does not store data locally. It queries the underlying products in real-time through their APIs. This ensures data is always current and respects existing access controls.",
        "Option D is INCORRECT: Copilot works directly with Defender XDR, Intune, Purview, and Entra ID — Sentinel ingestion is not required. Each product has its own plugin that Copilot queries independently."
      ],
      "codeSnippet": "// Built-in Microsoft plugins:\n// - Microsoft Defender XDR\n// - Microsoft Sentinel\n// - Microsoft Intune\n// - Microsoft Purview\n// - Microsoft Entra ID\n// - Microsoft Defender Threat Intelligence\n// - Natural Language to KQL\n// - Microsoft Defender EASM\n// Plus custom plugins via OpenAPI",
      "socTip": "Check which plugins are enabled in your Copilot settings. Disabled plugins mean Copilot cannot access that product's data. Enable all relevant plugins for comprehensive investigation capabilities.",
      "docRef": "Microsoft Learn: Manage plugins in Copilot for Security"
    }
  },
  {
    "id": "copilot-010",
    "topic": "Role-based access control for Copilot",
    "scenario": "Fabrikam's security team has 5 Copilot for Security users. The CISO wants Tier 1 analysts to use Copilot for incident summaries and script analysis, but wants to restrict them from managing SCU capacity, creating custom plugins, or uploading files to Copilot sessions.",
    "question": "How should the CISO configure access control for Copilot for Security?",
    "options": [
      "Assign Tier 1 analysts the 'Copilot Contributor' role which allows using Copilot features, and reserve the 'Copilot Owner' role for senior staff who need to manage SCUs, plugins, and settings",
      "Create a separate Azure AD tenant for each analyst tier",
      "Use network ACLs to block specific Copilot URLs for Tier 1 analysts",
      "There is no RBAC for Copilot — all users have the same permissions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security RBAC Roles",
      "analysis": [
        "Option A is CORRECT: Copilot for Security has two primary roles: 'Copilot Owner' (manage SCUs, plugins, settings, and use all features) and 'Copilot Contributor' (use Copilot features like prompts, promptbooks, and investigations without administrative access). These are assigned in Copilot settings.",
        "Option B is INCORRECT: Separate tenants are unnecessary and would prevent cross-team collaboration. RBAC within the same tenant provides granular access control.",
        "Option C is INCORRECT: Network ACLs cannot provide feature-level access control within Copilot. URL blocking would prevent all access, not granular feature restriction.",
        "Option D is INCORRECT: Copilot for Security does implement RBAC through the Owner and Contributor roles, providing differentiated access levels."
      ],
      "codeSnippet": "// Copilot for Security roles:\n//\n// Copilot Owner:\n//   - Manage SCU capacity\n//   - Enable/disable plugins\n//   - Upload custom plugins\n//   - Configure settings\n//   - Use all Copilot features\n//\n// Copilot Contributor:\n//   - Use prompts and promptbooks\n//   - View investigation results\n//   - Cannot manage SCUs or plugins",
      "socTip": "Assign the Copilot Owner role to no more than 2-3 people (SOC manager and security architect). All analysts should be Contributors to prevent accidental SCU changes or plugin modifications.",
      "docRef": "Microsoft Learn: Roles and permissions in Copilot for Security"
    }
  },
  {
    "id": "copilot-011",
    "topic": "Guided response recommendations",
    "scenario": "A Northwind Traders analyst uses the embedded Copilot in Defender XDR to investigate a malware incident. After Copilot summarizes the incident, the analyst asks 'What should I do next?' Copilot provides specific remediation steps.",
    "question": "What type of response does Copilot provide when asked for remediation guidance?",
    "options": [
      "Copilot provides guided response recommendations with specific, actionable steps tailored to the incident — such as 'Isolate device WORKSTATION-05', 'Reset credentials for user@contoso.com', and 'Run antivirus scan' — with direct action links in the portal",
      "Copilot only provides a generic link to Microsoft's incident response documentation",
      "Copilot automatically executes all remediation actions without analyst review",
      "Copilot provides recommendations only in PDF report format that must be downloaded"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Guided Response and Remediation Recommendations",
      "analysis": [
        "Option A is CORRECT: Copilot provides contextual, actionable remediation steps specific to the entities in the incident. Steps reference actual device names, user accounts, and file hashes from the investigation. In the embedded experience, these recommendations often include direct links or buttons to execute the action.",
        "Option B is INCORRECT: Copilot goes far beyond linking to documentation. It provides specific steps based on the actual incident entities and attack techniques observed in your environment.",
        "Option C is INCORRECT: Copilot recommends actions but does NOT automatically execute them. Analyst approval is always required before remediation actions are taken, maintaining human oversight.",
        "Option D is INCORRECT: Recommendations are provided inline in the Copilot conversation, not as downloadable PDFs. The interactive format allows follow-up questions and immediate action."
      ],
      "codeSnippet": "// Example guided response from Copilot:\n// 1. IMMEDIATE: Isolate WORKSTATION-05 to stop\n//    C2 communication [Isolate Device button]\n// 2. CREDENTIAL: Reset password for john@contoso.com\n//    and revoke active sessions [Reset button]\n// 3. INVESTIGATE: Check if payload.exe exists on\n//    other devices using Advanced Hunting\n// 4. PREVENT: Block hash abc123... in custom IOC list",
      "socTip": "After receiving Copilot's guided response, ask follow-up questions like 'Are there any other affected devices?' or 'Has this user's account shown suspicious activity before?' to deepen the investigation.",
      "docRef": "Microsoft Learn: Guided responses in Copilot for Security"
    }
  },
  {
    "id": "copilot-012",
    "topic": "File analysis in Copilot",
    "scenario": "A Litware SOC analyst has a suspicious PDF file that was flagged by Defender for Endpoint. The analyst wants to understand the file's behavior without detonating it. The analyst uploads the file hash to Copilot for Security for analysis.",
    "question": "What information can Copilot for Security provide about a suspicious file?",
    "options": [
      "File reputation from Microsoft Threat Intelligence, global prevalence (how many organizations have seen it), first/last seen timestamps, associated threat families, MITRE ATT&CK techniques, and related IOCs",
      "Only the file's MD5 hash and file size",
      "A decrypted version of the file's contents",
      "The physical location of the server hosting the file"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "File Intelligence and Reputation Analysis",
      "analysis": [
        "Option A is CORRECT: Copilot leverages MDTI and Defender XDR data to provide comprehensive file intelligence: reputation verdict, global prevalence (rarity), first/last seen dates, threat family classification, behavioral indicators, MITRE techniques, and related IOCs (other files, domains, IPs associated with the same campaign).",
        "Option B is INCORRECT: Copilot provides much more than basic hash and size information. It contextualizes the file within the broader threat landscape using Microsoft's extensive telemetry.",
        "Option C is INCORRECT: Copilot does not decrypt or modify files. It provides analytical intelligence about the file's reputation and behavior based on Microsoft's threat intelligence databases.",
        "Option D is INCORRECT: Copilot provides threat intelligence context, not physical infrastructure location data. Server geolocation is not part of the file analysis output."
      ],
      "codeSnippet": "// Example Copilot prompt:\n// \"Analyze file hash SHA256: abc123def456...\"\n//\n// Response:\n// Verdict: Malicious (High Confidence)\n// Threat Family: Emotet\n// Global Prevalence: Seen in 23 organizations\n// First Seen: 2026-07-15\n// Techniques: T1566.001, T1059.001\n// Related IOCs: 5 domains, 3 IP addresses",
      "socTip": "When investigating files, also ask Copilot 'Show me all devices in my organization where this file has been observed' to quickly assess the scope of exposure.",
      "docRef": "Microsoft Learn: File analysis in Copilot for Security"
    }
  },
  {
    "id": "copilot-013",
    "topic": "Copilot session management",
    "scenario": "An Adatum analyst has been investigating a complex incident using Copilot for Security over 3 hours, generating 25 prompts. The analyst needs to take a break and resume the investigation tomorrow. Another analyst on the night shift also wants to review the findings.",
    "question": "How does Copilot for Security handle investigation sessions?",
    "options": [
      "Sessions are automatically saved and persist — analysts can return to any previous session, and sessions can be shared with other team members via a shareable link",
      "Sessions expire after 30 minutes of inactivity and cannot be recovered",
      "Sessions can only be exported as PDF documents for sharing",
      "Each analyst has a completely isolated workspace with no sharing capability"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Session Persistence and Sharing",
      "analysis": [
        "Option A is CORRECT: Copilot for Security sessions are automatically saved and accessible from the session list. Analysts can resume investigations at any time. Sessions can be shared with other Copilot users in the organization through shareable links, enabling collaborative investigation.",
        "Option B is INCORRECT: Sessions do not expire after 30 minutes. They persist indefinitely and can be accessed from the session history at any time.",
        "Option C is INCORRECT: While session content can be exported, the primary sharing mechanism is direct session sharing within Copilot, which preserves the interactive context and allows the recipient to continue the conversation.",
        "Option D is INCORRECT: Copilot supports session sharing between team members. This is essential for SOC operations where incidents span multiple shifts and require collaborative investigation."
      ],
      "codeSnippet": "// Session management:\n// - Auto-save: All sessions persist automatically\n// - Resume: Click any session in the session list\n// - Share: Use 'Share session' to generate a link\n// - Pin: Pin important sessions for quick access\n// - Delete: Remove sessions you no longer need",
      "socTip": "Create a naming convention for Copilot sessions: 'INC-{number}-{description}'. This makes sessions searchable and easier to find during handoffs between shifts.",
      "docRef": "Microsoft Learn: Navigate Copilot for Security"
    }
  },
  {
    "id": "copilot-014",
    "topic": "Microsoft Defender EASM integration",
    "scenario": "Contoso wants to use Copilot for Security to understand their external attack surface. The CISO asks Copilot about internet-facing assets that might be misconfigured or exposed.",
    "question": "Which Copilot plugin provides external attack surface information?",
    "options": [
      "The Microsoft Defender External Attack Surface Management (EASM) plugin, which allows Copilot to query and summarize internet-facing assets, exposed services, CVE vulnerabilities, and misconfigurations discovered through external scanning",
      "The Microsoft Intune plugin, which manages internal device compliance",
      "The Microsoft Purview plugin, which handles data classification",
      "The Microsoft Entra ID plugin, which manages user identities"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "EASM Plugin for Attack Surface Intelligence",
      "analysis": [
        "Option A is CORRECT: The Defender EASM plugin enables Copilot to query external attack surface data including: internet-facing hosts, open ports, SSL certificate issues, CVE vulnerabilities on exposed services, and misconfigurations. Analysts can ask natural language questions about their attack surface.",
        "Option B is INCORRECT: Intune manages internal device compliance and configuration, not external-facing attack surface. Intune tracks corporate devices, not internet-exposed assets.",
        "Option C is INCORRECT: Purview handles data governance, classification, and compliance. It does not scan for external attack surface exposures.",
        "Option D is INCORRECT: Entra ID manages user identities and access. While identity security is important, external attack surface management (open ports, exposed services, SSL issues) is handled by EASM."
      ],
      "codeSnippet": "// Example EASM queries in Copilot:\n// \"Show me all internet-facing assets with\n//  expired SSL certificates\"\n// \"Which of our external hosts have critical\n//  CVEs that are unpatched?\"\n// \"List all domains in my EASM inventory\n//  with open port 3389 (RDP)\"",
      "socTip": "Ask Copilot 'What are my highest priority external exposures?' to get a risk-ranked list. Focus on exposed RDP (3389), SMB (445), and admin interfaces (8443, 8080) first.",
      "docRef": "Microsoft Learn: EASM plugin in Copilot for Security"
    }
  },
  {
    "id": "copilot-015",
    "topic": "Copilot in Microsoft Intune",
    "scenario": "A Fabrikam IT administrator receives a help desk ticket about a device that keeps failing compliance checks. The admin opens the device page in Intune and uses the embedded Copilot to troubleshoot the issue.",
    "question": "What can the embedded Copilot in Intune help with?",
    "options": [
      "Device troubleshooting — summarizing device compliance status, explaining why a policy failed, comparing device configurations against baselines, and providing remediation steps specific to the non-compliant settings",
      "Only generating PowerShell scripts for device management",
      "Only providing links to Intune documentation",
      "Remotely wiping the device without administrator confirmation"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Embedded Copilot in Microsoft Intune",
      "analysis": [
        "Option A is CORRECT: Copilot in Intune provides: device compliance summaries, root cause analysis for policy failures (e.g., 'Encryption is disabled because BitLocker policy conflicts with existing GPO'), configuration comparison against baselines, and specific remediation steps.",
        "Option B is INCORRECT: While Copilot can help generate scripts, its Intune capabilities are much broader, including device troubleshooting, policy analysis, and compliance investigation.",
        "Option C is INCORRECT: Copilot provides actionable, context-specific guidance — not just documentation links. It analyzes the specific device's configuration and compliance state.",
        "Option D is INCORRECT: Copilot never executes destructive actions (like device wipe) without explicit administrator confirmation. It only provides recommendations and requires human approval for actions."
      ],
      "codeSnippet": "// Copilot in Intune example prompts:\n// \"Why is this device non-compliant?\"\n// \"Compare this device's config to the baseline\"\n// \"What policies are applied to this device?\"\n// \"Help me troubleshoot BitLocker enrollment\n//  failure on this device\"",
      "socTip": "Use Copilot in Intune during incident response to quickly assess whether a compromised device had all security policies correctly applied. Non-compliance may be the root cause of the compromise.",
      "docRef": "Microsoft Learn: Microsoft Copilot in Intune"
    }
  },
  {
    "id": "copilot-016",
    "topic": "Copilot in Microsoft Entra ID",
    "scenario": "A Northwind Traders analyst suspects that a user account has been compromised. The analyst opens the user's profile in Microsoft Entra ID and uses the embedded Copilot to get a risk assessment.",
    "question": "What user risk information can Copilot provide in Entra ID?",
    "options": [
      "A summary of the user's risk level, recent risky sign-ins (locations, devices, applications), Conditional Access policy evaluations, group memberships, and privilege roles — all synthesized into a risk narrative",
      "Only the user's display name and last sign-in date",
      "The user's personal contact information and home address",
      "A credit score-style numerical risk rating from 0-850"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "User Risk Assessment in Entra ID",
      "analysis": [
        "Option A is CORRECT: Copilot in Entra ID synthesizes identity risk signals: user risk level (Low/Medium/High), risky sign-in details (impossible travel, anonymous IP, malware-linked IPs), Conditional Access policy results, role assignments (is the user a Global Admin?), and group memberships.",
        "Option B is INCORRECT: Copilot provides much more than basic profile information. It analyzes risk signals and sign-in patterns to provide a comprehensive security assessment.",
        "Option C is INCORRECT: Copilot does not expose personal contact information. It focuses on security-relevant identity data like sign-in patterns, risk signals, and access permissions.",
        "Option D is INCORRECT: Microsoft uses categorical risk levels (Low/Medium/High), not numerical credit-score-style ratings. Copilot presents these categories with explanatory context about what triggered the risk level."
      ],
      "codeSnippet": "// Copilot in Entra ID example prompts:\n// \"Summarize the risk for user john@northwind.com\"\n// \"Show recent risky sign-ins for this user\"\n// \"What privileged roles does this user have?\"\n// \"Which Conditional Access policies apply?\"\n// \"List all apps this user has consented to\"",
      "socTip": "During compromise investigation, ask Copilot 'Does this user have any privileged roles?' before resetting credentials. If the user is a Global Admin, the incident scope is significantly larger.",
      "docRef": "Microsoft Learn: Copilot in Microsoft Entra"
    }
  },
  {
    "id": "copilot-017",
    "topic": "Effective prompt engineering for security",
    "scenario": "A Contoso analyst wants to get the most useful results from Copilot for Security. The analyst has been writing vague prompts like 'Tell me about security' and getting generic responses. The SOC lead teaches the analyst about effective prompt engineering.",
    "question": "Which prompt technique produces the BEST results from Copilot for Security?",
    "options": [
      "Be specific and provide context: 'Analyze the incident INC-4521 in Defender XDR, focus on the lateral movement phase, and list the affected devices with their risk levels'",
      "Write extremely short prompts: 'Security?'",
      "Use technical jargon only: 'Enumerate TTPs T1566.001 T1059.001 T1547.001 for IOC correlation matrix'",
      "Ask multiple unrelated questions in a single prompt: 'What is phishing and also how do I configure Azure Firewall and also explain quantum computing?'"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Prompt Engineering Best Practices for Security",
      "analysis": [
        "Option A is CORRECT: Effective Copilot prompts include: specificity (incident number), context (which product, which phase of investigation), focus (lateral movement), and desired output format (list with risk levels). This guidance pattern produces actionable, targeted results.",
        "Option B is INCORRECT: Vague, one-word prompts produce generic responses that are not useful for investigation. Copilot needs context to provide relevant security analysis.",
        "Option C is INCORRECT: While MITRE ATT&CK technique IDs are useful, pure jargon without context makes it harder for Copilot to understand the investigation goal. Combine technical terms with natural language context.",
        "Option D is INCORRECT: Mixing unrelated questions in one prompt confuses the conversation thread and produces unfocused responses. Keep each prompt focused on one investigation area."
      ],
      "codeSnippet": "// Good prompt patterns:\n// 1. Specific + Contextual:\n//    \"Analyze incident INC-4521 and summarize\n//     the attack chain\"\n// 2. Scoped:\n//    \"Show sign-in anomalies for john@contoso.com\n//     in the last 48 hours\"\n// 3. Action-oriented:\n//    \"Generate a KQL query to find all devices\n//     with PowerShell encoded commands\"",
      "socTip": "Use the prompt pattern: [Action] + [Target] + [Scope] + [Format]. Example: 'Summarize' (action) 'incident INC-123' (target) 'focusing on email delivery' (scope) 'as a timeline' (format).",
      "docRef": "Microsoft Learn: Prompting tips for Copilot for Security"
    }
  },
  {
    "id": "copilot-018",
    "topic": "Copilot usage monitoring and reporting",
    "scenario": "After deploying Copilot for Security for 3 months, Fabrikam's CISO wants to measure adoption and ROI. The CISO needs data on which analysts are using Copilot, how many prompts are submitted, which plugins are invoked most frequently, and overall SCU consumption.",
    "question": "Where can the CISO find Copilot for Security usage data?",
    "options": [
      "The Copilot for Security Usage dashboard in the Copilot settings, which shows SCU consumption trends, prompt volume, active users, plugin invocation frequency, and session metrics",
      "The Azure Cost Management portal only, which shows billing but no usage patterns",
      "There is no built-in usage reporting — administrators must build custom reports from scratch",
      "The Microsoft 365 admin center usage reports, which track Teams and Email usage but not Copilot"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security Usage Dashboard",
      "analysis": [
        "Option A is CORRECT: Copilot for Security includes a built-in Usage dashboard accessible to Copilot Owners. It provides: SCU consumption over time, number of prompts per user, most-used plugins, session count, and peak usage periods. This data supports ROI measurement and capacity planning.",
        "Option B is INCORRECT: Azure Cost Management shows billing costs for SCUs but lacks the operational usage details (which analysts, which plugins, how many prompts) needed for adoption measurement.",
        "Option C is INCORRECT: Copilot provides built-in usage reporting. Custom reports are not required for standard adoption and consumption metrics.",
        "Option D is INCORRECT: M365 admin center usage reports do not currently include Copilot for Security metrics. Copilot usage is tracked within its own settings dashboard."
      ],
      "codeSnippet": "// Usage dashboard metrics:\n// - Total SCUs consumed (current billing period)\n// - SCU consumption by day/week/month\n// - Active users count\n// - Total prompts submitted\n// - Plugin invocation breakdown:\n//   - Defender XDR: 45%\n//   - Sentinel: 25%\n//   - Threat Intel: 15%\n//   - Custom plugins: 15%",
      "socTip": "Review usage data monthly to identify underutilized plugins and analysts who aren't using Copilot. Schedule training sessions focused on the capabilities they're not leveraging.",
      "docRef": "Microsoft Learn: Monitor usage in Copilot for Security"
    }
  },
  {
    "id": "copilot-019",
    "topic": "Copilot in Microsoft Purview",
    "scenario": "A Litware compliance officer receives a DLP alert indicating that an employee may have shared sensitive financial data via email. The officer opens the DLP alert in Microsoft Purview and uses the embedded Copilot to investigate.",
    "question": "How does Copilot help with DLP alert investigation in Purview?",
    "options": [
      "Copilot summarizes the DLP alert context — what sensitive data was detected, which policy was triggered, who sent it, who received it, the data classification labels, and whether the action was blocked or allowed — with recommendations for follow-up",
      "Copilot automatically deletes all emails containing sensitive data",
      "Copilot only provides a link to the DLP policy documentation",
      "Copilot creates a legal hold on the employee's mailbox without administrator review"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot-Assisted DLP Investigation",
      "analysis": [
        "Option A is CORRECT: Copilot in Purview provides context-rich DLP alert summaries: the sensitive information types detected (credit card numbers, SSNs), the triggered policy name and rule, sender/recipient details, the data classification, the action taken (block, allow with override), and recommended investigation steps.",
        "Option B is INCORRECT: Copilot never automatically deletes data. It provides analysis and recommendations, but destructive actions require explicit administrator action.",
        "Option C is INCORRECT: Copilot provides actionable, contextual summaries of the specific alert, not generic documentation links.",
        "Option D is INCORRECT: Copilot does not create legal holds. Legal holds are a deliberate administrative action in eDiscovery that require explicit approval and cannot be triggered by an AI assistant."
      ],
      "codeSnippet": "// Copilot DLP alert summary example:\n// Alert: DLP policy 'Financial Data Protection'\n// Rule: 'Block external sharing of credit cards'\n// Sender: jane@litware.com\n// Recipient: external@partner.com\n// Sensitive data: 3 credit card numbers detected\n// Action: Email blocked, sender notified\n// Recommendation: Review jane's recent email\n//   activity for patterns of data exfiltration",
      "socTip": "When investigating DLP alerts, ask Copilot 'Has this user triggered other DLP policies in the past 30 days?' to identify repeat offenders who may need additional training or closer monitoring.",
      "docRef": "Microsoft Learn: Copilot in Microsoft Purview"
    }
  },
  {
    "id": "copilot-020",
    "topic": "Logic App and Power Automate integration",
    "scenario": "Contoso wants to automate their SOC workflow so that whenever a high-severity incident is created in Defender XDR, Copilot for Security automatically generates an incident summary and posts it to the SOC's Teams channel.",
    "question": "How can Contoso automate Copilot for Security prompts?",
    "options": [
      "Use the Copilot for Security connector in Logic Apps or Power Automate to create automated workflows that submit prompts to Copilot, receive responses, and route them to Teams, email, or ticketing systems",
      "Copilot for Security cannot be automated — it only works with manual prompts",
      "Schedule a cron job on a server to open the Copilot web page and type prompts using RPA",
      "Use Microsoft Graph API to directly query Copilot's internal database"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security Automation with Logic Apps",
      "analysis": [
        "Option A is CORRECT: Copilot for Security has a Logic Apps / Power Automate connector that allows automated prompt submission and response handling. This enables workflows like: incident created → Copilot generates summary → summary posted to Teams → ticket updated in ServiceNow.",
        "Option B is INCORRECT: Copilot for Security is designed for both interactive and automated use. The Logic Apps connector provides a formal automation pathway.",
        "Option C is INCORRECT: RPA (robotic process automation) to control a web browser is fragile and unsupported. The official Logic Apps connector provides a reliable, API-level integration.",
        "Option D is INCORRECT: Copilot's responses are generated through its AI orchestrator, not stored in a queryable database. The correct integration is through the Logic Apps connector or the Copilot for Security API."
      ],
      "codeSnippet": "// Logic App workflow:\n// Trigger: Defender XDR incident created (High severity)\n// Action 1: Copilot for Security - Submit prompt\n//   Prompt: \"Summarize incident {incidentId}\"\n// Action 2: Parse Copilot response\n// Action 3: Post to Teams channel\n//   Message: Copilot summary + incident link\n// Action 4: Update ServiceNow ticket with summary",
      "socTip": "Create an automated Copilot workflow for shift handoffs: at the end of each shift, auto-generate summaries of all active high-severity incidents and post them to the incoming shift's Teams channel.",
      "docRef": "Microsoft Learn: Automate Copilot for Security with Logic Apps"
    }
  },
  {
    "id": "copilot-021",
    "topic": "Copilot for Security data residency and privacy",
    "scenario": "Adatum Corporation operates in the European Union and must comply with GDPR. The compliance team is concerned about where Copilot for Security processes and stores data, and whether customer data is used to train Microsoft's AI models.",
    "question": "How does Microsoft handle data privacy in Copilot for Security?",
    "options": [
      "Customer data processed by Copilot stays within the organization's geographic region, is not used to train Microsoft's foundation models, and prompts/responses are stored within the tenant's boundary with standard Microsoft compliance certifications",
      "All data is processed in US data centers regardless of the customer's location",
      "Customer prompts are shared with Microsoft's AI research team for model improvement",
      "Copilot stores all session data indefinitely in a global shared database"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data Privacy and Residency in Copilot for Security",
      "analysis": [
        "Option A is CORRECT: Microsoft's data privacy commitments for Copilot for Security include: geographic data residency (data processed in the customer's region when possible), no use of customer data to train foundation models, data stored within tenant boundaries, and compliance with SOC 2, ISO 27001, GDPR, and other certifications.",
        "Option B is INCORRECT: Microsoft respects data residency requirements and processes data in the customer's geographic region where capacity is available.",
        "Option C is INCORRECT: Microsoft explicitly commits that customer data (prompts, responses, organizational data) is not used to train or improve the underlying AI models.",
        "Option D is INCORRECT: Session data is stored within the customer's tenant boundary, not in a global shared database. Retention policies and data lifecycle controls apply."
      ],
      "codeSnippet": "// Data privacy controls in Copilot:\n// - Data residency: EU, US, UK, other regions\n// - Training exclusion: Customer data NOT used\n//   to train Microsoft AI models\n// - Compliance: SOC 2, ISO 27001, GDPR\n// - Encryption: At rest and in transit\n// - Access control: RBAC with Entra ID\n// - Audit logging: All prompts and responses logged",
      "socTip": "Review Copilot's data handling practices with your DPO (Data Protection Officer) before deployment. Ensure the selected data region aligns with your organization's data sovereignty requirements.",
      "docRef": "Microsoft Learn: Data privacy in Copilot for Security"
    }
  },
  {
    "id": "copilot-022",
    "topic": "Vulnerability impact assessment with Copilot",
    "scenario": "A new critical CVE affecting Microsoft Exchange Server is published. Fabrikam's SOC needs to quickly assess how many of their Exchange servers are affected and what the potential impact is.",
    "question": "How can Copilot for Security help assess vulnerability impact?",
    "options": [
      "Ask Copilot to assess the CVE impact — it queries Defender for Endpoint vulnerability data, MDTI for exploitation intelligence, and Threat Analytics for exposure metrics, then provides a natural language assessment of affected assets and remediation priority",
      "Copilot can only explain what the CVE does in general terms but cannot check your specific environment",
      "Copilot requires you to manually provide a list of affected servers before it can assess impact",
      "Copilot does not have access to vulnerability data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Assisted Vulnerability Impact Assessment",
      "analysis": [
        "Option A is CORRECT: Copilot combines data from multiple sources: Defender for Endpoint's threat and vulnerability management (which devices are vulnerable), MDTI (is the CVE being actively exploited in the wild?), and Threat Analytics (organizational exposure metrics). It synthesizes this into an actionable impact assessment.",
        "Option B is INCORRECT: Copilot can query your environment's data through the Defender for Endpoint plugin to identify specific affected devices, not just explain the CVE in general terms.",
        "Option C is INCORRECT: Copilot proactively queries Defender for Endpoint's vulnerability data to identify affected assets. Manual server lists are not needed.",
        "Option D is INCORRECT: Copilot has access to vulnerability data through the Defender for Endpoint and MDTI plugins, which include TVM (Threat and Vulnerability Management) data."
      ],
      "codeSnippet": "// Example Copilot prompt:\n// \"Assess the impact of CVE-2026-XXXX on my\n//  organization. How many devices are affected\n//  and is this being actively exploited?\"\n//\n// Response includes:\n// - Affected devices count and names\n// - Exploit status: Active/Not active\n// - CVSS score and severity\n// - Remediation: Patch available/not available\n// - Priority: Critical — patch within 24h",
      "socTip": "When a critical CVE is published, ask Copilot immediately: 'Is CVE-XXXX being actively exploited and how many of my devices are vulnerable?' This gives you a 30-second exposure assessment that would otherwise take hours.",
      "docRef": "Microsoft Learn: Vulnerability management with Copilot"
    }
  },
  {
    "id": "copilot-023",
    "topic": "Copilot for Security and Microsoft Sentinel",
    "scenario": "A Northwind Traders analyst uses Microsoft Sentinel as their primary SIEM. The analyst opens Copilot for Security and wants to investigate Sentinel incidents, query Sentinel tables, and analyze Sentinel workbook data.",
    "question": "How does Copilot for Security integrate with Microsoft Sentinel?",
    "options": [
      "Through the Microsoft Sentinel plugin, which allows Copilot to query Sentinel workspaces, summarize Sentinel incidents, generate KQL queries for Sentinel tables, and analyze hunting results — all from natural language prompts",
      "Copilot cannot access Sentinel data — it only works with Defender XDR",
      "Integration requires exporting Sentinel data to a CSV file and uploading it to Copilot",
      "Copilot can only read Sentinel dashboards but cannot query raw log data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Sentinel Plugin for Copilot",
      "analysis": [
        "Option A is CORRECT: The Microsoft Sentinel plugin enables Copilot to: query any table in your Sentinel workspace using natural language, summarize Sentinel incidents, list recent analytics rule matches, and generate KQL queries against Sentinel-specific tables (SecurityEvent, Syslog, CommonSecurityLog, etc.).",
        "Option B is INCORRECT: Copilot for Security explicitly supports Microsoft Sentinel through a dedicated plugin. Sentinel is one of the core Microsoft security products that Copilot integrates with.",
        "Option C is INCORRECT: No CSV exports are needed. The Sentinel plugin queries your Log Analytics workspace directly through the API in real-time.",
        "Option D is INCORRECT: Copilot can query raw log data in Sentinel tables, not just read dashboards. It generates and executes KQL queries against your Sentinel workspace."
      ],
      "codeSnippet": "// Copilot prompts for Sentinel:\n// \"Show me the top 10 Sentinel incidents this week\"\n// \"Query the SecurityEvent table for failed\n//  logon events from external IPs\"\n// \"Generate a KQL hunting query for DNS tunneling\"\n// \"Summarize Sentinel incident #12345\"\n// \"What analytics rules fired today?\"",
      "socTip": "If you use both Sentinel and Defender XDR, Copilot can correlate data across both platforms in a single conversation. Ask 'Show me Sentinel alerts that correlate with Defender XDR incident INC-567'.",
      "docRef": "Microsoft Learn: Sentinel plugin in Copilot for Security"
    }
  },
  {
    "id": "copilot-024",
    "topic": "Microsoft built-in promptbooks",
    "scenario": "Litware's SOC team is new to Copilot for Security. Instead of creating custom promptbooks from scratch, they want to use pre-built investigation workflows to get started immediately.",
    "question": "Does Microsoft provide pre-built promptbooks with Copilot for Security?",
    "options": [
      "Yes — Microsoft includes built-in promptbooks covering common security scenarios like vulnerability impact assessment, incident investigation, suspicious script analysis, threat actor profiling, and user risk assessment",
      "No — all promptbooks must be created manually by each organization",
      "Pre-built promptbooks are only available through a paid add-on subscription",
      "Pre-built promptbooks are only available for organizations with more than 1000 users"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Microsoft Built-in Promptbooks",
      "analysis": [
        "Option A is CORRECT: Microsoft provides a library of built-in promptbooks that cover common security investigation scenarios. These include vulnerability impact assessment, suspicious script analysis, incident investigation, threat actor research, and more. Organizations can use them as-is or customize them.",
        "Option B is INCORRECT: While organizations can create custom promptbooks, Microsoft provides a starter library of built-in promptbooks that are available immediately after deployment.",
        "Option C is INCORRECT: Built-in promptbooks are included with the Copilot for Security service at no additional cost beyond the SCU provisioning.",
        "Option D is INCORRECT: Built-in promptbooks are available to all Copilot for Security customers regardless of organization size."
      ],
      "codeSnippet": "// Built-in promptbook examples:\n// 1. Vulnerability Impact Assessment\n//    - Input: CVE ID\n//    - Steps: Check MDTI, query devices, assess risk\n// 2. Incident Investigation\n//    - Input: Incident ID\n//    - Steps: Summarize, analyze entities, recommend\n// 3. Script Analysis\n//    - Input: Script content\n//    - Steps: Decode, explain, extract IOCs",
      "socTip": "Start with built-in promptbooks for your first month, then create custom ones based on your organization's specific investigation patterns and the gaps you identify in the built-in options.",
      "docRef": "Microsoft Learn: Promptbooks in Copilot for Security"
    }
  },
  {
    "id": "copilot-025",
    "topic": "Copilot for Security API",
    "scenario": "Contoso's security engineering team wants to integrate Copilot for Security into their custom SOAR platform. They need to programmatically submit prompts and receive responses without using the web interface.",
    "question": "How can the engineering team programmatically interact with Copilot for Security?",
    "options": [
      "Use the Copilot for Security API, which provides REST endpoints for submitting prompts, receiving responses, managing sessions, and invoking promptbooks programmatically with standard OAuth 2.0 authentication",
      "Screen-scrape the Copilot web interface using Selenium or Playwright",
      "Use the Microsoft Graph API's /security/copilot endpoint",
      "Copilot for Security does not have a programmatic API"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security API",
      "analysis": [
        "Option A is CORRECT: Copilot for Security provides REST APIs for programmatic interaction. The API supports: submitting prompts, managing sessions, executing promptbooks, and retrieving responses. Authentication uses OAuth 2.0 with Azure AD tokens.",
        "Option B is INCORRECT: Screen-scraping is fragile, unsupported, and violates Microsoft's terms of service. The official API provides a reliable, versioned programmatic interface.",
        "Option C is INCORRECT: While Microsoft Graph provides security-related APIs, the Copilot for Security API has its own endpoint structure separate from Graph.",
        "Option D is INCORRECT: Copilot for Security does provide programmatic APIs for integration with custom tools and workflows."
      ],
      "codeSnippet": "// Copilot for Security API example (conceptual):\n// POST /api/sessions\n// Authorization: Bearer {token}\n// Body: { \"prompt\": \"Summarize incident INC-123\" }\n//\n// Response:\n// { \"sessionId\": \"abc-123\",\n//   \"response\": \"This incident involves...\",\n//   \"pluginsUsed\": [\"DefenderXDR\"] }",
      "socTip": "When integrating with custom SOAR platforms, implement rate limiting in your API client. SCU capacity is shared across all users and API calls — excessive programmatic usage can impact interactive analyst sessions.",
      "docRef": "Microsoft Learn: Copilot for Security API"
    }
  },
  {
    "id": "copilot-026",
    "topic": "Handling Copilot hallucinations and verification",
    "scenario": "An Adatum analyst asks Copilot for Security to summarize a threat actor. Copilot provides a detailed response, but the analyst is unsure if all the information is accurate. The analyst wants to verify Copilot's output.",
    "question": "What is the recommended approach for handling potential inaccuracies in Copilot responses?",
    "options": [
      "Always verify critical findings against the source data — Copilot provides references and citations that link back to the original data sources, and analysts should cross-reference important claims before taking action",
      "Accept all Copilot responses as 100% accurate since it's powered by advanced AI",
      "Ignore any response that doesn't include a confidence percentage",
      "File a support ticket with Microsoft every time you receive a suspicious response"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Response Verification and Source Citations",
      "analysis": [
        "Option A is CORRECT: Copilot's responses should be treated as AI-assisted analysis, not absolute truth. Copilot provides source citations and references that analysts should verify. Critical decisions (isolating devices, disabling accounts) should always be validated against the actual data in the product portals.",
        "Option B is INCORRECT: No AI system is 100% accurate. LLMs can hallucinate (generate plausible but incorrect information). Analyst verification is essential, especially for high-impact decisions.",
        "Option C is INCORRECT: Copilot doesn't always provide explicit confidence percentages. Analysts should verify claims regardless of whether a confidence score is displayed.",
        "Option D is INCORRECT: Occasional inaccuracies are expected with any AI system. Use the feedback mechanism (thumbs up/down) within Copilot to help Microsoft improve accuracy, rather than filing support tickets."
      ],
      "codeSnippet": "// Verification workflow:\n// 1. Read Copilot's response\n// 2. Click source citations to view original data\n// 3. Cross-reference claims in the product portal\n// 4. For critical decisions:\n//    - Verify device names exist in your inventory\n//    - Confirm user accounts are real\n//    - Validate IOCs against threat intel sources\n// 5. Provide feedback (thumbs up/down)",
      "socTip": "Use the thumbs up/down feedback buttons on every Copilot response. This helps Microsoft tune the model and improves accuracy over time for your organization's specific data patterns.",
      "docRef": "Microsoft Learn: Responsible AI in Copilot for Security"
    }
  },
  {
    "id": "copilot-027",
    "topic": "Copilot for Security and third-party plugins",
    "scenario": "Fabrikam uses CrowdStrike for endpoint detection on non-Windows devices and Splunk for SIEM. The security team wants Copilot for Security to also query data from these third-party tools.",
    "question": "Can Copilot for Security integrate with non-Microsoft security products?",
    "options": [
      "Yes — through third-party plugins that use OpenAPI specifications and API connectors, Copilot can query non-Microsoft security tools like CrowdStrike, Splunk, and ServiceNow alongside Microsoft products",
      "No — Copilot for Security only works with Microsoft security products",
      "Only through manual copy-paste of data between platforms",
      "Third-party integration requires a separate Microsoft product called Azure Logic Apps, which has no direct Copilot connection"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Third-Party Plugin Ecosystem",
      "analysis": [
        "Option A is CORRECT: Copilot for Security supports third-party plugins through OpenAPI specifications. Security vendors like CrowdStrike, Splunk, ServiceNow, and others can develop plugins that allow Copilot to query their platforms. Custom plugins can also be built for proprietary tools.",
        "Option B is INCORRECT: Copilot is explicitly designed to be vendor-agnostic through its plugin architecture. It can integrate with any security tool that has an API.",
        "Option C is INCORRECT: Manual copy-paste is not required when proper plugins are configured. Copilot queries third-party tools automatically through their API integrations.",
        "Option D is INCORRECT: While Logic Apps can complement Copilot workflows, third-party plugins are a native Copilot capability that doesn't require a separate product."
      ],
      "codeSnippet": "// Third-party plugin ecosystem:\n// Available/buildable plugins:\n// - CrowdStrike Falcon\n// - Splunk Enterprise Security\n// - ServiceNow Security Operations\n// - Palo Alto Networks XSOAR\n// - Rapid7 InsightConnect\n// - Custom OpenAPI plugins\n// All configured in Copilot > Settings > Plugins",
      "socTip": "If your organization uses a multi-vendor security stack, prioritize enabling plugins for your highest-volume data sources first. This gives Copilot the broadest investigation context.",
      "docRef": "Microsoft Learn: Third-party plugins in Copilot for Security"
    }
  },
  {
    "id": "copilot-028",
    "topic": "Identity risk summarization",
    "scenario": "A Northwind Traders analyst receives multiple Entra ID Protection alerts for a senior executive: impossible travel, anomalous token, and unfamiliar sign-in properties. The analyst asks Copilot to provide a comprehensive risk assessment for this identity.",
    "question": "What does Copilot's identity risk summary include?",
    "options": [
      "A consolidated view of all risk detections for the user, timeline of suspicious sign-ins, assessment of whether the account is likely compromised, affected resources, and specific remediation steps like 'Force MFA re-registration' or 'Revoke refresh tokens'",
      "Only the number of risk detections without context",
      "A prediction of the user's future risk level based on machine learning",
      "The user's complete browsing history and personal files"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Comprehensive Identity Risk Assessment",
      "analysis": [
        "Option A is CORRECT: Copilot aggregates all identity risk signals and presents a narrative: what risk detections occurred, when, the assessed compromise likelihood, what resources the user accessed during the suspicious period, and specific remediation actions tailored to the risk type.",
        "Option B is INCORRECT: Copilot provides rich contextual analysis, not just detection counts. It explains the relationships between detections and assesses the overall compromise likelihood.",
        "Option C is INCORRECT: Copilot provides analysis of past and current risk signals, not predictive future risk scoring. Future risk prediction is a function of Entra ID Protection, not Copilot.",
        "Option D is INCORRECT: Copilot does not access personal browsing history or files. It focuses on security-relevant identity signals like sign-in events, risk detections, and access patterns."
      ],
      "codeSnippet": "// Copilot identity risk prompt:\n// \"Assess the risk for executive@northwind.com\n//  and recommend actions\"\n//\n// Response:\n// Risk Level: HIGH - Likely compromised\n// Detections: Impossible travel (NYC→Tokyo),\n//   anomalous token, unfamiliar sign-in\n// Accessed: SharePoint, Teams, Exchange\n// Remediation:\n// 1. Revoke all refresh tokens immediately\n// 2. Force MFA re-registration\n// 3. Reset password\n// 4. Review last 48h of email activity",
      "socTip": "For executive account investigations, always ask Copilot to check for email forwarding rules created during the suspicious period. Attackers often create forwarding rules to maintain access even after credential reset.",
      "docRef": "Microsoft Learn: Identity risk assessment with Copilot"
    }
  },
  {
    "id": "copilot-029",
    "topic": "Copilot for Security provisioning and setup",
    "scenario": "Contoso's CISO approves the purchase of Copilot for Security. The security architect needs to understand the prerequisites and setup process before the SOC team can start using it.",
    "question": "What are the prerequisites for deploying Copilot for Security?",
    "options": [
      "An Azure subscription for SCU provisioning, Microsoft Entra ID for authentication, at least one Microsoft security product (Defender XDR, Sentinel, etc.) for data, and Copilot Owner role assignment for the initial administrator",
      "Only a Microsoft 365 E5 license — Copilot is automatically enabled",
      "A dedicated on-premises server running Windows Server 2022 with 64GB RAM",
      "A minimum of 500 users in the organization"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security Deployment Prerequisites",
      "analysis": [
        "Option A is CORRECT: The key prerequisites are: (1) Azure subscription to provision SCUs, (2) Entra ID tenant for authentication and RBAC, (3) at least one Microsoft security product for data (Defender XDR, Sentinel, Intune, Purview), and (4) a Global Admin or Security Admin to complete initial setup and assign the Copilot Owner role.",
        "Option B is INCORRECT: M365 E5 provides the underlying security products (Defender for Endpoint, Defender for Office 365) but does not include Copilot for Security. SCUs must be provisioned separately through an Azure subscription.",
        "Option C is INCORRECT: Copilot for Security is a cloud-native SaaS service. No on-premises servers are required. All processing happens in Microsoft's cloud infrastructure.",
        "Option D is INCORRECT: There is no minimum user count requirement. Even small organizations can deploy Copilot for Security with as few as 1 SCU."
      ],
      "codeSnippet": "// Copilot for Security setup checklist:\n// 1. Azure subscription (for SCU billing)\n// 2. Entra ID tenant (for authentication)\n// 3. Security product (Defender XDR, Sentinel)\n// 4. Global Admin / Security Admin role\n// 5. Navigate to security.microsoft.com/copilot\n// 6. Provision SCUs (minimum 1)\n// 7. Enable plugins for your security products\n// 8. Assign Copilot Owner/Contributor roles\n// 9. Create initial promptbooks\n// 10. Train SOC analysts",
      "socTip": "Start with a pilot group of 3-5 experienced analysts. Have them use Copilot for 2 weeks and document which prompts work well and which don't. Use their feedback to create organizational promptbooks before broader rollout.",
      "docRef": "Microsoft Learn: Get started with Copilot for Security"
    }
  },
  {
    "id": "copilot-030",
    "topic": "Copilot for Security and compliance investigations",
    "scenario": "Litware's compliance team uses Microsoft Purview for eDiscovery and insider risk management. A compliance investigator wants to use Copilot to help summarize a large eDiscovery case with thousands of documents.",
    "question": "How can Copilot assist with compliance investigations in Purview?",
    "options": [
      "Copilot can summarize eDiscovery case details, explain DLP policy matches, describe insider risk indicators, and help navigate complex compliance data — reducing the time needed to understand large investigation datasets",
      "Copilot can only be used for security operations, not compliance",
      "Copilot automatically generates legal reports that can be submitted to courts",
      "Copilot replaces the compliance team's need for legal counsel"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot in Compliance Workflows",
      "analysis": [
        "Option A is CORRECT: Copilot's Purview integration extends to compliance scenarios: eDiscovery case summaries, DLP alert analysis, insider risk signal explanation, communication compliance review assistance, and data lifecycle management. It helps investigators navigate large datasets more efficiently.",
        "Option B is INCORRECT: Copilot for Security's capabilities extend beyond security operations into compliance through the Purview plugin. Microsoft explicitly designed Copilot to assist with both security and compliance workflows.",
        "Option C is INCORRECT: Copilot provides analytical summaries for internal use, not court-admissible legal reports. Legal report generation requires proper legal tools and review by qualified attorneys.",
        "Option D is INCORRECT: Copilot is a tool that assists compliance teams — it does not replace the need for legal counsel. Complex compliance decisions require human legal expertise."
      ],
      "codeSnippet": "// Copilot compliance prompts:\n// \"Summarize the eDiscovery case 'Project Phoenix'\"\n// \"What insider risk indicators were detected\n//  for user@litware.com?\"\n// \"Explain why this email triggered the\n//  communication compliance policy\"\n// \"List all DLP incidents for the finance\n//  department this quarter\"",
      "socTip": "Use Copilot to triage large eDiscovery review sets. Ask it to summarize document themes and identify key documents, then have human reviewers focus on the flagged items rather than reviewing everything manually.",
      "docRef": "Microsoft Learn: Copilot in Microsoft Purview"
    }
  },
  {
    "id": "copilot-031",
    "topic": "Copilot for Security feedback and improvement",
    "scenario": "An Adatum analyst receives a Copilot response that contains incorrect information about a Defender for Endpoint feature. The analyst wants to help improve Copilot's accuracy for future queries.",
    "question": "How can analysts provide feedback on Copilot responses to improve accuracy?",
    "options": [
      "Use the thumbs up/down buttons on each response, and optionally add written feedback explaining what was incorrect — this feedback is used by Microsoft to improve Copilot's accuracy over time",
      "Email Microsoft Support with the incorrect response",
      "Post the incorrect response on the Microsoft Tech Community forum",
      "There is no feedback mechanism — accept all responses as final"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Feedback Loop for Copilot Improvement",
      "analysis": [
        "Option A is CORRECT: Each Copilot response has thumbs up/down feedback buttons. Analysts can rate the response and optionally provide written feedback. Microsoft uses this feedback to improve the AI model's accuracy and relevance for security-specific queries.",
        "Option B is INCORRECT: While Microsoft Support can help with product issues, the built-in feedback mechanism is the primary and most efficient way to report response quality issues.",
        "Option C is INCORRECT: Community forums are for general discussion, not structured feedback. The in-product feedback buttons provide a direct channel to Microsoft's AI improvement pipeline.",
        "Option D is INCORRECT: Copilot explicitly includes a feedback mechanism. Providing feedback is encouraged and helps improve the service for all customers."
      ],
      "codeSnippet": "// Feedback workflow:\n// 1. Read Copilot's response\n// 2. Click thumbs up (helpful) or thumbs down\n// 3. If thumbs down, optionally describe:\n//    - What was wrong\n//    - What the correct answer should be\n//    - Which plugin provided incorrect data\n// 4. Submit feedback\n// Feedback does NOT share your sensitive data",
      "socTip": "Make it a team habit to provide feedback on every Copilot response. Even thumbs-up on good responses helps Microsoft understand what works well. Teams that provide consistent feedback see improved response quality over time.",
      "docRef": "Microsoft Learn: Provide feedback in Copilot for Security"
    }
  },
  {
    "id": "copilot-032",
    "topic": "Copilot for incident report generation",
    "scenario": "After resolving a major security incident, a Contoso analyst needs to generate a formal incident report for management. The analyst wants Copilot to help compile the report from the investigation data.",
    "question": "How can Copilot assist with post-incident reporting?",
    "options": [
      "Ask Copilot to generate an incident report that includes the attack timeline, affected assets, TTPs used, remediation actions taken, and lessons learned — compiled from the investigation session data",
      "Copilot can only provide real-time investigation assistance, not post-incident reports",
      "Copilot generates reports only in STIX format for threat sharing",
      "Copilot sends the report directly to the CISO without analyst review"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Assisted Incident Report Generation",
      "analysis": [
        "Option A is CORRECT: Copilot can compile investigation findings into a structured incident report. The analyst can ask Copilot to summarize the full investigation (from the session context) into a report format covering: executive summary, timeline, affected assets, techniques, response actions, and recommendations.",
        "Option B is INCORRECT: Copilot is useful for both real-time investigation AND post-incident activities like report generation, lessons learned documentation, and improvement recommendations.",
        "Option C is INCORRECT: Copilot generates human-readable reports, not machine-readable STIX format. STIX export is handled by threat intelligence platforms, not Copilot.",
        "Option D is INCORRECT: Copilot never sends reports without analyst review. The analyst reviews, edits, and distributes the generated report through their normal channels."
      ],
      "codeSnippet": "// Post-incident report prompt:\n// \"Generate an executive incident report for\n//  the investigation in this session, including:\n//  1. Executive summary\n//  2. Attack timeline\n//  3. Affected assets and users\n//  4. MITRE ATT&CK techniques observed\n//  5. Remediation actions taken\n//  6. Recommendations to prevent recurrence\"",
      "socTip": "Use Copilot to generate the first draft of incident reports, then review and enhance with organizational context. This reduces report writing time from hours to minutes while maintaining quality.",
      "docRef": "Microsoft Learn: Incident reports with Copilot for Security"
    }
  },
  {
    "id": "copilot-033",
    "topic": "Multi-session investigation continuity",
    "scenario": "A Fabrikam analyst starts investigating a phishing campaign in Session 1 and discovers 3 compromised accounts. The next day, the analyst opens a new Session 2 and wants Copilot to reference findings from Session 1.",
    "question": "Can Copilot reference information from previous sessions?",
    "options": [
      "Copilot can access previous session context when the analyst references or pins a prior session, allowing continuity across investigation phases",
      "Each session is completely isolated with no way to reference prior sessions",
      "Copilot automatically merges all sessions into one continuous conversation",
      "Previous sessions are deleted after 24 hours"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Session Investigation Continuity",
      "analysis": [
        "Option A is CORRECT: Copilot sessions persist and analysts can reference previous sessions. Pinning important sessions makes them easily accessible. While each new session starts fresh, analysts can refer back to previous session findings.",
        "Option B is INCORRECT: Sessions are not completely isolated. Analysts can navigate between sessions and reference findings from prior investigations.",
        "Option C is INCORRECT: Sessions remain separate for organizational purposes but are accessible from the session list. They are not auto-merged.",
        "Option D is INCORRECT: Sessions persist beyond 24 hours and are accessible from the session history."
      ],
      "codeSnippet": "// Session management tips:\n// - Pin critical investigation sessions\n// - Name sessions descriptively\n// - Reference prior session findings\n//   in new session prompts",
      "socTip": "Name investigation sessions with the incident number and date for easy retrieval during follow-up investigations.",
      "docRef": "Microsoft Learn: Navigate Copilot for Security"
    }
  },
  {
    "id": "copilot-034",
    "topic": "Copilot for threat hunting assistance",
    "scenario": "A Northwind Traders analyst conducts proactive threat hunting. Instead of writing complex KQL queries, the analyst describes the hunting hypothesis to Copilot in natural language.",
    "question": "How does Copilot for Security assist with proactive threat hunting?",
    "options": [
      "Copilot translates hunting hypotheses from natural language into executable KQL queries, runs them against Advanced Hunting data, and helps interpret the results — enabling analysts without deep KQL expertise to conduct effective hunts",
      "Copilot cannot assist with proactive hunting — only reactive incident investigation",
      "Copilot provides hunting queries only for pre-defined threat scenarios",
      "Copilot requires a separate Threat Hunting license to use hunting features"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Assisted Threat Hunting",
      "analysis": [
        "Option A is CORRECT: Copilot's natural language to KQL translation makes proactive hunting accessible. Analysts describe what they want to find, Copilot generates the query, and helps analyze the results — lowering the barrier to entry for effective threat hunting.",
        "Option B is INCORRECT: Copilot supports both reactive investigation and proactive hunting through its natural language to KQL capability.",
        "Option C is INCORRECT: Copilot can generate queries for any hunting hypothesis, not just pre-defined scenarios. The natural language interface allows unlimited query generation.",
        "Option D is INCORRECT: Threat hunting with Copilot is included in the standard SCU-based billing. No separate license is required."
      ],
      "codeSnippet": "// Hunting prompt examples:\n// \"Find all devices running outdated OS versions\"\n// \"Show lateral movement via PsExec in last 7d\"\n// \"Detect DLL sideloading from temp folders\"",
      "socTip": "Start hunting sessions with broad hypotheses, then ask Copilot to refine the queries based on initial results.",
      "docRef": "Microsoft Learn: Threat hunting with Copilot"
    }
  },
  {
    "id": "copilot-035",
    "topic": "Copilot response language support",
    "scenario": "Adatum Corporation has SOC teams in multiple countries. Analysts in Japan, Germany, and Brazil want to use Copilot for Security in their native languages.",
    "question": "Does Copilot for Security support multiple languages?",
    "options": [
      "Yes — Copilot supports prompts and responses in multiple languages including English, Japanese, German, French, Portuguese, Spanish, Italian, Chinese, and Korean",
      "Copilot only supports English language prompts and responses",
      "Copilot supports multiple input languages but always responds in English",
      "Language support requires purchasing a separate translation add-on"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Multilingual Copilot for Security",
      "analysis": [
        "Option A is CORRECT: Copilot for Security supports multiple languages for both input prompts and output responses. Analysts can ask questions in their preferred language and receive answers in the same language.",
        "Option B is INCORRECT: Copilot supports multiple languages beyond English to serve global security teams.",
        "Option C is INCORRECT: Copilot responds in the language used for the prompt. It does not force English-only responses.",
        "Option D is INCORRECT: Multilingual support is built into Copilot for Security at no additional cost."
      ],
      "codeSnippet": "// Supported languages include:\n// English, Japanese, German, French,\n// Portuguese, Spanish, Italian,\n// Chinese (Simplified), Korean,\n// and more added over time",
      "socTip": "For best results in non-English languages, use clear, simple phrasing. Complex idiomatic expressions may produce less accurate results than straightforward technical descriptions.",
      "docRef": "Microsoft Learn: Copilot for Security language support"
    }
  },
  {
    "id": "copilot-036",
    "topic": "Copilot for Security evaluation and trial",
    "scenario": "Litware's CISO wants to evaluate Copilot for Security before committing to a full deployment. The CISO asks whether a trial or evaluation is available.",
    "question": "How can organizations evaluate Copilot for Security before full deployment?",
    "options": [
      "Provision a minimum of 1 SCU in Azure to start a pilot — SCUs can be scaled up or down at any time, and there is no long-term commitment. Organizations can run a focused pilot with a small team to evaluate ROI",
      "Copilot requires a 3-year enterprise agreement before any access is granted",
      "A free trial provides unlimited access for 90 days",
      "Evaluation is only available through Microsoft Partners, not direct"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot for Security Evaluation Strategy",
      "analysis": [
        "Option A is CORRECT: Organizations can start with just 1 SCU (minimum provisioning) for a focused pilot. SCUs are billed hourly and can be adjusted or deprovisioned at any time. This allows low-risk evaluation with real organizational data.",
        "Option B is INCORRECT: There is no multi-year commitment requirement. SCUs are provisioned on-demand through Azure with flexible scaling.",
        "Option C is INCORRECT: While Microsoft may offer promotional trials at times, the standard evaluation path is provisioning SCUs with flexible scaling — not an unlimited free trial.",
        "Option D is INCORRECT: Organizations can provision SCUs directly through their Azure subscription without requiring a partner."
      ],
      "codeSnippet": "// Evaluation approach:\n// 1. Provision 1 SCU in Azure (~$4/hour)\n// 2. Enable key plugins\n// 3. Select 3-5 pilot analysts\n// 4. Run for 2-4 weeks\n// 5. Measure: time saved per investigation\n// 6. Scale up or deprovision based on ROI",
      "socTip": "During evaluation, track 'time-to-investigate' metrics before and after Copilot. Most organizations see 40-60% reduction in investigation time for complex incidents.",
      "docRef": "Microsoft Learn: Get started with Copilot for Security"
    }
  },
  {
    "id": "copilot-037",
    "topic": "Copilot audit logging",
    "scenario": "Contoso's compliance team requires audit logs of all Copilot for Security usage for their SOC governance framework. They need to track which analysts submitted prompts, when, and what responses were generated.",
    "question": "Does Copilot for Security provide audit logging?",
    "options": [
      "Yes — all Copilot interactions (prompts, responses, plugin invocations, session management) are logged in the Microsoft 365 unified audit log, providing a complete audit trail for governance and compliance",
      "Copilot interactions are not logged anywhere",
      "Audit logs are only available for Copilot Owner actions, not Contributor prompts",
      "Audit logging requires a separate Microsoft Purview Audit (Premium) license"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Logging for Copilot Interactions",
      "analysis": [
        "Option A is CORRECT: Copilot for Security logs all interactions to the Microsoft 365 unified audit log. This includes: who submitted prompts, when, what plugins were invoked, session creation/sharing, and administrative actions. This supports SOC governance, compliance, and usage analytics.",
        "Option B is INCORRECT: Copilot interactions are comprehensively logged for audit and governance purposes.",
        "Option C is INCORRECT: Both Owner and Contributor activities are logged. All prompts, regardless of the user's role, are captured in the audit log.",
        "Option D is INCORRECT: Basic Copilot audit logging is available through the standard unified audit log. Advanced audit features may benefit from Purview Audit Premium, but basic logging is included."
      ],
      "codeSnippet": "// Audit log query for Copilot usage:\n// Search unified audit log:\n// Activities: CopilotInteraction\n// Date range: Last 30 days\n// Users: All SOC analysts\n//\n// Log fields: Timestamp, User, Prompt,\n//   Response, Plugins, SessionId",
      "socTip": "Set up automated audit log alerts for unusual Copilot usage patterns: excessive prompts from a single user, prompts submitted outside business hours, or access from unexpected locations.",
      "docRef": "Microsoft Learn: Audit logging in Copilot for Security"
    }
  },
  {
    "id": "copilot-038",
    "topic": "Copilot for device investigation",
    "scenario": "A Fabrikam analyst needs to quickly understand the security posture and recent activity of a specific device that was flagged by Defender for Endpoint. Instead of navigating through multiple portal pages, the analyst uses Copilot.",
    "question": "What device information can Copilot provide from a single prompt?",
    "options": [
      "A comprehensive device summary including: OS version, onboarding status, risk level, exposure score, active alerts, recent timeline events, installed software with known vulnerabilities, and logged-on users — all synthesized from Defender for Endpoint data",
      "Only the device name and IP address",
      "Only the device's antivirus scan history",
      "Copilot cannot query individual device information"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "AI-Assisted Device Investigation",
      "analysis": [
        "Option A is CORRECT: Copilot queries the Defender for Endpoint plugin to provide a comprehensive device profile: hardware/software details, security posture (risk level, exposure score), active alerts, recent process/network activity, vulnerability inventory, and logged-on users. This consolidates information from multiple portal pages into one response.",
        "Option B is INCORRECT: Copilot provides much more than basic device identification. It synthesizes security-relevant data from multiple Defender for Endpoint data sources.",
        "Option C is INCORRECT: Copilot provides holistic device security information, not just antivirus history. It covers risk, alerts, vulnerabilities, and user activity.",
        "Option D is INCORRECT: Device investigation is a core use case for Copilot's Defender for Endpoint plugin."
      ],
      "codeSnippet": "// Device investigation prompt:\n// \"Tell me about device WORKSTATION-05\"\n// \"What is the risk level and exposure score?\"\n// \"Show recent alerts and security events\"\n// \"List vulnerabilities on this device\"\n// \"Who has logged into this device recently?\"",
      "socTip": "When investigating a device, ask Copilot 'Is this device compliant with our security baseline?' to quickly identify configuration gaps that may have contributed to the security incident.",
      "docRef": "Microsoft Learn: Device investigation with Copilot"
    }
  },
  {
    "id": "copilot-039",
    "topic": "Copilot for security posture improvement",
    "scenario": "Northwind Traders' CISO asks the SOC team to use Copilot to identify areas where the organization's security posture can be improved.",
    "question": "Can Copilot for Security provide proactive security posture recommendations?",
    "options": [
      "Yes — Copilot can analyze Microsoft Secure Score, Threat Analytics exposure, and Identity Security Posture assessments to provide actionable recommendations for improving the organization's overall security posture",
      "Copilot only helps with reactive incident investigation, not proactive posture improvement",
      "Copilot's recommendations are limited to patching operating systems",
      "Proactive posture recommendations require a separate Microsoft consulting engagement"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Proactive Security Posture with Copilot",
      "analysis": [
        "Option A is CORRECT: Copilot can query Secure Score for improvement recommendations, Threat Analytics for exposure to active threats, and Identity Security Posture for AD configuration weaknesses. It synthesizes these into prioritized, actionable improvement recommendations.",
        "Option B is INCORRECT: Copilot supports both reactive (incident investigation) and proactive (posture improvement) security workflows.",
        "Option C is INCORRECT: Copilot's posture recommendations span endpoints, identity, email, cloud apps, and data — not just OS patching.",
        "Option D is INCORRECT: Copilot provides posture recommendations as a built-in capability, not through a separate consulting service."
      ],
      "codeSnippet": "// Posture improvement prompts:\n// \"What are my top 5 Secure Score improvements?\"\n// \"Which threat analytics reports show exposure?\"\n// \"What AD security issues should I fix first?\"\n// \"Show unpatched critical vulnerabilities\"",
      "socTip": "Schedule a weekly 'Copilot posture review' where a senior analyst asks Copilot to identify the top 5 security improvements. This creates a continuous improvement cycle driven by AI-assisted analysis.",
      "docRef": "Microsoft Learn: Security posture with Copilot"
    }
  },
  {
    "id": "copilot-040",
    "topic": "Copilot context window and token limits",
    "scenario": "An Adatum analyst is in a long Copilot session with 30+ prompts. The analyst notices that Copilot's responses are becoming less contextually aware of earlier prompts in the session.",
    "question": "Why might Copilot lose context in very long sessions?",
    "options": [
      "Copilot has a context window limit — very long sessions may exceed the AI model's ability to reference earlier prompts. The analyst should start a new session or summarize key findings before continuing to maintain investigation quality",
      "The analyst's internet connection is causing data loss",
      "Copilot deliberately forgets earlier prompts to protect privacy",
      "The session has expired and needs to be restarted"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Context Window Limitations",
      "analysis": [
        "Option A is CORRECT: Like all LLM-based systems, Copilot has a finite context window. Very long sessions with many prompts may exceed this window, causing earlier context to be deprioritized. Starting a new session or asking Copilot to summarize key findings helps maintain quality.",
        "Option B is INCORRECT: Network connectivity does not affect Copilot's ability to reference earlier prompts. This is an AI model limitation related to context window size.",
        "Option C is INCORRECT: Context limitation is a technical constraint of the AI model, not a deliberate privacy feature.",
        "Option D is INCORRECT: Sessions don't expire during active use. Context window limitations affect response quality but don't terminate the session."
      ],
      "codeSnippet": "// Managing long investigations:\n// 1. After 15-20 prompts, ask:\n//    \"Summarize our investigation findings so far\"\n// 2. Start a new session if context degrades\n// 3. Reference the previous session's summary\n//    in the new session's first prompt\n// 4. Use promptbooks for structured workflows",
      "socTip": "For complex investigations spanning 30+ prompts, break them into focused sessions: Session 1 (email analysis), Session 2 (endpoint investigation), Session 3 (identity assessment). This keeps each session's context sharp.",
      "docRef": "Microsoft Learn: Copilot for Security best practices"
    }
  },
  {
    "id": "copilot-041",
    "topic": "Copilot for regulatory compliance queries",
    "scenario": "Litware's compliance officer needs to understand whether the organization's current Microsoft 365 configuration meets GDPR Article 32 requirements for data security. Instead of reading hundreds of pages of documentation, the officer asks Copilot.",
    "question": "Can Copilot for Security help with regulatory compliance questions?",
    "options": [
      "Yes — Copilot can explain how Microsoft security products map to specific regulatory requirements (GDPR, HIPAA, PCI-DSS, SOC 2), assess current configuration against compliance frameworks, and identify gaps in policy coverage",
      "Copilot cannot answer regulatory or compliance questions",
      "Copilot provides legal advice that replaces the need for compliance consultants",
      "Copilot only supports US regulatory frameworks, not international ones"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Regulatory Compliance Assistance",
      "analysis": [
        "Option A is CORRECT: Copilot can explain how Microsoft security controls map to regulatory requirements, describe which product features address specific compliance articles, and help identify configuration gaps. It leverages Microsoft's compliance documentation and Purview compliance manager data.",
        "Option B is INCORRECT: Copilot can answer compliance-related questions by referencing Microsoft's compliance documentation and Purview data.",
        "Option C is INCORRECT: Copilot provides informational compliance guidance, not legal advice. Organizations should always consult qualified compliance professionals for regulatory decisions.",
        "Option D is INCORRECT: Copilot supports international regulatory frameworks including GDPR, ISO 27001, and other non-US standards."
      ],
      "codeSnippet": "// Compliance prompts:\n// \"How does Microsoft 365 support GDPR Art. 32?\"\n// \"What Purview compliance score is our tenant?\"\n// \"Which DLP policies address PCI-DSS Req. 4?\"\n// \"Show our compliance posture for ISO 27001\"",
      "socTip": "Use Copilot to create compliance mapping documents that show which Microsoft security controls address which regulatory requirements. This is valuable for audit preparation.",
      "docRef": "Microsoft Learn: Compliance with Copilot for Security"
    }
  },
  {
    "id": "copilot-042",
    "topic": "Copilot for Security embedded in Defender for Cloud",
    "scenario": "Contoso's cloud security team uses Microsoft Defender for Cloud to monitor Azure, AWS, and GCP workloads. The team wants to use Copilot to understand cloud security recommendations and prioritize remediation.",
    "question": "How does the embedded Copilot in Defender for Cloud assist with cloud security?",
    "options": [
      "Copilot summarizes security recommendations, explains why specific resources are vulnerable, provides risk context for cloud misconfigurations, and helps prioritize remediation based on exposure and exploitability across multi-cloud environments",
      "Copilot in Defender for Cloud only monitors Azure resources, not AWS or GCP",
      "Copilot automatically remediates all cloud misconfigurations without user review",
      "Copilot for Cloud requires a separate SCU pool from Copilot for Security"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot in Defender for Cloud",
      "analysis": [
        "Option A is CORRECT: The embedded Copilot in Defender for Cloud helps analysts understand security recommendations in context: why a resource is flagged, the risk of the misconfiguration, potential attack scenarios, and prioritized remediation steps. It works across Azure, AWS, and GCP through Defender for Cloud's multi-cloud capabilities.",
        "Option B is INCORRECT: Defender for Cloud (and its embedded Copilot) supports multi-cloud environments including Azure, AWS, and GCP.",
        "Option C is INCORRECT: Copilot provides recommendations but does not automatically remediate. All remediation actions require explicit administrator approval.",
        "Option D is INCORRECT: Copilot for Security uses a shared SCU pool across all plugins and embedded experiences, including Defender for Cloud."
      ],
      "codeSnippet": "// Copilot in Defender for Cloud prompts:\n// \"Explain this security recommendation\"\n// \"Why is this storage account flagged?\"\n// \"What's the attack path for this finding?\"\n// \"Prioritize my top 10 cloud security risks\"",
      "socTip": "Ask Copilot to explain attack paths for critical cloud findings. Understanding how an attacker could exploit a misconfiguration helps prioritize remediation based on real-world risk.",
      "docRef": "Microsoft Learn: Copilot in Defender for Cloud"
    }
  },
  {
    "id": "copilot-043",
    "topic": "Copilot Owner vs Contributor",
    "scenario": "Fabrikam needs Tier 1 analysts to use Copilot but not manage SCUs or plugins.",
    "question": "Which role should Tier 1 analysts receive?",
    "options": [
      "Copilot Contributor — use prompts and promptbooks without administrative rights",
      "Copilot Owner for everyone",
      "Global Administrator only",
      "There are no roles"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot RBAC Role Selection",
      "analysis": [
        "Option A is CORRECT: Contributor is the least-privilege analyst role.",
        "Option B is INCORRECT: Owner is for a small admin set.",
        "Option C is INCORRECT: Global Admin is excessive.",
        "Option D is INCORRECT: Owner and Contributor exist."
      ],
      "codeSnippet": "// Owner: SCUs, plugins, settings\n// Contributor: use features only",
      "socTip": "Limit Owner to 2–3 people; all analysts as Contributors.",
      "docRef": "Microsoft Learn: Roles and permissions in Copilot for Security"
    }
  },
  {
    "id": "copilot-044",
    "topic": "Plugin enablement checklist",
    "scenario": "After provisioning SCUs, Adatum analysts notice Copilot cannot query Intune devices.",
    "question": "What is the most likely cause?",
    "options": [
      "The Intune plugin is disabled or not authorized in Copilot settings",
      "SCUs must be set to at least 100",
      "Copilot never supports Intune",
      "Analysts need a separate Intune license for Copilot"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Plugin Configuration Requirements",
      "analysis": [
        "Option A is CORRECT: Disabled plugins block data access for that product.",
        "Option B is INCORRECT: Minimum SCU is 1.",
        "Option C is INCORRECT: Intune is a supported plugin.",
        "Option D is INCORRECT: Plugin enablement is the gate, not a special extra license for each query."
      ],
      "codeSnippet": "// Settings > Plugins > enable Intune",
      "socTip": "After setup, verify each required plugin shows as enabled and healthy.",
      "docRef": "Microsoft Learn: Manage plugins in Copilot for Security"
    }
  },
  {
    "id": "copilot-045",
    "topic": "File upload and analysis limits",
    "scenario": "An analyst wants Copilot to analyze a large log file from a compromised host.",
    "question": "What is the recommended approach for analyzing files with Copilot?",
    "options": [
      "Use supported analysis paths such as hash-based reputation queries, script paste analysis within practical size limits, and product plugins rather than expecting unlimited raw file ingestion",
      "Upload multi-gigabyte disk images directly into every prompt",
      "Copilot cannot help with any file-related questions",
      "Only MD5 is supported, never SHA256"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Practical File Analysis with Copilot",
      "analysis": [
        "Option A is CORRECT: Hash intel, script analysis, and plugins are the supported patterns.",
        "Option B is INCORRECT: Huge binaries are not practical prompt payloads.",
        "Option C is INCORRECT: File reputation and script analysis are core use cases.",
        "Option D is INCORRECT: SHA256 is commonly used."
      ],
      "codeSnippet": "// \"Analyze file hash SHA256:...\"\n// Or paste script content for analysis",
      "socTip": "Prefer hash lookups first; paste scripts only when content analysis is required.",
      "docRef": "Microsoft Learn: File analysis in Copilot for Security"
    }
  },
  {
    "id": "copilot-046",
    "topic": "Incident handoff with Copilot",
    "scenario": "End of shift at Contoso: three high-severity incidents are still active.",
    "question": "How can Copilot improve shift handoff quality?",
    "options": [
      "Generate concise incident summaries and share the Copilot session or summary notes so the next analyst immediately understands state and next steps",
      "Write nothing and hope the next shift re-discovers everything",
      "Export only raw JSON alert dumps without narrative",
      "Disable session sharing permanently"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Shift Handoff with AI Summaries",
      "analysis": [
        "Option A is CORRECT: Summaries plus shared sessions reduce handoff friction.",
        "Option B is INCORRECT: Poor operational practice.",
        "Option C is INCORRECT: Narrative context is what handoff needs.",
        "Option D is INCORRECT: Sharing is a feature for collaboration."
      ],
      "codeSnippet": "// \"Summarize open high-severity incidents for handoff\"",
      "socTip": "Name sessions with INC numbers so the next shift finds them in seconds.",
      "docRef": "Microsoft Learn: Navigate Copilot for Security"
    }
  },
  {
    "id": "copilot-047",
    "topic": "MITRE mapping assistance",
    "scenario": "An analyst observed PowerShell download cradles and scheduled task persistence.",
    "question": "How can Copilot help with ATT&CK mapping?",
    "options": [
      "Ask Copilot to map observed behaviors to MITRE ATT&CK techniques and suggest related actor profiles or hunts",
      "Copilot cannot reference MITRE",
      "ATT&CK mapping requires a separate MITRE product license inside Copilot",
      "Copilot only maps to CIS Controls"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ATT&CK Mapping with Copilot",
      "analysis": [
        "Option A is CORRECT: Copilot can relate behaviors to techniques and enrichment.",
        "Option B is INCORRECT: ATT&CK is commonly used in security responses.",
        "Option C is INCORRECT: No separate MITRE license is required for this assistance.",
        "Option D is INCORRECT: ATT&CK mapping is in scope."
      ],
      "codeSnippet": "// \"Map these behaviors to ATT&CK techniques\"",
      "socTip": "Use technique IDs in follow-up hunting prompts for tighter queries.",
      "docRef": "Microsoft Learn: Threat intelligence in Copilot for Security"
    }
  },
  {
    "id": "copilot-048",
    "topic": "Copilot and automatic attack disruption",
    "scenario": "Automatic attack disruption isolated a device. The analyst wants Copilot to explain what happened.",
    "question": "Can Copilot explain automatic attack disruption actions?",
    "options": [
      "Yes — Copilot can summarize disruption-related incident context, affected entities, and recommended follow-up validation steps using available incident and product data",
      "No — disruption events are invisible to Copilot",
      "Only Microsoft support can explain disruption",
      "Copilot automatically reverses disruption without approval"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Understanding Attack Disruption with Copilot",
      "analysis": [
        "Option A is CORRECT: Copilot can narrate incident context including disruption-related entities and next steps.",
        "Option B is INCORRECT: Incident data is available through plugins.",
        "Option C is INCORRECT: Analysts can investigate in-portal with Copilot help.",
        "Option D is INCORRECT: Reversal remains under human control."
      ],
      "codeSnippet": "// \"Explain the attack disruption actions on this incident\"",
      "socTip": "Always validate isolation scope after disruption before releasing devices.",
      "docRef": "Microsoft Learn: Guided responses in Copilot for Security"
    }
  },
  {
    "id": "copilot-049",
    "topic": "Multi-product correlation prompts",
    "scenario": "A user shows risky Entra sign-ins, a phishing email, and endpoint malware alerts.",
    "question": "What is an effective Copilot prompt pattern for multi-product correlation?",
    "options": [
      "Ask Copilot to correlate the user across email, identity, and endpoint signals in one session with a clear scope and desired output format",
      "Query each product in separate browsers without mentioning the user",
      "Only ask about documentation",
      "Disable all plugins except one"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cross-Product Correlation Prompts",
      "analysis": [
        "Option A is CORRECT: One scoped multi-product prompt leverages plugin orchestration.",
        "Option B is INCORRECT: Defeats XDR correlation value.",
        "Option C is INCORRECT: Operational investigation is the goal.",
        "Option D is INCORRECT: Multiple plugins enable correlation."
      ],
      "codeSnippet": "// \"Correlate user X across email, identity, endpoint last 7 days\"",
      "socTip": "Name the user/device once and ask for a timeline output format.",
      "docRef": "Microsoft Learn: Manage plugins in Copilot for Security"
    }
  },
  {
    "id": "copilot-050",
    "topic": "SCU capacity planning",
    "scenario": "Peak SOC hours cause slow Copilot responses during major incidents.",
    "question": "How should Fabrikam address SCU capacity issues?",
    "options": [
      "Monitor the usage dashboard and temporarily scale up SCU count during peak demand, then scale down to control cost",
      "SCUs cannot be changed after initial provisioning",
      "Buy one SCU per analyst permanently",
      "Disable Copilot during incidents"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Dynamic SCU Scaling",
      "analysis": [
        "Option A is CORRECT: SCUs can be adjusted to match demand.",
        "Option B is INCORRECT: Flexible scaling is supported.",
        "Option C is INCORRECT: Capacity is pooled, not per-user licenses.",
        "Option D is INCORRECT: Incidents are when Copilot is most valuable."
      ],
      "codeSnippet": "// Azure portal → adjust SCU count",
      "socTip": "Document a scale-up playbook for major incident bridges.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-051",
    "topic": "Promptbook parameters",
    "scenario": "Northwind builds a compromised-user promptbook that must work for any username.",
    "question": "How do promptbooks accept different inputs per run?",
    "options": [
      "Promptbooks support input parameters (e.g., username, IP) that analysts provide when executing the workflow",
      "Parameters are not supported; rewrite the promptbook each time",
      "Only global tenant settings can change inputs",
      "Parameters require Azure Functions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Parameterized Promptbooks",
      "analysis": [
        "Option A is CORRECT: Parameters make promptbooks reusable.",
        "Option B is INCORRECT: Parameters exist for reuse.",
        "Option C is INCORRECT: Runtime inputs are per execution.",
        "Option D is INCORRECT: Native promptbook feature."
      ],
      "codeSnippet": "// Input: <username>\n// Steps reference <username>",
      "socTip": "Standardize parameter names across promptbooks for analyst familiarity.",
      "docRef": "Microsoft Learn: Use promptbooks in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-052",
    "topic": "Embedded vs standalone choice",
    "scenario": "An analyst needs a quick incident summary inside the open incident page.",
    "question": "Which Copilot experience is most appropriate?",
    "options": [
      "Embedded Copilot in Defender XDR for contextual incident summary without leaving the page",
      "Only the standalone experience can summarize incidents",
      "Only PowerShell can summarize incidents",
      "Embedded Copilot cannot access incident data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Choosing Embedded Experience",
      "analysis": [
        "Option A is CORRECT: Embedded is designed for in-context actions.",
        "Option B is INCORRECT: Embedded supports incident summaries.",
        "Option C is INCORRECT: Not required.",
        "Option D is INCORRECT: Incident context is available embedded."
      ],
      "codeSnippet": "// Incident page → Summarize with Copilot",
      "socTip": "Use embedded for speed; standalone for deep multi-step hunts.",
      "docRef": "Microsoft Learn: Microsoft Copilot for Security experiences"
    }
  },
  {
    "id": "copilot-053",
    "topic": "Thumbs feedback quality",
    "scenario": "SOC leadership wants higher Copilot answer quality over time.",
    "question": "What team practice most directly improves Copilot quality?",
    "options": [
      "Consistently use thumbs up/down with brief notes on wrong answers so Microsoft can improve the model",
      "Never provide feedback",
      "Only email the CEO about errors",
      "Disable plugins after every wrong answer"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Feedback-Driven Quality Improvement",
      "analysis": [
        "Option A is CORRECT: In-product feedback is the designed improvement loop.",
        "Option B is INCORRECT: Feedback is encouraged.",
        "Option C is INCORRECT: Not an efficient channel.",
        "Option D is INCORRECT: Overreacting reduces capability."
      ],
      "codeSnippet": "// Thumbs down + short note on error",
      "socTip": "Make feedback a required step in Tier 1 runbooks.",
      "docRef": "Microsoft Learn: Provide feedback in Copilot for Security"
    }
  },
  {
    "id": "copilot-054",
    "topic": "Copilot and KQL review",
    "scenario": "Copilot generated a hunting query a junior analyst does not fully understand.",
    "question": "What should the analyst do before running the query broadly?",
    "options": [
      "Review table names, filters, and time range; test on a narrow scope; then expand — never blindly run AI-generated queries at full estate scale first",
      "Run it against all tenants immediately",
      "Disable Advanced Hunting",
      "Assume all generated queries are perfect"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Human Review of Generated KQL",
      "analysis": [
        "Option A is CORRECT: Verification prevents costly mistakes.",
        "Option B is INCORRECT: Too broad initially.",
        "Option C is INCORRECT: Hunting remains essential.",
        "Option D is INCORRECT: AI output needs review."
      ],
      "codeSnippet": "// Review | where, project, join keys",
      "socTip": "Keep a short checklist: time range, tables, joins, output columns.",
      "docRef": "Microsoft Learn: Generate KQL queries with Copilot in Defender"
    }
  },
  {
    "id": "copilot-055",
    "topic": "Session naming standards",
    "scenario": "Night shift cannot find the day shift's Copilot investigation for INC-8891.",
    "question": "What operational practice helps?",
    "options": [
      "Use a naming convention such as INC-8891-phishing-dayshift and pin critical sessions",
      "Leave all sessions untitled",
      "Delete sessions at end of each day",
      "Store findings only in personal email"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Session Naming for Collaboration",
      "analysis": [
        "Option A is CORRECT: Names and pins make retrieval reliable.",
        "Option B is INCORRECT: Untitled sessions are hard to find.",
        "Option C is INCORRECT: Deletes destroy continuity.",
        "Option D is INCORRECT: Loses portal context."
      ],
      "codeSnippet": "// INC-{id}-{topic}-{shift}",
      "socTip": "Document the naming standard in the SOC wiki.",
      "docRef": "Microsoft Learn: Navigate Copilot for Security"
    }
  },
  {
    "id": "copilot-056",
    "topic": "Copilot for lateral movement analysis",
    "scenario": "Alerts show the same account authenticating to many servers quickly.",
    "question": "How can Copilot assist lateral movement investigation?",
    "options": [
      "Ask Copilot to timeline the account's authentications, list devices accessed, and recommend containment steps using identity and endpoint data",
      "Copilot cannot discuss lateral movement",
      "Only network TACACS logs can be used",
      "Disable the account without investigation always"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Lateral Movement Investigation Assistance",
      "analysis": [
        "Option A is CORRECT: Multi-plugin correlation supports movement analysis.",
        "Option B is INCORRECT: Core investigation use case.",
        "Option C is INCORRECT: Identity/endpoint plugins apply.",
        "Option D is INCORRECT: Investigate then contain appropriately."
      ],
      "codeSnippet": "// \"Timeline lateral movement for user X last 24h\"",
      "socTip": "Follow with 'which of these devices are high value?' for prioritization.",
      "docRef": "Microsoft Learn: Guided responses in Copilot for Security"
    }
  },
  {
    "id": "copilot-057",
    "topic": "Plugin authentication failures",
    "scenario": "Copilot returns errors when querying a custom TIP plugin.",
    "question": "What should engineers check first?",
    "options": [
      "Plugin OpenAPI auth configuration, API key/OAuth validity, network allowlists, and operation summaries used for invocation",
      "Delete Copilot entirely",
      "Increase SCUs to 1000",
      "Disable TLS on the TIP"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Plugin Troubleshooting",
      "analysis": [
        "Option A is CORRECT: Auth and connectivity are the usual failure points.",
        "Option B is INCORRECT: Overkill.",
        "Option C is INCORRECT: Unrelated to auth errors.",
        "Option D is INCORRECT: Insecure and wrong fix."
      ],
      "codeSnippet": "// Verify OpenAPI securitySchemes and test endpoint",
      "socTip": "Add a health-check operation with a clear summary for easier diagnosis.",
      "docRef": "Microsoft Learn: Manage plugins in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-058",
    "topic": "Copilot for Secure Score explanations",
    "scenario": "CISO asks why Secure Score dropped after onboarding new subscriptions.",
    "question": "How can Copilot help explain Secure Score changes?",
    "options": [
      "Ask Copilot for top score drivers, new failing recommendations, and prioritized improvement actions based on available posture data",
      "Secure Score is invisible to Copilot",
      "Only email Microsoft for score explanations",
      "Score drops cannot be investigated"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Posture Explanation with Copilot",
      "analysis": [
        "Option A is CORRECT: Copilot can summarize posture improvement opportunities.",
        "Option B is INCORRECT: Posture data can be queried.",
        "Option C is INCORRECT: Self-service investigation is preferred.",
        "Option D is INCORRECT: Changes are investigable."
      ],
      "codeSnippet": "// \"Why did Secure Score change this week?\"",
      "socTip": "Pair score explanation with owners for the top failing controls.",
      "docRef": "Microsoft Learn: Security posture with Copilot"
    }
  },
  {
    "id": "copilot-059",
    "topic": "Responsible AI use in SOC",
    "scenario": "A Tier 1 analyst isolates a device solely because Copilot suggested it, without checking evidence.",
    "question": "What is the correct operating principle?",
    "options": [
      "Treat Copilot as an assistant: verify critical actions against source evidence before containment or account disruption",
      "Always execute every Copilot suggestion immediately",
      "Never use Copilot for incidents",
      "Ignore all citations"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Human-in-the-Loop for High-Impact Actions",
      "analysis": [
        "Option A is CORRECT: Verification is mandatory for irreversible actions.",
        "Option B is INCORRECT: Unsafe.",
        "Option C is INCORRECT: Copilot is valuable with oversight.",
        "Option D is INCORRECT: Citations support verification."
      ],
      "codeSnippet": "// Verify entities → then act",
      "socTip": "Require dual control for mass isolation or mass account disable.",
      "docRef": "Microsoft Learn: Responsible AI in Copilot for Security"
    }
  },
  {
    "id": "copilot-060",
    "topic": "Copilot for phishing campaign scope",
    "scenario": "One user clicked a phish. The SOC needs campaign scope quickly.",
    "question": "How can Copilot accelerate phishing scope analysis?",
    "options": [
      "Ask Copilot to identify related emails, recipients, clickers, and any subsequent endpoint or identity alerts tied to the campaign entities",
      "Only interview the one user",
      "Disable email for the company",
      "Copilot cannot access email security data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Phishing Campaign Scoping with Copilot",
      "analysis": [
        "Option A is CORRECT: Email and XDR plugins support campaign expansion.",
        "Option B is INCORRECT: Incomplete.",
        "Option C is INCORRECT: Overly disruptive.",
        "Option D is INCORRECT: Office/XDR data is available via plugins."
      ],
      "codeSnippet": "// \"Scope phishing campaign for subject/sender X\"",
      "socTip": "Follow with remediation recommendations for remaining unopened messages.",
      "docRef": "Microsoft Learn: Summarize an incident with Copilot in Defender"
    }
  },
  {
    "id": "copilot-061",
    "topic": "Exporting Copilot outputs",
    "scenario": "Management wants a PDF-style narrative of a closed incident produced with Copilot help.",
    "question": "What is a practical approach?",
    "options": [
      "Use Copilot to draft the report narrative, then export or copy into the organization's reporting template for review and distribution",
      "Have Copilot email the CISO without review",
      "Only STIX is allowed as output",
      "Copilot forbids any export of text"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Drafting Reports from Copilot Sessions",
      "analysis": [
        "Option A is CORRECT: Draft then human-edit into official templates.",
        "Option B is INCORRECT: Review required.",
        "Option C is INCORRECT: Human reports are normal.",
        "Option D is INCORRECT: Analysts can use generated text in workflows."
      ],
      "codeSnippet": "// \"Generate executive incident report sections 1-6\"",
      "socTip": "Keep a report promptbook for consistent section structure.",
      "docRef": "Microsoft Learn: Incident reports with Copilot for Security"
    }
  },
  {
    "id": "copilot-062",
    "topic": "Copilot Contributor limitations",
    "scenario": "A Contributor tries to upload a custom plugin and is denied.",
    "question": "Why was the action blocked?",
    "options": [
      "Plugin and SCU administration are Owner capabilities; Contributors cannot manage plugins",
      "The tenant has no internet",
      "Plugins can only be uploaded on weekends",
      "Contributors can upload plugins but only via email"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Contributor Permission Boundaries",
      "analysis": [
        "Option A is CORRECT: Owner vs Contributor separation enforces least privilege.",
        "Option B is INCORRECT: Unrelated.",
        "Option C is INCORRECT: No such restriction.",
        "Option D is INCORRECT: Not the admin path."
      ],
      "codeSnippet": "// Owner required for plugin management",
      "socTip": "Route plugin requests through the security architecture owners.",
      "docRef": "Microsoft Learn: Roles and permissions in Copilot for Security"
    }
  },
  {
    "id": "copilot-063",
    "topic": "Natural language incident queries",
    "scenario": "A junior analyst cannot find the right Defender portal blades for an incident.",
    "question": "How does Copilot reduce portal navigation burden?",
    "options": [
      "Natural language questions return synthesized answers and guidance drawn from incident and product data without requiring the analyst to know every blade",
      "Copilot only opens random pages",
      "Analysts must memorize all URLs first",
      "Copilot replaces the need for any portal access forever"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Natural Language Navigation of Security Data",
      "analysis": [
        "Option A is CORRECT: NL interface abstracts portal complexity.",
        "Option B is INCORRECT: Responses are query-driven.",
        "Option C is INCORRECT: Copilot lowers that barrier.",
        "Option D is INCORRECT: Portal remains for actions and deep links."
      ],
      "codeSnippet": "// \"What devices are in incident INC-1204?\"",
      "socTip": "Still open key entities in the portal when taking response actions.",
      "docRef": "Microsoft Learn: Microsoft Copilot for Security experiences"
    }
  },
  {
    "id": "copilot-064",
    "topic": "Copilot for identity privilege review",
    "scenario": "Before resetting a potentially compromised admin, the SOC must know role assignments.",
    "question": "How can Copilot help?",
    "options": [
      "Ask Copilot to list privileged roles, group memberships, and recent risky sign-ins for the account",
      "Guess the roles",
      "Only HR systems contain role data",
      "Copilot cannot query Entra ID"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Privilege Context Before Containment",
      "analysis": [
        "Option A is CORRECT: Entra plugin supplies privilege and risk context.",
        "Option B is INCORRECT: Unsafe.",
        "Option C is INCORRECT: Entra holds cloud roles.",
        "Option D is INCORRECT: Entra plugin exists."
      ],
      "codeSnippet": "// \"List privileged roles for admin@contoso.com\"",
      "socTip": "Check for standing Global Admin before mass session revocation.",
      "docRef": "Microsoft Learn: Copilot in Microsoft Entra"
    }
  },
  {
    "id": "copilot-065",
    "topic": "SCU minimum provisioning",
    "scenario": "A small SOC wants the lowest cost pilot.",
    "question": "What is the minimum SCU provisioning typically required to start?",
    "options": [
      "1 SCU — organizations can start small and scale based on measured usage",
      "100 SCUs minimum",
      "SCUs are only sold in packs of 50",
      "SCUs are not required if you have E5"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Minimum SCU for Pilot",
      "analysis": [
        "Option A is CORRECT: Minimum is 1 SCU for flexible pilots.",
        "Option B is INCORRECT: Not the minimum.",
        "Option C is INCORRECT: Count is adjustable.",
        "Option D is INCORRECT: Separate capacity model."
      ],
      "codeSnippet": "// Provision 1 SCU for pilot",
      "socTip": "Measure concurrent sessions during a busy hour before scaling.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-066",
    "topic": "Copilot for malware family context",
    "scenario": "A file is classified as belonging to a known malware family.",
    "question": "What additional context can Copilot provide?",
    "options": [
      "Family behavior summary, typical TTPs, related IOCs, and organizational prevalence if available through threat intel and XDR data",
      "Only the family name with no context",
      "A full decryptor for all ransomware families automatically",
      "Physical arrest warrants"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Malware Family Enrichment",
      "analysis": [
        "Option A is CORRECT: TI + XDR enrichment supports response.",
        "Option B is INCORRECT: Richer context is available.",
        "Option C is INCORRECT: Not a decryptor service guarantee.",
        "Option D is INCORRECT: Outside product scope."
      ],
      "codeSnippet": "// \"Explain malware family Emotet and related IOCs\"",
      "socTip": "Extract IOCs and hunt estate-wide immediately.",
      "docRef": "Microsoft Learn: Threat intelligence in Copilot for Security"
    }
  },
  {
    "id": "copilot-067",
    "topic": "Avoiding sensitive data in prompts",
    "scenario": "An analyst is about to paste customer PII into a Copilot prompt for analysis.",
    "question": "What is the safer practice?",
    "options": [
      "Minimize sensitive data in prompts; prefer IDs, hashes, and portal-linked entities, and follow organizational data handling policies",
      "Paste entire HR databases into prompts routinely",
      "Disable all audit logging so prompts are untracked",
      "Share prompts publicly on social media"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data Minimization in Prompts",
      "analysis": [
        "Option A is CORRECT: Least data exposure is best practice even with strong platform controls.",
        "Option B is INCORRECT: Excessive exposure.",
        "Option C is INCORRECT: Audit remains required.",
        "Option D is INCORRECT: Confidentiality breach."
      ],
      "codeSnippet": "// Prefer: user UPN, device name, file hash",
      "socTip": "Train analysts on what not to paste into prompts.",
      "docRef": "Microsoft Learn: Data privacy in Copilot for Security"
    }
  },
  {
    "id": "copilot-068",
    "topic": "Copilot for cloud recommendation explanation",
    "scenario": "A Defender for Cloud recommendation about open management ports confuses a cloud engineer.",
    "question": "How can embedded Copilot in Defender for Cloud help?",
    "options": [
      "Explain why the resource is flagged, describe risk and likely attack paths, and suggest prioritized remediation steps",
      "Silently open the ports wider",
      "Only translate the recommendation to Latin",
      "Copilot cannot access Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Recommendation Explanation",
      "analysis": [
        "Option A is CORRECT: Embedded Copilot clarifies cloud posture findings.",
        "Option B is INCORRECT: Would increase risk.",
        "Option C is INCORRECT: Not useful.",
        "Option D is INCORRECT: Supported experience."
      ],
      "codeSnippet": "// \"Explain this security recommendation and attack path\"",
      "socTip": "Ask for business impact framing when talking to resource owners.",
      "docRef": "Microsoft Learn: Copilot in Defender for Cloud"
    }
  },
  {
    "id": "copilot-069",
    "topic": "Concurrent session capacity",
    "scenario": "During a major incident, multiple analysts report Copilot slowdowns.",
    "question": "What primarily governs concurrent processing capacity?",
    "options": [
      "Provisioned SCU capacity shared across the organization",
      "The number of monitors on each analyst desk",
      "Windows license count",
      "DNS TTL settings"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "SCU Shared Capacity Model",
      "analysis": [
        "Option A is CORRECT: SCUs pool capacity for concurrent use.",
        "Option B is INCORRECT: Irrelevant.",
        "Option C is INCORRECT: Unrelated.",
        "Option D is INCORRECT: Unrelated."
      ],
      "codeSnippet": "// Scale SCUs during major incidents",
      "socTip": "Pre-approve emergency SCU scale-up in the incident response plan.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-070",
    "topic": "Promptbook sharing permissions",
    "scenario": "A senior analyst creates a high-quality promptbook and wants the whole SOC to use it.",
    "question": "How are promptbooks shared?",
    "options": [
      "Promptbooks can be shared with the organization or team so other Copilot users can run the same investigation workflow",
      "Promptbooks are permanently private to the creator with no sharing",
      "Sharing requires mailing the prompts as text files only",
      "Promptbooks auto-share to the public internet"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Promptbook Sharing",
      "analysis": [
        "Option A is CORRECT: Sharing enables SOC standardization.",
        "Option B is INCORRECT: Sharing is supported.",
        "Option C is INCORRECT: In-product sharing is preferred.",
        "Option D is INCORRECT: Sharing is within the organization boundary."
      ],
      "codeSnippet": "// Share promptbook → SOC group",
      "socTip": "Curate an approved promptbook gallery with owners.",
      "docRef": "Microsoft Learn: Use promptbooks in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-071",
    "topic": "Audit of Copilot prompts",
    "scenario": "Compliance asks who asked Copilot about a specific executive last month.",
    "question": "Where is that activity recorded?",
    "options": [
      "Microsoft 365 unified audit log captures Copilot interactions for governance review",
      "Nowhere",
      "Only on the analyst's laptop event log",
      "Only in printed paper logs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot Interaction Audit Trail",
      "analysis": [
        "Option A is CORRECT: Unified audit log records interactions.",
        "Option B is INCORRECT: Logging exists.",
        "Option C is INCORRECT: Cloud audit is authoritative.",
        "Option D is INCORRECT: Digital audit trail."
      ],
      "codeSnippet": "// Search audit: CopilotInteraction",
      "socTip": "Alert on Copilot access to VIP identities outside change windows.",
      "docRef": "Microsoft Learn: Audit logging in Copilot for Security"
    }
  },
  {
    "id": "copilot-072",
    "topic": "Copilot for device isolation decision support",
    "scenario": "An analyst is unsure whether to isolate a VIP laptop based on current evidence.",
    "question": "How should Copilot be used in this decision?",
    "options": [
      "Ask Copilot to summarize evidence, impacted assets, and recommended containment options, then have a human make the isolation decision",
      "Let Copilot isolate automatically without review",
      "Never isolate VIP devices",
      "Only isolate after 30 days"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Decision Support Not Autonomous Containment",
      "analysis": [
        "Option A is CORRECT: Copilot advises; humans decide high-impact actions.",
        "Option B is INCORRECT: Approval required.",
        "Option C is INCORRECT: VIPs can be isolated when risk warrants.",
        "Option D is INCORRECT: Delay increases impact."
      ],
      "codeSnippet": "// \"Summarize evidence and containment options for DEVICE\"",
      "socTip": "Document the decision rationale in the incident notes.",
      "docRef": "Microsoft Learn: Guided responses in Copilot for Security"
    }
  },
  {
    "id": "copilot-073",
    "topic": "Language quality for non-English SOC",
    "scenario": "A Japanese SOC team gets weaker results with highly idiomatic prompts.",
    "question": "What improves non-English Copilot results?",
    "options": [
      "Use clear, simple technical phrasing in the preferred language rather than complex idioms",
      "Switch permanently to English only",
      "Disable multilingual support",
      "Translate via public web translators into prompts with PII"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Clear Multilingual Prompting",
      "analysis": [
        "Option A is CORRECT: Simple technical language improves reliability.",
        "Option B is INCORRECT: Native language is supported.",
        "Option C is INCORRECT: Multilingual is built-in.",
        "Option D is INCORRECT: Avoid leaking PII to public tools."
      ],
      "codeSnippet": "// Prefer direct technical requests",
      "socTip": "Maintain a bilingual promptbook library for common playbooks.",
      "docRef": "Microsoft Learn: Copilot for Security language support"
    }
  },
  {
    "id": "copilot-074",
    "topic": "Copilot for exposure management questions",
    "scenario": "CISO asks which internet-facing assets have critical CVEs.",
    "question": "Which capability path should analysts use with Copilot?",
    "options": [
      "Use EASM-oriented prompts via the EASM plugin to summarize external assets, exposures, and related vulnerabilities",
      "Ignore external assets",
      "Only scan internal printers",
      "EASM data is offline-only CD-ROM"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "External Exposure Queries",
      "analysis": [
        "Option A is CORRECT: EASM plugin answers outside-in questions.",
        "Option B is INCORRECT: External exposure is critical.",
        "Option C is INCORRECT: Incomplete.",
        "Option D is INCORRECT: Online plugin access."
      ],
      "codeSnippet": "// \"Highest priority external exposures with critical CVEs\"",
      "socTip": "Reconcile EASM findings with internal inventory weekly.",
      "docRef": "Microsoft Learn: EASM plugin in Copilot for Security"
    }
  },
  {
    "id": "copilot-075",
    "topic": "Integrating Copilot outputs into ITSM",
    "scenario": "Every high-severity incident must create a ServiceNow ticket including a Copilot summary.",
    "question": "What integration approach fits?",
    "options": [
      "Logic Apps/Power Automate with Copilot connector to generate summary text and create/update the ITSM ticket",
      "Manual retyping only forever",
      "Disable ticketing",
      "Email the summary to a shared mailbox without ticket IDs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot to ITSM Automation",
      "analysis": [
        "Option A is CORRECT: Connector-based automation is the scalable path.",
        "Option B is INCORRECT: Does not scale.",
        "Option C is INCORRECT: ITSM remains required.",
        "Option D is INCORRECT: Weaker than linked tickets."
      ],
      "codeSnippet": "// Incident → Copilot summary → ServiceNow create",
      "socTip": "Include incident deep link and severity in the ticket body.",
      "docRef": "Microsoft Learn: Automate Copilot for Security with Logic Apps"
    }
  },
  {
    "id": "copilot-076",
    "topic": "Copilot session pin and search",
    "scenario": "An analyst needs to return to a complex investigation from last week.",
    "question": "What features help retrieve prior work?",
    "options": [
      "Session history list, search/naming, and pinning important sessions for quick access",
      "Sessions cannot be reopened",
      "Only if the same browser cookie exists for 10 minutes",
      "Sessions are stored exclusively in RAM"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Retrieving Prior Copilot Sessions",
      "analysis": [
        "Option A is CORRECT: Persistence, naming, and pins support retrieval.",
        "Option B is INCORRECT: Sessions persist.",
        "Option C is INCORRECT: Cloud persistence is broader.",
        "Option D is INCORRECT: Persisted service-side."
      ],
      "codeSnippet": "// Pin + naming convention",
      "socTip": "Pin anything related to open major incidents.",
      "docRef": "Microsoft Learn: Navigate Copilot for Security"
    }
  },
  {
    "id": "copilot-077",
    "topic": "Evaluating ROI of Copilot",
    "scenario": "After a pilot, leadership asks for ROI evidence.",
    "question": "Which metrics best support Copilot ROI evaluation?",
    "options": [
      "Time-to-triage, time-to-investigate, prompt volume, SCU cost, and qualitative analyst feedback on investigation quality",
      "Only the number of emojis in prompts",
      "Only electricity usage of laptops",
      "ROI cannot be measured"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Copilot Pilot ROI Metrics",
      "analysis": [
        "Option A is CORRECT: Time savings and quality plus cost form ROI.",
        "Option B is INCORRECT: Not meaningful.",
        "Option C is INCORRECT: Not the value driver.",
        "Option D is INCORRECT: Measurable with discipline."
      ],
      "codeSnippet": "// Baseline MTTR before/after pilot",
      "socTip": "Track a sample of 20 matched incident types pre/post Copilot.",
      "docRef": "Microsoft Learn: Monitor usage in Copilot for Security"
    }
  },
  {
    "id": "copilot-078",
    "topic": "Copilot for threat actor comparison",
    "scenario": "Two possible actor hypotheses emerge from overlapping TTPs.",
    "question": "How can Copilot assist?",
    "options": [
      "Ask Copilot to compare the actors' known TTPs, targets, and recent activity to the observed incident behaviors",
      "Flip a coin",
      "Ignore attribution entirely always",
      "Only the FBI can discuss actors"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Actor Hypothesis Comparison",
      "analysis": [
        "Option A is CORRECT: TI summarization supports structured comparison.",
        "Option B is INCORRECT: Not analytical.",
        "Option C is INCORRECT: Attribution context can aid defense.",
        "Option D is INCORRECT: Analysts can use commercial TI responsibly."
      ],
      "codeSnippet": "// \"Compare actor A vs B against these TTPs\"",
      "socTip": "Treat attribution as hypothesis, not court fact.",
      "docRef": "Microsoft Learn: Threat intelligence in Copilot for Security"
    }
  },
  {
    "id": "copilot-079",
    "topic": "Disabling a risky plugin",
    "scenario": "A third-party plugin starts returning untrusted data.",
    "question": "What should administrators do?",
    "options": [
      "Disable the plugin in Copilot settings until the vendor issue is resolved, preserving other plugins",
      "Unplug the corporate internet",
      "Delete the Azure tenant",
      "Grant the plugin Global Admin"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Plugin Kill Switch",
      "analysis": [
        "Option A is CORRECT: Per-plugin disable is the controlled response.",
        "Option B is INCORRECT: Excessive.",
        "Option C is INCORRECT: Catastrophic.",
        "Option D is INCORRECT: Increases risk."
      ],
      "codeSnippet": "// Settings > Plugins > disable",
      "socTip": "Document plugin owners and break-glass disable steps.",
      "docRef": "Microsoft Learn: Manage plugins in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-080",
    "topic": "Handling empty plugin results",
    "scenario": "Copilot says no data found for a device that should exist.",
    "question": "What are sensible next checks?",
    "options": [
      "Verify device onboarding/name, plugin enablement, time range, and permissions — then retry with corrected identifiers",
      "Assume the device is permanently safe",
      "Delete all hunting data",
      "Disable audit logs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Empty Result Troubleshooting",
      "analysis": [
        "Option A is CORRECT: Data path and identifier issues are common.",
        "Option B is INCORRECT: Absence of evidence is not evidence of absence.",
        "Option C is INCORRECT: Destructive and wrong.",
        "Option D is INCORRECT: Unrelated fix."
      ],
      "codeSnippet": "// Confirm DeviceName/ID in inventory first",
      "socTip": "Copy identifiers from the portal entity page to avoid typos.",
      "docRef": "Microsoft Learn: Manage plugins in Copilot for Security"
    }
  },
  {
    "id": "copilot-081",
    "topic": "Copilot for recommended next hunts",
    "scenario": "After containing a malware incident, the SOC wants proactive hunts for related IOCs.",
    "question": "How can Copilot help post-incident hunting?",
    "options": [
      "Ask Copilot to extract IOCs and suggest Advanced Hunting queries to find additional impacted devices or related activity",
      "Stop all hunting after containment",
      "Only hunt manually without IOCs",
      "Publish IOCs to Twitter first"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Post-Incident Hunt Suggestions",
      "analysis": [
        "Option A is CORRECT: IOC extraction plus query suggestions accelerate cleanup validation.",
        "Option B is INCORRECT: Residual risk may remain.",
        "Option C is INCORRECT: IOCs focus hunts.",
        "Option D is INCORRECT: Operational security risk."
      ],
      "codeSnippet": "// \"Extract IOCs and generate hunt queries\"",
      "socTip": "Run suggested hunts before declaring incident fully closed.",
      "docRef": "Microsoft Learn: Analyze scripts with Copilot in Defender"
    }
  },
  {
    "id": "copilot-082",
    "topic": "SCU billing attribution",
    "scenario": "Finance wants to know whether SCUs are billed per analyst seat.",
    "question": "How is Copilot for Security capacity billed?",
    "options": [
      "By provisioned SCUs (capacity) billed hourly, not by named user seats",
      "By each analyst's Entra object ID monthly",
      "By number of prompts only with no capacity model",
      "Free unlimited for all E3 customers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Capacity Billing Not Seat Billing",
      "analysis": [
        "Option A is CORRECT: SCU capacity model.",
        "Option B is INCORRECT: Not per-user seat licensing for SCUs.",
        "Option C is INCORRECT: Capacity pooling, not pure per-prompt retail.",
        "Option D is INCORRECT: Not free unlimited via E3."
      ],
      "codeSnippet": "// Azure SCU provisioning and hourly billing",
      "socTip": "Chargeback can still allocate cost by usage dashboard metrics if needed.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-083",
    "topic": "Copilot for Intune policy conflict analysis",
    "scenario": "A device fails compliance due to conflicting encryption settings.",
    "question": "How can embedded Copilot in Intune help?",
    "options": [
      "Explain likely policy conflicts, summarize compliance failure reasons, and suggest remediation steps for the device",
      "Wipe the device automatically without approval",
      "Only show the Intune marketing page",
      "Intune Copilot cannot see compliance state"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Intune Compliance Troubleshooting with Copilot",
      "analysis": [
        "Option A is CORRECT: Embedded Copilot supports compliance diagnosis.",
        "Option B is INCORRECT: Destructive actions need confirmation.",
        "Option C is INCORRECT: Operational guidance is provided.",
        "Option D is INCORRECT: Compliance context is available."
      ],
      "codeSnippet": "// \"Why is this device non-compliant?\"",
      "socTip": "Use during IR to verify security baseline enforcement on compromised devices.",
      "docRef": "Microsoft Learn: Microsoft Copilot in Intune"
    }
  },
  {
    "id": "copilot-084",
    "topic": "Versioning promptbooks",
    "scenario": "A promptbook was improved but some teams still use the old version.",
    "question": "What is a good governance practice?",
    "options": [
      "Maintain named versions, communicate changes, and retire obsolete promptbooks from the shared gallery",
      "Allow infinite conflicting copies with no owner",
      "Never update promptbooks",
      "Store promptbooks only in personal OneNote"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Promptbook Lifecycle Governance",
      "analysis": [
        "Option A is CORRECT: Versioning and retirement keep SOC quality consistent.",
        "Option B is INCORRECT: Causes drift.",
        "Option C is INCORRECT: Continuous improvement needed.",
        "Option D is INCORRECT: Sharing in-product is preferred."
      ],
      "codeSnippet": "// Promptbook: Compromised User v3",
      "socTip": "Assign an owner per promptbook like a detection rule owner.",
      "docRef": "Microsoft Learn: Use promptbooks in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-085",
    "topic": "Copilot during greenfield setup",
    "scenario": "A new tenant enables Copilot before any security products have data.",
    "question": "What will limit Copilot effectiveness?",
    "options": [
      "Lack of underlying security product data and enabled plugins — Copilot needs Defender/Sentinel/etc. telemetry to analyze",
      "Too many SCUs",
      "Having Entra ID",
      "Using HTTPS"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data Prerequisites for Value",
      "analysis": [
        "Option A is CORRECT: Copilot analyzes product data; empty products yield little value.",
        "Option B is INCORRECT: SCUs without data still cannot invent telemetry.",
        "Option C is INCORRECT: Entra is a prerequisite, not a limiter.",
        "Option D is INCORRECT: HTTPS is expected."
      ],
      "codeSnippet": "// Enable products + plugins before pilot success metrics",
      "socTip": "Onboard core workloads first, then measure Copilot impact.",
      "docRef": "Microsoft Learn: Get started with Copilot for Security"
    }
  },
  {
    "id": "copilot-086",
    "topic": "Summarize multiple incidents",
    "scenario": "Monday morning, 12 active incidents await the SOC lead.",
    "question": "How can Copilot help the SOC lead prioritize?",
    "options": [
      "Ask Copilot for a prioritized summary of active high/medium incidents with key entities and suggested order of work",
      "Close all incidents unread",
      "Only look at the oldest informational alert",
      "Randomize the queue"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Queue Prioritization Assistance",
      "analysis": [
        "Option A is CORRECT: Natural language prioritization support saves lead time.",
        "Option B is INCORRECT: Dangerous.",
        "Option C is INCORRECT: Wrong priority signal.",
        "Option D is INCORRECT: Not risk-based."
      ],
      "codeSnippet": "// \"Prioritize active high and medium incidents\"",
      "socTip": "Re-run prioritization after major new alerts arrive.",
      "docRef": "Microsoft Learn: Summarize an incident with Copilot in Defender"
    }
  },
  {
    "id": "copilot-087",
    "topic": "Copilot and custom detection ideas",
    "scenario": "A successful hunt found a new LOLBin pattern with no built-in alert.",
    "question": "How can Copilot support turning hunts into detections?",
    "options": [
      "Ask Copilot to help refine the KQL and outline a custom detection rule structure for Advanced Hunting/XDR",
      "Custom detections cannot use KQL",
      "Only Microsoft can create detections",
      "Delete the hunt results"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "From Hunt to Custom Detection",
      "analysis": [
        "Option A is CORRECT: Query assistance supports detection engineering.",
        "Option B is INCORRECT: Custom detections use KQL.",
        "Option C is INCORRECT: Customers create custom detections.",
        "Option D is INCORRECT: Preserve and operationalize."
      ],
      "codeSnippet": "// \"Turn this hunt into a custom detection rule outline\"",
      "socTip": "Still validate false positive rates before enabling the rule.",
      "docRef": "Microsoft Learn: Generate KQL queries with Copilot in Defender"
    }
  },
  {
    "id": "copilot-088",
    "topic": "Security of Copilot admin actions",
    "scenario": "Only a break-glass account should change SCU counts.",
    "question": "How should admin access to Copilot settings be controlled?",
    "options": [
      "Limit Copilot Owner role to minimal privileged accounts, monitor audit logs for settings changes, and use change control",
      "Give Owner to all Tier 1 analysts",
      "Share Owner credentials on a whiteboard",
      "Disable auditing of Owner actions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Protecting Copilot Administrative Plane",
      "analysis": [
        "Option A is CORRECT: Least privilege plus audit and change control.",
        "Option B is INCORRECT: Excessive.",
        "Option C is INCORRECT: Credential hygiene failure.",
        "Option D is INCORRECT: Audit is required."
      ],
      "codeSnippet": "// Owner group = break-glass + CISO delegates",
      "socTip": "Alert on SCU or plugin changes outside maintenance windows.",
      "docRef": "Microsoft Learn: Roles and permissions in Copilot for Security"
    }
  },
  {
    "id": "copilot-089",
    "topic": "Copilot for blended identity and endpoint IR",
    "scenario": "Token theft is suspected after a phishing click, with unusual device processes.",
    "question": "What Copilot investigation pattern fits best?",
    "options": [
      "Single session correlating email click, sign-in anomalies, token risk, and device process timeline with recommended response actions",
      "Separate tools with no cross-reference",
      "Only reset the password without checking devices",
      "Ignore endpoint signals"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Blended Identity-Endpoint Investigation",
      "analysis": [
        "Option A is CORRECT: Multi-plugin session matches modern token theft IR.",
        "Option B is INCORRECT: Loses correlation.",
        "Option C is INCORRECT: Incomplete containment.",
        "Option D is INCORRECT: Endpoint evidence is critical."
      ],
      "codeSnippet": "// Correlate phish → sign-in → device activity",
      "socTip": "Revoke refresh tokens and review new MFA registrations.",
      "docRef": "Microsoft Learn: Identity risk assessment with Copilot"
    }
  },
  {
    "id": "copilot-090",
    "topic": "Copilot for email authentication failures",
    "scenario": "Spoofed partner domains fail DMARC and users still report lookalike messages.",
    "question": "How can Copilot assist email authentication investigations?",
    "options": [
      "Summarize related email security signals, affected recipients, and recommended policy or user-response actions using available Defender email data",
      "Disable all inbound email permanently",
      "Only check physical mailrooms",
      "Copilot cannot discuss email security"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Email Authentication Investigation Assistance",
      "analysis": [
        "Option A is CORRECT: Email security plugins support authentication and phishing context.",
        "Option B is INCORRECT: Overly disruptive.",
        "Option C is INCORRECT: Digital investigation is required.",
        "Option D is INCORRECT: Email is a core domain."
      ],
      "codeSnippet": "// \"Summarize spoofing/phish signals for domain X\"",
      "socTip": "Pair with Threat Explorer pivots for campaign scope.",
      "docRef": "Microsoft Learn: Summarize an incident with Copilot in Defender"
    }
  },
  {
    "id": "copilot-091",
    "topic": "Copilot for privileged access workstation review",
    "scenario": "A PAW device shows unusual process activity.",
    "question": "How should analysts use Copilot for PAW investigations?",
    "options": [
      "Request a device risk summary, recent processes/alerts, and compliance posture, then verify before isolation",
      "Assume PAWs are immune and ignore alerts",
      "Wipe all PAWs nightly without evidence",
      "PAWs cannot be queried"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "High-Value Device Investigation",
      "analysis": [
        "Option A is CORRECT: Standard device investigation with higher caution.",
        "Option B is INCORRECT: PAWs are high value targets.",
        "Option C is INCORRECT: Evidence-based response.",
        "Option D is INCORRECT: Device plugins apply."
      ],
      "codeSnippet": "// \"Summarize risk and alerts for PAW device Y\"",
      "socTip": "Prioritize PAW and DC-class devices in triage order.",
      "docRef": "Microsoft Learn: Device investigation with Copilot"
    }
  },
  {
    "id": "copilot-092",
    "topic": "Prompt injection awareness",
    "scenario": "An analyst pastes untrusted email content that tries to instruct Copilot to ignore policies.",
    "question": "What is the correct handling approach?",
    "options": [
      "Treat untrusted content cautiously, avoid following instructions embedded in attacker text, and verify any sensitive actions against portal data",
      "Obey all instructions found inside phishing emails",
      "Disable all safety systems",
      "Publish the attacker instructions org-wide"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Prompt Injection Awareness for SOC Analysts",
      "analysis": [
        "Option A is CORRECT: Untrusted text may attempt prompt injection; analysts stay in control.",
        "Option B is INCORRECT: Dangerous.",
        "Option C is INCORRECT: Safety remains important.",
        "Option D is INCORRECT: Spreads attacker content."
      ],
      "codeSnippet": "// Analyze indicators, do not execute embedded instructions",
      "socTip": "Prefer structured fields (headers, hashes) over full raw body when possible.",
      "docRef": "Microsoft Learn: Responsible AI in Copilot for Security"
    }
  },
  {
    "id": "copilot-093",
    "topic": "Copilot for conditional access troubleshooting",
    "scenario": "A user is blocked by Conditional Access after a risky sign-in.",
    "question": "How can Copilot in Entra help?",
    "options": [
      "Summarize applicable Conditional Access results, risk signals, and recommended remediation such as password reset or MFA re-registration",
      "Remove all Conditional Access policies automatically",
      "Only suggest buying new laptops",
      "Entra Copilot cannot see sign-in risk"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Conditional Access Context via Copilot",
      "analysis": [
        "Option A is CORRECT: Risk and policy context support identity IR.",
        "Option B is INCORRECT: Unsafe.",
        "Option C is INCORRECT: Irrelevant.",
        "Option D is INCORRECT: Risk signals are available."
      ],
      "codeSnippet": "// \"Explain CA failures and risk for user Z\"",
      "socTip": "Confirm device compliance state before blaming CA alone.",
      "docRef": "Microsoft Learn: Copilot in Microsoft Entra"
    }
  },
  {
    "id": "copilot-094",
    "topic": "Shared SCU pool across experiences",
    "scenario": "Embedded Copilot in multiple portals feels slower when standalone usage spikes.",
    "question": "Why might that happen?",
    "options": [
      "SCU capacity is shared across standalone and embedded experiences for the tenant",
      "Each portal has unlimited isolated SCUs by default",
      "Slowness is always caused by DNS only",
      "Embedded experiences do not use SCUs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Shared SCU Capacity Across Experiences",
      "analysis": [
        "Option A is CORRECT: Shared capacity explains cross-experience contention.",
        "Option B is INCORRECT: Capacity is pooled.",
        "Option C is INCORRECT: Incomplete explanation.",
        "Option D is INCORRECT: Embedded also consumes capacity."
      ],
      "codeSnippet": "// Monitor usage; scale SCUs if needed",
      "socTip": "Track concurrent usage during incident bridges.",
      "docRef": "Microsoft Learn: Get started with Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-095",
    "topic": "Copilot for evidence quality checks",
    "scenario": "Copilot cites a device that does not appear in inventory under that name.",
    "question": "What should the analyst do?",
    "options": [
      "Treat it as a verification failure — confirm entity names in the portal, check for renames or typos, and do not act on unverified entities",
      "Isolate every similarly named device",
      "Accept all citations without checking",
      "Disable inventory"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Citation Verification Discipline",
      "analysis": [
        "Option A is CORRECT: Verify entities before action.",
        "Option B is INCORRECT: Overbroad.",
        "Option C is INCORRECT: Violates responsible use.",
        "Option D is INCORRECT: Inventory is needed."
      ],
      "codeSnippet": "// Click citations; confirm in Device inventory",
      "socTip": "Mismatched names are a top hallucination symptom to catch.",
      "docRef": "Microsoft Learn: Responsible AI in Copilot for Security"
    }
  },
  {
    "id": "copilot-096",
    "topic": "Onboarding analysts to Copilot",
    "scenario": "Ten new Tier 1 analysts join next week.",
    "question": "What is a solid onboarding plan?",
    "options": [
      "Grant Contributor roles, enable required plugins, train on prompt patterns and verification, and start with supervised use of built-in promptbooks",
      "Give Owner to all new hires on day one",
      "No training is needed",
      "Block Copilot until they pass a networking exam only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Analyst Onboarding for Copilot",
      "analysis": [
        "Option A is CORRECT: Role, plugins, training, supervised practice.",
        "Option B is INCORRECT: Excessive privilege.",
        "Option C is INCORRECT: Training required.",
        "Option D is INCORRECT: Overly narrow gate."
      ],
      "codeSnippet": "// Contributor + promptbook lab + verification checklist",
      "socTip": "Pair each new analyst with a mentor for first 10 Copilot-assisted incidents.",
      "docRef": "Microsoft Learn: Get started with Copilot for Security"
    }
  },
  {
    "id": "copilot-097",
    "topic": "Maintaining promptbook quality",
    "scenario": "Some shared promptbooks produce outdated guidance after product UI changes.",
    "question": "How should the SOC maintain promptbook quality?",
    "options": [
      "Assign owners, review quarterly, update steps, and retire stale promptbooks",
      "Never review promptbooks after creation",
      "Let every analyst fork silently forever",
      "Encode promptbooks in Latin only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Promptbook Quality Management",
      "analysis": [
        "Option A is CORRECT: Ownership and periodic review keep content accurate.",
        "Option B is INCORRECT: Drift will occur.",
        "Option C is INCORRECT: Causes inconsistency.",
        "Option D is INCORRECT: Not helpful."
      ],
      "codeSnippet": "// Quarterly promptbook review board",
      "socTip": "Link each promptbook to a detection or IR procedure ID.",
      "docRef": "Microsoft Learn: Use promptbooks in Microsoft Copilot for Security"
    }
  },
  {
    "id": "copilot-098",
    "topic": "Copilot for zero-day Threat Analytics",
    "scenario": "A new Threat Analytics report appears for an actively exploited zero-day.",
    "question": "How can Copilot accelerate response?",
    "options": [
      "Ask Copilot to summarize organizational exposure, related alerts, and recommended mitigations based on Threat Analytics and environment data",
      "Wait a month before reading the report",
      "Only forward the report without analysis",
      "Disable all sensors"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Zero-Day Exposure Acceleration",
      "analysis": [
        "Option A is CORRECT: Combines TI report context with environment impact.",
        "Option B is INCORRECT: Too slow.",
        "Option C is INCORRECT: Analysis required.",
        "Option D is INCORRECT: Reduces visibility."
      ],
      "codeSnippet": "// \"Summarize exposure for Threat Analytics report X\"",
      "socTip": "Track mitigation completion daily until exposure reaches zero.",
      "docRef": "Microsoft Learn: Threat intelligence in Copilot for Security"
    }
  },
  {
    "id": "copilot-099",
    "topic": "Final Copilot operating model",
    "scenario": "Leadership asks for a one-line operating model for Copilot in the SOC.",
    "question": "Which statement best captures a mature operating model?",
    "options": [
      "Copilot augments analysts with summaries, hunts, and guidance while humans verify evidence and approve high-impact actions under RBAC, audit, and promptbook standards",
      "Copilot fully replaces the SOC",
      "Copilot is only for writing marketing blogs",
      "Copilot should run without logging"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Mature Copilot SOC Operating Model",
      "analysis": [
        "Option A is CORRECT: Assistive AI with human control, governance, and standards.",
        "Option B is INCORRECT: Humans remain accountable.",
        "Option C is INCORRECT: SOC operational tool.",
        "Option D is INCORRECT: Audit is mandatory."
      ],
      "codeSnippet": "// Assist → Verify → Act → Audit",
      "socTip": "Publish this model in the SOC charter and IR plan.",
      "docRef": "Microsoft Learn: Responsible AI in Copilot for Security"
    }
  },
  {
    "id": "copilot-100",
    "topic": "Copilot for mass password reset decisions",
    "scenario": "A large password spray may have touched hundreds of accounts; leadership asks whether to force reset all users.",
    "question": "How should Copilot be used in a mass credential-reset decision?",
    "options": [
      "Use Copilot to help identify likely compromised accounts from risk and sign-in evidence, then apply targeted resets and session revocation with human approval rather than blindly resetting the entire tenant",
      "Always force reset every account in the tenant without evidence",
      "Never reset any passwords after sprays",
      "Only reset passwords for shared service accounts and ignore users"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Targeted Containment Using Evidence",
      "analysis": [
        "Option A is CORRECT: Evidence-driven targeting reduces business disruption while addressing real risk.",
        "Option B is INCORRECT: Mass resets without evidence are highly disruptive.",
        "Option C is INCORRECT: Compromised credentials must be addressed.",
        "Option D is INCORRECT: User accounts are often the primary target."
      ],
      "codeSnippet": "// Identify risky users → targeted reset + revoke sessions",
      "socTip": "Combine risk detections with successful unusual sign-ins before expanding reset scope.",
      "docRef": "Microsoft Learn: Identity risk assessment with Copilot"
    }
  }
]

def build_questions():
    """Attach module/audioSummary; keep explicit id for tracking 001-100."""
    result = []
    for i, q in enumerate(QUESTIONS):
        # Prefer explicit id; fall back to sequential if missing
        qid = q.get("id") or f"copilot-{i+1:03d}"
        concept = q["explanation"]["concept"]
        correct_analysis = q["explanation"]["analysis"][q["correctIndex"]]
        audio = concept + ". " + (
            correct_analysis.split(": ", 1)[1][:200]
            if ": " in correct_analysis else correct_analysis[:200]
        )
        result.append({
            "id": qid,
            "module": "copilot",
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
    output = "const COPILOT_QUESTIONS = " + json.dumps(questions, indent=2, ensure_ascii=False) + ";\n"
    with open("questions_copilot_v2.js", "w", encoding="utf-8") as f:
        f.write(output)

    stems = set(q["question"] for q in questions)
    scenarios = set(q["scenario"][:80] for q in questions)
    ids = [q["id"] for q in questions]
    ci_dist = {}
    for q in questions:
        ci_dist[q["correctIndex"]] = ci_dist.get(q["correctIndex"], 0) + 1

    print(f"[+] Generated {len(questions)} Copilot questions -> questions_copilot_v2.js")
    print(f"    ID range: {ids[0]} .. {ids[-1]}")
    print(f"    Unique IDs: {len(set(ids))}/{len(questions)}")
    print(f"    Unique question stems: {len(stems)}/{len(questions)}")
    print(f"    Unique scenario prefixes: {len(scenarios)}/{len(questions)}")
    print(f"    correctIndex distribution: {ci_dist}")
    # Easy track checklist
    expected = [f"copilot-{i:03d}" for i in range(1, 101)]
    missing = [e for e in expected if e not in set(ids)]
    print(f"    Missing IDs: {missing if missing else 'none (complete 001-100)'}")
