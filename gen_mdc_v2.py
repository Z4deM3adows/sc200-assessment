"""
SC-200 Question Generator — Microsoft Defender for Cloud Module (100 Questions)
Each question has unique scenario, varied stem, 4 specific options, per-option explanations, and SOC tips.
"""
import json

QUESTIONS = [
  {
    "topic": "CSPM vs CWPP",
    "scenario": "Contoso is evaluating Microsoft Defender for Cloud. The CISO asks how posture management differs from workload protection.",
    "question": "What is the primary difference between CSPM and CWPP in Microsoft Defender for Cloud?",
    "options": [
      "CSPM assesses configuration and compliance posture (recommendations, secure score); CWPP provides runtime threat detection and protection for specific workloads such as servers, containers, and databases",
      "CSPM only works on AWS while CWPP only works on Azure",
      "CSPM and CWPP are identical marketing names for the same feature",
      "CWPP is free and CSPM is always paid"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "CSPM vs Cloud Workload Protection",
      "analysis": [
        "Option A is CORRECT: Cloud Security Posture Management focuses on configuration hygiene and compliance; Cloud Workload Protection Platform monitors runtime behavior and detects active threats against workloads.",
        "Option B is INCORRECT: Both CSPM and CWPP support multi-cloud scenarios with appropriate connectors and Arc.",
        "Option C is INCORRECT: They are complementary but distinct capability sets.",
        "Option D is INCORRECT: Foundational CSPM has a free tier; CWPP plans are typically paid enhancements."
      ],
      "codeSnippet": "// CSPM: recommendations, secure score, compliance\n// CWPP: Defender for Servers, Containers, SQL, Storage, etc.\n// Enable plans under Environment settings / Defender plans",
      "socTip": "Enable Foundational CSPM everywhere first for visibility, then add CWPP plans only for workload types that need runtime protection.",
      "docRef": "Microsoft Learn: Defender for Cloud introduction"
    }
  },
  {
    "topic": "Foundational CSPM vs Defender CSPM",
    "scenario": "Fabrikam wants advanced features such as attack path analysis and risk-based prioritization of recommendations.",
    "question": "Which plan provides advanced CSPM capabilities including attack path analysis and risk prioritization?",
    "options": [
      "Defender CSPM (paid) — includes advanced posture features such as attack path analysis, Cloud Security Explorer, agentless scanning insights, and risk-prioritized recommendations",
      "Foundational CSPM only — it already includes attack path analysis at no cost",
      "Defender for Servers Plan 1 only",
      "Microsoft Sentinel alone provides attack path analysis for cloud resources"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender CSPM Advanced Capabilities",
      "analysis": [
        "Option A is CORRECT: Defender CSPM unlocks advanced posture tools beyond the free Foundational CSPM tier.",
        "Option B is INCORRECT: Foundational CSPM provides core recommendations and secure score but not the full advanced graph and risk prioritization feature set.",
        "Option C is INCORRECT: Defender for Servers is a CWPP plan, not the advanced CSPM plan.",
        "Option D is INCORRECT: Sentinel correlates logs; attack path analysis for cloud posture is a Defender for Cloud CSPM capability."
      ],
      "codeSnippet": "// Environment settings → enable Defender CSPM\n// Features: attack paths, Cloud Security Explorer,\n//   risk prioritization, agentless insights",
      "socTip": "If your SOC struggles with recommendation overload, enable Defender CSPM so risk prioritization surfaces the findings that matter most.",
      "docRef": "Microsoft Learn: Cloud Security Posture Management"
    }
  },
  {
    "topic": "Secure Score",
    "scenario": "Northwind Traders’ CISO wants a single metric that reflects cloud security posture improvement over time.",
    "question": "What does the Secure Score (Cloud Secure Score) in Defender for Cloud represent?",
    "options": [
      "A numerical summary of security posture based on completed recommendations relative to applicable controls; improving the score indicates reduced identified risk from configuration gaps",
      "A count of open security alerts only",
      "A credit-style score of individual users",
      "A public ranking of the organization against other tenants"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Secure Score",
      "analysis": [
        "Option A is CORRECT: Secure Score aggregates the impact of remediated vs. outstanding recommendations (primarily from MCSB) into a 0–100 style posture metric.",
        "Option B is INCORRECT: Alert volume is separate from configuration posture scoring.",
        "Option C is INCORRECT: It is an environmental posture score, not a per-user score.",
        "Option D is INCORRECT: Scores are private to the tenant."
      ],
      "codeSnippet": "// Defender for Cloud → Secure Score / Overview\n// Drill into controls and recommendations\n// Track score history over time",
      "socTip": "Report Secure Score monthly to leadership and pair it with the top 5 recommendations by risk or affected resource count.",
      "docRef": "Microsoft Learn: Secure score in Defender for Cloud"
    }
  },
  {
    "topic": "Security recommendations",
    "scenario": "An analyst opens a high-severity recommendation about unrestricted network access to a storage account.",
    "question": "What information does a security recommendation typically provide?",
    "options": [
      "Description of the misconfiguration, severity/risk level, affected resources, remediation steps, and often attack-path or MITRE context to help prioritize and fix the issue",
      "Only a binary pass/fail with no guidance",
      "Only a link to a general Azure documentation home page",
      "A mandatory automatic fix that cannot be reviewed"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Actionable Security Recommendations",
      "analysis": [
        "Option A is CORRECT: Recommendations are designed to be actionable with remediation guidance and prioritization context.",
        "Option B is INCORRECT: Rich detail is provided.",
        "Option C is INCORRECT: Guidance is specific to the finding.",
        "Option D is INCORRECT: Remediation is guided; automatic fixes require explicit workflow automation or approval."
      ],
      "codeSnippet": "// Recommendations blade → open item\n// View affected resources, remediation steps\n// Exempt, remediate, or create ticket",
      "socTip": "Use risk level and attack path count to triage recommendations when the queue is large.",
      "docRef": "Microsoft Learn: Review security recommendations"
    }
  },
  {
    "topic": "Microsoft Cloud Security Benchmark",
    "scenario": "Litware enables Defender for Cloud on a new subscription and notices a default security standard is applied.",
    "question": "What is the Microsoft Cloud Security Benchmark (MCSB) in Defender for Cloud?",
    "options": [
      "A built-in security standard that maps cloud security principles to detailed technical controls for Azure and multi-cloud; its recommendations primarily drive the Secure Score",
      "A third-party ISO certification that Microsoft sells",
      "A network firewall rule set only",
      "A list of deprecated Azure services"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Microsoft Cloud Security Benchmark",
      "analysis": [
        "Option A is CORRECT: MCSB is the default foundational standard applied to subscriptions and is the main contributor to Secure Score recommendations.",
        "Option B is INCORRECT: MCSB is Microsoft’s own control framework guidance, not a paid ISO cert.",
        "Option C is INCORRECT: It covers identity, data, network, compute, and more—not only firewalls.",
        "Option D is INCORRECT: It is a positive security baseline, not a deprecation list."
      ],
      "codeSnippet": "// Environment settings → Security policy\n// Standards: Microsoft Cloud Security Benchmark\n// Recommendations from MCSB feed Secure Score",
      "socTip": "Treat MCSB as your minimum cloud baseline; add regulatory standards (PCI, ISO, NIST) as needed for compliance reporting.",
      "docRef": "Microsoft Learn: Microsoft cloud security benchmark"
    }
  },
  {
    "topic": "Defender for Servers plans",
    "scenario": "Adatum needs endpoint detection and vulnerability assessment on Azure VMs and Arc-enabled servers.",
    "question": "What is a key distinction between Defender for Servers Plan 1 and Plan 2?",
    "options": [
      "Plan 2 includes broader capabilities such as richer threat detection, vulnerability assessment options, and additional features beyond the more limited Plan 1 feature set",
      "Plan 1 includes everything and Plan 2 is a downgrade",
      "Plan 2 only supports Linux and Plan 1 only supports Windows",
      "There is no difference between the plans"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Servers P1 vs P2",
      "analysis": [
        "Option A is CORRECT: Plan 2 is the fuller server protection tier; Plan 1 is a lighter option. Exact feature matrices evolve, but P2 is the more complete offering.",
        "Option B is INCORRECT: Plan 2 is the higher capability plan.",
        "Option C is INCORRECT: Both plans support Windows and Linux with appropriate agents/extensions.",
        "Option D is INCORRECT: Feature differences exist and matter for licensing decisions."
      ],
      "codeSnippet": "// Defender plans → Servers\n// Choose Plan 1 or Plan 2 per subscription\n// Arc for non-Azure servers",
      "socTip": "Map required capabilities (MDE integration, VA, just-in-time, etc.) to the current Plan 1/2 matrix before purchasing at scale.",
      "docRef": "Microsoft Learn: Defender for Servers plans"
    }
  },
  {
    "topic": "Just-in-time VM access",
    "scenario": "Contoso’s security team wants to reduce persistent exposure of RDP and SSH on management ports of Azure VMs.",
    "question": "How does just-in-time (JIT) VM access improve security?",
    "options": [
      "JIT locks down management ports by default and opens them only for approved users for a limited time window, reducing the attack surface from persistent open RDP/SSH",
      "JIT permanently disables all remote access forever",
      "JIT only encrypts disks",
      "JIT replaces the need for NSGs entirely"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Just-in-Time VM Access",
      "analysis": [
        "Option A is CORRECT: JIT uses temporary, approved access requests instead of always-open management ports.",
        "Option B is INCORRECT: Access remains available when requested and approved.",
        "Option C is INCORRECT: Disk encryption is a separate control (e.g., Azure Disk Encryption / CMEK).",
        "Option D is INCORRECT: JIT works with NSGs/ASGs; it does not eliminate network controls."
      ],
      "codeSnippet": "// Defender for Cloud → JIT VM access\n// Configure ports (3389, 22, etc.)\n// Users request access → time-bound allow",
      "socTip": "Enable JIT on all internet-facing or high-value VMs and audit access requests regularly for anomalous patterns.",
      "docRef": "Microsoft Learn: Just-in-time machine access"
    }
  },
  {
    "topic": "Multi-cloud AWS/GCP connectors",
    "scenario": "Fabrikam runs workloads in Azure, AWS, and GCP and wants unified posture and protection in Defender for Cloud.",
    "question": "How does Defender for Cloud extend to AWS and GCP?",
    "options": [
      "Native environment connectors onboard AWS accounts and GCP projects for agentless CSPM and, with additional components such as Arc, CWPP coverage for supported workloads",
      "Only by exporting CSV reports weekly from each cloud",
      "Defender for Cloud cannot see non-Azure resources",
      "Only through a third-party CASB with no Microsoft connector"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Multi-Cloud Connectors",
      "analysis": [
        "Option A is CORRECT: Environment settings provide AWS and GCP connectors for unified CSPM; CWPP for non-Azure often depends on Arc and plan-specific agents.",
        "Option B is INCORRECT: Continuous connectors replace manual exports.",
        "Option C is INCORRECT: Multi-cloud is a first-class capability.",
        "Option D is INCORRECT: Microsoft provides native connectors."
      ],
      "codeSnippet": "// Environment settings → Add environment\n// AWS / GCP connector\n// Configure permissions / federated auth\n// Verify recommendations appear",
      "socTip": "Use least-privilege connector roles and prefer federated authentication over long-lived access keys.",
      "docRef": "Microsoft Learn: Connect multi-cloud environments"
    }
  },
  {
    "topic": "Azure Arc hybrid coverage",
    "scenario": "Northwind has on-premises Windows and Linux servers that must appear in Defender for Cloud for posture and threat protection.",
    "question": "What role does Azure Arc play for non-Azure servers in Defender for Cloud?",
    "options": [
      "Azure Arc projects on-premises and multi-cloud machines into Azure as Arc-enabled servers so Defender for Cloud plans (e.g., Defender for Servers) can protect them like Azure VMs",
      "Arc only works for Kubernetes and cannot protect servers",
      "Arc replaces Active Directory Domain Services",
      "Arc is required for every Azure VM"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Azure Arc for Hybrid Server Protection",
      "analysis": [
        "Option A is CORRECT: Arc is the bridge that brings non-Azure servers into Azure resource management and Defender for Cloud scope.",
        "Option B is INCORRECT: Arc supports servers as well as Kubernetes and other resource types.",
        "Option C is INCORRECT: Arc does not replace AD DS.",
        "Option D is INCORRECT: Native Azure VMs do not need Arc."
      ],
      "codeSnippet": "// Install Arc agent on server\n// Resource appears in Azure\n// Enable Defender for Servers on subscription\n// Verify in inventory and recommendations",
      "socTip": "Standardize Arc onboarding in your server build pipeline so new hybrid machines are protected automatically.",
      "docRef": "Microsoft Learn: Azure Arc and Defender for Cloud"
    }
  },
  {
    "topic": "Defender for Containers",
    "scenario": "Litware runs AKS and also has EKS clusters. They want vulnerability and runtime protection for containers.",
    "question": "What does Defender for Containers provide?",
    "options": [
      "Vulnerability assessment of images and running containers, runtime threat detection, and Kubernetes environment hardening recommendations across supported Azure, AWS, and GCP clusters",
      "Only Docker Hub marketing emails",
      "Only host OS antivirus with no container awareness",
      "Container protection only for Azure Container Instances with no Kubernetes support"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Containers",
      "analysis": [
        "Option A is CORRECT: The plan covers image scanning, runtime detection, and Kubernetes posture across supported environments.",
        "Option B is INCORRECT: It is a security product capability.",
        "Option C is INCORRECT: It is container- and Kubernetes-aware.",
        "Option D is INCORRECT: Kubernetes (AKS/EKS/GKE/Arc) is a primary focus."
      ],
      "codeSnippet": "// Defender plans → Containers\n// Enable for subscriptions / connectors\n// Review recommendations and runtime alerts",
      "socTip": "Scan images in CI/CD before deployment and monitor runtime alerts for anomalous process or network behavior in clusters.",
      "docRef": "Microsoft Learn: Defender for Containers"
    }
  },
  {
    "topic": "Defender for Storage",
    "scenario": "Contoso stores sensitive documents in Azure Storage and wants malware scanning on uploaded blobs.",
    "question": "What capability can Defender for Storage provide for blob protection?",
    "options": [
      "Malware scanning of uploaded blobs (when configured), detection of unusual access patterns, and security recommendations for storage account configuration",
      "Only encryption key rotation with no threat detection",
      "Only public website hosting features",
      "Storage protection is limited to on-premises file servers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Storage Protections",
      "analysis": [
        "Option A is CORRECT: Defender for Storage includes threat detection and optional malware scanning for blobs, plus posture recommendations.",
        "Option B is INCORRECT: Key management is separate (Key Vault); Defender for Storage focuses on threats and posture.",
        "Option C is INCORRECT: Hosting is not the security feature set.",
        "Option D is INCORRECT: It targets Azure Storage (and related) cloud resources."
      ],
      "codeSnippet": "// Defender plans → Storage\n// Configure malware scanning if required\n// Monitor alerts for suspicious access",
      "socTip": "Enable malware scanning on storage accounts that accept untrusted uploads (user content, partner drop zones).",
      "docRef": "Microsoft Learn: Defender for Storage"
    }
  },
  {
    "topic": "Defender for SQL",
    "scenario": "Adatum’s database team needs threat detection and vulnerability assessment for Azure SQL and SQL on machines.",
    "question": "What does Defender for SQL provide?",
    "options": [
      "Threat detection for anomalous database activities, vulnerability assessment, and security recommendations for SQL workloads including Azure SQL and SQL on machines (with appropriate setup)",
      "Only automatic query performance tuning",
      "Only backup scheduling",
      "SQL protection without any alerting capability"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for SQL",
      "analysis": [
        "Option A is CORRECT: The plan focuses on threat detection and vulnerability assessment for SQL estates.",
        "Option B is INCORRECT: Performance tuning is an Azure SQL feature set, not the core of Defender for SQL.",
        "Option C is INCORRECT: Backup is separate (Azure Backup / native SQL backup).",
        "Option D is INCORRECT: Alerts are a primary output."
      ],
      "codeSnippet": "// Defender plans → Databases / SQL\n// Enable VA and threat detection\n// Review findings and alerts",
      "socTip": "Treat SQL vulnerability assessment results like endpoint VA—track remediation SLAs for high findings on production databases.",
      "docRef": "Microsoft Learn: Defender for SQL"
    }
  },
  {
    "topic": "Defender for Key Vault",
    "scenario": "A suspicious principal is enumerating secrets in Azure Key Vault. The SOC wants detection for such activity.",
    "question": "How does Defender for Key Vault help?",
    "options": [
      "It detects unusual and potentially malicious access patterns to Key Vault (e.g., anomalous secret access or enumeration) and raises security alerts for investigation",
      "It automatically deletes all secrets daily",
      "It only manages DNS records",
      "Key Vault cannot be monitored by Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Key Vault Threat Detection",
      "analysis": [
        "Option A is CORRECT: The plan focuses on anomalous access and potential exfiltration or abuse patterns against Key Vault.",
        "Option B is INCORRECT: Secrets are not auto-deleted by the plan.",
        "Option C is INCORRECT: DNS is unrelated.",
        "Option D is INCORRECT: Key Vault is a supported workload plan."
      ],
      "codeSnippet": "// Defender plans → Key Vault\n// Monitor alerts for anomalous access\n// Correlate with identity signs of compromise",
      "socTip": "Pair Key Vault alerts with Entra ID sign-in and Identity Protection signals when investigating potential secret theft.",
      "docRef": "Microsoft Learn: Defender for Key Vault"
    }
  },
  {
    "topic": "Security alerts investigation",
    "scenario": "A high-severity alert indicates possible cryptomining on an Azure VM protected by Defender for Servers.",
    "question": "What should an analyst typically do when investigating a Defender for Cloud security alert?",
    "options": [
      "Review alert details, affected resource, kill chain / MITRE mapping, evidence, and take response actions or follow remediation steps; optionally trigger automation or escalate to an incident",
      "Ignore all high-severity alerts because they are always false positives",
      "Only reboot the VM without investigation",
      "Delete the resource immediately without evidence collection"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Investigation Workflow",
      "analysis": [
        "Option A is CORRECT: Structured investigation uses the alert context, evidence, and guided response before destructive actions.",
        "Option B is INCORRECT: High-severity alerts deserve priority triage.",
        "Option C is INCORRECT: Reboot alone may destroy forensic evidence and not remove persistence.",
        "Option D is INCORRECT: Evidence and impact assessment should precede deletion."
      ],
      "codeSnippet": "// Security alerts → open alert\n// Review evidence, MITRE tactics\n// Take action / remediate / suppress if FP",
      "socTip": "For compute alerts, correlate with MDE (if integrated) and identity logs before concluding the blast radius.",
      "docRef": "Microsoft Learn: Manage security alerts in Defender for Cloud"
    }
  },
  {
    "topic": "Workflow automation",
    "scenario": "Northwind wants every high-severity Defender for Cloud alert to create a ServiceNow ticket and post to a Teams channel.",
    "question": "How can response to Defender for Cloud alerts be automated?",
    "options": [
      "Configure workflow automation (Logic Apps) triggered by alerts or recommendations to run playbooks that notify, ticket, or remediate according to policy",
      "Automation is impossible; every alert must be handled only in the portal UI",
      "Only email can be sent and only once per month",
      "Automation requires disabling all Defender plans"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Workflow Automation with Logic Apps",
      "analysis": [
        "Option A is CORRECT: Workflow automation connects alerts/recommendations to Logic Apps playbooks for SOAR-style response.",
        "Option B is INCORRECT: Automation is a built-in capability.",
        "Option C is INCORRECT: Rich actions beyond infrequent email are supported.",
        "Option D is INCORRECT: Automation complements plans; it does not require disabling them."
      ],
      "codeSnippet": "// Workflow automation → Add\n// Trigger: Security alert / Recommendation\n// Action: Logic App playbook\n// Filter by severity or alert type",
      "socTip": "Start with notification-only playbooks, then add enrichment and auto-remediation for well-understood, low-risk alert types.",
      "docRef": "Microsoft Learn: Workflow automation in Defender for Cloud"
    }
  },
  {
    "topic": "Alert suppression rules",
    "scenario": "A noisy alert about a known-benign administrative tool fires repeatedly on a management subnet.",
    "question": "How can false-positive alert noise be reduced without disabling the underlying detection globally?",
    "options": [
      "Create an alert suppression rule scoped to the specific alert type, resource, or other attributes so matching alerts are suppressed while the detection remains active elsewhere",
      "Disable Defender for Cloud on the entire subscription permanently",
      "Delete the virtual network",
      "Suppression rules are not supported"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Suppression",
      "analysis": [
        "Option A is CORRECT: Scoped suppression preserves detection coverage while silencing known benign patterns.",
        "Option B is INCORRECT: Over-broad and removes protection.",
        "Option C is INCORRECT: Destructive and unrelated to alert tuning.",
        "Option D is INCORRECT: Suppression is supported."
      ],
      "codeSnippet": "// Security alerts → Suppression rules\n// Define entities / alert types to suppress\n// Document owner and review date",
      "socTip": "Require a ticket number and expiry date on every suppression rule to avoid permanent blind spots.",
      "docRef": "Microsoft Learn: Suppress alerts from Defender for Cloud"
    }
  },
  {
    "topic": "Attack path analysis",
    "scenario": "Defender CSPM shows an attack path from an internet-exposed VM to a sensitive data store via over-privileged identity.",
    "question": "What does attack path analysis help the SOC understand?",
    "options": [
      "Chained risks showing how an attacker could move from an entry point through misconfigurations and identities to reach critical assets, enabling prioritized remediation of the path",
      "Only the physical cable layout of the datacenter",
      "Only email phishing paths",
      "Attack paths are decorative and have no remediation value"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Attack Path Analysis",
      "analysis": [
        "Option A is CORRECT: Attack paths connect posture findings into realistic compromise scenarios for prioritization.",
        "Option B is INCORRECT: It is logical/cloud topology and identity based, not physical cabling.",
        "Option C is INCORRECT: Focus is cloud resource and identity paths.",
        "Option D is INCORRECT: Paths drive high-value remediation decisions."
      ],
      "codeSnippet": "// Defender CSPM → Attack path analysis\n// Review entry points, chokepoints, targets\n// Remediate critical nodes on the path",
      "socTip": "Fix the highest-leverage node on an attack path (often internet exposure or standing admin privileges) to collapse multiple scenarios at once.",
      "docRef": "Microsoft Learn: Attack path analysis"
    }
  },
  {
    "topic": "Cloud Security Explorer",
    "scenario": "A hunter wants to proactively find all internet-facing resources that also have critical severity vulnerabilities.",
    "question": "What is Cloud Security Explorer used for?",
    "options": [
      "Graph-based querying of the cloud security graph to proactively discover resources matching complex risk combinations (exposure, vulnerabilities, identities, sensitive data)",
      "Only editing NSG rules one at a time",
      "Only purchasing Azure reservations",
      "Exploring the Azure retail website"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Security Explorer",
      "analysis": [
        "Option A is CORRECT: Explorer lets analysts query the security graph for advanced hunting-style posture questions.",
        "Option B is INCORRECT: NSG management is elsewhere.",
        "Option C is INCORRECT: Unrelated to cost management.",
        "Option D is INCORRECT: It is a security graph tool."
      ],
      "codeSnippet": "// Cloud Security Explorer\n// Build query: Internet exposed + Critical VA\n// Review results and related attack paths",
      "socTip": "Save common Explorer queries (exposed + sensitive data, admin without MFA context, etc.) as part of weekly posture hunting.",
      "docRef": "Microsoft Learn: Cloud Security Explorer"
    }
  },
  {
    "topic": "Regulatory compliance dashboard",
    "scenario": "Litware must demonstrate alignment with ISO 27001 and PCI-DSS controls for an audit.",
    "question": "How does Defender for Cloud help with regulatory compliance reporting?",
    "options": [
      "The regulatory compliance dashboard maps resources to controls in selected standards (ISO, PCI, NIST, etc.), shows pass/fail status, and supports audit-ready reporting",
      "Compliance can only be proven by manual spreadsheets with no portal support",
      "Defender for Cloud only supports a single proprietary standard with no industry frameworks",
      "The dashboard deletes evidence after 24 hours"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Regulatory Compliance Standards",
      "analysis": [
        "Option A is CORRECT: Built-in and selectable standards provide continuous compliance assessment and reporting.",
        "Option B is INCORRECT: The portal provides continuous assessment.",
        "Option C is INCORRECT: Many industry and regulatory standards are available.",
        "Option D is INCORRECT: Status is retained for ongoing reporting."
      ],
      "codeSnippet": "// Regulatory compliance → add standards\n// Review control status and evidence\n// Export reports for auditors",
      "socTip": "Assign control owners for failed regulatory controls and track them in the same cadence as Secure Score improvements.",
      "docRef": "Microsoft Learn: Regulatory compliance in Defender for Cloud"
    }
  },
  {
    "topic": "Agentless scanning",
    "scenario": "Fabrikam wants vulnerability and secret scanning on cloud VMs without deploying additional agents on every machine.",
    "question": "What is agentless scanning in Defender for Cloud?",
    "options": [
      "Disk and configuration scanning performed without installing a monitoring agent on the VM, providing vulnerability and secrets insights with lower operational overhead",
      "Scanning that only works when the VM is powered off permanently",
      "A replacement for all network firewalls",
      "Agentless scanning is not available in Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Agentless Disk and Configuration Scanning",
      "analysis": [
        "Option A is CORRECT: Agentless methods reduce agent footprint while still surfacing critical posture and vulnerability data.",
        "Option B is INCORRECT: Scanning is designed for normal operational states per product design.",
        "Option C is INCORRECT: Unrelated to firewall replacement.",
        "Option D is INCORRECT: Agentless capabilities are a key CSPM/CWPP feature."
      ],
      "codeSnippet": "// Defender CSPM / Servers settings\n// Agentless scanning options\n// Review findings in recommendations / VA",
      "socTip": "Use agentless scanning for broad coverage and agents/extensions where deeper runtime detection is required.",
      "docRef": "Microsoft Learn: Agentless scanning"
    }
  },
  {
    "topic": "Adaptive application controls",
    "scenario": "Contoso wants to allow only known-good applications to run on a group of sensitive VMs.",
    "question": "What do adaptive application controls do?",
    "options": [
      "They create allow-lists of applications based on observed behavior and can alert or enforce when unapproved applications run on configured machine groups",
      "They automatically uninstall Office from all VMs",
      "They only control outbound internet bandwidth",
      "They replace Microsoft Entra Conditional Access"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Adaptive Application Controls",
      "analysis": [
        "Option A is CORRECT: AAC learns or defines application allow-lists for VM groups and monitors deviations.",
        "Option B is INCORRECT: It does not mass-uninstall productivity software.",
        "Option C is INCORRECT: Bandwidth control is not the feature purpose.",
        "Option D is INCORRECT: Conditional Access is an identity control plane feature."
      ],
      "codeSnippet": "// Adaptive application controls\n// Create group → audit → enforce\n// Review alerts for unlisted apps",
      "socTip": "Run AAC in audit mode long enough to capture legitimate change windows before enforcing.",
      "docRef": "Microsoft Learn: Adaptive application controls"
    }
  },
  {
    "topic": "File integrity monitoring",
    "scenario": "Adatum needs to detect unauthorized changes to critical system files and registry keys on servers.",
    "question": "What does file integrity monitoring (FIM) provide in Defender for Cloud?",
    "options": [
      "Monitoring of changes to specified files, registries, and paths on protected machines, generating alerts when unexpected modifications occur",
      "Automatic daily full disk encryption only",
      "Only cloud file share capacity metrics",
      "FIM is only available for mobile devices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "File Integrity Monitoring",
      "analysis": [
        "Option A is CORRECT: FIM tracks integrity of critical system and application artifacts for change detection.",
        "Option B is INCORRECT: Encryption is separate.",
        "Option C is INCORRECT: Capacity metrics are not FIM.",
        "Option D is INCORRECT: FIM targets servers/VMs in this context."
      ],
      "codeSnippet": "// Defender for Servers capabilities\n// Configure FIM rules / workspace\n// Investigate change alerts",
      "socTip": "Baseline FIM on domain controllers, jump boxes, and Tier 0 assets first where unauthorized change risk is highest.",
      "docRef": "Microsoft Learn: File integrity monitoring"
    }
  },
  {
    "topic": "Continuous export",
    "scenario": "Northwind streams Defender for Cloud recommendations and alerts into Log Analytics and a SIEM for long-term retention.",
    "question": "What does continuous export enable?",
    "options": [
      "Ongoing export of security alerts, recommendations, and secure score data to Log Analytics workspaces, Event Hubs, or other destinations for SIEM, reporting, and retention",
      "A one-time PDF download only",
      "Export only of VM screenshots",
      "Continuous export deletes data from Defender for Cloud after sending"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Continuous Export of Security Data",
      "analysis": [
        "Option A is CORRECT: Continuous export keeps downstream systems synchronized with Defender for Cloud security data.",
        "Option B is INCORRECT: Export is continuous, not one-shot PDF only.",
        "Option C is INCORRECT: Security metadata is exported, not screenshots.",
        "Option D is INCORRECT: Export does not purge the source service data as its purpose."
      ],
      "codeSnippet": "// Environment settings → Continuous export\n// Target: Log Analytics / Event Hub\n// Select data types: alerts, recommendations, score",
      "socTip": "Export to the same Log Analytics workspace used by Sentinel when you want unified KQL hunting across cloud posture and other signals.",
      "docRef": "Microsoft Learn: Continuous export"
    }
  },
  {
    "topic": "Roles and permissions",
    "scenario": "Litware wants SOC analysts to view recommendations and alerts but not change Defender plans or pricing tier settings.",
    "question": "Which approach follows least privilege for SOC analysts in Defender for Cloud?",
    "options": [
      "Assign roles such as Security Reader or a custom role with read/alert permissions, reserving Subscription Contributor / Security Admin / Owner for platform security engineers",
      "Give every analyst Owner on all subscriptions",
      "Roles cannot be used; everyone has full access",
      "Only the Global Administrator of Entra ID can view alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "RBAC for Defender for Cloud",
      "analysis": [
        "Option A is CORRECT: Built-in and custom Azure RBAC roles separate read/respond from configuration and billing changes.",
        "Option B is INCORRECT: Owner is excessive for Tier 1 analysts.",
        "Option C is INCORRECT: Azure RBAC fully applies.",
        "Option D is INCORRECT: Security roles enable SOC access without Global Admin."
      ],
      "codeSnippet": "// Azure RBAC on subscription / MG\n// Security Reader, Security Admin, etc.\n// Custom roles for finer control",
      "socTip": "Prefer management-group scoped assignments for consistent SOC access across many subscriptions.",
      "docRef": "Microsoft Learn: Roles in Defender for Cloud"
    }
  },
  {
    "topic": "Defender for App Service",
    "scenario": "Contoso hosts customer-facing web apps on Azure App Service and needs threat detection for those workloads.",
    "question": "What does Defender for App Service focus on?",
    "options": [
      "Threat detection for Azure App Service applications, identifying attacks and suspicious behaviors targeting web apps hosted on the platform",
      "Only DNS zone management",
      "Only virtual network peering configuration",
      "App Service apps cannot be protected by Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for App Service",
      "analysis": [
        "Option A is CORRECT: The plan provides threat detection tailored to App Service workloads.",
        "Option B is INCORRECT: DNS has its own considerations and plans.",
        "Option C is INCORRECT: Networking configuration is separate.",
        "Option D is INCORRECT: App Service is a supported plan target."
      ],
      "codeSnippet": "// Defender plans → App Service\n// Monitor alerts for web app attacks",
      "socTip": "Correlate App Service alerts with WAF logs and identity signals for full request context.",
      "docRef": "Microsoft Learn: Defender for App Service"
    }
  },
  {
    "topic": "Defender for Resource Manager",
    "scenario": "An attacker uses stolen credentials to create unusual deployments and role assignments via Azure Resource Manager.",
    "question": "How does Defender for Resource Manager help detect control-plane abuse?",
    "options": [
      "It monitors Azure Resource Manager operations for suspicious patterns such as anomalous management activity, potential exploitation, and unusual control-plane behavior",
      "It only protects blob storage downloads",
      "It disables Resource Manager APIs entirely",
      "Resource Manager activity cannot be monitored"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Resource Manager",
      "analysis": [
        "Option A is CORRECT: The plan focuses on control-plane threat detection across ARM operations.",
        "Option B is INCORRECT: Storage has its own plan.",
        "Option C is INCORRECT: Monitoring does not mean disabling ARM.",
        "Option D is INCORRECT: Monitoring is the purpose of the plan."
      ],
      "codeSnippet": "// Defender plans → Resource Manager\n// Investigate anomalous management alerts\n// Correlate with Entra ID sign-ins",
      "socTip": "Treat unusual ARM activity from new IPs or disabled accounts as high priority—control-plane compromise is often game over.",
      "docRef": "Microsoft Learn: Defender for Resource Manager"
    }
  },
  {
    "topic": "Defender for DNS",
    "scenario": "Malware on a VM is suspected of using DNS tunneling for C2.",
    "question": "What does Defender for DNS detect?",
    "options": [
      "Suspicious DNS layer activity such as communication with malicious domains, DNS tunneling patterns, and other DNS-based threats using Azure DNS data",
      "Only email SPF failures",
      "Only certificate expiry on websites",
      "DNS protection is limited to on-premises BIND servers"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for DNS",
      "analysis": [
        "Option A is CORRECT: The plan analyzes DNS traffic patterns for threats including tunneling and malicious domains.",
        "Option B is INCORRECT: Email authentication is a different domain.",
        "Option C is INCORRECT: Certificate monitoring is separate.",
        "Option D is INCORRECT: Focus is Azure DNS related telemetry in this plan context."
      ],
      "codeSnippet": "// Defender plans → DNS\n// Review DNS-related security alerts",
      "socTip": "Combine DNS alerts with device network events (MDE) when the querying host is an onboarded endpoint or Arc server.",
      "docRef": "Microsoft Learn: Defender for DNS"
    }
  },
  {
    "topic": "Defender for AI services",
    "scenario": "Litware is deploying Azure OpenAI and related AI services and wants threat protection for those workloads.",
    "question": "What is the purpose of Defender for AI services in Defender for Cloud?",
    "options": [
      "To provide security posture and threat protections tailored to AI/ML services, helping detect and respond to risks targeting AI workloads",
      "To train customer models on Microsoft’s private data automatically",
      "To replace Azure OpenAI content filters entirely",
      "AI workloads cannot be covered by Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for AI Services",
      "analysis": [
        "Option A is CORRECT: Emerging AI workload protections extend CWPP/CSPM thinking to AI services.",
        "Option B is INCORRECT: Customer data handling follows Microsoft privacy commitments; this is not a training-data harvest feature.",
        "Option C is INCORRECT: Content safety features remain complementary.",
        "Option D is INCORRECT: AI-oriented plans and posture features exist."
      ],
      "codeSnippet": "// Defender plans → AI services (as available)\n// Review AI-related recommendations and alerts",
      "socTip": "Include AI service principals and endpoints in attack path reviews—exposed AI endpoints with privileged identities are high-value targets.",
      "docRef": "Microsoft Learn: Defender for AI services"
    }
  },
  {
    "topic": "Defender for APIs",
    "scenario": "Northwind publishes APIs through Azure API Management and wants security insights and threat detection.",
    "question": "What does Defender for APIs help with?",
    "options": [
      "Security posture and threat detection for APIs, including visibility into API risks and suspicious API activity when integrated with supported API platforms",
      "Only generating random API keys",
      "Only building OpenAPI specifications without security",
      "API security is out of scope for Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for APIs",
      "analysis": [
        "Option A is CORRECT: The plan extends protection and posture to API estates.",
        "Option B is INCORRECT: Key generation is not the security plan purpose.",
        "Option C is INCORRECT: Spec generation is a design activity, not threat protection.",
        "Option D is INCORRECT: APIs are a supported focus area."
      ],
      "codeSnippet": "// Defender plans → APIs\n// Connect API Management / supported sources\n// Monitor API security findings",
      "socTip": "Prioritize external-facing APIs with sensitive data access when triaging API-related recommendations and alerts.",
      "docRef": "Microsoft Learn: Defender for APIs"
    }
  },
  {
    "topic": "Defender for DevOps",
    "scenario": "Contoso wants security findings from GitHub and Azure DevOps pipelines surfaced in Defender for Cloud.",
    "question": "What does Defender for DevOps enable?",
    "options": [
      "Integration with DevOps platforms to surface code, secret, and pipeline security findings in Defender for Cloud for unified visibility from code to cloud",
      "Automatic production deployments without review",
      "Deletion of all repositories weekly",
      "DevOps security is only available through a non-Microsoft CASB"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for DevOps",
      "analysis": [
        "Option A is CORRECT: Code-to-cloud visibility pulls pipeline and repository security signals into the same posture plane.",
        "Option B is INCORRECT: Security findings inform risk; they do not force unreviewed deploys.",
        "Option C is INCORRECT: Repositories are not auto-deleted.",
        "Option D is INCORRECT: Native integration exists."
      ],
      "codeSnippet": "// Environment settings → DevOps connectors\n// GitHub / Azure DevOps\n// Review code and pipeline findings",
      "socTip": "Fail builds on critical secret or dependency findings before they become runtime cloud risks.",
      "docRef": "Microsoft Learn: Defender for DevOps"
    }
  },
  {
    "topic": "Inventory and coverage",
    "scenario": "The SOC manager asks whether all subscriptions and plans are fully covered.",
    "question": "How can coverage gaps be identified in Defender for Cloud?",
    "options": [
      "Use inventory, coverage workbooks, and environment settings to see which resources and plans are enabled versus unprotected across subscriptions and connected clouds",
      "Coverage cannot be measured",
      "Only Microsoft support tickets reveal coverage",
      "Coverage is always 100% with no gaps possible"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Coverage and Inventory Visibility",
      "analysis": [
        "Option A is CORRECT: Inventory and coverage views highlight unprotected resources and missing plan enablement.",
        "Option B is INCORRECT: Measurement is built in.",
        "Option C is INCORRECT: Customers have self-service visibility.",
        "Option D is INCORRECT: Gaps are common until plans and connectors are fully configured."
      ],
      "codeSnippet": "// Inventory / Coverage workbook\n// Environment settings → plans per subscription\n// Close gaps systematically",
      "socTip": "Review coverage after every new subscription or cloud account is created—new environments often start unprotected.",
      "docRef": "Microsoft Learn: Asset inventory"
    }
  },
  {
    "topic": "Recommendation exemption",
    "scenario": "A recommendation flags a storage account that must remain publicly readable for a legitimate static website scenario.",
    "question": "How should accepted risk be handled for a recommendation?",
    "options": [
      "Create a documented exemption (with scope, justification, and expiration) so the finding is excluded from score impact while retaining an audit trail",
      "Ignore the recommendation silently with no record",
      "Disable Secure Score entirely",
      "Delete the storage account and the business workload"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Recommendation Exemptions",
      "analysis": [
        "Option A is CORRECT: Exemptions formalize accepted risk with accountability and time bounds.",
        "Option B is INCORRECT: Silent ignores fail audits and drift tracking.",
        "Option C is INCORRECT: Disabling scoring hides posture globally.",
        "Option D is INCORRECT: Business needs can be met with controlled exceptions."
      ],
      "codeSnippet": "// Recommendation → Exempt\n// Scope, justification, expiration\n// Review exemptions periodically",
      "socTip": "Set exemption expirations and a quarterly review so temporary exceptions do not become permanent debt.",
      "docRef": "Microsoft Learn: Exempt recommendations"
    }
  },
  {
    "topic": "Email notifications for alerts",
    "scenario": "Fabrikam wants the on-call SOC channel to receive email when high-severity Defender for Cloud alerts fire.",
    "question": "How are email notifications configured for Defender for Cloud alerts?",
    "options": [
      "Configure email notification settings (and optionally workflow automation) to send alert notifications to specified security contacts based on severity and other filters",
      "Email notifications are impossible",
      "Only the Azure invoice email address can receive alerts",
      "Notifications can only be sent via postal mail"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Email Notifications",
      "analysis": [
        "Option A is CORRECT: Security contacts and notification settings drive email alerts; Logic Apps can extend delivery channels.",
        "Option B is INCORRECT: Notifications are supported.",
        "Option C is INCORRECT: Security contact emails are configurable.",
        "Option D is INCORRECT: Digital notifications are the mechanism."
      ],
      "codeSnippet": "// Environment settings → Email notifications\n// Security contacts + severity filters\n// Or Logic App for Teams/SMS",
      "socTip": "Prefer a distribution list or on-call rotation address over personal mailboxes for alert notifications.",
      "docRef": "Microsoft Learn: Configure email notifications"
    }
  },
  {
    "topic": "Integration with Microsoft Sentinel",
    "scenario": "Adatum uses Microsoft Sentinel as the primary SIEM and wants Defender for Cloud alerts in incidents.",
    "question": "How are Defender for Cloud alerts brought into Microsoft Sentinel?",
    "options": [
      "Use the Microsoft Defender for Cloud data connector (or Defender XDR connector paths as applicable) to ingest alerts into Sentinel for correlation, incidents, and SOAR",
      "Only by manually copying alert text into Sentinel notes",
      "Sentinel cannot receive cloud workload alerts",
      "Integration requires disabling Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Cloud to Sentinel Connector",
      "analysis": [
        "Option A is CORRECT: Official connectors stream alerts into Sentinel workspaces.",
        "Option B is INCORRECT: Automated connectors replace manual copy.",
        "Option C is INCORRECT: Ingestion is a standard pattern.",
        "Option D is INCORRECT: Products are designed to work together."
      ],
      "codeSnippet": "// Sentinel → Data connectors\n// Microsoft Defender for Cloud\n// Enable alert ingestion / bi-directional sync options as needed",
      "socTip": "Decide whether Defender for Cloud or Sentinel is the system of record for cloud alert closure to avoid dual-triage confusion.",
      "docRef": "Microsoft Learn: Connect Defender for Cloud to Sentinel"
    }
  },
  {
    "topic": "Governance rules",
    "scenario": "Contoso wants owners automatically assigned to recommendations so remediation SLAs are clear.",
    "question": "What can governance rules accomplish in Defender for Cloud?",
    "options": [
      "Automatically assign owners, set due dates, and apply governance to recommendations so remediation accountability is enforced at scale",
      "Governance rules only change Azure region pricing",
      "Governance rules delete all recommendations nightly",
      "Governance is not available in Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Recommendation Governance Rules",
      "analysis": [
        "Option A is CORRECT: Governance rules operationalize ownership and timelines for posture findings.",
        "Option B is INCORRECT: Unrelated to pricing.",
        "Option C is INCORRECT: Rules assign responsibility; they do not wipe findings.",
        "Option D is INCORRECT: Governance features exist for posture management."
      ],
      "codeSnippet": "// Governance rules → create\n// Conditions + owner + due date\n// Monitor completion metrics",
      "socTip": "Map recommendation categories to team DL owners (network, identity, compute) via governance rules.",
      "docRef": "Microsoft Learn: Governance rules"
    }
  },
  {
    "topic": "Vulnerability assessment on VMs",
    "scenario": "Northwind enables vulnerability assessment for Azure VMs under Defender for Servers.",
    "question": "How are VM vulnerabilities surfaced in Defender for Cloud?",
    "options": [
      "Vulnerability assessment (agent-based and/or agentless depending on configuration and plan) finds missing patches and software weaknesses and surfaces them as recommendations/findings",
      "Vulnerabilities are never shown for VMs",
      "Only physical server barcode scans are supported",
      "VA requires exporting disks to on-premises scanners only"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "VM Vulnerability Assessment",
      "analysis": [
        "Option A is CORRECT: Integrated VA provides findings that feed recommendations and prioritization.",
        "Option B is INCORRECT: VA is a core server protection capability.",
        "Option C is INCORRECT: Focus is software vulnerabilities on cloud/hybrid machines.",
        "Option D is INCORRECT: Cloud-integrated assessment is available."
      ],
      "codeSnippet": "// Defender for Servers → Vulnerability assessment\n// Review findings per machine\n// Track remediation",
      "socTip": "Align VA remediation SLAs with your existing patch cadence and elevate internet-exposed vulnerable VMs.",
      "docRef": "Microsoft Learn: Vulnerability assessment for machines"
    }
  },
  {
    "topic": "Network map / topology insights",
    "scenario": "An analyst investigating lateral movement wants a visual understanding of possible network paths between resources.",
    "question": "How can network-related posture and topology insights help investigations?",
    "options": [
      "Network insights and recommendations highlight overly permissive rules and connectivity risks; combined with attack paths they show how network exposure enables movement toward critical assets",
      "Network maps replace the need for any NSGs",
      "Topology insights only show office floor plans",
      "Network data is unavailable in Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Network Posture and Path Context",
      "analysis": [
        "Option A is CORRECT: Network recommendations and path analysis contextualize exposure for investigations and hardening.",
        "Option B is INCORRECT: Insights guide NSG/ASG improvements; they do not eliminate controls.",
        "Option C is INCORRECT: Focus is cloud network topology and rules.",
        "Option D is INCORRECT: Network posture is a major CSPM domain."
      ],
      "codeSnippet": "// Recommendations → Network category\n// Attack path with network hops\n// Harden NSG / private endpoints",
      "socTip": "When an alert involves a VM, check whether its NSG still allows wide internet management access—common root cause.",
      "docRef": "Microsoft Learn: Network recommendations"
    }
  },
  {
    "topic": "Private endpoints and storage hardening",
    "scenario": "A recommendation urges Contoso to use private endpoints for a storage account holding sensitive data.",
    "question": "Why might Defender for Cloud recommend private endpoints for storage?",
    "options": [
      "Private endpoints reduce public internet exposure by placing access on a private network interface in the VNet, aligning with least-exposure architecture",
      "Private endpoints make storage accounts free",
      "Private endpoints disable all encryption",
      "Recommendations never mention networking"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Private Endpoint Hardening Recommendations",
      "analysis": [
        "Option A is CORRECT: Reducing public exposure of data services is a standard posture improvement.",
        "Option B is INCORRECT: Cost is separate from the security control.",
        "Option C is INCORRECT: Encryption remains available and recommended.",
        "Option D is INCORRECT: Network exposure is a frequent recommendation category."
      ],
      "codeSnippet": "// Recommendation: use private endpoints\n// Implement Private Link / private endpoint\n// Restrict public network access",
      "socTip": "Combine private endpoints with firewall rules and identity-based access for defense in depth on data stores.",
      "docRef": "Microsoft Learn: Storage security recommendations"
    }
  },
  {
    "topic": "Identity recommendations in CSPM",
    "scenario": "Secure Score is pulled down by findings about overprivileged identities and missing MFA-related controls on critical resources.",
    "question": "How does Defender for Cloud incorporate identity posture?",
    "options": [
      "Recommendations include identity and access control gaps (excessive permissions, insecure authentication patterns on resources) that affect cloud risk and secure score",
      "Identity is completely out of scope for Defender for Cloud",
      "Only passwords in cleartext files are checked with no RBAC analysis",
      "Identity recommendations only apply to on-premises AD DS"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Identity-Related Cloud Recommendations",
      "analysis": [
        "Option A is CORRECT: Identity misconfigurations are a major driver of cloud risk and appear in posture assessments.",
        "Option B is INCORRECT: Identity controls are central to CSPM.",
        "Option C is INCORRECT: RBAC and access patterns are assessed more broadly.",
        "Option D is INCORRECT: Cloud IAM (Entra ID, AWS IAM, GCP IAM) is in scope via connectors."
      ],
      "codeSnippet": "// Recommendations → Identity and Access\n// Reduce standing admin, enforce better auth",
      "socTip": "Cross-check identity recommendations with Entra PIM and Access Reviews for human privileged roles.",
      "docRef": "Microsoft Learn: Identity recommendations"
    }
  },
  {
    "topic": "Auto-provisioning / extensions",
    "scenario": "When new VMs are created, Contoso wants monitoring agents/extensions required by Defender plans installed automatically.",
    "question": "How does Defender for Cloud help ensure new machines receive required components?",
    "options": [
      "Auto-provisioning settings can automatically deploy needed agents and extensions (such as Log Analytics/Azure Monitor agent patterns or Defender components) to new supported machines",
      "Every agent must always be installed only by hand forever",
      "Auto-provisioning only works for classic ASM VMs from 2014",
      "Agents cannot be associated with Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Auto-Provisioning of Monitoring Components",
      "analysis": [
        "Option A is CORRECT: Auto-provisioning reduces gaps when VMs scale out.",
        "Option B is INCORRECT: Automation is supported for many components.",
        "Option C is INCORRECT: Modern Azure Resource Manager VMs are the primary target.",
        "Option D is INCORRECT: Agents/extensions underpin several CWPP capabilities."
      ],
      "codeSnippet": "// Environment settings → Auto provisioning\n// Enable required extensions/components\n// Verify on newly created VMs",
      "socTip": "After enabling auto-provisioning, sample newly built VMs weekly for the first month to confirm components actually land.",
      "docRef": "Microsoft Learn: Auto provisioning"
    }
  },
  {
    "topic": "Secure Score controls",
    "scenario": "An analyst drills into Secure Score and sees security controls with multiple recommendations.",
    "question": "How are Secure Score controls organized?",
    "options": [
      "Controls group related recommendations (e.g., Restrict unauthorized network access) and show potential score increase if all recommendations in the control are completed",
      "Controls are random unrelated lists",
      "Controls only exist for email security",
      "Controls cannot be remediated"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Secure Score Controls Grouping",
      "analysis": [
        "Option A is CORRECT: Controls aggregate related recommendations and show score impact.",
        "Option B is INCORRECT: Grouping is intentional by security domain.",
        "Option C is INCORRECT: Controls span cloud resource domains.",
        "Option D is INCORRECT: Remediation of recommendations improves the control and score."
      ],
      "codeSnippet": "// Secure Score → Control → Recommendations\n// Remediate highest impact first",
      "socTip": "Sort controls by potential score increase to maximize posture gains per engineering hour.",
      "docRef": "Microsoft Learn: Secure score controls"
    }
  },
  {
    "topic": "Risk prioritization factors",
    "scenario": "Two recommendations have the same severity label but different risk levels under Defender CSPM.",
    "question": "What factors influence risk prioritization of recommendations?",
    "options": [
      "Contextual factors such as internet exposure, sensitive data, lateral movement potential, and exploitability of the affected resources",
      "Only alphabetical order of resource names",
      "Only the Azure region of the resource",
      "Risk is always identical to static severity"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Risk-Based Recommendation Prioritization",
      "analysis": [
        "Option A is CORRECT: Defender CSPM enriches severity with environmental risk context.",
        "Option B is INCORRECT: Names are not risk factors.",
        "Option C is INCORRECT: Region alone is not the prioritization model.",
        "Option D is INCORRECT: Risk level adds context beyond static severity."
      ],
      "codeSnippet": "// Recommendations sorted by risk level\n// Inspect risk factors on each item",
      "socTip": "When time is limited, clear critical risk-level findings on internet-exposed resources first.",
      "docRef": "Microsoft Learn: Risk prioritization"
    }
  },
  {
    "topic": "Custom security standards",
    "scenario": "Litware wants to encode internal baseline rules beyond MCSB using KQL-based assessments.",
    "question": "How can custom assessments be added?",
    "options": [
      "Create custom recommendations within custom standards using KQL assessment logic (with Defender CSPM) so internal requirements appear alongside built-in findings",
      "Custom standards are impossible",
      "Only XML files emailed to Microsoft support create standards",
      "Custom standards disable MCSB permanently"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Custom Standards and Recommendations",
      "analysis": [
        "Option A is CORRECT: Custom standards/recommendations extend posture to organization-specific rules.",
        "Option B is INCORRECT: Customization is supported with appropriate plans.",
        "Option C is INCORRECT: Portal/API configuration is used.",
        "Option D is INCORRECT: Custom standards complement MCSB."
      ],
      "codeSnippet": "// Security policy → custom standard\n// Custom recommendation with KQL",
      "socTip": "Start with a small set of high-value custom checks (e.g., required tags, forbidden SKUs) before building a large custom catalog.",
      "docRef": "Microsoft Learn: Custom recommendations"
    }
  },
  {
    "topic": "Management group scope",
    "scenario": "Contoso manages 50 subscriptions under a hierarchy and wants consistent Defender plan enablement.",
    "question": "Why configure Defender for Cloud at management group scope?",
    "options": [
      "Management group scope allows centralized policy and plan settings to inherit across many subscriptions, reducing configuration drift",
      "Management groups only apply to Active Directory OUs",
      "Scope can only be a single resource group forever",
      "Management group settings never inherit"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Management Group Configuration Scope",
      "analysis": [
        "Option A is CORRECT: MG-level configuration scales governance across subscriptions.",
        "Option B is INCORRECT: Azure management groups are an Azure Resource Manager hierarchy.",
        "Option C is INCORRECT: Multiple scopes are supported.",
        "Option D is INCORRECT: Inheritance is a primary benefit."
      ],
      "codeSnippet": "// Configure at MG → inherit to subscriptions\n// Override only where business requires",
      "socTip": "Put production and non-production under separate MGs if plan tiers or automation differ.",
      "docRef": "Microsoft Learn: Configure at scale"
    }
  },
  {
    "topic": "Alert severity levels",
    "scenario": "A new analyst sees alerts labeled High, Medium, Low, and Informational.",
    "question": "How should severity influence triage in Defender for Cloud?",
    "options": [
      "Higher severity generally indicates greater potential impact or confidence and should be triaged first, while still considering asset criticality and business context",
      "Severity should be ignored completely",
      "Only Informational alerts matter",
      "Severity is assigned randomly"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Severity Triage",
      "analysis": [
        "Option A is CORRECT: Severity is a primary but not sole triage signal.",
        "Option B is INCORRECT: Severity is meaningful.",
        "Option C is INCORRECT: Informational is lowest priority typically.",
        "Option D is INCORRECT: Severity follows detection logic."
      ],
      "codeSnippet": "// Filter alerts by High first\n// Then Medium on critical assets",
      "socTip": "Document exceptions where Medium alerts on crown-jewel assets outrank High alerts on disposable lab VMs.",
      "docRef": "Microsoft Learn: Security alerts"
    }
  },
  {
    "topic": "Remediate recommendation quickly",
    "scenario": "A recommendation offers a Quick Fix button for a misconfigured setting.",
    "question": "What is a Quick Fix (or similar guided remediation) in recommendations?",
    "options": [
      "An assisted remediation action that applies the recommended configuration change with analyst/admin confirmation where supported",
      "A forced change that never asks for approval",
      "A link that only opens Bing search",
      "Quick Fix deletes the resource"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Guided Recommendation Remediation",
      "analysis": [
        "Option A is CORRECT: Quick fixes accelerate safe configuration changes with appropriate consent.",
        "Option B is INCORRECT: Changes are not silent forced actions without context.",
        "Option C is INCORRECT: Remediation is in-product.",
        "Option D is INCORRECT: Fix corrects configuration; it does not delete the resource by design."
      ],
      "codeSnippet": "// Recommendation → Remediate / Quick fix\n// Confirm scope → apply",
      "socTip": "Use Quick Fix in non-production first when learning a new recommendation type.",
      "docRef": "Microsoft Learn: Remediate recommendations"
    }
  },
  {
    "topic": "Subassessments and VA findings",
    "scenario": "A vulnerability assessment recommendation expands into many CVE findings on a VM.",
    "question": "What are subassessments in this context?",
    "options": [
      "Detailed findings under a parent recommendation (such as individual CVEs or specific misconfiguration instances) that provide granular remediation targets",
      "Subassessments are billing line items only",
      "Subassessments only exist for email alerts",
      "Subassessments replace the need for Secure Score"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Subassessments under Recommendations",
      "analysis": [
        "Option A is CORRECT: Subassessments break a control into actionable instance-level findings.",
        "Option B is INCORRECT: They are security findings, not invoices.",
        "Option C is INCORRECT: They apply broadly including VA.",
        "Option D is INCORRECT: They feed posture; they do not replace scoring."
      ],
      "codeSnippet": "// Recommendation → Subassessments / findings\n// Filter critical CVEs first",
      "socTip": "Export critical subassessments into your patch management backlog with asset owner fields populated.",
      "docRef": "Microsoft Learn: Recommendations and findings"
    }
  },
  {
    "topic": "AWS connector permissions",
    "scenario": "Security engineering is onboarding an AWS account and must grant Microsoft access to assess posture.",
    "question": "What is a security best practice when creating the AWS connector?",
    "options": [
      "Grant least-privilege roles required by the connector documentation and prefer federated access patterns over long-lived access keys where supported",
      "Grant AdministratorAccess to the world",
      "Share root account passwords in email",
      "Skip permissions and hope recommendations appear"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Least Privilege Multi-Cloud Onboarding",
      "analysis": [
        "Option A is CORRECT: Least privilege and federation reduce connector compromise impact.",
        "Option B is INCORRECT: Excessive permissions increase risk.",
        "Option C is INCORRECT: Root credentials must never be shared.",
        "Option D is INCORRECT: Proper permissions are required for assessment."
      ],
      "codeSnippet": "// Follow Microsoft docs for AWS role template\n// Use federated auth when available",
      "socTip": "Store connector configuration in IaC so permissions are reviewable in pull requests.",
      "docRef": "Microsoft Learn: AWS connector"
    }
  },
  {
    "topic": "GCP connector",
    "scenario": "Fabrikam adds a GCP project to Defender for Cloud for CSPM visibility.",
    "question": "What is required to assess GCP resources in Defender for Cloud?",
    "options": [
      "Configure a GCP connector with the required project permissions so agentless CSPM assessments can run against the project’s resources",
      "GCP can never be connected",
      "Only a VPN to on-premises is required with no IAM setup",
      "Connectors only work for Gmail accounts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "GCP Environment Connector",
      "analysis": [
        "Option A is CORRECT: Connector + permissions enable CSPM for GCP.",
        "Option B is INCORRECT: GCP is supported.",
        "Option C is INCORRECT: IAM/API permissions are essential.",
        "Option D is INCORRECT: Focus is cloud project resources."
      ],
      "codeSnippet": "// Environment settings → GCP\n// Provide org/project access as documented",
      "socTip": "Onboard a non-production GCP project first to validate permissions and recommendation quality.",
      "docRef": "Microsoft Learn: GCP connector"
    }
  },
  {
    "topic": "Defender for open-source databases",
    "scenario": "Adatum uses Azure Database for PostgreSQL and wants threat detection.",
    "question": "Which plan targets open-source relational databases on Azure?",
    "options": [
      "Defender for open-source relational databases — threat protection for supported Azure Database for PostgreSQL, MySQL, and MariaDB services",
      "Defender for DNS only",
      "Defender for App Service only",
      "Open-source databases cannot be protected"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Open-Source DB Workload Protection",
      "analysis": [
        "Option A is CORRECT: A dedicated plan covers supported open-source PaaS databases.",
        "Option B is INCORRECT: DNS is separate.",
        "Option C is INCORRECT: App Service is separate.",
        "Option D is INCORRECT: Protection plans exist."
      ],
      "codeSnippet": "// Defender plans → Open-source relational databases",
      "socTip": "Enable the plan on subscriptions hosting production PostgreSQL/MySQL before exposing them to broader networks.",
      "docRef": "Microsoft Learn: Defender for open-source databases"
    }
  },
  {
    "topic": "Defender for Cosmos DB",
    "scenario": "Litware stores operational data in Azure Cosmos DB and needs security monitoring.",
    "question": "What does Defender for Azure Cosmos DB focus on?",
    "options": [
      "Threat detection and security insights for Azure Cosmos DB accounts to identify suspicious database activity and related risks",
      "Only geo-replication configuration UI",
      "Only RU/s autoscale settings",
      "Cosmos DB is excluded from Defender for Cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Defender for Cosmos DB",
      "analysis": [
        "Option A is CORRECT: The plan targets Cosmos DB threat detection.",
        "Option B is INCORRECT: Replication is a platform feature, not the Defender plan purpose.",
        "Option C is INCORRECT: Throughput settings are performance, not the security plan.",
        "Option D is INCORRECT: Cosmos DB has a plan."
      ],
      "codeSnippet": "// Defender plans → Cosmos DB\n// Monitor alerts on accounts",
      "socTip": "Watch for anomalous data access patterns that may indicate key leakage or compromised application identities.",
      "docRef": "Microsoft Learn: Defender for Cosmos DB"
    }
  },
  {
    "topic": "Sample alert types for servers",
    "scenario": "A SOC playbook lists common Defender for Servers alert categories.",
    "question": "Which of the following is a typical class of Defender for Servers alerts?",
    "options": [
      "Suspicious process execution, malware, cryptomining, anomalous network activity, and other runtime threats on protected machines",
      "Only password expiry reminders for end users",
      "Only Azure invoice anomalies",
      "Only printer offline notices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Server Runtime Threat Alerts",
      "analysis": [
        "Option A is CORRECT: Server plans generate host-based threat alerts.",
        "Option B is INCORRECT: Identity hygiene is mostly Entra ID.",
        "Option C is INCORRECT: Billing is Cost Management.",
        "Option D is INCORRECT: Unrelated to cloud workload protection."
      ],
      "codeSnippet": "// Security alerts filter: Servers / Resource type VM",
      "socTip": "Map high-volume alert types to dedicated playbooks to speed Tier 1 handling.",
      "docRef": "Microsoft Learn: Alerts for Windows/Linux machines"
    }
  },
  {
    "topic": "Kill chain and MITRE in alerts",
    "scenario": "An alert page shows MITRE ATT&CK tactics.",
    "question": "Why are MITRE tactics shown on Defender for Cloud alerts?",
    "options": [
      "To help analysts understand the stage of the attack and relate cloud detections to a common adversary technique framework for consistent investigation",
      "MITRE labels are decorative only",
      "MITRE tactics replace the need for remediation",
      "MITRE mapping means the alert is a false positive"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "MITRE Mapping on Alerts",
      "analysis": [
        "Option A is CORRECT: ATT&CK mapping aids investigation narrative and coverage analysis.",
        "Option B is INCORRECT: Mapping is operationally useful.",
        "Option C is INCORRECT: Remediation is still required.",
        "Option D is INCORRECT: Mapping does not imply false positive."
      ],
      "codeSnippet": "// Alert details → MITRE tactics/techniques\n// Use in incident timeline narrative",
      "socTip": "Track which ATT&CK tactics generate the most cloud alerts to guide detection engineering priorities.",
      "docRef": "Microsoft Learn: Security alerts reference"
    }
  },
  {
    "topic": "Bi-directional alert sync",
    "scenario": "When closing an alert in Sentinel, the team wants status reflected in Defender for Cloud or vice versa.",
    "question": "What can bi-directional sync provide between Sentinel and Defender for Cloud?",
    "options": [
      "Synchronized alert status so closure or triage actions in one system can update the other, reducing duplicate work",
      "Automatic deletion of all cloud resources when an alert closes",
      "Sync of only wallpaper images",
      "Bi-directional sync is not a documented integration pattern"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Status Synchronization",
      "analysis": [
        "Option A is CORRECT: Bi-directional sync reduces dual-console toil when configured.",
        "Option B is INCORRECT: Closing alerts does not destroy resources.",
        "Option C is INCORRECT: Security alert metadata is synchronized.",
        "Option D is INCORRECT: Sync options exist in connector configuration."
      ],
      "codeSnippet": "// Sentinel connector settings\n// Enable bi-directional sync if desired",
      "socTip": "Pick one primary console for closure ownership to avoid conflicting status updates.",
      "docRef": "Microsoft Learn: Sentinel Defender for Cloud connector"
    }
  },
  {
    "topic": "Pricing / plans enablement impact",
    "scenario": "Enabling several CWPP plans increases cost. Leadership asks for a prioritization approach.",
    "question": "What is a practical approach to enabling Defender plans cost-effectively?",
    "options": [
      "Prioritize plans for internet-facing and data-sensitive workloads first (e.g., Servers, Storage, SQL on production), measure alert value, then expand",
      "Enable every plan on every subscription including empty dev subscriptions on day one without review",
      "Never enable any paid plan",
      "Enable plans only during audits then disable"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Risk-Based Plan Enablement",
      "analysis": [
        "Option A is CORRECT: Risk-based rollout maximizes security return on spend.",
        "Option B is INCORRECT: Unscoped enablement wastes budget.",
        "Option C is INCORRECT: Paid plans deliver critical detections.",
        "Option D is INCORRECT: Continuous protection is the goal."
      ],
      "codeSnippet": "// Inventory critical workloads\n// Enable plans on production first\n// Expand after tuning",
      "socTip": "Tag subscriptions by environment and data classification to automate plan enablement policy.",
      "docRef": "Microsoft Learn: Defender for Cloud pricing plans"
    }
  },
  {
    "topic": "Security policy assignment",
    "scenario": "A subscription shows fewer recommendations than expected after onboarding.",
    "question": "What determines which assessments run on a subscription?",
    "options": [
      "Enabled security standards/policies and Defender plans determine which recommendations and threat detections are active for resources in scope",
      "Assessments are chosen randomly each night",
      "Only resources with the tag Assess=true are scanned",
      "Policies cannot be assigned to subscriptions"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Policy and Plan Scope Determine Assessments",
      "analysis": [
        "Option A is CORRECT: Standards and plans drive assessment coverage.",
        "Option B is INCORRECT: Deterministic configuration controls coverage.",
        "Option C is INCORRECT: Tagging may be used in custom logic but is not the default sole switch.",
        "Option D is INCORRECT: Assignment to subscriptions/MGs is standard."
      ],
      "codeSnippet": "// Security policy → enabled standards\n// Defender plans → enabled workloads",
      "socTip": "When recommendations look thin, verify both standards and CWPP plans are enabled on the subscription.",
      "docRef": "Microsoft Learn: Security policies"
    }
  },
  {
    "topic": "Workspace configuration",
    "scenario": "Defender for Cloud needs a Log Analytics workspace for certain data collection scenarios.",
    "question": "Why is a Log Analytics workspace sometimes associated with Defender for Cloud?",
    "options": [
      "Certain data collection, agent configurations, and integrations use a Log Analytics workspace as the destination or configuration anchor for monitoring components",
      "Workspaces are only for storing VM screenshots",
      "A workspace replaces Azure AD entirely",
      "Workspaces are optional for every feature without exception"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Log Analytics Workspace Integration",
      "analysis": [
        "Option A is CORRECT: Workspace linkage supports monitoring agent scenarios and data routing.",
        "Option B is INCORRECT: Security telemetry is the focus.",
        "Option C is INCORRECT: Identity remains Entra ID.",
        "Option D is INCORRECT: Some features depend on workspace configuration."
      ],
      "codeSnippet": "// Environment settings → workspace configuration\n// Select target Log Analytics workspace",
      "socTip": "Centralize on fewer regional workspaces where possible to simplify hunting and RBAC.",
      "docRef": "Microsoft Learn: Configure workspace"
    }
  },
  {
    "topic": "Alert enrichment with resource context",
    "scenario": "An alert includes subscription, resource group, tags, and owner metadata.",
    "question": "Why is resource context on alerts valuable to the SOC?",
    "options": [
      "It accelerates triage by showing where the resource lives, who owns it, and business tags—enabling faster containment and correct escalation",
      "Resource context is irrelevant noise",
      "Tags always mean the alert is benign",
      "Subscription ID alone is enough without owner data"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Resource Context for Triage",
      "analysis": [
        "Option A is CORRECT: Context shortens mean time to understand impact and ownership.",
        "Option B is INCORRECT: Context is highly actionable.",
        "Option C is INCORRECT: Tags do not imply benign activity.",
        "Option D is INCORRECT: Owner and criticality tags improve response quality."
      ],
      "codeSnippet": "// Alert → Resource details / tags\n// Escalate to tag Owner",
      "socTip": "Enforce mandatory Owner and Environment tags via Azure Policy to make alert context reliable.",
      "docRef": "Microsoft Learn: Investigate alerts"
    }
  },
  {
    "topic": "Preventive vs detective controls",
    "scenario": "A recommendation to close management ports is preventive; a cryptomining alert is detective.",
    "question": "How do recommendations and alerts complement each other in Defender for Cloud?",
    "options": [
      "Recommendations drive preventive hardening (posture); alerts provide detective response to active or suspicious behavior—together they reduce likelihood and impact of incidents",
      "Only alerts matter and recommendations can be ignored",
      "Only recommendations matter and alerts can be ignored",
      "They are mutually exclusive and cannot both be enabled"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Preventive Posture + Detective Alerts",
      "analysis": [
        "Option A is CORRECT: CSPM and CWPP form a complementary control loop.",
        "Option B is INCORRECT: Prevention reduces alert load and risk.",
        "Option C is INCORRECT: Detection catches residual risk.",
        "Option D is INCORRECT: Both operate together."
      ],
      "codeSnippet": "// Track Secure Score (preventive)\n// Track MTTA/MTTR on alerts (detective)",
      "socTip": "After major incidents, create recommendations/governance actions that would have prevented the entry path.",
      "docRef": "Microsoft Learn: Defender for Cloud overview"
    }
  },
  {
    "topic": "Cloud Security Graph",
    "scenario": "Attack path analysis and Cloud Security Explorer rely on a graph of relationships.",
    "question": "What is the cloud security graph in Defender CSPM?",
    "options": [
      "A contextual graph of cloud resources, identities, permissions, and exposures used to compute attack paths and answer complex risk queries",
      "A social network graph of employees",
      "A graph only of DNS records",
      "A chart of Azure retail prices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Security Graph",
      "analysis": [
        "Option A is CORRECT: The graph powers path analysis and Explorer queries.",
        "Option B is INCORRECT: It models cloud assets and identities, not social connections.",
        "Option C is INCORRECT: Broader than DNS.",
        "Option D is INCORRECT: Not a pricing graph."
      ],
      "codeSnippet": "// Used by Attack path analysis\n// Queried via Cloud Security Explorer",
      "socTip": "When an identity alert fires, use the graph mindset: what resources could this identity reach?",
      "docRef": "Microsoft Learn: Cloud security graph"
    }
  },
  {
    "topic": "EASM relationship",
    "scenario": "Contoso also uses Defender External Attack Surface Management alongside Defender for Cloud.",
    "question": "How does EASM complement Defender for Cloud?",
    "options": [
      "EASM discovers internet-facing assets from an outside-in perspective, helping find unknown or shadow exposures that internal CSPM may not fully inventory",
      "EASM replaces Defender for Cloud entirely",
      "EASM only scans internal east-west traffic",
      "EASM is unrelated to cloud security"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "EASM Outside-In Discovery",
      "analysis": [
        "Option A is CORRECT: EASM adds external discovery to internal posture management.",
        "Option B is INCORRECT: Complementary, not a replacement.",
        "Option C is INCORRECT: Focus is external attack surface.",
        "Option D is INCORRECT: Directly relevant to exposure management."
      ],
      "codeSnippet": "// EASM inventory of domains/hosts\n// Correlate with Defender for Cloud resources",
      "socTip": "Reconcile EASM-discovered endpoints with cloud inventory weekly to find untracked public assets.",
      "docRef": "Microsoft Learn: Defender EASM"
    }
  },
  {
    "topic": "Data-aware security posture",
    "scenario": "Defender CSPM highlights a data store containing sensitive information that is also publicly exposed.",
    "question": "What is data-aware security posture?",
    "options": [
      "Posture insights that consider sensitivity of data on resources when prioritizing risk—so exposed sensitive data ranks higher than similar exposure on non-sensitive stores",
      "Data-aware means the SOC memorizes all data without tools",
      "It only applies to on-premises file shares",
      "It disables all storage accounts automatically"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Data-Aware Posture Prioritization",
      "analysis": [
        "Option A is CORRECT: Sensitivity context improves prioritization quality.",
        "Option B is INCORRECT: Tooling provides the awareness.",
        "Option C is INCORRECT: Cloud data stores are in scope.",
        "Option D is INCORRECT: Prioritization is not automatic mass disablement."
      ],
      "codeSnippet": "// Recommendations with sensitive data context\n// Prioritize exposed sensitive stores",
      "socTip": "Ensure data classification labels or sensitivity signals are available so prioritization is accurate.",
      "docRef": "Microsoft Learn: Data-aware security posture"
    }
  },
  {
    "topic": "Remediation tracking",
    "scenario": "Leadership asks whether recommendation remediation is actually happening.",
    "question": "How can remediation progress be tracked?",
    "options": [
      "Use Secure Score trends, governance rule completion, recommendation status, and exported metrics/workbooks to monitor closure rates over time",
      "Progress cannot be tracked",
      "Only annual pen tests track progress",
      "Tracking requires disabling all alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Posture Remediation Metrics",
      "analysis": [
        "Option A is CORRECT: Multiple dashboards and exports support KPI tracking.",
        "Option B is INCORRECT: Tracking is built in.",
        "Option C is INCORRECT: Continuous metrics complement occasional tests.",
        "Option D is INCORRECT: Alerts and posture tracking coexist."
      ],
      "codeSnippet": "// Secure Score history\n// Governance reports\n// Workbooks / export to SIEM",
      "socTip": "Report % of critical recommendations closed within SLA as a SOC/cloud engineering shared KPI.",
      "docRef": "Microsoft Learn: Track secure score"
    }
  },
  {
    "topic": "Subscription vs resource alerts",
    "scenario": "Some alerts are tied to a specific VM; others seem broader.",
    "question": "What is true about alert scope in Defender for Cloud?",
    "options": [
      "Alerts are typically associated with specific resources (and their subscription/resource group context), enabling targeted investigation and response on the affected asset",
      "All alerts are only subscription-wide with no resource ID",
      "Alerts never include resource identifiers",
      "Alerts only reference on-premises machine names"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Resource-Scoped Security Alerts",
      "analysis": [
        "Option A is CORRECT: Resource association is fundamental for investigation.",
        "Option B is INCORRECT: Resource-level binding is standard.",
        "Option C is INCORRECT: Resource IDs are included.",
        "Option D is INCORRECT: Azure resource IDs are primary for cloud alerts."
      ],
      "codeSnippet": "// Alert → Affected resource\n// Pivot to resource blade / related alerts",
      "socTip": "From the alert, open the resource’s recommendations too—active compromise often coexists with posture gaps.",
      "docRef": "Microsoft Learn: Security alerts"
    }
  },
  {
    "topic": "Hybrid architecture summary",
    "scenario": "A solution architect diagrams Azure + Arc servers + AWS connector for a customer.",
    "question": "Which statement best describes a hybrid/multi-cloud Defender for Cloud architecture?",
    "options": [
      "Azure-native resources use platform integration; Arc brings non-Azure servers into Azure management; cloud connectors extend CSPM (and supported CWPP) to AWS/GCP for unified posture and protection",
      "Only Azure resources can ever be secured",
      "Hybrid requires turning off CSPM",
      "Multi-cloud requires a separate Microsoft tenant per cloud"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Unified Hybrid and Multi-Cloud Model",
      "analysis": [
        "Option A is CORRECT: Arc + connectors + plans form the unified model.",
        "Option B is INCORRECT: Hybrid/multi-cloud is supported.",
        "Option C is INCORRECT: CSPM is valuable across clouds.",
        "Option D is INCORRECT: Single control plane is the goal."
      ],
      "codeSnippet": "// Azure resources + Arc servers + AWS/GCP connectors\n// Unified recommendations and alerts",
      "socTip": "Document which plan features work agentlessly vs require Arc/agents for each cloud in your architecture decision record.",
      "docRef": "Microsoft Learn: Multicloud security"
    }
  },
  {
    "topic": "First-time enablement checklist",
    "scenario": "A greenfield subscription is being onboarded to Defender for Cloud.",
    "question": "What is a sensible first-time enablement sequence?",
    "options": [
      "Enable Foundational CSPM/MCSB, review Secure Score, enable critical CWPP plans for existing workloads, configure notifications/automation, then expand multi-cloud/Arc as needed",
      "Disable all logging first",
      "Only enable the most expensive plans with no CSPM",
      "Skip recommendations and wait for breaches"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Onboarding Sequence Best Practices",
      "analysis": [
        "Option A is CORRECT: Visibility first, then runtime protection, then operationalization.",
        "Option B is INCORRECT: Logging/telemetry underpin detection.",
        "Option C is INCORRECT: CSPM provides foundational value cost-effectively.",
        "Option D is INCORRECT: Proactive posture is the point."
      ],
      "codeSnippet": "// 1 CSPM 2 Secure Score review\n// 3 CWPP for critical workloads\n// 4 Notifications + automation\n// 5 Multi-cloud/Arc",
      "socTip": "Capture a baseline Secure Score screenshot on day one to demonstrate improvement later.",
      "docRef": "Microsoft Learn: Quickstart Defender for Cloud"
    }
  },
  {
    "topic": "False positive handling process",
    "scenario": "The SOC repeatedly sees a specific alert from a penetration test subnet.",
    "question": "What is the mature process for handling expected test activity alerts?",
    "options": [
      "Validate the activity, suppress or exempt with tight scope and expiration during the test window, and restore full detection afterward—documenting the change",
      "Permanently disable the detection for the whole enterprise",
      "Ignore without documentation",
      "Unplug the internet from the office"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Controlled Suppression for Tests",
      "analysis": [
        "Option A is CORRECT: Time-bounded, scoped suppression preserves security while enabling tests.",
        "Option B is INCORRECT: Permanent global disable is dangerous.",
        "Option C is INCORRECT: Lack of documentation fails audit and knowledge transfer.",
        "Option D is INCORRECT: Not a serious control process."
      ],
      "codeSnippet": "// Suppression rule: resource/subnet + timebox\n// Remove after test",
      "socTip": "Integrate red-team calendars with SOC so suppressions are pre-staged and removed on time.",
      "docRef": "Microsoft Learn: Suppress alerts"
    }
  },
  {
    "topic": "Cross-walk to MITRE for posture",
    "scenario": "A security engineer maps recommendations to ATT&CK for coverage reporting.",
    "question": "Why map cloud recommendations and alerts to MITRE ATT&CK?",
    "options": [
      "To communicate coverage and gaps in a common language across preventive controls and detective alerts, improving detection engineering and executive reporting",
      "MITRE mapping is required to enable Secure Score",
      "Without MITRE mapping, VMs cannot start",
      "MITRE mapping increases Azure compute prices"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "ATT&CK for Coverage Communication",
      "analysis": [
        "Option A is CORRECT: Shared taxonomy improves prioritization and storytelling.",
        "Option B is INCORRECT: Secure Score does not require manual ATT&CK mapping to function.",
        "Option C is INCORRECT: Unrelated to VM power state.",
        "Option D is INCORRECT: Mapping is analytical, not a billing meter."
      ],
      "codeSnippet": "// Tag playbooks and recommendations with tactics\n// Report coverage heatmaps",
      "socTip": "Focus mapping effort on high-frequency alert types and critical recommendation categories first.",
      "docRef": "Microsoft Learn: MITRE ATT&CK in security products"
    }
  },
  {
    "topic": "Emergency lockdown scenario",
    "scenario": "Active compromise is confirmed on a VM with a high-severity alert.",
    "question": "Which response combination is most appropriate from a cloud SOC perspective?",
    "options": [
      "Isolate/contain the VM (network isolation, revoke credentials, stop free internet egress), preserve evidence, remediate per alert guidance, and fix enabling posture gaps",
      "Only add a cosmetic tag to the VM",
      "Only email the user hoping they reboot",
      "Delete the entire subscription immediately without evidence"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cloud Containment and Evidence",
      "analysis": [
        "Option A is CORRECT: Containment + forensics + remediation + hardening is the complete loop.",
        "Option B is INCORRECT: Tags do not contain attackers.",
        "Option C is INCORRECT: Passive notification is insufficient for active compromise.",
        "Option D is INCORRECT: Over-destructive and may destroy evidence and shared services."
      ],
      "codeSnippet": "// NSG lockdown / isolate\n// Credential rotation\n// Snapshot disks if needed\n// Remediate + posture fix",
      "socTip": "Pre-approve emergency isolation runbooks with cloud operations so SOC can act within minutes.",
      "docRef": "Microsoft Learn: Respond to alerts"
    }
  },
  {
    "topic": "Measuring SOC success with MDC",
    "scenario": "After six months of Defender for Cloud adoption, leadership requests outcome metrics.",
    "question": "Which metrics best show Defender for Cloud program success?",
    "options": [
      "Secure Score trend, critical recommendation age, alert MTTA/MTTR, coverage % of critical workloads, and reduction in high-risk attack paths",
      "Only the number of portal logins by analysts",
      "Only the count of enabled plans regardless of outcome",
      "Success cannot be measured"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Outcome Metrics for Cloud Security",
      "analysis": [
        "Option A is CORRECT: Outcome-oriented metrics tie posture and response performance to risk reduction.",
        "Option B is INCORRECT: Activity metrics are weak proxies.",
        "Option C is INCORRECT: Enablement without outcomes is incomplete.",
        "Option D is INCORRECT: Metrics are available and expected."
      ],
      "codeSnippet": "// Dashboard: score, open criticals, MTTR, coverage",
      "socTip": "Publish a monthly one-page cloud security scorecard combining posture and detection KPIs.",
      "docRef": "Microsoft Learn: Improve secure score"
    }
  },
  {
    "topic": "NSG hardening recommendations",
    "scenario": "Secure Score is reduced by findings about overly permissive network security groups.",
    "question": "What does an NSG hardening recommendation typically advise?",
    "options": [
      "Tighten overly broad allow rules (such as any-any or wide internet management access) to least-privilege sources and ports based on observed traffic patterns and security best practices",
      "Delete all NSGs immediately",
      "Disable virtual networks entirely",
      "NSG recommendations only apply to AWS security groups"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "NSG Hardening Recommendations",
      "analysis": [
        "Option A is CORRECT: Recommendations guide reduction of excessive network exposure.",
        "Option B is INCORRECT: NSGs are needed controls; they should be tightened not blindly deleted.",
        "Option C is INCORRECT: VNets remain required for private architectures.",
        "Option D is INCORRECT: Azure NSGs are in scope; multi-cloud has analogous findings."
      ],
      "codeSnippet": "// Recommendations → Networking\n// Review permissive rules → restrict",
      "socTip": "Use JIT and private endpoints together with NSG hardening for management and data planes.",
      "docRef": "Microsoft Learn: Network security recommendations"
    }
  },
  {
    "topic": "Disk encryption recommendations",
    "scenario": "VMs show recommendations to enable encryption at rest.",
    "question": "Why does Defender for Cloud recommend disk encryption?",
    "options": [
      "Encryption at rest protects data on disks if storage media are accessed outside the running VM trust boundary, supporting compliance and defense in depth",
      "Encryption slows CPUs so much that Microsoft recommends it only for labs",
      "Disk encryption replaces network controls",
      "Recommendations never mention encryption"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Disk Encryption Posture",
      "analysis": [
        "Option A is CORRECT: Encryption at rest is a foundational data protection control.",
        "Option B is INCORRECT: Modern encryption overhead is generally acceptable.",
        "Option C is INCORRECT: Encryption complements network controls.",
        "Option D is INCORRECT: Encryption is a common recommendation category."
      ],
      "codeSnippet": "// Recommendations → enable disk encryption / CMEK where required",
      "socTip": "Standardize encryption policy via Azure Policy so new disks comply automatically.",
      "docRef": "Microsoft Learn: Disk encryption recommendations"
    }
  },
  {
    "topic": "Key Vault soft delete and purge protection",
    "scenario": "A recommendation flags Key Vaults without soft-delete or purge protection.",
    "question": "Why are soft-delete and purge protection recommended for Key Vault?",
    "options": [
      "They help prevent permanent accidental or malicious deletion of secrets, keys, and certificates by enabling recovery windows and blocking immediate purge",
      "They make Key Vault free of charge",
      "They disable all access logging",
      "They are only cosmetic settings"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Key Vault Deletion Protection",
      "analysis": [
        "Option A is CORRECT: Soft-delete and purge protection are critical operational safeguards.",
        "Option B is INCORRECT: Not a pricing feature.",
        "Option C is INCORRECT: Logging remains important and separate.",
        "Option D is INCORRECT: These settings have real recovery impact."
      ],
      "codeSnippet": "// Key Vault → enable soft-delete + purge protection\n// Verify recommendation clears",
      "socTip": "Enforce purge protection on production vaults via policy; recovery from purge is otherwise impossible.",
      "docRef": "Microsoft Learn: Key Vault recommendations"
    }
  },
  {
    "topic": "Public IP exposure",
    "scenario": "Attack path analysis shows a VM with a public IP and open management ports.",
    "question": "What is a common remediation for unnecessary public IP exposure on VMs?",
    "options": [
      "Remove public IPs where not required, use private access patterns (bastion, private endpoints, VPN/ER), and restrict remaining public exposure with JIT and tight NSGs",
      "Assign more public IPs to every NIC",
      "Public IPs cannot be removed once assigned",
      "Exposure recommendations only apply to storage accounts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Reduce Public Exposure",
      "analysis": [
        "Option A is CORRECT: Minimizing public endpoints is a primary cloud hardening pattern.",
        "Option B is INCORRECT: More public IPs increase exposure.",
        "Option C is INCORRECT: Public IPs can be disassociated.",
        "Option D is INCORRECT: Compute exposure is a major theme."
      ],
      "codeSnippet": "// Remove public IP / use Bastion\n// Enable JIT for residual needs",
      "socTip": "Inventory all public IPs monthly and require business justification for each.",
      "docRef": "Microsoft Learn: Attack path and exposure"
    }
  },
  {
    "topic": "SQL auditing and threat detection",
    "scenario": "Azure SQL recommendations include enabling auditing and advanced threat protection features.",
    "question": "How do auditing and threat detection help SQL security?",
    "options": [
      "Auditing provides accountability trails; threat detection surfaces anomalous database activities such as unusual access or potential injection patterns for investigation",
      "Auditing only stores query plans for performance",
      "Threat detection disables the database firewall",
      "These features only work for MySQL on-premises"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "SQL Auditing and Threat Detection",
      "analysis": [
        "Option A is CORRECT: Complementary detective controls for database workloads.",
        "Option B is INCORRECT: Security auditing is about security events.",
        "Option C is INCORRECT: Detection does not disable firewalls.",
        "Option D is INCORRECT: Azure SQL and related services are in scope."
      ],
      "codeSnippet": "// Azure SQL → Auditing + Defender for SQL\n// Review alerts and audit logs",
      "socTip": "Send SQL audit logs to Log Analytics/Sentinel for correlation with identity signals.",
      "docRef": "Microsoft Learn: Defender for SQL"
    }
  },
  {
    "topic": "Container image scan findings",
    "scenario": "Defender for Containers reports critical CVEs in an image used by production pods.",
    "question": "What should teams do with critical container image vulnerabilities?",
    "options": [
      "Prioritize rebuilding images from patched bases, block deployment of critical vulnerable images in CI/CD, and roll out updated workloads",
      "Ignore CVEs because containers are ephemeral",
      "Only reboot nodes without rebuilding images",
      "Disable the Containers plan"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Container Image CVE Remediation",
      "analysis": [
        "Option A is CORRECT: Fix at image build time and prevent redeploy of vulnerable tags.",
        "Option B is INCORRECT: Ephemeral does not mean invulnerable.",
        "Option C is INCORRECT: Node reboot does not patch application image contents.",
        "Option D is INCORRECT: Disabling detection removes visibility."
      ],
      "codeSnippet": "// Registry scan findings → rebuild\n// Gate deployments on severity",
      "socTip": "Fail the pipeline on critical/high CVEs for production branches.",
      "docRef": "Microsoft Learn: Container vulnerability assessment"
    }
  },
  {
    "topic": "Kubernetes admission and posture",
    "scenario": "Recommendations suggest tightening Kubernetes RBAC and admission controls on AKS.",
    "question": "Why does Defender for Cloud surface Kubernetes posture recommendations?",
    "options": [
      "Misconfigured cluster RBAC, network policies, and admission settings can enable privilege escalation and lateral movement inside clusters",
      "Kubernetes posture is irrelevant to security",
      "Recommendations only care about node hostnames",
      "Posture findings only apply to Docker Swarm"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Kubernetes Security Posture",
      "analysis": [
        "Option A is CORRECT: Cluster configuration weaknesses are high-impact.",
        "Option B is INCORRECT: K8s posture is critical.",
        "Option C is INCORRECT: Control plane and RBAC matter more than hostnames.",
        "Option D is INCORRECT: Kubernetes is a primary focus."
      ],
      "codeSnippet": "// Defender for Containers recommendations\n// Harden RBAC, network policies, admissions",
      "socTip": "Treat cluster-admin bindings and privileged pods as Tier-0 style risks in cloud native estates.",
      "docRef": "Microsoft Learn: Kubernetes recommendations"
    }
  },
  {
    "topic": "Storage anonymous access",
    "scenario": "A recommendation warns that containers allow anonymous blob access.",
    "question": "Why is anonymous public access to storage containers a risk?",
    "options": [
      "Anyone on the internet may read or write data depending on the setting, enabling data leakage or malicious uploads without authentication",
      "Anonymous access always encrypts data better",
      "Anonymous access is required for all private VNets",
      "Recommendations incorrectly flag this every time"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Storage Anonymous Access Risk",
      "analysis": [
        "Option A is CORRECT: Public anonymous access is a frequent cause of data exposure incidents.",
        "Option B is INCORRECT: Access control is separate from encryption.",
        "Option C is INCORRECT: Private architectures should avoid anonymous public access.",
        "Option D is INCORRECT: The finding is valid for public anonymous configurations."
      ],
      "codeSnippet": "// Storage account → disable anonymous access\n// Use SAS/AAD auth instead",
      "socTip": "Search inventory for public containers regularly; attackers scan for them continuously.",
      "docRef": "Microsoft Learn: Storage access recommendations"
    }
  },
  {
    "topic": "MFA recommendations for privileged roles",
    "scenario": "CSPM findings highlight privileged accounts without strong authentication controls in cloud IAM.",
    "question": "How should the SOC respond to privileged access posture gaps?",
    "options": [
      "Enforce strong authentication, reduce standing privileges (PIM/JIT), and monitor privileged activity—closing the recommendation and reducing attack path likelihood",
      "Add more permanent Global Administrator accounts",
      "Disable logging for admins",
      "Ignore identity findings because cloud is different"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Privileged Identity Hardening",
      "analysis": [
        "Option A is CORRECT: Least privilege + strong auth is the standard response.",
        "Option B is INCORRECT: More standing admins increase risk.",
        "Option C is INCORRECT: Admin activity must be logged.",
        "Option D is INCORRECT: Identity is central to cloud security."
      ],
      "codeSnippet": "// Entra PIM + Conditional Access\n// Clear identity recommendations",
      "socTip": "Join cloud identity recommendations with Entra ID Protection risky sign-in workflows.",
      "docRef": "Microsoft Learn: Identity recommendations"
    }
  },
  {
    "topic": "Guest accounts and external identities",
    "scenario": "Recommendations mention guest user access to sensitive subscriptions.",
    "question": "What is a common best practice for guest access in cloud environments?",
    "options": [
      "Limit guest privileges to least necessary, review access regularly, and monitor guest activity especially on production subscriptions",
      "Grant guests Owner on all management groups by default",
      "Guests cannot be governed by recommendations",
      "Guest access has no security implications"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Guest Access Governance",
      "analysis": [
        "Option A is CORRECT: Guests expand the trust boundary and need tight control.",
        "Option B is INCORRECT: Excessive guest privilege is dangerous.",
        "Option C is INCORRECT: Identity recommendations often include external access.",
        "Option D is INCORRECT: Guest compromise is a real vector."
      ],
      "codeSnippet": "// Review guest role assignments\n// Access reviews + least privilege",
      "socTip": "Run quarterly access reviews on external identities with cloud role assignments.",
      "docRef": "Microsoft Learn: External identity risks"
    }
  },
  {
    "topic": "Diagnostic logging enablement",
    "scenario": "Many recommendations ask to enable diagnostic logs on Key Vault, Azure SQL, and Activity Log retention.",
    "question": "Why does Defender for Cloud emphasize diagnostic logging?",
    "options": [
      "Logs provide detective evidence for investigations, support compliance, and feed SIEM/Sentinel analytics for threat detection",
      "Logs only exist to increase storage bills with no security value",
      "Logging disables Secure Score",
      "Logging is optional for all regulated workloads without exception"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Diagnostic Logging as a Control",
      "analysis": [
        "Option A is CORRECT: Logging underpins detection and investigation.",
        "Option B is INCORRECT: Security value is primary; cost should be managed with retention policies.",
        "Option C is INCORRECT: Enabling logging improves posture.",
        "Option D is INCORRECT: Regulated environments typically require logging."
      ],
      "codeSnippet": "// Enable diagnostics → Log Analytics / Event Hub\n// Set retention appropriately",
      "socTip": "Centralize diagnostics to the Sentinel workspace for high-value resource types first.",
      "docRef": "Microsoft Learn: Logging recommendations"
    }
  },
  {
    "topic": "Azure Policy integration",
    "scenario": "Contoso wants to prevent non-compliant resources from being created, not only detect them after the fact.",
    "question": "How does Azure Policy work with Defender for Cloud posture goals?",
    "options": [
      "Azure Policy can deny or audit non-compliant configurations at deployment time, complementing Defender for Cloud’s continuous assessment and recommendations",
      "Azure Policy replaces Defender for Cloud alerts",
      "Policy only works for on-premises Group Policy objects",
      "Policy cannot affect cloud resources"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Preventive Azure Policy + Detective CSPM",
      "analysis": [
        "Option A is CORRECT: Policy prevents drift; CSPM detects residual issues.",
        "Option B is INCORRECT: Different control types.",
        "Option C is INCORRECT: Azure Policy is cloud ARM-centric.",
        "Option D is INCORRECT: Policy is designed for cloud resources."
      ],
      "codeSnippet": "// Azure Policy initiatives aligned to MCSB\n// Deny + DeployIfNotExists effects",
      "socTip": "Use DeployIfNotExists for auto-remediation of logging and tagging; Deny for high-risk network exposures.",
      "docRef": "Microsoft Learn: Azure Policy and Defender for Cloud"
    }
  },
  {
    "topic": "Secure Score export for executives",
    "scenario": "The CISO wants a weekly email of Secure Score by subscription.",
    "question": "How can Secure Score be reported outside the portal?",
    "options": [
      "Use continuous export, Azure Resource Graph/API queries, workbooks, or Logic Apps to report Secure Score trends to email/dashboards",
      "Secure Score is only visible inside the portal with no export",
      "Score can only be read by Microsoft employees",
      "Export requires turning off all plans"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Secure Score Reporting Channels",
      "analysis": [
        "Option A is CORRECT: Multiple automation and export paths support executive reporting.",
        "Option B is INCORRECT: Export and API access exist.",
        "Option C is INCORRECT: Customers own their score data.",
        "Option D is INCORRECT: Export does not require disabling protection."
      ],
      "codeSnippet": "// Continuous export / ARG query\n// Logic App weekly email",
      "socTip": "Include top failing controls in the same email so executives see actionable drivers, not only a number.",
      "docRef": "Microsoft Learn: Secure score API/export"
    }
  },
  {
    "topic": "Resource tags for prioritization",
    "scenario": "Two VMs have the same CVE; one is tagged Environment=Prod, Criticality=High.",
    "question": "How should tags influence remediation priority?",
    "options": [
      "Business tags (environment, criticality, data classification, owner) should elevate priority for production and sensitive assets even when technical severity is similar",
      "Tags should be ignored during triage",
      "Only color tags matter",
      "Tags replace the need for vulnerability assessment"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Business Context via Tags",
      "analysis": [
        "Option A is CORRECT: Business context differentiates equal technical findings.",
        "Option B is INCORRECT: Tags are valuable triage inputs.",
        "Option C is INCORRECT: Semantic tags matter, not aesthetics.",
        "Option D is INCORRECT: Tags complement VA; they do not replace it."
      ],
      "codeSnippet": "// Require tags via Policy\n// Use in hunting and governance rules",
      "socTip": "Standardize a small mandatory tag set: Owner, Environment, Criticality, DataClass.",
      "docRef": "Microsoft Learn: Governance and prioritization"
    }
  },
  {
    "topic": "Alert status workflow",
    "scenario": "An analyst determines an alert was a true positive that has been fully remediated.",
    "question": "How should the alert status be updated?",
    "options": [
      "Mark the alert with an appropriate status (e.g., resolved/dismissed with reason) and classification where supported so metrics and sync remain accurate",
      "Leave all alerts active forever",
      "Delete the subscription to clear alerts",
      "Status updates are not possible"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Alert Lifecycle Management",
      "analysis": [
        "Option A is CORRECT: Proper closure supports metrics and multi-tool sync.",
        "Option B is INCORRECT: Queue hygiene requires closure.",
        "Option C is INCORRECT: Destructive and unrelated.",
        "Option D is INCORRECT: Status management is supported."
      ],
      "codeSnippet": "// Alert → take action → resolve/dismiss\n// Add notes for audit",
      "socTip": "Require a one-line disposition note on every closed high-severity alert for after-action reviews.",
      "docRef": "Microsoft Learn: Manage security alerts"
    }
  },
  {
    "topic": "Multi-subscription secure score rollup",
    "scenario": "An enterprise has scores varying widely across 40 subscriptions.",
    "question": "How should multi-subscription posture be managed?",
    "options": [
      "Monitor scores per subscription and at management group aggregates, prioritize worst production subscriptions, and apply governance rules consistently",
      "Only watch a single lab subscription",
      "Average scores hide problems so never look at aggregates",
      "Disable scoring on production"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Scaled Secure Score Management",
      "analysis": [
        "Option A is CORRECT: Hierarchical visibility plus targeted remediation works at enterprise scale.",
        "Option B is INCORRECT: Production needs attention.",
        "Option C is INCORRECT: Aggregates help leadership; details drive work.",
        "Option D is INCORRECT: Production scoring is most important."
      ],
      "codeSnippet": "// MG secure score views\n// Rank subscriptions by critical open recommendations",
      "socTip": "Create a bottom-10 subscriptions list each month for focused engineering sprints.",
      "docRef": "Microsoft Learn: Secure score at scale"
    }
  },
  {
    "topic": "Defender plan for App Service vs WAF",
    "scenario": "A web app is protected by Azure WAF and also has Defender for App Service enabled.",
    "question": "How do WAF and Defender for App Service relate?",
    "options": [
      "WAF provides network/application layer filtering at the edge; Defender for App Service adds platform threat detection for App Service-hosted apps—they are complementary",
      "WAF fully replaces Defender for App Service",
      "Defender for App Service fully replaces WAF",
      "Only one can be enabled in a tenant"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Complementary Web App Protections",
      "analysis": [
        "Option A is CORRECT: Edge filtering and platform detection cover different layers.",
        "Option B is INCORRECT: Different control planes.",
        "Option C is INCORRECT: WAF remains valuable for HTTP exploits.",
        "Option D is INCORRECT: Both can be used together."
      ],
      "codeSnippet": "// App Gateway/Front Door WAF + Defender for App Service",
      "socTip": "Correlate WAF blocked requests with App Service alerts when investigating application attacks.",
      "docRef": "Microsoft Learn: Defender for App Service"
    }
  },
  {
    "topic": "Sample onboarding of Arc server",
    "scenario": "A Linux server in a branch office must be protected similarly to Azure VMs.",
    "question": "What is the high-level onboarding path for that server?",
    "options": [
      "Install the Azure Arc agent, ensure the server appears as an Arc resource, enable Defender for Servers on the target subscription, and verify recommendations/alerts flow",
      "Ship the physical server to an Azure datacenter only",
      "Arc cannot protect Linux",
      "Only Windows servers work with Arc and Defender"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Arc Server Onboarding Path",
      "analysis": [
        "Option A is CORRECT: Arc + Defender for Servers is the hybrid path.",
        "Option B is INCORRECT: Arc exists to avoid physical relocation.",
        "Option C is INCORRECT: Linux is supported.",
        "Option D is INCORRECT: Both OS families are supported with appropriate agents."
      ],
      "codeSnippet": "// azcmagent connect\n// Enable Defender for Servers\n// Validate in inventory",
      "socTip": "Include Arc onboarding in the standard server build for any machine that may process company data.",
      "docRef": "Microsoft Learn: Arc-enabled servers"
    }
  },
  {
    "topic": "Threat intelligence in alerts",
    "scenario": "An alert references known malicious IPs or campaigns.",
    "question": "How does threat intelligence enhance Defender for Cloud alerts?",
    "options": [
      "Microsoft threat intelligence enriches detections with known-bad indicators and campaign context, improving confidence and prioritization",
      "Threat intelligence is never used in cloud alerts",
      "Intelligence only applies to email products",
      "Intelligence automatically patches VMs"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "TI-Enriched Cloud Detections",
      "analysis": [
        "Option A is CORRECT: TI increases signal quality on network and behavioral detections.",
        "Option B is INCORRECT: TI is integral to many detections.",
        "Option C is INCORRECT: Cloud workload alerts also benefit.",
        "Option D is INCORRECT: TI informs detection; patching is separate."
      ],
      "codeSnippet": "// Alert details may cite TI indicators\n// Hunt related IOCs across estate",
      "socTip": "Pivot TI indicators from a cloud alert into MDE and Sentinel hunts for broader compromise.",
      "docRef": "Microsoft Learn: Threat intelligence in alerts"
    }
  },
  {
    "topic": "Automation trigger types",
    "scenario": "A cloud engineer configures workflow automation and sees multiple trigger options.",
    "question": "Which triggers are commonly available for Defender for Cloud workflow automation?",
    "options": [
      "Security alerts and security recommendations (and related events) can trigger Logic Apps playbooks for notification or remediation",
      "Only Azure AD user creation events",
      "Only monthly calendar triggers",
      "Automation cannot trigger on recommendations"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Workflow Automation Triggers",
      "analysis": [
        "Option A is CORRECT: Alerts and recommendations are primary triggers.",
        "Option B is INCORRECT: Identity events are handled in other products.",
        "Option C is INCORRECT: Event-driven security triggers are the point.",
        "Option D is INCORRECT: Recommendation triggers are supported."
      ],
      "codeSnippet": "// Workflow automation → trigger on alert/recommendation\n// Filter severity → run playbook",
      "socTip": "Use recommendation triggers for auto-opening ITSM tickets with owner fields from tags.",
      "docRef": "Microsoft Learn: Workflow automation"
    }
  },
  {
    "topic": "Exemption vs suppression difference",
    "scenario": "An analyst confuses recommendation exemptions with alert suppression.",
    "question": "What is the difference between recommendation exemption and alert suppression?",
    "options": [
      "Exemptions accept posture risk for configuration findings (affecting score/compliance tracking); suppressions hide or auto-handle alert noise for detection events",
      "They are identical in all cases",
      "Exemptions only apply to email",
      "Suppressions change Secure Score directly"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Exemption vs Suppression",
      "analysis": [
        "Option A is CORRECT: Exemptions = posture accepted risk; suppressions = detection noise control.",
        "Option B is INCORRECT: Different objects and purposes.",
        "Option C is INCORRECT: Exemptions apply to cloud recommendations broadly.",
        "Option D is INCORRECT: Suppressions target alerts; score is driven by recommendations."
      ],
      "codeSnippet": "// Exempt recommendation (posture)\n// Suppress alert (detection)",
      "socTip": "Use different approval workflows: architecture review for exemptions, SOC lead for suppressions.",
      "docRef": "Microsoft Learn: Exemptions and suppressions"
    }
  },
  {
    "topic": "Agentless vs agent-based tradeoffs",
    "scenario": "Security architects debate deploying agents on every VM versus relying on agentless scanning.",
    "question": "What is an accurate comparison?",
    "options": [
      "Agentless reduces operational overhead and covers many posture/VA scenarios; agents/extensions enable deeper runtime detection and certain CWPP capabilities—many estates use both",
      "Agentless always replaces agents completely for all runtime threats",
      "Agents are obsolete and never needed",
      "Agentless requires physical access to datacenters"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Agentless and Agent Complementary Use",
      "analysis": [
        "Option A is CORRECT: Defense in depth often combines both approaches.",
        "Option B is INCORRECT: Runtime detection still benefits from agents/sensors.",
        "Option C is INCORRECT: Agents remain important for EDR-class signals.",
        "Option D is INCORRECT: Agentless is cloud API/snapshot based."
      ],
      "codeSnippet": "// Agentless VA + Defender sensor/MDE where needed",
      "socTip": "Default to agentless for broad inventory; deploy deeper sensors on high-value and internet-facing systems.",
      "docRef": "Microsoft Learn: Agentless scanning"
    }
  },
  {
    "topic": "Business continuity during remediation",
    "scenario": "Remediating a recommendation may briefly affect application connectivity.",
    "question": "What should teams do before applying impactful remediation?",
    "options": [
      "Assess business impact, use change windows, test in non-production, and have rollback plans—especially for network and auth changes",
      "Apply all remediations instantly to production without review",
      "Never remediate anything",
      "Only remediate during peak traffic"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Safe Remediation Practices",
      "analysis": [
        "Option A is CORRECT: Change management prevents self-inflicted outages.",
        "Option B is INCORRECT: High risk of downtime.",
        "Option C is INCORRECT: Risk acceptance must be explicit, not default.",
        "Option D is INCORRECT: Peak traffic is the worst time for risky changes."
      ],
      "codeSnippet": "// Change ticket + test + rollback\n// Then remediate recommendation",
      "socTip": "For NSG and private endpoint changes, validate with a canary application first.",
      "docRef": "Microsoft Learn: Remediate recommendations"
    }
  },
  {
    "topic": "Cloud workload protection for hybrid SQL",
    "scenario": "SQL Server on an Arc-enabled machine needs Defender coverage.",
    "question": "How can SQL on machines be protected with Defender for Cloud?",
    "options": [
      "With appropriate Defender for SQL on machines configuration and Arc onboarding, SQL instances on hybrid machines can receive vulnerability assessment and threat protection capabilities",
      "SQL on machines is never supported",
      "Only Azure SQL PaaS can be protected",
      "Arc blocks SQL protection"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "SQL on Machines Protection",
      "analysis": [
        "Option A is CORRECT: Hybrid SQL coverage is a designed scenario via Arc and SQL plans.",
        "Option B is INCORRECT: Supported with correct setup.",
        "Option C is INCORRECT: On-machines coverage exists.",
        "Option D is INCORRECT: Arc enables the hybrid scenario."
      ],
      "codeSnippet": "// Arc server + Defender for SQL on machines\n// Discover/register SQL instances",
      "socTip": "Ensure SQL discovery/registration completes after Arc onboarding or VA may not appear.",
      "docRef": "Microsoft Learn: SQL on machines"
    }
  },
  {
    "topic": "Recommendations for Microsoft Defender for Endpoint integration",
    "scenario": "Defender for Servers can integrate with Microsoft Defender for Endpoint.",
    "question": "What benefit does integrating MDE with Defender for Servers provide?",
    "options": [
      "Unified endpoint detection and response signals on servers, richer investigation in the Defender portal, and coordinated protection across server workloads",
      "It removes all server telemetry",
      "Integration only works for Windows 95",
      "MDE integration disables CSPM"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "MDE Integration on Servers",
      "analysis": [
        "Option A is CORRECT: MDE brings EDR quality detection to server fleets under Defender for Cloud plans.",
        "Option B is INCORRECT: Integration increases visibility.",
        "Option C is INCORRECT: Modern OS support is required.",
        "Option D is INCORRECT: CSPM continues independently."
      ],
      "codeSnippet": "// Defender for Servers + MDE integration\n// Investigate server alerts in Defender XDR portal",
      "socTip": "Onboard servers to MDE for advanced hunting parity with workstation investigations.",
      "docRef": "Microsoft Learn: Defender for Servers and MDE"
    }
  },
  {
    "topic": "Service principal and automation account risks",
    "scenario": "Attack path analysis includes a powerful service principal with broad RBAC rights.",
    "question": "Why are overprivileged service principals a high-risk finding?",
    "options": [
      "Compromised automation identities can modify infrastructure at scale without interactive login, enabling stealthy persistence and widespread impact",
      "Service principals cannot be assigned RBAC roles",
      "Service principals always have MFA",
      "Findings about service principals are always false positives"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Non-Human Identity Risk",
      "analysis": [
        "Option A is CORRECT: Workload identities are high-value targets in cloud breaches.",
        "Option B is INCORRECT: They frequently hold privileged roles.",
        "Option C is INCORRECT: MFA does not apply the same way to non-human identities.",
        "Option D is INCORRECT: These findings are often critical true risks."
      ],
      "codeSnippet": "// Review SP role assignments\n// Reduce scope + rotate credentials/federate",
      "socTip": "Prefer federated workload identities over long-lived secrets for automation.",
      "docRef": "Microsoft Learn: Identity attack paths"
    }
  },
  {
    "topic": "Compliance evidence export",
    "scenario": "Auditors request evidence of control status for PCI controls mapped in Defender for Cloud.",
    "question": "How can compliance evidence be provided?",
    "options": [
      "Use the regulatory compliance dashboard exports/reports and underlying recommendation evidence to show control pass/fail status at a point in time",
      "Auditors only accept handwritten notes",
      "Compliance dashboards cannot be exported",
      "Evidence is only available 5 years later"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Audit Evidence from Compliance Dashboard",
      "analysis": [
        "Option A is CORRECT: Built-in reporting supports audit conversations.",
        "Option B is INCORRECT: Digital evidence is standard.",
        "Option C is INCORRECT: Export/report capabilities exist.",
        "Option D is INCORRECT: Point-in-time reports are available when needed."
      ],
      "codeSnippet": "// Regulatory compliance → download reports\n// Attach to audit package",
      "socTip": "Snapshot compliance reports before major changes and at audit period end dates.",
      "docRef": "Microsoft Learn: Regulatory compliance reports"
    }
  },
  {
    "topic": "Cost control while maintaining protection",
    "scenario": "Finance flags Defender for Cloud spend growth.",
    "question": "What are responsible ways to optimize cost without gutting security?",
    "options": [
      "Right-size plans by environment (full CWPP on prod, lighter on ephemeral labs), remove duplicate agents, and eliminate unused connectors—while keeping CSPM visibility",
      "Disable all plans on production to save money",
      "Only enable plans during business hours",
      "Delete all log data permanently"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Cost-Aware Security Coverage",
      "analysis": [
        "Option A is CORRECT: Environment-tiered coverage preserves protection where risk is highest.",
        "Option B is INCORRECT: Production needs the strongest controls.",
        "Option C is INCORRECT: Attacks are not business-hours limited.",
        "Option D is INCORRECT: Logs are needed for detection and forensics."
      ],
      "codeSnippet": "// Tag env=lab → lighter plans\n// Prod → full CWPP + CSPM",
      "socTip": "Review plan enablement quarterly against actual resource inventory to drop spend on empty subscriptions.",
      "docRef": "Microsoft Learn: Plan selection guidance"
    }
  },
  {
    "topic": "Incident correlation with cloud alerts",
    "scenario": "A Defender XDR incident includes both endpoint alerts and Defender for Cloud VM alerts.",
    "question": "What does cross-product incident correlation enable?",
    "options": [
      "A single investigation narrative spanning endpoint and cloud workload signals, improving blast-radius understanding and coordinated response",
      "Forced deletion of either endpoint or cloud data",
      "Correlation only for email phishing",
      "Incidents cannot include cloud alerts"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "XDR Correlation Including Cloud",
      "analysis": [
        "Option A is CORRECT: Unified incidents accelerate multi-domain response.",
        "Option B is INCORRECT: Correlation does not delete telemetry.",
        "Option C is INCORRECT: Correlation spans multiple workloads.",
        "Option D is INCORRECT: Cloud alerts participate in XDR incidents."
      ],
      "codeSnippet": "// Defender portal incidents\n// Mixed MDE + Defender for Cloud alerts",
      "socTip": "When cloud and endpoint alerts share a time window and identity, investigate as one campaign.",
      "docRef": "Microsoft Learn: Incidents in Defender XDR"
    }
  },
  {
    "topic": "Final program maturity check",
    "scenario": "After a year, the cloud security program wants a maturity self-assessment.",
    "question": "Which set of capabilities indicates a mature Defender for Cloud deployment?",
    "options": [
      "Broad CSPM coverage multi-cloud/hybrid, risk-prioritized remediation SLAs, tuned CWPP alerts with automation, governance ownership, and measurable Secure Score/attack-path reduction",
      "Portal access for one admin only with no plans enabled",
      "Only foundational CSPM on a single empty subscription",
      "No automation and permanent alert fatigue"
    ],
    "correctIndex": 0,
    "explanation": {
      "concept": "Mature Cloud Security Operations",
      "analysis": [
        "Option A is CORRECT: Coverage, prioritization, response, governance, and outcomes define maturity.",
        "Option B is INCORRECT: Single-admin no-plan setups are immature.",
        "Option C is INCORRECT: Incomplete coverage.",
        "Option D is INCORRECT: Fatigue without automation is a failure mode."
      ],
      "codeSnippet": "// Maturity scorecard: coverage, MTTR, score trend, path reduction",
      "socTip": "Revisit maturity annually against new Defender CSPM/CWPP capabilities and your multi-cloud footprint.",
      "docRef": "Microsoft Learn: Improve security posture"
    }
  }
]

def build_questions():
    result = []
    for i, q in enumerate(QUESTIONS):
        concept = q["explanation"]["concept"]
        correct_analysis = q["explanation"]["analysis"][q["correctIndex"]]
        audio = concept + ". " + (correct_analysis.split(": ", 1)[1][:200] if ": " in correct_analysis else correct_analysis[:200])
        q_obj = {
            "id": f"mdc-{i+1:03d}",
            "module": "mdc",
            "topic": q["topic"],
            "scenario": q["scenario"],
            "question": q["question"],
            "options": q["options"],
            "correctIndex": q["correctIndex"],
            "audioSummary": audio,
            "explanation": q["explanation"]
        }
        result.append(q_obj)
    return result

if __name__ == "__main__":
    questions = build_questions()
    output = "const MDC_QUESTIONS = " + json.dumps(questions, indent=2, ensure_ascii=False) + ";\n"
    with open("questions_mdc_v2.js", "w", encoding="utf-8") as f:
        f.write(output)
    print(f"[+] Generated {len(questions)} MDC questions -> questions_mdc_v2.js")
    stems = set(q["question"] for q in questions)
    scenarios = set(q["scenario"][:80] for q in questions)
    ci_dist = {}
    for q in questions:
        ci = q["correctIndex"]
        ci_dist[ci] = ci_dist.get(ci, 0) + 1
    print(f"    Unique question stems: {len(stems)}/{len(questions)}")
    print(f"    Unique scenario prefixes: {len(scenarios)}/{len(questions)}")
    print(f"    correctIndex distribution: {ci_dist}")
