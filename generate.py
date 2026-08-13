import json
import random
import os

topics = [
    'Copilot standalone experience vs embedded experience',
    'Promptbook creation and management',
    'Custom plugin development',
    'Script analysis and reverse engineering',
    'Incident summary generation',
    'Guided response recommendations',
    'KQL query generation from natural language',
    'Threat intelligence summarization',
    'Vulnerability impact assessment',
    'Device posture assessment via Copilot',
    'User risk profile analysis',
    'Suspicious email analysis',
    'File hash reputation lookup',
    'IP address reputation and geolocation',
    'Domain reputation investigation',
    'Natural language to KQL translation accuracy',
    'Copilot role-based access control',
    'Security Compute Unit (SCU) capacity planning',
    'SCU usage monitoring and optimization',
    'Copilot audit logging',
    'Data residency and privacy in Copilot',
    'Copilot integration with Microsoft Sentinel',
    'Copilot integration with Defender XDR',
    'Copilot integration with Intune',
    'Copilot integration with Entra ID',
    'Copilot integration with Purview',
    'Copilot integration with Defender for Cloud',
    'Promptbook sharing and collaboration',
    'Custom prompt engineering best practices',
    'Multi-turn conversation context management',
    'Incident report generation for stakeholders',
    'Threat actor profile research',
    'CVE analysis and remediation guidance',
    'Attack path analysis with Copilot',
    'Risk score interpretation',
    'Compliance posture assessment',
    'Policy recommendation generation',
    'Log analysis acceleration',
    'Alert triage prioritization',
    'False positive identification assistance',
    'Malware analysis capabilities',
    'Phishing email investigation',
    'Identity compromise investigation workflow',
    'Lateral movement detection with Copilot',
    'Data exfiltration risk assessment',
    'Insider threat investigation',
    'Third-party threat intelligence plugin',
    'MDTI (Microsoft Defender Threat Intelligence) integration',
    'Geopolitical threat briefing',
    'Industry-specific threat landscape',
    'Copilot session management',
    'Pinboard creation for investigations',
    'Investigation handoff between analysts',
    'Copilot API access and automation',
    'Performance benchmarking of Copilot responses',
    'Copilot output validation best practices',
    'Sensitive data handling in prompts',
    'Copilot error handling and retry logic',
    'Multi-workspace Copilot deployment',
    'Copilot for Security licensing model',
    'Embedded Copilot in Defender XDR incidents page',
    'Embedded Copilot in Sentinel hunting',
    'Embedded Copilot in Intune device management',
    'Embedded Copilot in Entra sign-in logs',
    'Embedded Copilot in Purview DLP alerts',
    'Script deobfuscation capabilities',
    'PowerShell script analysis',
    'Command line argument analysis',
    'Registry modification analysis',
    'Network traffic pattern analysis',
    'Certificate and TLS inspection guidance',
    'DNS query analysis',
    'SIEM query optimization suggestions',
    'Sentinel analytics rule creation via Copilot',
    'Sentinel workbook generation',
    'Sentinel playbook recommendation',
    'Incident severity recommendation',
    'Impact assessment for executive reporting',
    'Remediation action sequencing',
    'Post-incident review summarization',
    'Threat hunting hypothesis generation',
    'IOC extraction from reports',
    'STIX/TAXII intelligence correlation',
    'Attack simulation planning',
    'Purple team exercise support',
    'Compliance framework mapping (NIST, CIS)',
    'Regulatory requirement interpretation',
    'Security architecture review',
    'Cloud configuration assessment',
    'Container security posture evaluation',
    'API security assessment',
    'Identity governance recommendations',
    'Privileged access management guidance',
    'Zero Trust maturity assessment',
    'Security awareness training content',
    'Copilot feedback loop and improvement',
    'Custom knowledge base integration',
    'Multi-language support in Copilot',
    'Copilot usage analytics and ROI measurement',
    'Copilot deployment planning and rollout strategy'
]

questions = []

companies = ['Contoso', 'Fabrikam', 'Litware', 'Northwind', 'Adatum']

for i, topic in enumerate(topics):
    company = random.choice(companies)
    q_id = f'copilot-{i+1:03d}'
    
    scenario = f'You are a SOC analyst at {company} investigating an incident related to {topic}. You notice anomalous behaviors spanning multiple data sources. You need to leverage Microsoft Copilot for Security to accelerate the investigation.'
    
    question = f'Which method should you use to properly address {topic}?'
    
    correct_idx = random.randint(0, 3)
    options = [
        f'Navigate to Defender settings and configure {topic}',
        f'Review the documentation for {topic} and apply manually',
        f'Use the standalone Copilot portal to evaluate {topic}',
        f'Assign a custom RBAC role for {topic}'
    ]
    options[correct_idx] = f'Execute the appropriate Copilot prompt or plugin for {topic}'
    
    analysis = [
        f'Option A: This action does not leverage Copilot directly for {topic}.',
        f'Option B: Manual review is not the recommended first step when Copilot can assist with {topic}.',
        f'Option C: While Copilot is used, this specific option does not directly solve the {topic} requirement.',
        f'Option D: RBAC changes do not investigate or resolve {topic}.'
    ]
    analysis[correct_idx] = f'Option {chr(65+correct_idx)}: This is correct as using the targeted Copilot capability is the standard method for {topic}.'
    
    snippet = """// Real KQL query
SecurityIncident
| where Title contains \"suspicious\"
| summarize count() by Severity"""

    q_obj = {
        'id': q_id,
        'module': 'copilot',
        'topic': topic,
        'scenario': scenario,
        'question': question,
        'options': options,
        'correctIndex': correct_idx,
        'audioSummary': f'Summary of the key concept being tested: {topic}.',
        'explanation': {
            'concept': topic,
            'analysis': analysis,
            'codeSnippet': snippet,
            'socTip': f'Always verify Copilot output for accuracy before acting on {topic}.',
            'docRef': f'Microsoft Learn: Copilot for Security - {topic}'
        }
    }
    questions.append(q_obj)

js_content = 'const COPILOT_QUESTIONS = ' + json.dumps(questions, indent=2) + ';\n'

os.makedirs(r'd:\general\sc200-assessment', exist_ok=True)
with open(r'd:\general\sc200-assessment\questions_copilot.js', 'w', encoding='utf-8') as f:
    f.write(js_content)

print('File written successfully.')
