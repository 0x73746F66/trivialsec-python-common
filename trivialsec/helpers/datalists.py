from trivialsec.models import Feeds


namespaces = {
    'name': 'namespaces',
    'options': [
        'Software and Configuration Checks',
        'TTPs',
        'Effects',
        'Unusual Behaviors',
        'Sensitive Data Identifications',
    ]
}
software_and_configuration_checks = {
    'name': 'softwareandconfigurationchecks',
    'options': [
        'Vulnerabilities',
        'AWS Security Best Practices',
        'Industry and Regulatory Standards',
    ]
}
ttps = {
    'name': 'ttps',
    'options': [
        'Data Exposure',
        'Data Exfiltration',
        'Data Destruction',
        'Denial of Service',
        'Resource Consumption',
    ]
}
effects = {
    'name': 'effects',
    'options': [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Command and Control',
    ]
}
unusual_behaviors = {
    'name': 'unusualbehaviors',
    'options': [
        'Application',
        'Network Flow',
        'IP address',
        'User',
        'VM',
        'Container',
        'Serverless',
        'Process',
        'Database',
        'Data',
    ]
}
sensitive_data_identifications = {
    'name': 'sensitivedataidentifications',
    'options': [
        'PII',
        'Passwords',
        'Legal',
        'Financial',
        'Security',
        'Business',
    ]
}
vulnerabilities = {
    'name': 'vulnerabilities',
    'options': [
        'CVE',
        'CWE',
    ]
}
aws_security_best_practices = {
    'name': 'awssecuritybestpractices',
    'options': [
        'Network Reachability',
        'Runtime Behavior Analysis',
    ]
}
industry_and_regulatory_standards = {
    'name': 'industryandregulatorystandards',
    'options': [
        'CIS Host Hardening Benchmarks',
        'CIS AWS Foundations Benchmark',
        'PCI-DSS Controls',
        'Cloud Security Alliance Controls',
        'ISO 90001 Controls',
        'ISO 27001 Controls',
        'ISO 27017 Controls',
        'ISO 27018 Controls',
        'SOC 1',
        'SOC 2',
        'HIPAA Controls (USA)',
        'NIST 800-53 Controls (USA)',
        'NIST CSF Controls (USA)',
        'IRAP Controls (Australia)',
        'K-ISMS Controls (Korea)',
        'MTCS Controls (Singapore)',
        'FISC Controls (Japan)',
        'My Number Act Controls (Japan)',
        'ENS Controls (Spain)',
        'Cyber Essentials Plus Controls (UK)',
        'G-Cloud Controls (UK)',
        'C5 Controls (Germany)',
        'IT-Grundschutz Controls (Germany)',
        'GDPR Controls (Europe)',
        'TISAX Controls (Europe)',
    ]
}
methods = {
    'name': 'methods',
    'options': ['http', 'ftp']
}
types = {
    'name': 'types',
    'options': Feeds().distinct('type')
}
categories = {
    'name': 'categories',
    'options': Feeds().distinct('category')
}
