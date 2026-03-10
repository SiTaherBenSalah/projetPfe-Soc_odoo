# -*- coding: utf-8 -*-
{
    'name': 'SOC Management',
    'version': '17.0.2.0.0',
    'category': 'Security',
    'summary': 'SOC Platform with Wazuh, AI Threat Intelligence & DevSecOps Pipeline',
    'description': """
        SOC Management Platform for Odoo
        =================================
        - Receive and manage security alerts from Wazuh SIEM
        - AI-powered threat intelligence filtering (using open-source LLMs via Ollama)
        - Automatic false positive detection and filtering
        - Tunisia-specific threat landscape focus (known attack patterns & local IP ranges)
        - Incident lifecycle management (detection → triage → response → closure)
        - Real-time dashboard with KPIs and visualizations
        - Integration with open-source threat intelligence feeds (AbuseIPDB, OTX, VirusTotal)
        - MITRE ATT&CK mapping
        - Automated enrichment of IOCs (Indicators of Compromise)

        DevSecOps Pipeline
        ==================
        - Docker & container security scanning (Trivy, Docker Bench)
        - Kubernetes security auditing (kube-bench, kube-hunter, kubeaudit)
        - SAST: Static code analysis (Bandit, Semgrep, SonarQube)
        - SCA: OWASP Dependency Check, Trivy filesystem
        - IaC security: Checkov (Terraform, CloudFormation, K8s manifests)
        - Secrets detection: Gitleaks
        - Cloud security: ScoutSuite, Prowler, CloudSploit
        - DAST: OWASP ZAP, Nuclei
        - Jenkins CI/CD integration with auto-generated Jenkinsfiles
        - Policy gates: block deployments on critical vulnerabilities
    """,
    'author': 'SOC Team',
    'website': '',
    'license': 'LGPL-3',
    'depends': [
        'base',
        'mail',
        'web',
    ],
    'data': [
        'security/ir.model.access.csv',
        'data/soc_data.xml',
        'data/cron_data.xml',
        'data/tunisia_ip_ranges.xml',
        'data/mitre_attack_data.xml',
        'data/devsecops_data.xml',
        'views/soc_alert_views.xml',
        'views/soc_incident_views.xml',
        'views/soc_dashboard_views.xml',
        'views/soc_threat_intel_views.xml',
        'views/soc_wazuh_config_views.xml',
        'views/soc_devsecops_views.xml',
        'views/soc_menus.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'soc_management/static/src/css/dashboard.css',
            'soc_management/static/src/js/dashboard.js',
            'soc_management/static/src/xml/dashboard_template.xml',
        ],
    },
    'installable': True,
    'application': True,
    'auto_install': False,
    'images': ['static/description/icon.png'],
}
