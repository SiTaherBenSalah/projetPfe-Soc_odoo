# -*- coding: utf-8 -*-
"""
DevSecOps Pipeline Runner
Executes security scanning tools via CLI and parses their JSON output.
Each tool is called via subprocess and results are stored as findings.

Supported tools (all open-source / free tier):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SAST:        Bandit, Semgrep, SonarQube Scanner
SCA:         OWASP Dependency Check, Trivy (fs mode)
Container:   Trivy (image), Docker Bench Security
Kubernetes:  kube-bench, kube-hunter, kubeaudit, Falco
IaC:         Checkov, Trivy (config mode)
Secrets:     Gitleaks
Cloud:       ScoutSuite, Prowler, CloudSploit
DAST:        OWASP ZAP, Nuclei
"""
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime

from odoo import models, fields, api, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class DevSecOpsPipeline(models.Model):
    """
    Pipeline runner that orchestrates security scanning tools.
    All tools are invoked via CLI with JSON output parsing.
    """
    _name = 'soc.devsecops.pipeline'
    _description = 'DevSecOps Pipeline Runner'

    name = fields.Char(default='DevSecOps Pipeline Runner')

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Helper Methods                                               ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def _run_command(self, cmd, timeout=600):
        """Execute a shell command and return stdout."""
        _logger.info("Running DevSecOps command: %s", ' '.join(cmd) if isinstance(cmd, list) else cmd)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=isinstance(cmd, str),
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            _logger.warning("Command timed out: %s", cmd)
            return '', 'Command timed out', -1
        except FileNotFoundError:
            _logger.warning("Command not found: %s", cmd)
            return '', f'Command not found: {cmd}', -1
        except Exception as e:
            _logger.error("Command error: %s", str(e))
            return '', str(e), -1

    def _create_finding(self, scan, data):
        """Create a finding record from parsed scanner data."""
        return self.env['soc.devsecops.finding'].sudo().create({
            'scan_id': scan.id,
            'title': data.get('title', 'Unknown Finding'),
            'description': data.get('description', ''),
            'scanner': data.get('scanner', 'trivy'),
            'severity': data.get('severity', 'medium'),
            'vulnerability_id': data.get('vulnerability_id', ''),
            'cvss_score': data.get('cvss_score', 0),
            'cwe_id': data.get('cwe_id', ''),
            'affected_component': data.get('affected_component', ''),
            'installed_version': data.get('installed_version', ''),
            'fixed_version': data.get('fixed_version', ''),
            'file_path': data.get('file_path', ''),
            'line_number': data.get('line_number', 0),
            'category': data.get('category', 'vulnerability'),
            'remediation': data.get('remediation', ''),
            'reference_urls': data.get('reference_urls', ''),
            'raw_data': data.get('raw_data', ''),
        })

    def _map_severity(self, sev_str):
        """Map various severity strings to our standard values."""
        sev_str = (sev_str or '').upper().strip()
        mapping = {
            'CRITICAL': 'critical', 'CRIT': 'critical',
            'HIGH': 'high', 'IMPORTANT': 'high', 'ERROR': 'high',
            'MEDIUM': 'medium', 'MODERATE': 'medium', 'WARNING': 'medium',
            'LOW': 'low', 'MINOR': 'low',
            'INFO': 'info', 'INFORMATIONAL': 'info', 'NOTE': 'info',
            'UNKNOWN': 'info', 'NEGLIGIBLE': 'info',
        }
        return mapping.get(sev_str, 'medium')

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  TRIVY - Container / Filesystem / IaC Scanner                 ║
    # ║  https://github.com/aquasecurity/trivy                        ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_trivy(self, scan):
        """
        Run Trivy scanner against Docker images, filesystems, or IaC configs.
        Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
        """
        findings = []
        target = scan.target_value

        # Determine scan mode based on target type
        if scan.target_type == 'docker_image':
            cmd = ['trivy', 'image', '--format', 'json', '--severity',
                   'CRITICAL,HIGH,MEDIUM,LOW', target]
        elif scan.target_type == 'filesystem':
            cmd = ['trivy', 'fs', '--format', 'json', '--severity',
                   'CRITICAL,HIGH,MEDIUM,LOW', target]
        elif scan.target_type == 'iac':
            cmd = ['trivy', 'config', '--format', 'json', target]
        elif scan.target_type == 'git_repo':
            cmd = ['trivy', 'repo', '--format', 'json', target]
        else:
            cmd = ['trivy', 'image', '--format', 'json', target]

        stdout, stderr, rc = self._run_command(cmd)

        if stdout:
            try:
                data = json.loads(stdout)
                results = data.get('Results', [])
                for result in results:
                    target_name = result.get('Target', '')
                    vulns = result.get('Vulnerabilities', [])
                    for vuln in (vulns or []):
                        finding = self._create_finding(scan, {
                            'title': f"{vuln.get('VulnerabilityID', 'N/A')}: {vuln.get('Title', vuln.get('PkgName', 'Unknown'))}",
                            'description': vuln.get('Description', ''),
                            'scanner': 'trivy',
                            'severity': self._map_severity(vuln.get('Severity', 'MEDIUM')),
                            'vulnerability_id': vuln.get('VulnerabilityID', ''),
                            'cvss_score': (vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0)
                                          or vuln.get('CVSS', {}).get('redhat', {}).get('V3Score', 0)),
                            'affected_component': vuln.get('PkgName', ''),
                            'installed_version': vuln.get('InstalledVersion', ''),
                            'fixed_version': vuln.get('FixedVersion', ''),
                            'file_path': target_name,
                            'category': 'vulnerability',
                            'remediation': f"Update {vuln.get('PkgName', '')} to version {vuln.get('FixedVersion', 'latest')}",
                            'reference_urls': '\n'.join(vuln.get('References', [])[:5]),
                            'raw_data': json.dumps(vuln, indent=2)[:5000],
                        })
                        findings.append(finding)

                    # IaC misconfigurations
                    misconfigs = result.get('Misconfigurations', [])
                    for mc in (misconfigs or []):
                        finding = self._create_finding(scan, {
                            'title': mc.get('Title', 'IaC Misconfiguration'),
                            'description': mc.get('Description', ''),
                            'scanner': 'trivy',
                            'severity': self._map_severity(mc.get('Severity', 'MEDIUM')),
                            'vulnerability_id': mc.get('ID', ''),
                            'affected_component': mc.get('Type', ''),
                            'file_path': target_name,
                            'category': 'iac',
                            'remediation': mc.get('Resolution', ''),
                            'reference_urls': '\n'.join(mc.get('References', [])[:5]),
                        })
                        findings.append(finding)

                    # Secrets
                    secrets = result.get('Secrets', [])
                    for secret in (secrets or []):
                        finding = self._create_finding(scan, {
                            'title': f"Secret detected: {secret.get('Title', 'Unknown')}",
                            'description': secret.get('Match', ''),
                            'scanner': 'trivy',
                            'severity': 'critical',
                            'file_path': target_name,
                            'line_number': secret.get('StartLine', 0),
                            'category': 'secret',
                            'remediation': 'Remove the secret and rotate the credential immediately.',
                        })
                        findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("Trivy: Could not parse JSON output")

        _logger.info("Trivy found %d findings for scan %s", len(findings), scan.name)
        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  OWASP DEPENDENCY CHECK                                       ║
    # ║  https://github.com/jeremylong/DependencyCheck                ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_owasp_dependency_check(self, scan):
        """
        Run OWASP Dependency Check for SCA (Software Composition Analysis).
        Install: Download from https://owasp.org/www-project-dependency-check/
        """
        findings = []
        report_file = tempfile.mktemp(suffix='.json')

        cmd = [
            'dependency-check',
            '--scan', scan.target_value,
            '--format', 'JSON',
            '--out', report_file,
            '--disableAssembly',
            '--noupdate' if os.environ.get('OWASP_DC_NOUPDATE') else '',
        ]
        cmd = [c for c in cmd if c]  # Remove empty strings

        stdout, stderr, rc = self._run_command(cmd, timeout=900)

        if os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                dependencies = data.get('dependencies', [])
                for dep in dependencies:
                    vulns = dep.get('vulnerabilities', [])
                    for vuln in vulns:
                        cvss_v3 = vuln.get('cvssv3', {})
                        finding = self._create_finding(scan, {
                            'title': f"{vuln.get('name', 'Unknown')}: {dep.get('fileName', '')}",
                            'description': vuln.get('description', ''),
                            'scanner': 'owasp_dc',
                            'severity': self._map_severity(vuln.get('severity', 'MEDIUM')),
                            'vulnerability_id': vuln.get('name', ''),
                            'cvss_score': cvss_v3.get('baseScore', 0),
                            'cwe_id': vuln.get('cwe', ''),
                            'affected_component': dep.get('fileName', ''),
                            'category': 'dependency',
                            'remediation': f"Update dependency {dep.get('fileName', '')} to a patched version.",
                            'reference_urls': '\n'.join([
                                r.get('url', '') for r in vuln.get('references', [])[:5]
                            ]),
                            'raw_data': json.dumps(vuln, indent=2)[:5000],
                        })
                        findings.append(finding)
            except Exception as e:
                _logger.warning("OWASP DC: Error parsing report: %s", str(e))
            finally:
                if os.path.exists(report_file):
                    os.unlink(report_file)

        _logger.info("OWASP DC found %d findings for scan %s", len(findings), scan.name)
        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  BANDIT - Python SAST                                         ║
    # ║  https://github.com/PyCQA/bandit                              ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_bandit(self, scan):
        """
        Run Bandit for Python static security analysis.
        Install: pip install bandit
        """
        findings = []
        cmd = ['bandit', '-r', scan.target_value, '-f', 'json', '-ll']

        stdout, stderr, rc = self._run_command(cmd)

        if stdout:
            try:
                data = json.loads(stdout)
                for result in data.get('results', []):
                    finding = self._create_finding(scan, {
                        'title': f"[{result.get('test_id', '')}] {result.get('test_name', 'Unknown')}",
                        'description': result.get('issue_text', ''),
                        'scanner': 'bandit',
                        'severity': self._map_severity(result.get('issue_severity', 'MEDIUM')),
                        'cwe_id': result.get('issue_cwe', {}).get('id', ''),
                        'file_path': result.get('filename', ''),
                        'line_number': result.get('line_number', 0),
                        'category': 'code_smell',
                        'remediation': f"Review code at {result.get('filename', '')}:{result.get('line_number', '')}. "
                                       f"Confidence: {result.get('issue_confidence', 'N/A')}",
                        'raw_data': json.dumps(result, indent=2)[:3000],
                    })
                    findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("Bandit: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  SEMGREP - Multi-language SAST                                ║
    # ║  https://github.com/returntocorp/semgrep                     ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_semgrep(self, scan):
        """
        Run Semgrep for multi-language static analysis.
        Install: pip install semgrep
        """
        findings = []
        cmd = [
            'semgrep', 'scan',
            '--config', 'auto',
            '--json',
            '--severity', 'WARNING',
            scan.target_value,
        ]

        stdout, stderr, rc = self._run_command(cmd, timeout=600)

        if stdout:
            try:
                data = json.loads(stdout)
                for result in data.get('results', []):
                    extra = result.get('extra', {})
                    metadata = extra.get('metadata', {})
                    finding = self._create_finding(scan, {
                        'title': f"[Semgrep] {result.get('check_id', 'Unknown')}",
                        'description': extra.get('message', ''),
                        'scanner': 'semgrep',
                        'severity': self._map_severity(extra.get('severity', 'WARNING')),
                        'cwe_id': ', '.join(metadata.get('cwe', [])) if isinstance(metadata.get('cwe'), list) else metadata.get('cwe', ''),
                        'file_path': result.get('path', ''),
                        'line_number': result.get('start', {}).get('line', 0),
                        'category': 'code_smell',
                        'remediation': extra.get('fix', '') or metadata.get('fix', ''),
                        'reference_urls': '\n'.join(metadata.get('references', [])[:5]),
                        'raw_data': json.dumps(result, indent=2)[:3000],
                    })
                    findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("Semgrep: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  GITLEAKS - Secrets Detection                                 ║
    # ║  https://github.com/gitleaks/gitleaks                        ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_gitleaks(self, scan):
        """
        Run Gitleaks for detecting hardcoded secrets in repositories.
        Install: https://github.com/gitleaks/gitleaks/releases
        """
        findings = []
        report_file = tempfile.mktemp(suffix='.json')

        if scan.target_type == 'git_repo':
            cmd = ['gitleaks', 'detect', '--source', scan.target_value,
                   '--report-format', 'json', '--report-path', report_file]
        else:
            cmd = ['gitleaks', 'detect', '--source', scan.target_value,
                   '--no-git', '--report-format', 'json', '--report-path', report_file]

        self._run_command(cmd)

        if os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                for leak in (data if isinstance(data, list) else []):
                    finding = self._create_finding(scan, {
                        'title': f"Secret Leak: {leak.get('Description', leak.get('RuleID', 'Unknown'))}",
                        'description': f"Rule: {leak.get('RuleID', '')}\nMatch: {leak.get('Match', '')[:200]}",
                        'scanner': 'gitleaks',
                        'severity': 'critical',
                        'file_path': leak.get('File', ''),
                        'line_number': leak.get('StartLine', 0),
                        'category': 'secret',
                        'remediation': 'Remove the secret, rotate the credential, and add to .gitignore or .gitleaksignore.',
                    })
                    findings.append(finding)
            except Exception as e:
                _logger.warning("Gitleaks: Error parsing report: %s", str(e))
            finally:
                if os.path.exists(report_file):
                    os.unlink(report_file)

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  DOCKER BENCH SECURITY                                        ║
    # ║  https://github.com/docker/docker-bench-security              ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_docker_bench(self, scan):
        """
        Run Docker Bench for Security (CIS Docker Benchmark).
        Install: git clone https://github.com/docker/docker-bench-security.git
        """
        findings = []
        cmd = ['docker', 'run', '--rm', '--net', 'host', '--pid', 'host',
               '--userns', 'host', '--cap-add', 'audit_control',
               '-e', 'DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST',
               '-v', '/var/lib:/var/lib:ro',
               '-v', '/var/run/docker.sock:/var/run/docker.sock:ro',
               '-v', '/usr/lib/systemd:/usr/lib/systemd:ro',
               '-v', '/etc:/etc:ro',
               'docker/docker-bench-security', '-l', '/dev/stdout', '-j']

        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        if stdout:
            for line in stdout.strip().split('\n'):
                try:
                    entry = json.loads(line)
                    if entry.get('result') in ('WARN', 'FAIL'):
                        sev = 'high' if entry.get('result') == 'FAIL' else 'medium'
                        finding = self._create_finding(scan, {
                            'title': f"[Docker CIS] {entry.get('id', '')}: {entry.get('desc', 'Unknown')}",
                            'description': entry.get('desc', ''),
                            'scanner': 'docker_bench',
                            'severity': sev,
                            'category': 'container',
                            'remediation': entry.get('remediation', 'Follow CIS Docker Benchmark guidance.'),
                        })
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  KUBE-BENCH - CIS Kubernetes Benchmark                       ║
    # ║  https://github.com/aquasecurity/kube-bench                  ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_kube_bench(self, scan):
        """
        Run kube-bench for CIS Kubernetes Benchmark.
        Install: https://github.com/aquasecurity/kube-bench/releases
        Or: kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
        """
        findings = []
        cmd = ['kube-bench', 'run', '--json']

        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        if stdout:
            try:
                data = json.loads(stdout)
                controls = data.get('Controls', [])
                for control in controls:
                    for test in control.get('tests', []):
                        for result in test.get('results', []):
                            if result.get('status') in ('FAIL', 'WARN'):
                                sev = 'high' if result.get('status') == 'FAIL' else 'medium'
                                finding = self._create_finding(scan, {
                                    'title': f"[K8s CIS {result.get('test_number', '')}] {result.get('test_desc', 'Unknown')}",
                                    'description': result.get('test_desc', ''),
                                    'scanner': 'kube_bench',
                                    'severity': sev,
                                    'category': 'k8s',
                                    'remediation': result.get('remediation', ''),
                                    'affected_component': control.get('text', ''),
                                })
                                findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("kube-bench: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  KUBE-HUNTER - K8s Penetration Testing                       ║
    # ║  https://github.com/aquasecurity/kube-hunter                 ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_kube_hunter(self, scan):
        """
        Run kube-hunter for Kubernetes penetration testing.
        Install: pip install kube-hunter
        """
        findings = []
        cmd = ['kube-hunter', '--pod', '--report', 'json']

        stdout, stderr, rc = self._run_command(cmd, timeout=300)

        if stdout:
            try:
                data = json.loads(stdout)
                for vuln in data.get('vulnerabilities', []):
                    finding = self._create_finding(scan, {
                        'title': f"[kube-hunter] {vuln.get('vulnerability', 'Unknown')}",
                        'description': vuln.get('description', ''),
                        'scanner': 'kube_hunter',
                        'severity': self._map_severity(vuln.get('severity', 'medium')),
                        'category': 'k8s',
                        'affected_component': vuln.get('category', ''),
                        'remediation': vuln.get('evidence', ''),
                    })
                    findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("kube-hunter: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  KUBEAUDIT - K8s Security Audit                              ║
    # ║  https://github.com/Shopify/kubeaudit                        ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_kubeaudit(self, scan):
        """
        Run kubeaudit for Kubernetes security auditing.
        Install: https://github.com/Shopify/kubeaudit/releases
        """
        findings = []

        if scan.target_type == 'kubernetes':
            cmd = ['kubeaudit', 'all', '-f', 'json']
        else:
            cmd = ['kubeaudit', 'all', '-f', 'json', '--manifest', scan.target_value]

        stdout, stderr, rc = self._run_command(cmd)

        if stdout:
            for line in stdout.strip().split('\n'):
                try:
                    entry = json.loads(line)
                    if entry.get('level') in ('error', 'warning'):
                        sev = 'high' if entry.get('level') == 'error' else 'medium'
                        finding = self._create_finding(scan, {
                            'title': f"[kubeaudit] {entry.get('AuditResultName', entry.get('msg', 'Unknown'))}",
                            'description': entry.get('msg', ''),
                            'scanner': 'kubeaudit',
                            'severity': sev,
                            'category': 'k8s',
                            'affected_component': entry.get('ResourceKind', ''),
                        })
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  CHECKOV - IaC Security Scanner                              ║
    # ║  https://github.com/bridgecrewio/checkov                     ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_checkov(self, scan):
        """
        Run Checkov for IaC security scanning (Terraform, K8s, CloudFormation, Dockerfiles).
        Install: pip install checkov
        """
        findings = []
        cmd = ['checkov', '-d', scan.target_value, '-o', 'json', '--compact']

        stdout, stderr, rc = self._run_command(cmd, timeout=600)

        if stdout:
            try:
                data = json.loads(stdout)
                if isinstance(data, list):
                    all_results = data
                else:
                    all_results = [data]

                for check_type in all_results:
                    failed = check_type.get('results', {}).get('failed_checks', [])
                    for check in failed:
                        finding = self._create_finding(scan, {
                            'title': f"[{check.get('check_id', '')}] {check.get('check_name', 'Unknown')}",
                            'description': check.get('check_name', ''),
                            'scanner': 'checkov',
                            'severity': self._map_severity(check.get('severity', 'MEDIUM')),
                            'file_path': check.get('file_path', ''),
                            'line_number': check.get('file_line_range', [0])[0] if check.get('file_line_range') else 0,
                            'category': 'iac',
                            'affected_component': check.get('resource', ''),
                            'remediation': check.get('guideline', ''),
                        })
                        findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("Checkov: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  SCOUTSUITE - Multi-Cloud Security Auditing                  ║
    # ║  https://github.com/nccgroup/ScoutSuite                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_scoutsuite(self, scan):
        """
        Run ScoutSuite for cloud security auditing (AWS, Azure, GCP).
        Install: pip install scoutsuite
        """
        findings = []
        provider_map = {
            'cloud_aws': 'aws',
            'cloud_azure': 'azure',
            'cloud_gcp': 'gcp',
        }
        provider = provider_map.get(scan.target_type, 'aws')
        report_dir = tempfile.mkdtemp()

        cmd = ['scout', provider, '--no-browser', '--report-dir', report_dir, '--result-format', 'json']

        stdout, stderr, rc = self._run_command(cmd, timeout=1800)

        # Parse ScoutSuite results
        results_file = os.path.join(report_dir, 'scoutsuite-results', 'scoutsuite_results.json')
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    data = json.load(f)
                services = data.get('services', {})
                for service_name, service_data in services.items():
                    for finding_key, finding_data in service_data.get('findings', {}).items():
                        if finding_data.get('flagged_items', 0) > 0:
                            finding = self._create_finding(scan, {
                                'title': f"[ScoutSuite-{provider.upper()}] {finding_data.get('description', finding_key)}",
                                'description': f"Service: {service_name}\n"
                                               f"Flagged items: {finding_data.get('flagged_items', 0)}\n"
                                               f"Level: {finding_data.get('level', 'warning')}",
                                'scanner': 'scoutsuite',
                                'severity': self._map_severity(finding_data.get('level', 'warning')),
                                'category': 'cloud',
                                'affected_component': f"{provider}/{service_name}",
                                'remediation': finding_data.get('remediation', ''),
                            })
                            findings.append(finding)
            except Exception as e:
                _logger.warning("ScoutSuite: Error parsing results: %s", str(e))

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  PROWLER - AWS/Azure Security Assessment                     ║
    # ║  https://github.com/prowler-cloud/prowler                    ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_prowler(self, scan):
        """
        Run Prowler for AWS/Azure security best practices assessment.
        Install: pip install prowler
        """
        findings = []
        report_file = tempfile.mktemp(suffix='.json')

        provider = 'aws' if scan.target_type == 'cloud_aws' else 'azure'
        cmd = ['prowler', provider, '-M', 'json', '-F', report_file]

        self._run_command(cmd, timeout=1800)

        if os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get('StatusExtended', '') and entry.get('Status') == 'FAIL':
                                finding = self._create_finding(scan, {
                                    'title': f"[Prowler] {entry.get('CheckTitle', entry.get('CheckID', 'Unknown'))}",
                                    'description': entry.get('StatusExtended', ''),
                                    'scanner': 'prowler',
                                    'severity': self._map_severity(entry.get('Severity', 'medium')),
                                    'category': 'cloud',
                                    'affected_component': entry.get('ResourceId', ''),
                                    'remediation': entry.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                                    'reference_urls': entry.get('Remediation', {}).get('Recommendation', {}).get('Url', ''),
                                })
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                _logger.warning("Prowler: Error parsing report: %s", str(e))

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  CLOUDSPLOIT - Cloud Security Monitoring                     ║
    # ║  https://github.com/aquasecurity/cloudsploit                 ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_cloudsploit(self, scan):
        """
        Run CloudSploit for cloud security configuration monitoring.
        Install: npm install -g cloudsploit
        """
        findings = []
        cmd = ['cloudsploit', 'scan', '--json', '--console', 'none']

        stdout, stderr, rc = self._run_command(cmd, timeout=900)

        if stdout:
            try:
                data = json.loads(stdout)
                for result in data:
                    status = result.get('status', '')
                    if status in ('FAIL', 'WARN', 'UNKNOWN'):
                        sev_map = {'FAIL': 'high', 'WARN': 'medium', 'UNKNOWN': 'low'}
                        finding = self._create_finding(scan, {
                            'title': f"[CloudSploit] {result.get('plugin', 'Unknown')}: {result.get('message', '')}",
                            'description': result.get('message', ''),
                            'scanner': 'cloudsploit',
                            'severity': sev_map.get(status, 'medium'),
                            'category': 'cloud',
                            'affected_component': f"{result.get('category', '')}/{result.get('plugin', '')}",
                            'remediation': result.get('description', ''),
                        })
                        findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("CloudSploit: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  NUCLEI - Vulnerability Scanner                              ║
    # ║  https://github.com/projectdiscovery/nuclei                  ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_nuclei(self, scan):
        """
        Run Nuclei for template-based vulnerability scanning.
        Install: https://github.com/projectdiscovery/nuclei/releases
        """
        findings = []
        cmd = ['nuclei', '-target', scan.target_value, '-json', '-severity',
               'critical,high,medium', '-silent']

        stdout, stderr, rc = self._run_command(cmd, timeout=600)

        if stdout:
            for line in stdout.strip().split('\n'):
                try:
                    entry = json.loads(line)
                    info = entry.get('info', {})
                    finding = self._create_finding(scan, {
                        'title': f"[Nuclei] {info.get('name', 'Unknown')}",
                        'description': info.get('description', ''),
                        'scanner': 'nuclei',
                        'severity': self._map_severity(info.get('severity', 'medium')),
                        'vulnerability_id': ', '.join(info.get('reference', [])[:3]) if info.get('reference') else '',
                        'affected_component': entry.get('matched-at', ''),
                        'category': 'vulnerability',
                        'remediation': info.get('remediation', ''),
                        'reference_urls': '\n'.join(info.get('reference', [])[:5]) if info.get('reference') else '',
                    })
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  OWASP ZAP - Dynamic Application Security Testing           ║
    # ║  https://github.com/zaproxy/zaproxy                         ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_owasp_zap(self, scan):
        """
        Run OWASP ZAP for DAST scanning.
        Install: https://www.zaproxy.org/download/
        API mode: zap.sh -daemon -port 8080
        """
        findings = []
        cmd = [
            'docker', 'run', '--rm',
            'ghcr.io/zaproxy/zaproxy:stable',
            'zap-baseline.py', '-t', scan.target_value,
            '-J', '/dev/stdout',
        ]

        stdout, stderr, rc = self._run_command(cmd, timeout=900)

        if stdout:
            try:
                data = json.loads(stdout)
                for site in data.get('site', []):
                    for alert in site.get('alerts', []):
                        finding = self._create_finding(scan, {
                            'title': f"[ZAP] {alert.get('name', 'Unknown')}",
                            'description': alert.get('desc', ''),
                            'scanner': 'zap',
                            'severity': self._map_severity(
                                {'3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'INFO'}.get(
                                    str(alert.get('riskcode', 0)), 'MEDIUM')
                            ),
                            'cwe_id': alert.get('cweid', ''),
                            'category': 'vulnerability',
                            'affected_component': alert.get('url', ''),
                            'remediation': alert.get('solution', ''),
                            'reference_urls': alert.get('reference', ''),
                        })
                        findings.append(finding)
            except json.JSONDecodeError:
                _logger.warning("ZAP: Could not parse JSON output")

        return findings

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  SONARQUBE SCANNER                                           ║
    # ║  https://github.com/SonarSource/sonarqube                   ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def run_sonarqube(self, scan):
        """
        Fetch results from SonarQube API after scan.
        Install SonarQube: docker run -d --name sonarqube -p 9000:9000 sonarqube
        Scanner: https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/
        """
        findings = []
        config = self.env['soc.devsecops.jenkins.config'].search([], limit=1)
        sonar_url = config.sonarqube_url if config else 'http://localhost:9000'
        sonar_token = config.sonarqube_token if config else ''

        if not sonar_token:
            _logger.warning("SonarQube token not configured")
            return findings

        # First trigger scan
        cmd = [
            'sonar-scanner',
            f'-Dsonar.projectBaseDir={scan.target_value}',
            f'-Dsonar.host.url={sonar_url}',
            f'-Dsonar.token={sonar_token}',
        ]
        self._run_command(cmd, timeout=600)

        # Then fetch results via API
        import requests
        try:
            project_key = os.path.basename(scan.target_value)
            api_url = f"{sonar_url}/api/issues/search"
            params = {
                'componentKeys': project_key,
                'types': 'VULNERABILITY,BUG',
                'statuses': 'OPEN,CONFIRMED,REOPENED',
                'ps': 100,
            }
            headers = {'Authorization': f'Bearer {sonar_token}'}
            response = requests.get(api_url, params=params, headers=headers, timeout=30)
            if response.ok:
                data = response.json()
                for issue in data.get('issues', []):
                    finding = self._create_finding(scan, {
                        'title': f"[SonarQube] {issue.get('message', 'Unknown')}",
                        'description': issue.get('message', ''),
                        'scanner': 'sonarqube',
                        'severity': self._map_severity(issue.get('severity', 'MAJOR')),
                        'file_path': issue.get('component', ''),
                        'line_number': issue.get('line', 0),
                        'category': 'code_smell' if issue.get('type') == 'BUG' else 'vulnerability',
                        'affected_component': issue.get('rule', ''),
                    })
                    findings.append(finding)
        except Exception as e:
            _logger.warning("SonarQube API error: %s", str(e))

        return findings
