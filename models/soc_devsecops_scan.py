# -*- coding: utf-8 -*-
"""
DevSecOps Pipeline Scanner - Core Model
Manages security scanning pipelines integrating:
- Trivy (container/IaC/filesystem scanning)
- OWASP Dependency Check
- SAST tools (Bandit, Semgrep, SonarQube)
- Docker image scanning
- Kubernetes security (kube-bench, kube-hunter, Falco)
- Cloud security (ScoutSuite, Prowler, CloudSploit)
- Jenkins CI/CD integration
"""
import json
import logging
from datetime import timedelta

from odoo import models, fields, api, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class DevSecOpsScanProfile(models.Model):
    """Scan profile defining which tools to run and their configuration."""
    _name = 'soc.devsecops.scan.profile'
    _description = 'DevSecOps Scan Profile'
    _order = 'name'

    name = fields.Char(string='Profile Name', required=True)
    description = fields.Text(string='Description')
    active = fields.Boolean(default=True)

    # ── Enabled Scanners ──────────────────────────────────────────────
    enable_trivy = fields.Boolean(string='Trivy Scanner', default=True,
        help='Container, filesystem, IaC, and SBOM scanning')
    enable_owasp_dc = fields.Boolean(string='OWASP Dependency Check', default=True,
        help='Detect publicly disclosed vulnerabilities in project dependencies')
    enable_bandit = fields.Boolean(string='Bandit (Python SAST)', default=True,
        help='Security linter for Python code')
    enable_semgrep = fields.Boolean(string='Semgrep (Multi-language SAST)', default=True,
        help='Lightweight static analysis for many languages')
    enable_sonarqube = fields.Boolean(string='SonarQube Scanner', default=False,
        help='Continuous inspection of code quality and security')
    enable_gitleaks = fields.Boolean(string='Gitleaks (Secrets Detection)', default=True,
        help='Detect hardcoded secrets in git repos')
    enable_docker_bench = fields.Boolean(string='Docker Bench Security', default=True,
        help='CIS Docker benchmark checks')
    enable_kube_bench = fields.Boolean(string='kube-bench (K8s CIS)', default=True,
        help='CIS Kubernetes Benchmark checks')
    enable_kube_hunter = fields.Boolean(string='kube-hunter', default=True,
        help='Hunt for security weaknesses in Kubernetes clusters')
    enable_falco = fields.Boolean(string='Falco (Runtime Security)', default=False,
        help='Cloud-native runtime security monitoring')
    enable_kubeaudit = fields.Boolean(string='kubeaudit', default=True,
        help='Audit Kubernetes clusters for security concerns')
    enable_scoutsuite = fields.Boolean(string='ScoutSuite (Cloud Audit)', default=False,
        help='Multi-cloud security auditing (AWS, Azure, GCP)')
    enable_prowler = fields.Boolean(string='Prowler (AWS Security)', default=False,
        help='AWS and Azure security best practices assessments')
    enable_cloudsploit = fields.Boolean(string='CloudSploit', default=False,
        help='Cloud security configuration monitoring')
    enable_checkov = fields.Boolean(string='Checkov (IaC Security)', default=True,
        help='Static analysis for Terraform, CloudFormation, K8s, etc.')
    enable_nuclei = fields.Boolean(string='Nuclei (Vuln Scanner)', default=False,
        help='Fast vulnerability scanner based on templates')
    enable_zap = fields.Boolean(string='OWASP ZAP (DAST)', default=False,
        help='Dynamic Application Security Testing')

    scan_count = fields.Integer(string='Scans Run', compute='_compute_scan_count')

    def _compute_scan_count(self):
        scan_model = self.env['soc.devsecops.scan']
        for rec in self:
            rec.scan_count = scan_model.search_count([('profile_id', '=', rec.id)])


class DevSecOpsScan(models.Model):
    """
    Represents a single DevSecOps pipeline scan execution.
    A scan can include multiple tools running against a target.
    """
    _name = 'soc.devsecops.scan'
    _description = 'DevSecOps Pipeline Scan'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'
    _rec_name = 'display_name'

    name = fields.Char(string='Scan ID', required=True, readonly=True,
        default=lambda self: _('New'), copy=False)
    display_name = fields.Char(compute='_compute_display_name', store=True)

    # ── Scan Target ───────────────────────────────────────────────────
    target_type = fields.Selection([
        ('docker_image', 'Docker Image'),
        ('git_repo', 'Git Repository'),
        ('filesystem', 'Filesystem Path'),
        ('kubernetes', 'Kubernetes Cluster'),
        ('cloud_aws', 'AWS Account'),
        ('cloud_azure', 'Azure Subscription'),
        ('cloud_gcp', 'GCP Project'),
        ('url', 'Web Application URL'),
        ('iac', 'Infrastructure as Code'),
    ], string='Target Type', required=True, default='docker_image', tracking=True)

    target_value = fields.Char(string='Target', required=True, tracking=True,
        help='Docker image name, git URL, filesystem path, k8s context, etc.')
    target_branch = fields.Char(string='Branch / Tag', default='main')
    target_environment = fields.Selection([
        ('development', 'Development'),
        ('staging', 'Staging'),
        ('production', 'Production'),
    ], string='Environment', default='development')

    profile_id = fields.Many2one('soc.devsecops.scan.profile', string='Scan Profile',
        required=True)

    # ── Status ────────────────────────────────────────────────────────
    state = fields.Selection([
        ('draft', 'Draft'),
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ], string='Status', default='draft', tracking=True, required=True)

    # ── Jenkins Integration ───────────────────────────────────────────
    jenkins_job_url = fields.Char(string='Jenkins Job URL')
    jenkins_build_number = fields.Integer(string='Jenkins Build #')
    jenkins_triggered = fields.Boolean(string='Triggered from Jenkins')

    # ── Timestamps ────────────────────────────────────────────────────
    started_at = fields.Datetime(string='Started At')
    completed_at = fields.Datetime(string='Completed At')
    duration_minutes = fields.Float(string='Duration (min)',
        compute='_compute_duration', store=True)

    # ── Results Summary ───────────────────────────────────────────────
    total_vulnerabilities = fields.Integer(string='Total Vulnerabilities',
        compute='_compute_vuln_summary', store=True)
    critical_count = fields.Integer(string='Critical',
        compute='_compute_vuln_summary', store=True)
    high_count = fields.Integer(string='High',
        compute='_compute_vuln_summary', store=True)
    medium_count = fields.Integer(string='Medium',
        compute='_compute_vuln_summary', store=True)
    low_count = fields.Integer(string='Low',
        compute='_compute_vuln_summary', store=True)
    info_count = fields.Integer(string='Info',
        compute='_compute_vuln_summary', store=True)

    pass_fail = fields.Selection([
        ('pass', 'PASS ✅'),
        ('fail', 'FAIL ❌'),
        ('warning', 'WARNING ⚠️'),
    ], string='Result', compute='_compute_pass_fail', store=True)

    # ── Relations ─────────────────────────────────────────────────────
    finding_ids = fields.One2many('soc.devsecops.finding', 'scan_id',
        string='Findings')
    finding_count = fields.Integer(compute='_compute_finding_count')
    analyst_id = fields.Many2one('res.users', string='Analyst',
        default=lambda self: self.env.uid)

    # ── Notes ─────────────────────────────────────────────────────────
    notes = fields.Text(string='Notes')
    raw_output = fields.Text(string='Raw Scanner Output')

    @api.depends('name', 'target_value')
    def _compute_display_name(self):
        for rec in self:
            rec.display_name = f"[{rec.name}] {rec.target_value or ''}"

    @api.depends('started_at', 'completed_at')
    def _compute_duration(self):
        for rec in self:
            if rec.started_at and rec.completed_at:
                delta = rec.completed_at - rec.started_at
                rec.duration_minutes = round(delta.total_seconds() / 60, 1)
            else:
                rec.duration_minutes = 0

    @api.depends('finding_ids.severity')
    def _compute_vuln_summary(self):
        for rec in self:
            findings = rec.finding_ids
            rec.critical_count = len(findings.filtered(lambda f: f.severity == 'critical'))
            rec.high_count = len(findings.filtered(lambda f: f.severity == 'high'))
            rec.medium_count = len(findings.filtered(lambda f: f.severity == 'medium'))
            rec.low_count = len(findings.filtered(lambda f: f.severity == 'low'))
            rec.info_count = len(findings.filtered(lambda f: f.severity == 'info'))
            rec.total_vulnerabilities = len(findings)

    @api.depends('critical_count', 'high_count')
    def _compute_pass_fail(self):
        for rec in self:
            if rec.critical_count > 0:
                rec.pass_fail = 'fail'
            elif rec.high_count > 0:
                rec.pass_fail = 'warning'
            else:
                rec.pass_fail = 'pass'

    def _compute_finding_count(self):
        for rec in self:
            rec.finding_count = len(rec.finding_ids)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self.env['ir.sequence'].next_by_code('soc.devsecops.scan') or _('New')
        return super().create(vals_list)

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Actions                                                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def action_start_scan(self):
        """Queue the scan for execution."""
        self.ensure_one()
        self.write({
            'state': 'queued',
            'started_at': fields.Datetime.now(),
        })
        # Trigger actual scan via DevSecOps pipeline runner
        self.sudo()._run_pipeline()

    def action_cancel(self):
        self.write({'state': 'cancelled'})

    def action_reset_draft(self):
        self.write({'state': 'draft', 'started_at': False, 'completed_at': False})

    def action_view_findings(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Scan Findings'),
            'res_model': 'soc.devsecops.finding',
            'view_mode': 'tree,form',
            'domain': [('scan_id', '=', self.id)],
            'context': {'default_scan_id': self.id},
        }

    def action_create_alert_from_critical(self):
        """Create SOC alerts from critical findings."""
        self.ensure_one()
        alert_model = self.env['soc.alert']
        count = 0
        for finding in self.finding_ids.filtered(lambda f: f.severity in ('critical', 'high')):
            if not finding.alert_id:
                alert = alert_model.create({
                    'title': f"[DevSecOps] {finding.title}",
                    'description': (
                        f"Scanner: {finding.scanner}\n"
                        f"Target: {self.target_value}\n"
                        f"Vulnerability: {finding.vulnerability_id or 'N/A'}\n\n"
                        f"{finding.description}\n\n"
                        f"Remediation: {finding.remediation or 'N/A'}"
                    ),
                    'source': 'api',
                    'severity': finding.severity,
                    'category': 'suspicious_activity',
                    'state': 'new',
                })
                finding.write({'alert_id': alert.id})
                count += 1
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Alerts Created'),
                'message': _('%d SOC alerts created from critical findings.') % count,
                'type': 'success',
            },
        }

    def _run_pipeline(self):
        """
        Execute the DevSecOps scanning pipeline.
        Calls each enabled scanner tool and collects findings.
        """
        self.write({'state': 'running'})
        pipeline = self.env['soc.devsecops.pipeline']

        try:
            profile = self.profile_id
            results = []

            if profile.enable_trivy:
                results += pipeline.run_trivy(self)
            if profile.enable_owasp_dc:
                results += pipeline.run_owasp_dependency_check(self)
            if profile.enable_bandit:
                results += pipeline.run_bandit(self)
            if profile.enable_semgrep:
                results += pipeline.run_semgrep(self)
            if profile.enable_gitleaks:
                results += pipeline.run_gitleaks(self)
            if profile.enable_docker_bench:
                results += pipeline.run_docker_bench(self)
            if profile.enable_kube_bench:
                results += pipeline.run_kube_bench(self)
            if profile.enable_kube_hunter:
                results += pipeline.run_kube_hunter(self)
            if profile.enable_kubeaudit:
                results += pipeline.run_kubeaudit(self)
            if profile.enable_checkov:
                results += pipeline.run_checkov(self)
            if profile.enable_scoutsuite:
                results += pipeline.run_scoutsuite(self)
            if profile.enable_prowler:
                results += pipeline.run_prowler(self)
            if profile.enable_cloudsploit:
                results += pipeline.run_cloudsploit(self)
            if profile.enable_nuclei:
                results += pipeline.run_nuclei(self)
            if profile.enable_zap:
                results += pipeline.run_owasp_zap(self)
            if profile.enable_sonarqube:
                results += pipeline.run_sonarqube(self)

            self.write({
                'state': 'completed',
                'completed_at': fields.Datetime.now(),
            })
            _logger.info("DevSecOps scan %s completed with %d findings",
                         self.name, len(results))

        except Exception as e:
            self.write({
                'state': 'failed',
                'completed_at': fields.Datetime.now(),
                'notes': f"Pipeline error: {str(e)}",
            })
            _logger.error("DevSecOps scan %s failed: %s", self.name, str(e))


class DevSecOpsFinding(models.Model):
    """
    Individual security finding from a DevSecOps scan.
    """
    _name = 'soc.devsecops.finding'
    _description = 'DevSecOps Security Finding'
    _order = 'severity_order desc, create_date desc'

    scan_id = fields.Many2one('soc.devsecops.scan', string='Scan',
        ondelete='cascade', required=True)
    title = fields.Char(string='Finding Title', required=True)
    description = fields.Text(string='Description')

    scanner = fields.Selection([
        ('trivy', 'Trivy'),
        ('owasp_dc', 'OWASP Dependency Check'),
        ('bandit', 'Bandit'),
        ('semgrep', 'Semgrep'),
        ('sonarqube', 'SonarQube'),
        ('gitleaks', 'Gitleaks'),
        ('docker_bench', 'Docker Bench'),
        ('kube_bench', 'kube-bench'),
        ('kube_hunter', 'kube-hunter'),
        ('kubeaudit', 'kubeaudit'),
        ('falco', 'Falco'),
        ('checkov', 'Checkov'),
        ('scoutsuite', 'ScoutSuite'),
        ('prowler', 'Prowler'),
        ('cloudsploit', 'CloudSploit'),
        ('nuclei', 'Nuclei'),
        ('zap', 'OWASP ZAP'),
    ], string='Scanner Tool', required=True)

    severity = fields.Selection([
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ], string='Severity', required=True, default='medium')

    severity_order = fields.Integer(compute='_compute_severity_order', store=True)

    # ── Vulnerability Details ─────────────────────────────────────────
    vulnerability_id = fields.Char(string='CVE / Vulnerability ID',
        help='CVE-XXXX-XXXXX or custom vulnerability identifier')
    cvss_score = fields.Float(string='CVSS Score', digits=(3, 1))
    cwe_id = fields.Char(string='CWE ID', help='Common Weakness Enumeration')
    affected_component = fields.Char(string='Affected Component',
        help='Package, library, file, or resource affected')
    installed_version = fields.Char(string='Installed Version')
    fixed_version = fields.Char(string='Fixed Version')
    file_path = fields.Char(string='File Path')
    line_number = fields.Integer(string='Line Number')

    # ── Classification ────────────────────────────────────────────────
    category = fields.Selection([
        ('vulnerability', 'Known Vulnerability (CVE)'),
        ('misconfiguration', 'Misconfiguration'),
        ('secret', 'Exposed Secret/Credential'),
        ('code_smell', 'Code Security Smell'),
        ('dependency', 'Vulnerable Dependency'),
        ('compliance', 'Compliance Violation'),
        ('runtime', 'Runtime Security Issue'),
        ('iac', 'IaC Security Issue'),
        ('cloud', 'Cloud Misconfiguration'),
        ('container', 'Container Security Issue'),
        ('k8s', 'Kubernetes Security Issue'),
    ], string='Finding Category', default='vulnerability')

    # ── Status ────────────────────────────────────────────────────────
    state = fields.Selection([
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('accepted_risk', 'Accepted Risk'),
        ('false_positive', 'False Positive'),
    ], string='Status', default='open', tracking=True)

    remediation = fields.Text(string='Remediation Guidance')
    reference_urls = fields.Text(string='Reference URLs')
    raw_data = fields.Text(string='Raw Scanner Data')

    # ── Link to SOC Alert ─────────────────────────────────────────────
    alert_id = fields.Many2one('soc.alert', string='Linked SOC Alert')

    @api.depends('severity')
    def _compute_severity_order(self):
        order_map = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
        for rec in self:
            rec.severity_order = order_map.get(rec.severity, 0)

    def action_mark_resolved(self):
        self.write({'state': 'resolved'})

    def action_accept_risk(self):
        self.write({'state': 'accepted_risk'})

    def action_mark_false_positive(self):
        self.write({'state': 'false_positive'})
