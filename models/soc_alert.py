# -*- coding: utf-8 -*-
import logging
from datetime import timedelta
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class SocAlert(models.Model):
    """
    SOC Alert - Represents a security alert received from Wazuh or other sources.
    Alerts are filtered by the AI agent to remove false positives and focus on
    Tunisia-relevant threats.
    """
    _name = 'soc.alert'
    _description = 'SOC Security Alert'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'timestamp desc, severity_level desc'
    _rec_name = 'display_name'

    # ── Basic Fields ──────────────────────────────────────────────────
    name = fields.Char(
        string='Alert ID',
        required=True,
        readonly=True,
        default=lambda self: _('New'),
        copy=False,
    )
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
    )
    title = fields.Char(
        string='Alert Title',
        required=True,
        tracking=True,
    )
    description = fields.Text(
        string='Description',
        tracking=True,
    )
    raw_log = fields.Text(
        string='Raw Log Data',
        help='Original raw log data from Wazuh',
    )

    # ── Source Information ────────────────────────────────────────────
    source = fields.Selection([
        ('wazuh', 'Wazuh SIEM'),
        ('manual', 'Manual Entry'),
        ('api', 'External API'),
        ('threat_feed', 'Threat Intelligence Feed'),
    ], string='Source', default='wazuh', tracking=True)

    wazuh_rule_id = fields.Char(string='Wazuh Rule ID')
    wazuh_rule_description = fields.Char(string='Wazuh Rule Description')
    wazuh_agent_id = fields.Char(string='Wazuh Agent ID')
    wazuh_agent_name = fields.Char(string='Wazuh Agent Name')
    wazuh_manager = fields.Char(string='Wazuh Manager')
    wazuh_full_log = fields.Text(string='Wazuh Full Log')

    # ── Network Information ───────────────────────────────────────────
    source_ip = fields.Char(string='Source IP Address', tracking=True, index=True)
    destination_ip = fields.Char(string='Destination IP Address', tracking=True, index=True)
    source_port = fields.Integer(string='Source Port')
    destination_port = fields.Integer(string='Destination Port')
    protocol = fields.Char(string='Protocol')
    is_tunisia_ip = fields.Boolean(
        string='Tunisia IP',
        compute='_compute_is_tunisia_ip',
        store=True,
        help='Whether the source or destination IP belongs to Tunisia IP range',
    )

    # ── Severity & Classification ─────────────────────────────────────
    severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], string='Severity', default='medium', tracking=True, required=True)

    severity_level = fields.Integer(
        string='Severity Level (Wazuh)',
        help='Wazuh rule level (0-15)',
    )

    category = fields.Selection([
        ('intrusion_attempt', 'Intrusion Attempt'),
        ('malware', 'Malware Detection'),
        ('ddos', 'DDoS Attack'),
        ('brute_force', 'Brute Force'),
        ('phishing', 'Phishing'),
        ('ransomware', 'Ransomware'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('lateral_movement', 'Lateral Movement'),
        ('web_attack', 'Web Application Attack'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('command_injection', 'Command Injection'),
        ('reconnaissance', 'Reconnaissance/Scanning'),
        ('policy_violation', 'Policy Violation'),
        ('authentication_failure', 'Authentication Failure'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('apt', 'Advanced Persistent Threat'),
        ('supply_chain', 'Supply Chain Attack'),
        ('zero_day', 'Zero-Day Exploit'),
        ('other', 'Other'),
    ], string='Attack Category', tracking=True)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────
    mitre_tactic_id = fields.Many2one(
        'soc.mitre.tactic',
        string='MITRE ATT&CK Tactic',
    )
    mitre_technique_ids = fields.Many2many(
        'soc.mitre.technique',
        string='MITRE ATT&CK Techniques',
    )

    # ── Status & Workflow ─────────────────────────────────────────────
    state = fields.Selection([
        ('new', 'New'),
        ('analyzing', 'Analyzing'),
        ('confirmed', 'Confirmed Threat'),
        ('false_positive', 'False Positive'),
        ('escalated', 'Escalated to Incident'),
        ('closed', 'Closed'),
    ], string='Status', default='new', tracking=True, required=True)

    is_false_positive = fields.Boolean(
        string='Is False Positive',
        compute='_compute_is_false_positive',
        store=True,
    )
    false_positive_reason = fields.Text(string='False Positive Reason')

    ai_analysis = fields.Text(
        string='AI Analysis',
        help='Analysis result from the AI threat intelligence agent',
    )
    ai_confidence_score = fields.Float(
        string='AI Confidence Score',
        help='Confidence score from AI analysis (0-100)',
        digits=(5, 2),
    )
    ai_is_false_positive = fields.Boolean(
        string='AI Detected False Positive',
        help='Whether the AI agent classified this as a false positive',
    )
    ai_recommended_action = fields.Text(
        string='AI Recommended Action',
    )

    # ── Timestamps ────────────────────────────────────────────────────
    timestamp = fields.Datetime(
        string='Alert Timestamp',
        default=fields.Datetime.now,
        required=True,
        index=True,
    )
    analyzed_at = fields.Datetime(string='Analyzed At')
    closed_at = fields.Datetime(string='Closed At')

    # ── Relations ─────────────────────────────────────────────────────
    incident_id = fields.Many2one(
        'soc.incident',
        string='Related Incident',
        tracking=True,
    )
    analyst_id = fields.Many2one(
        'res.users',
        string='Assigned Analyst',
        tracking=True,
    )

    # ── Threat Intelligence ───────────────────────────────────────────
    threat_intel_ids = fields.One2many(
        'soc.threat.intel',
        'alert_id',
        string='Threat Intelligence',
    )
    ioc_type = fields.Selection([
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash_md5', 'MD5 Hash'),
        ('hash_sha1', 'SHA1 Hash'),
        ('hash_sha256', 'SHA256 Hash'),
        ('email', 'Email Address'),
        ('filename', 'Filename'),
        ('other', 'Other'),
    ], string='IOC Type')
    ioc_value = fields.Char(string='IOC Value')

    # ── Tunisia Relevance ─────────────────────────────────────────────
    tunisia_relevance_score = fields.Float(
        string='Tunisia Relevance Score',
        digits=(5, 2),
        help='Score (0-100) indicating relevance to Tunisia threat landscape',
    )
    is_tunisia_relevant = fields.Boolean(
        string='Relevant to Tunisia',
        compute='_compute_is_tunisia_relevant',
        store=True,
    )

    # ── Counts ────────────────────────────────────────────────────────
    alert_count = fields.Integer(
        string='Similar Alerts Count',
        compute='_compute_alert_count',
    )

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Computed Fields                                              ║
    # ╚═══════════════════════════════════════════════════════════════╝

    @api.depends('name', 'title')
    def _compute_display_name(self):
        for record in self:
            record.display_name = f"[{record.name}] {record.title or ''}"

    @api.depends('state')
    def _compute_is_false_positive(self):
        for record in self:
            record.is_false_positive = record.state == 'false_positive'

    @api.depends('source_ip', 'destination_ip')
    def _compute_is_tunisia_ip(self):
        tunisia_ip_model = self.env['soc.tunisia.ip.range']
        for record in self:
            is_tn = False
            if record.source_ip:
                is_tn = tunisia_ip_model.is_tunisia_ip(record.source_ip)
            if not is_tn and record.destination_ip:
                is_tn = tunisia_ip_model.is_tunisia_ip(record.destination_ip)
            record.is_tunisia_ip = is_tn

    @api.depends('tunisia_relevance_score', 'is_tunisia_ip', 'category')
    def _compute_is_tunisia_relevant(self):
        # Categories of major attacks known in Tunisia
        major_tunisia_categories = [
            'brute_force', 'phishing', 'ransomware', 'ddos',
            'web_attack', 'sql_injection', 'malware', 'apt',
            'data_exfiltration', 'reconnaissance',
        ]
        for record in self:
            record.is_tunisia_relevant = (
                record.tunisia_relevance_score >= 50
                or record.is_tunisia_ip
                or record.category in major_tunisia_categories
            )

    def _compute_alert_count(self):
        for record in self:
            record.alert_count = self.search_count([
                ('source_ip', '=', record.source_ip),
                ('source_ip', '!=', False),
                ('id', '!=', record.id),
            ])

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  CRUD & Lifecycle                                             ║
    # ╚═══════════════════════════════════════════════════════════════╝

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self.env['ir.sequence'].next_by_code('soc.alert') or _('New')
        records = super().create(vals_list)
        # Auto-trigger AI analysis for new alerts
        for record in records:
            record.sudo()._trigger_ai_analysis()
        return records

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Actions                                                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def action_analyze(self):
        """Start analysis of the alert."""
        self.ensure_one()
        self.write({
            'state': 'analyzing',
            'analyst_id': self.env.uid,
        })

    def action_confirm_threat(self):
        """Confirm the alert as a real threat."""
        self.ensure_one()
        self.write({
            'state': 'confirmed',
            'analyzed_at': fields.Datetime.now(),
        })

    def action_mark_false_positive(self):
        """Mark the alert as a false positive."""
        self.ensure_one()
        self.write({
            'state': 'false_positive',
            'analyzed_at': fields.Datetime.now(),
        })

    def action_escalate_to_incident(self):
        """Escalate the alert to a security incident."""
        self.ensure_one()
        incident = self.env['soc.incident'].create({
            'name': _('New'),
            'title': f"Incident from Alert: {self.title}",
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'alert_ids': [(4, self.id)],
            'analyst_id': self.env.uid,
            'mitre_tactic_id': self.mitre_tactic_id.id if self.mitre_tactic_id else False,
        })
        self.write({
            'state': 'escalated',
            'incident_id': incident.id,
        })
        return {
            'type': 'ir.actions.act_window',
            'name': _('Security Incident'),
            'res_model': 'soc.incident',
            'res_id': incident.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_close(self):
        """Close the alert."""
        self.ensure_one()
        self.write({
            'state': 'closed',
            'closed_at': fields.Datetime.now(),
        })

    def action_enrich_ioc(self):
        """Enrich the alert with threat intelligence data."""
        self.ensure_one()
        ai_agent = self.env['soc.ai.agent']
        ai_agent.enrich_alert_ioc(self)

    def _trigger_ai_analysis(self):
        """Trigger asynchronous AI analysis of the alert."""
        try:
            ai_agent = self.env['soc.ai.agent']
            ai_agent.analyze_alert(self)
        except Exception as e:
            _logger.warning("AI analysis failed for alert %s: %s", self.name, str(e))

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Cron Methods                                                 ║
    # ╚═══════════════════════════════════════════════════════════════╝

    @api.model
    def cron_auto_close_false_positives(self):
        """Auto-close alerts marked as false positives after 24h."""
        threshold = fields.Datetime.now() - timedelta(hours=24)
        alerts = self.search([
            ('state', '=', 'false_positive'),
            ('analyzed_at', '<=', threshold),
        ])
        alerts.write({
            'state': 'closed',
            'closed_at': fields.Datetime.now(),
        })
        _logger.info("Auto-closed %d false positive alerts", len(alerts))

    @api.model
    def cron_fetch_wazuh_alerts(self):
        """Fetch new alerts from Wazuh API."""
        connector = self.env['soc.wazuh.connector']
        connector.fetch_alerts()
