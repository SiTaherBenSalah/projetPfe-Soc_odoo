# -*- coding: utf-8 -*-
import logging
from odoo import models, fields, api, _

_logger = logging.getLogger(__name__)


class SocIncident(models.Model):
    """
    SOC Incident - Represents a confirmed security incident.
    Incidents are escalated from verified alerts and tracked through
    their full lifecycle.
    """
    _name = 'soc.incident'
    _description = 'SOC Security Incident'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc, severity_priority desc'
    _rec_name = 'display_name'

    # ── Basic Fields ──────────────────────────────────────────────────
    name = fields.Char(
        string='Incident ID',
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
        string='Incident Title',
        required=True,
        tracking=True,
    )
    description = fields.Text(
        string='Description',
        tracking=True,
    )
    summary = fields.Text(
        string='Executive Summary',
        help='High-level summary for management reporting',
    )

    # ── Severity & Classification ─────────────────────────────────────
    severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], string='Severity', default='medium', tracking=True, required=True)

    severity_priority = fields.Integer(
        string='Severity Priority',
        compute='_compute_severity_priority',
        store=True,
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

    impact = fields.Selection([
        ('none', 'None'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], string='Business Impact', default='none', tracking=True)

    # ── Status & Workflow ─────────────────────────────────────────────
    state = fields.Selection([
        ('new', 'New'),
        ('triage', 'Triage'),
        ('investigation', 'Investigation'),
        ('containment', 'Containment'),
        ('eradication', 'Eradication'),
        ('recovery', 'Recovery'),
        ('post_incident', 'Post-Incident Review'),
        ('closed', 'Closed'),
    ], string='Status', default='new', tracking=True, required=True)

    # ── Network Information ───────────────────────────────────────────
    source_ip = fields.Char(string='Source IP', tracking=True)
    destination_ip = fields.Char(string='Destination IP', tracking=True)
    affected_systems = fields.Text(string='Affected Systems')

    # ── MITRE ATT&CK ─────────────────────────────────────────────────
    mitre_tactic_id = fields.Many2one(
        'soc.mitre.tactic',
        string='MITRE ATT&CK Tactic',
    )
    mitre_technique_ids = fields.Many2many(
        'soc.mitre.technique',
        'soc_incident_mitre_technique_rel',
        string='MITRE ATT&CK Techniques',
    )

    # ── Timestamps ────────────────────────────────────────────────────
    detection_date = fields.Datetime(
        string='Detection Date',
        default=fields.Datetime.now,
    )
    containment_date = fields.Datetime(string='Containment Date')
    eradication_date = fields.Datetime(string='Eradication Date')
    recovery_date = fields.Datetime(string='Recovery Date')
    closed_date = fields.Datetime(string='Closed Date')

    # ── Time Metrics ──────────────────────────────────────────────────
    time_to_detect = fields.Float(
        string='Time to Detect (hours)',
        compute='_compute_time_metrics',
        store=True,
    )
    time_to_contain = fields.Float(
        string='Time to Contain (hours)',
        compute='_compute_time_metrics',
        store=True,
    )
    time_to_resolve = fields.Float(
        string='Time to Resolve (hours)',
        compute='_compute_time_metrics',
        store=True,
    )

    # ── Relations ─────────────────────────────────────────────────────
    alert_ids = fields.One2many(
        'soc.alert',
        'incident_id',
        string='Related Alerts',
    )
    alert_count = fields.Integer(
        string='Alert Count',
        compute='_compute_alert_count',
    )
    analyst_id = fields.Many2one(
        'res.users',
        string='Lead Analyst',
        tracking=True,
    )
    team_member_ids = fields.Many2many(
        'res.users',
        'soc_incident_team_rel',
        string='Response Team',
    )

    # ── Response ──────────────────────────────────────────────────────
    response_plan = fields.Text(string='Response Plan')
    containment_actions = fields.Text(string='Containment Actions')
    eradication_actions = fields.Text(string='Eradication Actions')
    recovery_actions = fields.Text(string='Recovery Actions')
    lessons_learned = fields.Text(string='Lessons Learned')
    recommendations = fields.Text(string='Recommendations')

    # ── AI Analysis ───────────────────────────────────────────────────
    ai_analysis = fields.Text(string='AI Threat Analysis')
    ai_response_suggestion = fields.Text(string='AI Response Suggestion')

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Computed Fields                                              ║
    # ╚═══════════════════════════════════════════════════════════════╝

    @api.depends('name', 'title')
    def _compute_display_name(self):
        for record in self:
            record.display_name = f"[{record.name}] {record.title or ''}"

    @api.depends('severity')
    def _compute_severity_priority(self):
        priority_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        for record in self:
            record.severity_priority = priority_map.get(record.severity, 0)

    def _compute_alert_count(self):
        for record in self:
            record.alert_count = len(record.alert_ids)

    @api.depends('detection_date', 'containment_date', 'closed_date')
    def _compute_time_metrics(self):
        for record in self:
            record.time_to_detect = 0
            record.time_to_contain = 0
            record.time_to_resolve = 0
            if record.detection_date and record.create_date:
                delta = record.detection_date - record.create_date
                record.time_to_detect = delta.total_seconds() / 3600
            if record.containment_date and record.detection_date:
                delta = record.containment_date - record.detection_date
                record.time_to_contain = delta.total_seconds() / 3600
            if record.closed_date and record.detection_date:
                delta = record.closed_date - record.detection_date
                record.time_to_resolve = delta.total_seconds() / 3600

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  CRUD                                                         ║
    # ╚═══════════════════════════════════════════════════════════════╝

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self.env['ir.sequence'].next_by_code('soc.incident') or _('New')
        return super().create(vals_list)

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Actions                                                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def action_start_triage(self):
        self.write({'state': 'triage'})

    def action_start_investigation(self):
        self.write({'state': 'investigation'})

    def action_start_containment(self):
        self.write({
            'state': 'containment',
            'containment_date': fields.Datetime.now(),
        })

    def action_start_eradication(self):
        self.write({
            'state': 'eradication',
            'eradication_date': fields.Datetime.now(),
        })

    def action_start_recovery(self):
        self.write({
            'state': 'recovery',
            'recovery_date': fields.Datetime.now(),
        })

    def action_post_incident(self):
        self.write({'state': 'post_incident'})

    def action_close(self):
        self.write({
            'state': 'closed',
            'closed_date': fields.Datetime.now(),
        })

    def action_reopen(self):
        self.write({'state': 'investigation'})

    def action_ai_analyze(self):
        """Run AI analysis on the incident."""
        self.ensure_one()
        ai_agent = self.env['soc.ai.agent']
        ai_agent.analyze_incident(self)

    def action_view_alerts(self):
        """View related alerts."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Related Alerts'),
            'res_model': 'soc.alert',
            'view_mode': 'tree,form',
            'domain': [('incident_id', '=', self.id)],
            'context': {'default_incident_id': self.id},
        }
