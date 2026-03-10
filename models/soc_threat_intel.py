# -*- coding: utf-8 -*-
"""
Threat Intelligence model - stores enrichment data from external sources.
"""
import logging
from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SocThreatIntel(models.Model):
    """Stores threat intelligence data from various open-source feeds."""
    _name = 'soc.threat.intel'
    _description = 'SOC Threat Intelligence Data'
    _order = 'create_date desc'

    alert_id = fields.Many2one(
        'soc.alert',
        string='Related Alert',
        ondelete='cascade',
    )
    source = fields.Selection([
        ('abuseipdb', 'AbuseIPDB'),
        ('otx', 'OTX AlienVault'),
        ('virustotal', 'VirusTotal'),
        ('misp', 'MISP'),
        ('manual', 'Manual Entry'),
    ], string='Intelligence Source', required=True)

    indicator = fields.Char(string='Indicator Value', required=True, index=True)
    indicator_type = fields.Selection([
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'File Hash'),
        ('email', 'Email'),
    ], string='Indicator Type', default='ip')

    raw_data = fields.Text(string='Raw API Response')
    confidence_score = fields.Float(
        string='Confidence Score',
        digits=(5, 2),
    )
    is_malicious = fields.Boolean(
        string='Is Malicious',
        compute='_compute_is_malicious',
        store=True,
    )
    country_code = fields.Char(string='Country Code')
    tags = fields.Char(string='Tags')
    notes = fields.Text(string='Analyst Notes')

    @api.depends('confidence_score')
    def _compute_is_malicious(self):
        for record in self:
            record.is_malicious = record.confidence_score >= 50
