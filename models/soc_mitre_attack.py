# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Framework data models for SOC Management.
"""
from odoo import models, fields


class SocMitreTactic(models.Model):
    """MITRE ATT&CK Tactic (e.g., Initial Access, Execution, Persistence)."""
    _name = 'soc.mitre.tactic'
    _description = 'MITRE ATT&CK Tactic'
    _order = 'sequence'

    name = fields.Char(string='Tactic Name', required=True)
    mitre_id = fields.Char(string='MITRE ID', required=True)
    description = fields.Text(string='Description')
    url = fields.Char(string='Reference URL')
    sequence = fields.Integer(string='Sequence', default=10)
    technique_ids = fields.One2many(
        'soc.mitre.technique',
        'tactic_id',
        string='Techniques',
    )


class SocMitreTechnique(models.Model):
    """MITRE ATT&CK Technique (e.g., T1566 Phishing, T1190 Exploit Public-Facing Application)."""
    _name = 'soc.mitre.technique'
    _description = 'MITRE ATT&CK Technique'
    _order = 'mitre_id'

    name = fields.Char(string='Technique Name', required=True)
    mitre_id = fields.Char(string='MITRE ID', required=True)
    description = fields.Text(string='Description')
    url = fields.Char(string='Reference URL')
    tactic_id = fields.Many2one(
        'soc.mitre.tactic',
        string='Tactic',
        ondelete='cascade',
    )
    is_subtechnique = fields.Boolean(string='Is Sub-technique')
    parent_technique_id = fields.Many2one(
        'soc.mitre.technique',
        string='Parent Technique',
    )
    detection = fields.Text(string='Detection Guidance')
    mitigation = fields.Text(string='Mitigation')
