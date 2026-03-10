# -*- coding: utf-8 -*-
"""
Wizard to escalate an alert to an incident with additional details.
"""
from odoo import models, fields, api, _


class SocAlertEscalateWizard(models.TransientModel):
    """Wizard for escalating an alert to an incident."""
    _name = 'soc.alert.escalate.wizard'
    _description = 'Escalate Alert to Incident'

    alert_id = fields.Many2one(
        'soc.alert',
        string='Alert',
        required=True,
    )
    incident_title = fields.Char(
        string='Incident Title',
        required=True,
    )
    severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], string='Severity', required=True)
    description = fields.Text(string='Description')
    affected_systems = fields.Text(string='Affected Systems')
    analyst_id = fields.Many2one(
        'res.users',
        string='Lead Analyst',
        default=lambda self: self.env.uid,
    )

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        if self._context.get('active_id'):
            alert = self.env['soc.alert'].browse(self._context['active_id'])
            res.update({
                'alert_id': alert.id,
                'incident_title': f"Incident: {alert.title}",
                'severity': alert.severity,
                'description': alert.description,
            })
        return res

    def action_escalate(self):
        """Create the incident from the alert."""
        self.ensure_one()
        incident = self.env['soc.incident'].create({
            'title': self.incident_title,
            'description': self.description,
            'severity': self.severity,
            'category': self.alert_id.category,
            'source_ip': self.alert_id.source_ip,
            'destination_ip': self.alert_id.destination_ip,
            'affected_systems': self.affected_systems,
            'alert_ids': [(4, self.alert_id.id)],
            'analyst_id': self.analyst_id.id,
        })
        self.alert_id.write({
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
