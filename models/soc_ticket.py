# -*- coding: utf-8 -*-
from odoo import models, fields, api, _

class SocTicket(models.Model):
    _name = 'soc.ticket'
    _description = 'SOC Team Ticket'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'create_date desc'

    name = fields.Char(string='Ticket Reference', required=True, copy=False, readonly=True, default=lambda self: _('New'))
    first_name = fields.Char(string='Nom', required=True, tracking=True)
    last_name = fields.Char(string='Prénom', required=True, tracking=True)
    level = fields.Selection([
        ('1', 'Niveau 1'),
        ('2', 'Niveau 2'),
        ('3', 'Niveau 3'),
    ], string='Niveau', required=True, default='1', tracking=True)
    description = fields.Text(string='Description', tracking=True)
    state = fields.Selection([
        ('new', 'Nouveau'),
        ('in_progress', 'En cours'),
        ('resolved', 'Résolu'),
        ('closed', 'Clôturé'),
    ], string='Statut', default='new', tracking=True)
    
    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self.env['ir.sequence'].next_by_code('soc.ticket') or _('New')
        return super().create(vals_list)

    def action_start(self):
        self.write({'state': 'in_progress'})

    def action_resolve(self):
        self.write({'state': 'resolved'})

    def action_close(self):
        self.write({'state': 'closed'})
