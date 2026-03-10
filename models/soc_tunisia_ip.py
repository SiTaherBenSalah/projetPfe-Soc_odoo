# -*- coding: utf-8 -*-
"""
Tunisia IP Range Management
Manages IP address ranges for servers hosted in Tunisia.
Used for filtering Wazuh alerts to focus on Tunisia-relevant traffic.
"""
import ipaddress
import logging

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SocTunisiaIpRange(models.Model):
    """
    Tunisia IP ranges - major ISPs and hosting providers.
    Includes ranges from:
    - Tunisie Telecom
    - Ooredoo Tunisia
    - Orange Tunisia
    - TOPNET
    - Hexabyte
    - ATI (Agence Tunisienne d'Internet)
    - Government networks
    """
    _name = 'soc.tunisia.ip.range'
    _description = 'Tunisia IP Address Range'
    _order = 'name'

    name = fields.Char(string='Range Name', required=True)
    network = fields.Char(
        string='Network (CIDR)',
        required=True,
        help='IP network in CIDR notation (e.g., 197.0.0.0/8)',
    )
    provider = fields.Selection([
        ('tunisie_telecom', 'Tunisie Telecom'),
        ('ooredoo', 'Ooredoo Tunisia'),
        ('orange', 'Orange Tunisia'),
        ('topnet', 'TOPNET'),
        ('hexabyte', 'Hexabyte'),
        ('ati', 'ATI (Agence Tunisienne d\'Internet)'),
        ('government', 'Government Network'),
        ('hosting', 'Hosting Provider'),
        ('university', 'University/Research'),
        ('other', 'Other'),
    ], string='Provider', default='other')

    description = fields.Text(string='Description')
    active = fields.Boolean(default=True)
    is_critical = fields.Boolean(
        string='Critical Infrastructure',
        help='Mark if this range hosts critical infrastructure',
    )

    @api.model
    def is_tunisia_ip(self, ip_str):
        """
        Check if a given IP address belongs to any Tunisia IP range.
        Returns True if the IP is within any configured Tunisia range.
        """
        if not ip_str:
            return False

        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        ranges = self.search([('active', '=', True)])
        for ip_range in ranges:
            try:
                network = ipaddress.ip_network(ip_range.network.strip(), strict=False)
                if ip in network:
                    return True
            except ValueError:
                continue

        return False

    @api.model
    def get_range_info(self, ip_str):
        """Get the range and provider info for a given IP."""
        if not ip_str:
            return None

        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return None

        ranges = self.search([('active', '=', True)])
        for ip_range in ranges:
            try:
                network = ipaddress.ip_network(ip_range.network.strip(), strict=False)
                if ip in network:
                    return {
                        'name': ip_range.name,
                        'network': ip_range.network,
                        'provider': ip_range.provider,
                        'is_critical': ip_range.is_critical,
                    }
            except ValueError:
                continue

        return None
