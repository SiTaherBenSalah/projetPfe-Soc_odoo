# -*- coding: utf-8 -*-
"""
Wazuh SIEM Connector for SOC Management
Handles API communication with Wazuh Manager to fetch and process alerts.
"""
import json
import logging
from datetime import datetime, timedelta

import requests
from requests.auth import HTTPBasicAuth

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)

# Mapping Wazuh rule levels to our severity
WAZUH_SEVERITY_MAP = {
    range(0, 4): 'low',
    range(4, 8): 'medium',
    range(8, 12): 'high',
    range(12, 16): 'critical',
}

# Major attack categories commonly seen in Tunisia
TUNISIA_MAJOR_ATTACK_RULES = {
    # Brute force attacks
    '5710', '5712', '5720', '5503', '5504',
    # Web attacks (SQL Injection, XSS, etc.)
    '31101', '31102', '31103', '31104', '31105', '31106',
    '31151', '31152', '31153', '31154', '31155',
    '31161', '31162', '31163', '31164', '31165',
    # Malware / Rootkit
    '510', '511', '512', '513', '514', '515', '516',
    # DDoS indicators
    '100100', '100101', '100102',
    # Ransomware indicators
    '87101', '87102', '87103', '87104',
    # Reconnaissance / Scanning
    '581', '582', '583', '584', '585',
    # Privilege escalation
    '5401', '5402', '5501', '5502',
    # Authentication failures
    '5501', '5502', '5503', '5551', '5552',
    # Shellshock, Log4j, and similar
    '31168', '31169', '31170', '31171',
    # File integrity monitoring
    '550', '551', '552', '553', '554',
    # Suspicious process execution
    '80700', '80701', '80702', '80710', '80711',
    # Phishing indicators
    '87200', '87201', '87202',
}

# Rule ID to Category mapping
RULE_CATEGORY_MAP = {
    '5710': 'brute_force', '5712': 'brute_force', '5720': 'brute_force',
    '5503': 'brute_force', '5504': 'brute_force',
    '31101': 'web_attack', '31102': 'sql_injection', '31103': 'xss',
    '31104': 'command_injection', '31105': 'web_attack', '31106': 'web_attack',
    '510': 'malware', '511': 'malware', '512': 'malware',
    '100100': 'ddos', '100101': 'ddos', '100102': 'ddos',
    '87101': 'ransomware', '87102': 'ransomware',
    '5401': 'privilege_escalation', '5402': 'privilege_escalation',
    '581': 'reconnaissance', '582': 'reconnaissance',
    '87200': 'phishing', '87201': 'phishing',
}


def get_severity_from_level(level):
    """Convert Wazuh rule level to our severity."""
    for level_range, severity in WAZUH_SEVERITY_MAP.items():
        if level in level_range:
            return severity
    return 'medium'


class SocWazuhConnector(models.Model):
    """
    Wazuh Connector Configuration and Management.
    Handles the connection to Wazuh Manager API and fetching alerts.
    """
    _name = 'soc.wazuh.connector'
    _description = 'Wazuh SIEM Connector'
    _rec_name = 'name'

    name = fields.Char(string='Connection Name', required=True, default='Wazuh Manager')
    
    # ── Connection Settings ───────────────────────────────────────────
    wazuh_host = fields.Char(
        string='Wazuh API Host',
        required=True,
        default='https://192.168.102.146',
        help='Wazuh Manager API host URL (e.g., https://192.168.102.146)',
    )
    wazuh_port = fields.Integer(
        string='Wazuh API Port',
        required=True,
        default=55000,
    )
    wazuh_user = fields.Char(
        string='API Username',
        required=True,
        default='wazuh-wui',
    )
    wazuh_password = fields.Char(
        string='API Password',
        required=True,
    )
    verify_ssl = fields.Boolean(
        string='Verify SSL',
        default=False,
        help='Whether to verify SSL certificates',
    )
    api_token = fields.Char(
        string='JWT Token',
        help='Current JWT authentication token',
    )
    token_expiry = fields.Datetime(string='Token Expiry')

    # ── Filtering Settings ────────────────────────────────────────────
    min_rule_level = fields.Integer(
        string='Minimum Rule Level',
        default=7,
        help='Only import alerts with rule level >= this value',
    )
    filter_tunisia_only = fields.Boolean(
        string='Filter Tunisia IPs Only',
        default=False,
        help='Only import alerts related to Tunisia IP ranges',
    )
    filter_major_attacks = fields.Boolean(
        string='Filter Major Attacks Only',
        default=False,
        help='Only import alerts matching major attack patterns in Tunisia',
    )
    fetch_interval_minutes = fields.Integer(
        string='Fetch Interval (minutes)',
        default=5,
    )
    last_fetch_time = fields.Datetime(string='Last Fetch Time')

    # ── Status ────────────────────────────────────────────────────────
    state = fields.Selection([
        ('disconnected', 'Disconnected'),
        ('connected', 'Connected'),
        ('error', 'Error'),
    ], string='Connection Status', default='disconnected')
    last_error = fields.Text(string='Last Error')
    total_alerts_fetched = fields.Integer(string='Total Alerts Fetched', default=0)

    active = fields.Boolean(default=True)

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  API Communication                                            ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def _get_base_url(self):
        """Get the Wazuh API base URL."""
        self.ensure_one()
        return f"{self.wazuh_host}:{self.wazuh_port}"

    def _authenticate(self):
        """Authenticate with the Wazuh API and get a JWT token."""
        self.ensure_one()
        url = f"{self._get_base_url()}/security/user/authenticate"
        try:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.wazuh_user, self.wazuh_password),
                verify=self.verify_ssl,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            token = data.get('data', {}).get('token', '')
            self.write({
                'api_token': token,
                'token_expiry': fields.Datetime.now() + timedelta(minutes=15),
                'state': 'connected',
                'last_error': False,
            })
            return token
        except requests.exceptions.RequestException as e:
            error_msg = f"Wazuh authentication failed: {str(e)}"
            _logger.error(error_msg)
            self.write({
                'state': 'error',
                'last_error': error_msg,
            })
            raise UserError(_(error_msg))

    def _get_headers(self):
        """Get the request headers with valid JWT token."""
        self.ensure_one()
        # Re-authenticate if token expired
        if not self.api_token or (
            self.token_expiry and fields.Datetime.now() >= self.token_expiry
        ):
            self._authenticate()
        return {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
        }

    def _api_request(self, method, endpoint, params=None, data=None):
        """Make an authenticated API request to Wazuh."""
        self.ensure_one()
        url = f"{self._get_base_url()}{endpoint}"
        headers = self._get_headers()
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=data,
                verify=self.verify_ssl,
                timeout=60,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            error_msg = f"Wazuh API request failed: {str(e)}"
            _logger.error(error_msg)
            self.write({'last_error': error_msg})
            raise UserError(_(error_msg))

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Actions                                                      ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def action_test_connection(self):
        """Test the connection to the Wazuh API."""
        self.ensure_one()
        try:
            self._authenticate()
            # Test with a simple API call
            result = self._api_request('GET', '/manager/info')
            if result:
                self.write({'state': 'connected', 'last_error': False})
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Success'),
                        'message': _('Successfully connected to Wazuh Manager!'),
                        'type': 'success',
                        'sticky': False,
                    },
                }
        except Exception as e:
            self.write({'state': 'error', 'last_error': str(e)})
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Connection Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                },
            }

    def action_fetch_alerts(self):
        """Manually trigger alert fetching."""
        self.ensure_one()
        count = self.fetch_alerts()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Alerts Fetched'),
                'message': _('%d new alerts imported from Wazuh.') % count,
                'type': 'success',
                'sticky': False,
            },
        }

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Alert Fetching & Processing                                  ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def fetch_alerts(self):
        """
        Fetch alerts from Wazuh Manager API.
        Applies filtering based on:
        - Minimum rule level
        - Tunisia IP ranges
        - Major attack categories
        Returns the count of new alerts imported.
        """
        self.ensure_one()
        alert_model = self.env['soc.alert']
        tunisia_ip_model = self.env['soc.tunisia.ip.range']
        count = 0

        try:
            # Build query parameters
            params = {
                'limit': 500,
                'sort': '-timestamp',
                'q': f'rule.level>={self.min_rule_level}',
            }

            # Add time filter if we have a last fetch time
            if self.last_fetch_time:
                params['q'] += f';timestamp>{self.last_fetch_time.isoformat()}'

            # Fetch alerts from Wazuh
            result = self._api_request('GET', '/alerts', params=params)
            alerts_data = result.get('data', {}).get('affected_items', [])

            for alert_data in alerts_data:
                try:
                    processed = self._process_wazuh_alert(alert_data, tunisia_ip_model)
                    if processed:
                        alert_model.sudo().create(processed)
                        count += 1
                except Exception as e:
                    _logger.warning(
                        "Error processing Wazuh alert: %s",
                        str(e),
                    )
                    continue

            self.write({
                'last_fetch_time': fields.Datetime.now(),
                'total_alerts_fetched': self.total_alerts_fetched + count,
                'last_error': False,
            })
            _logger.info("Fetched %d alerts from Wazuh", count)

        except Exception as e:
            _logger.error("Failed to fetch Wazuh alerts: %s", str(e))
            self.write({'last_error': str(e)})

        return count

    def _process_wazuh_alert(self, alert_data, tunisia_ip_model):
        """
        Process a single Wazuh alert and determine if it should be imported.
        Returns the prepared values dict or None if filtered out.
        """
        rule = alert_data.get('rule', {})
        rule_id = str(rule.get('id', ''))
        rule_level = rule.get('level', 0)
        agent = alert_data.get('agent', {})

        # Extract network data
        data = alert_data.get('data', {})
        source_ip = (
            data.get('srcip')
            or data.get('src_ip')
            or alert_data.get('data', {}).get('srcip')
        )
        dest_ip = (
            data.get('dstip')
            or data.get('dst_ip')
            or alert_data.get('data', {}).get('dstip')
        )
        src_port = data.get('srcport', 0)
        dst_port = data.get('dstport', 0)
        protocol = data.get('protocol', '')

        # ── Filter: Major attacks only ─────────────────────────────
        if self.filter_major_attacks:
            if rule_id not in TUNISIA_MAJOR_ATTACK_RULES and rule_level < 10:
                return None

        # ── Filter: Tunisia IPs only ──────────────────────────────
        if self.filter_tunisia_only:
            is_tn_src = tunisia_ip_model.is_tunisia_ip(source_ip) if source_ip else False
            is_tn_dst = tunisia_ip_model.is_tunisia_ip(dest_ip) if dest_ip else False
            # Allow if either source or destination is in Tunisia,
            # OR if rule level is critical (>= 12)
            if not (is_tn_src or is_tn_dst) and rule_level < 12:
                return None

        # Determine severity
        severity = get_severity_from_level(rule_level)

        # Determine category
        category = RULE_CATEGORY_MAP.get(rule_id, 'suspicious_activity')

        # Map to MITRE ATT&CK if possible
        mitre_ids = rule.get('mitre', {}).get('id', [])
        mitre_tactics = rule.get('mitre', {}).get('tactic', [])

        # Build values
        vals = {
            'title': rule.get('description', f'Wazuh Alert - Rule {rule_id}'),
            'description': rule.get('description', ''),
            'raw_log': json.dumps(alert_data, indent=2),
            'source': 'wazuh',
            'wazuh_rule_id': rule_id,
            'wazuh_rule_description': rule.get('description', ''),
            'wazuh_agent_id': agent.get('id', ''),
            'wazuh_agent_name': agent.get('name', ''),
            'wazuh_full_log': alert_data.get('full_log', ''),
            'source_ip': source_ip or '',
            'destination_ip': dest_ip or '',
            'source_port': int(src_port) if src_port else 0,
            'destination_port': int(dst_port) if dst_port else 0,
            'protocol': protocol,
            'severity': severity,
            'severity_level': rule_level,
            'category': category,
            'timestamp': alert_data.get('timestamp', fields.Datetime.now()),
            'state': 'new',
        }

        return vals

    @api.model
    def fetch_alerts_cron(self):
        """Cron job to fetch alerts from all active connectors."""
        connectors = self.search([
            ('active', '=', True),
            ('state', 'in', ['connected', 'disconnected']),
        ])
        for connector in connectors:
            try:
                connector.fetch_alerts()
            except Exception as e:
                _logger.error(
                    "Cron: Failed to fetch from connector %s: %s",
                    connector.name, str(e),
                )
