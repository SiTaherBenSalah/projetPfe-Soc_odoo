# -*- coding: utf-8 -*-
"""
Wazuh Webhook Controller
Receives real-time alerts from Wazuh via webhook integration.
Configure Wazuh to send alerts to: POST /soc/wazuh/webhook
"""
import json
import logging
import hmac
import hashlib

from odoo import http
from odoo.http import request
from . import wazuh_filters

_logger = logging.getLogger(__name__)


class WazuhWebhookController(http.Controller):
    """
    HTTP Controller to receive Wazuh alerts via webhook.
    
    Wazuh Integration Setup:
    1. In Wazuh, configure an integration in ossec.conf:
       <integration>
         <name>custom-odoo</name>
         <hook_url>http://your-odoo-server:8069/soc/wazuh/webhook</hook_url>
         <level>7</level>
         <alert_format>json</alert_format>
       </integration>
    
    2. Create a custom integration script that sends alerts via HTTP POST.
    """

    @http.route(
        '/soc/wazuh/webhook',
        type='json',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def wazuh_webhook(self, **kwargs):
        """
        Receive alerts from Wazuh SIEM via webhook.
        Expects JSON payload with Wazuh alert data.
        """
        try:
            data = request.jsonrequest
            if not data:
                return {'status': 'error', 'message': 'No data received'}

            _logger.info("Received Wazuh webhook alert")

            # Extract alert data
            alert_data = data
            rule = alert_data.get('rule', {})
            agent = alert_data.get('agent', {})
            net_data = alert_data.get('data', {})

            rule_id = str(rule.get('id', ''))
            rule_level = rule.get('level', 0)

            # Get Tunisia IP checker
            tunisia_ip = request.env['soc.tunisia.ip.range'].sudo()

            # Apply python file criteria filters
            if not wazuh_filters.apply_filters(alert_data):
                _logger.info("Alert filtered out by wazuh_filters.py criteria.")
                return {'status': 'success', 'message': 'Alert filtered out due to custom criteria'}
                 
            source_ip = (
                net_data.get('srcip')
                or net_data.get('src_ip', '')
            )
            dest_ip = (
                net_data.get('dstip')
                or net_data.get('dst_ip', '')
            )

            # Determine severity
            if rule_level >= 12:
                severity = 'critical'
            elif rule_level >= 8:
                severity = 'high'
            elif rule_level >= 4:
                severity = 'medium'
            else:
                severity = 'low'

            # Map rule to category (simplified)
            category = 'suspicious_activity'
            rule_groups = rule.get('groups', [])
            if 'authentication_failed' in rule_groups:
                category = 'authentication_failure'
            elif 'web' in rule_groups or 'attack' in rule_groups:
                category = 'web_attack'
            elif 'syscheck' in rule_groups:
                category = 'suspicious_activity'
            elif 'rootcheck' in rule_groups:
                category = 'malware'

            # Create alert in Odoo
            alert_vals = {
                'title': rule.get('description', f'Wazuh Alert #{rule_id}'),
                'description': rule.get('description', ''),
                'raw_log': json.dumps(alert_data, indent=2),
                'source': 'wazuh',
                'wazuh_rule_id': rule_id,
                'wazuh_rule_description': rule.get('description', ''),
                'wazuh_agent_id': agent.get('id', ''),
                'wazuh_agent_name': agent.get('name', ''),
                'wazuh_full_log': alert_data.get('full_log', ''),
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'source_port': int(net_data.get('srcport', 0) or 0),
                'destination_port': int(net_data.get('dstport', 0) or 0),
                'protocol': net_data.get('protocol', ''),
                'severity': severity,
                'severity_level': rule_level,
                'category': category,
                'state': 'new',
            }

            alert = request.env['soc.alert'].sudo().create(alert_vals)
            _logger.info("Created alert %s from Wazuh webhook", alert.name)

            return {
                'status': 'success',
                'alert_id': alert.name,
                'message': f'Alert {alert.name} created successfully',
            }

        except Exception as e:
            _logger.error("Wazuh webhook error: %s", str(e))
            return {
                'status': 'error',
                'message': str(e),
            }

    @http.route(
        '/soc/wazuh/webhook/health',
        type='http',
        auth='public',
        methods=['GET'],
        csrf=False,
    )
    def wazuh_webhook_health(self, **kwargs):
        """Health check endpoint for the Wazuh webhook."""
        return request.make_response(
            json.dumps({
                'status': 'ok',
                'service': 'SOC Management - Wazuh Webhook',
            }),
            headers=[('Content-Type', 'application/json')],
        )

    @http.route(
        '/soc/api/dashboard',
        type='json',
        auth='user',
        methods=['POST'],
    )
    def get_dashboard_data(self, **kwargs):
        """API endpoint for dashboard data (used by the JS dashboard)."""
        dashboard = request.env['soc.dashboard'].sudo()
        return dashboard.get_dashboard_data()

    @http.route(
        '/soc/api/layer_alerts',
        type='json',
        auth='user',
        methods=['POST'],
    )
    def get_layer_alerts(self, layer=None, **kwargs):
        """API endpoint for layer-specific alerts (interactive architecture).
        
        Returns alerts relevant to the specified architecture layer:
        - Layer 1 (Detection): Recent Wazuh/detection source alerts
        - Layer 2 (Threat Intel): OpenCTI IOC indicators (handled client-side)
        - Layer 3 (IA & Analysis): AI-analyzed alerts
        - Layer 4 (SOAR): Automated response info (handled client-side)
        - Layer 5 (Dashboard): Escalated alerts
        """
        dashboard = request.env['soc.dashboard'].sudo()
        return dashboard.get_layer_alerts(layer)
