# -*- coding: utf-8 -*-
"""
SOC Dashboard - Provides computed data for the dashboard view.
"""
import logging
from datetime import timedelta
from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SocDashboard(models.Model):
    """Virtual model for SOC Dashboard data aggregation."""
    _name = 'soc.dashboard'
    _description = 'SOC Dashboard'

    name = fields.Char(default='SOC Dashboard')

    @api.model
    def get_dashboard_data(self):
        """
        Aggregate all dashboard KPIs and chart data.
        This method is called by the JavaScript dashboard client action.
        """
        alert_model = self.env['soc.alert']
        incident_model = self.env['soc.incident']

        now = fields.Datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)

        # ── Alert KPIs ──────────────────────────────────────────────
        total_alerts = alert_model.search_count([])
        alerts_today = alert_model.search_count([
            ('timestamp', '>=', today_start),
        ])
        alerts_this_week = alert_model.search_count([
            ('timestamp', '>=', week_ago),
        ])
        new_alerts = alert_model.search_count([
            ('state', '=', 'new'),
        ])
        confirmed_alerts = alert_model.search_count([
            ('state', '=', 'confirmed'),
        ])
        false_positives = alert_model.search_count([
            ('state', '=', 'false_positive'),
        ])
        escalated_alerts = alert_model.search_count([
            ('state', '=', 'escalated'),
        ])
        tunisia_alerts = alert_model.search_count([
            ('is_tunisia_relevant', '=', True),
            ('state', 'not in', ['false_positive', 'closed']),
        ])

        # ── Alert Severity Distribution ──────────────────────────────
        severity_data = {}
        for sev in ['low', 'medium', 'high', 'critical']:
            severity_data[sev] = alert_model.search_count([
                ('severity', '=', sev),
                ('state', 'not in', ['false_positive', 'closed']),
            ])

        # ── Alert Category Distribution ──────────────────────────────
        category_data = []
        categories = [
            ('brute_force', 'Brute Force'),
            ('malware', 'Malware'),
            ('phishing', 'Phishing'),
            ('ddos', 'DDoS'),
            ('web_attack', 'Web Attack'),
            ('sql_injection', 'SQL Injection'),
            ('ransomware', 'Ransomware'),
            ('reconnaissance', 'Reconnaissance'),
            ('privilege_escalation', 'Privilege Escalation'),
            ('data_exfiltration', 'Data Exfiltration'),
            ('apt', 'APT'),
        ]
        for cat_key, cat_label in categories:
            count = alert_model.search_count([
                ('category', '=', cat_key),
                ('state', 'not in', ['false_positive', 'closed']),
            ])
            if count > 0:
                category_data.append({'label': cat_label, 'count': count})
        category_data.sort(key=lambda x: x['count'], reverse=True)

        # ── Alerts by Day (last 7 days) ──────────────────────────────
        daily_alerts = []
        for i in range(7):
            day = now - timedelta(days=6 - i)
            day_start = day.replace(hour=0, minute=0, second=0)
            day_end = day.replace(hour=23, minute=59, second=59)
            count = alert_model.search_count([
                ('timestamp', '>=', day_start),
                ('timestamp', '<=', day_end),
            ])
            daily_alerts.append({
                'date': day_start.strftime('%Y-%m-%d'),
                'day': day_start.strftime('%a'),
                'count': count,
            })

        # ── Incident KPIs ────────────────────────────────────────────
        total_incidents = incident_model.search_count([])
        open_incidents = incident_model.search_count([
            ('state', 'not in', ['closed', 'post_incident']),
        ])
        critical_incidents = incident_model.search_count([
            ('severity', '=', 'critical'),
            ('state', 'not in', ['closed']),
        ])

        # ── Incident Status Distribution ──────────────────────────────
        incident_status_data = {}
        for status in ['new', 'triage', 'investigation', 'containment',
                       'eradication', 'recovery', 'post_incident', 'closed']:
            incident_status_data[status] = incident_model.search_count([
                ('state', '=', status),
            ])

        # ── Top Source IPs ──────────────────────────────────────────
        top_source_ips = []
        self.env.cr.execute("""
            SELECT source_ip, COUNT(*) as cnt
            FROM soc_alert
            WHERE source_ip IS NOT NULL
              AND source_ip != ''
              AND state NOT IN ('false_positive', 'closed')
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 10
        """)
        for row in self.env.cr.fetchall():
            top_source_ips.append({
                'ip': row[0],
                'count': row[1],
            })

        # ── Recent Critical Alerts ────────────────────────────────────
        recent_critical = alert_model.search([
            ('severity', 'in', ['high', 'critical']),
            ('state', 'not in', ['false_positive', 'closed']),
        ], limit=10, order='timestamp desc')

        recent_critical_data = [{
            'id': a.id,
            'name': a.name,
            'title': a.title,
            'severity': a.severity,
            'category': a.category or 'N/A',
            'source_ip': a.source_ip or 'N/A',
            'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M') if a.timestamp else '',
            'state': a.state,
        } for a in recent_critical]

        # ── AI Agent Stats ────────────────────────────────────────────
        ai_agent = self.env['soc.ai.agent'].search([], limit=1)
        ai_stats = {}
        if ai_agent:
            ai_stats = {
                'total_analyses': ai_agent.total_analyses,
                'false_positives_detected': ai_agent.false_positives_detected,
            }

        # ── False Positive Rate ───────────────────────────────────────
        fp_rate = 0
        if total_alerts > 0:
            fp_rate = round((false_positives / total_alerts) * 100, 1)

        # ── MTTR (Mean Time to Resolve) ──────────────────────────────
        self.env.cr.execute("""
            SELECT AVG(time_to_resolve)
            FROM soc_incident
            WHERE time_to_resolve > 0
              AND closed_date IS NOT NULL
        """)
        result = self.env.cr.fetchone()
        mttr = round(result[0], 1) if result and result[0] else 0

        # ── OpenCTI Data (placeholder until pycti integration) ────────
        opencti_data = {
            'status': 'not_configured',
            'total_indicators': 0,
            'total_reports': 0,
            'recent_indicators': [],
            'recent_reports': [],
        }

        # Try to get real OpenCTI data if configured
        try:
            opencti_config = self.env['ir.config_parameter'].sudo()
            opencti_url = opencti_config.get_param('soc.opencti_url', '')
            opencti_token = opencti_config.get_param('soc.opencti_token', '')
            if opencti_url and opencti_token:
                opencti_data['status'] = 'configured'
                opencti_data['url'] = opencti_url
        except Exception as e:
            _logger.warning("OpenCTI config check failed: %s", e)

        return {
            # Alert KPIs
            'total_alerts': total_alerts,
            'alerts_today': alerts_today,
            'alerts_this_week': alerts_this_week,
            'new_alerts': new_alerts,
            'confirmed_alerts': confirmed_alerts,
            'false_positives': false_positives,
            'escalated_alerts': escalated_alerts,
            'tunisia_alerts': tunisia_alerts,
            'fp_rate': fp_rate,
            # Charts
            'severity_data': severity_data,
            'category_data': category_data,
            'daily_alerts': daily_alerts,
            # Incidents
            'total_incidents': total_incidents,
            'open_incidents': open_incidents,
            'critical_incidents': critical_incidents,
            'incident_status_data': incident_status_data,
            # Tables
            'top_source_ips': top_source_ips,
            'recent_critical': recent_critical_data,
            # AI
            'ai_stats': ai_stats,
            'mttr': mttr,
            # OpenCTI
            'opencti_data': opencti_data,
        }
