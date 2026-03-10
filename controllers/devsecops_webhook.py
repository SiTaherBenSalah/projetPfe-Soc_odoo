# -*- coding: utf-8 -*-
"""
DevSecOps Webhook Controller
Receives scan results from Jenkins CI/CD pipelines.
"""
import json
import logging

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class DevSecOpsWebhookController(http.Controller):
    """Receive DevSecOps scan results from Jenkins/CI pipelines."""

    @http.route(
        '/soc/devsecops/webhook',
        type='json',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def devsecops_webhook(self, **kwargs):
        """
        Receive scan results from Jenkins pipeline.
        Expected payload:
        {
            "scan_id": "SCAN-2026-00001",
            "status": "completed",
            "build_number": 42,
            "job_url": "http://jenkins:8080/job/devsecops/42",
            "findings": [...]  // Optional: inline findings
        }
        """
        try:
            data = request.jsonrequest
            scan_id = data.get('scan_id')
            status = data.get('status', 'completed')

            if not scan_id:
                return {'status': 'error', 'message': 'scan_id is required'}

            scan = request.env['soc.devsecops.scan'].sudo().search([
                ('name', '=', scan_id)
            ], limit=1)

            if not scan:
                return {'status': 'error', 'message': f'Scan {scan_id} not found'}

            # Update scan with Jenkins info
            update_vals = {
                'jenkins_build_number': data.get('build_number', 0),
                'jenkins_job_url': data.get('job_url', ''),
                'jenkins_triggered': True,
            }

            if status == 'completed':
                update_vals['state'] = 'completed'
                update_vals['completed_at'] = request.env['soc.devsecops.scan']._fields['completed_at'].now()
            elif status == 'failed':
                update_vals['state'] = 'failed'

            scan.write(update_vals)

            # Process inline findings if provided
            inline_findings = data.get('findings', [])
            for f in inline_findings:
                request.env['soc.devsecops.finding'].sudo().create({
                    'scan_id': scan.id,
                    'title': f.get('title', 'Unknown'),
                    'description': f.get('description', ''),
                    'scanner': f.get('scanner', 'trivy'),
                    'severity': f.get('severity', 'medium'),
                    'vulnerability_id': f.get('vulnerability_id', ''),
                    'cvss_score': f.get('cvss_score', 0),
                    'affected_component': f.get('affected_component', ''),
                    'file_path': f.get('file_path', ''),
                    'category': f.get('category', 'vulnerability'),
                    'remediation': f.get('remediation', ''),
                })

            _logger.info("DevSecOps webhook: Scan %s status=%s, %d inline findings",
                         scan_id, status, len(inline_findings))

            return {
                'status': 'success',
                'scan_id': scan_id,
                'findings_count': len(inline_findings),
            }

        except Exception as e:
            _logger.error("DevSecOps webhook error: %s", str(e))
            return {'status': 'error', 'message': str(e)}

    @http.route(
        '/soc/devsecops/upload-report',
        type='http',
        auth='user',
        methods=['POST'],
        csrf=False,
    )
    def upload_scan_report(self, **kwargs):
        """
        Upload a scan report file (JSON) for processing.
        Supports Trivy, OWASP DC, Bandit, Semgrep, Checkov report formats.
        """
        try:
            scan_id = kwargs.get('scan_id')
            scanner = kwargs.get('scanner', 'trivy')
            report_file = kwargs.get('report_file')

            if not scan_id or not report_file:
                return request.make_response(
                    json.dumps({'error': 'scan_id and report_file are required'}),
                    headers=[('Content-Type', 'application/json')],
                )

            scan = request.env['soc.devsecops.scan'].search([
                ('name', '=', scan_id)
            ], limit=1)

            if not scan:
                return request.make_response(
                    json.dumps({'error': f'Scan {scan_id} not found'}),
                    headers=[('Content-Type', 'application/json')],
                )

            # Store raw report
            report_content = report_file.read().decode('utf-8')
            scan.write({'raw_output': report_content})

            return request.make_response(
                json.dumps({'status': 'success', 'scan_id': scan_id}),
                headers=[('Content-Type', 'application/json')],
            )

        except Exception as e:
            return request.make_response(
                json.dumps({'error': str(e)}),
                headers=[('Content-Type', 'application/json')],
            )
