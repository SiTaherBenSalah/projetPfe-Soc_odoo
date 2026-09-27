from odoo import http
from odoo.http import request
import json

class SOCWebhookController(http.Controller):
    @http.route('/api/soc/alert', type='json', auth='none', methods=['POST'], csrf=False)
    def receive_alert(self, **kw):
        # استلام البيانات القادمة من Shuffle كـ JSON
        data = request.jsonrequest

        # إنشاء التذكرة أو التنبيه في موديل الأنشطة/الحوادث
        ticket = request.env['soc.incident'].sudo().create({
            'name': data.get('rule_description', 'Alert from Wazuh'),
            'agent_name': data.get('agent_name'),
            'severity': data.get('level'),
            'payload': json.dumps(data),
        })

        return {'status': 'success', 'ticket_id': ticket.id}
