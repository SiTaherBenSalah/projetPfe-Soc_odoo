# -*- coding: utf-8 -*-
"""
AI Agent for SOC Threat Intelligence
Uses Ollama (open-source LLM) and open-source threat intel APIs for:
- Alert analysis and classification
- False positive detection
- IOC enrichment via AbuseIPDB, OTX AlienVault, VirusTotal
- Tunisia-specific threat assessment
"""
import json
import logging
import re

import requests
from OTXv2 import OTXv2, IndicatorTypes

from odoo import models, fields, api, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class SocAiAgent(models.Model):
    """
    AI-powered Threat Intelligence Agent.
    Uses open-source tools:
    - Ollama for local LLM inference (Mistral, Llama, etc.)
    - AbuseIPDB API for IP reputation
    - OTX AlienVault for threat intel
    - VirusTotal API for malware analysis
    """
    _name = 'soc.ai.agent'
    _description = 'SOC AI Threat Intelligence Agent'

    name = fields.Char(string='Agent Name', default='SOC AI Agent')

    # ── LLM Configuration ─────────────────────────────────────────────
    ollama_host = fields.Char(
        string='Ollama Host',
        default='http://localhost:11434',
        help='Ollama API endpoint for local LLM inference',
    )
    ollama_model = fields.Char(
        string='LLM Model',
        default='mistral',
        help='Ollama model to use (mistral, llama2, codellama, etc.)',
    )

    # ── API Keys for Open-Source Threat Intel ──────────────────────────
    abuseipdb_api_key = fields.Char(
        string='AbuseIPDB API Key',
        default='998e25bbefb8a0ec63ca1e982e44778b36625b707cd37724cdbd4b967c2718c28f5d7b0fc02733ce',
        help='Free API key from abuseipdb.com',
    )
    otx_api_key = fields.Char(
        string='OTX AlienVault API Key',
        help='Free API key from otx.alienvault.com',
    )
    virustotal_api_key = fields.Char(
        string='VirusTotal API Key',
        help='Free API key from virustotal.com',
    )

    # ── Statistics ────────────────────────────────────────────────────
    total_analyses = fields.Integer(string='Total Analyses', default=0)
    false_positives_detected = fields.Integer(string='False Positives Detected', default=0)
    active = fields.Boolean(default=True)

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  LLM Communication (Ollama)                                   ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def _query_ollama(self, prompt, system_prompt=None):
        """
        Query the local Ollama LLM for threat analysis.
        Uses the Ollama REST API (open-source, runs locally).
        """
        config = self.search([], limit=1)
        if not config:
            _logger.warning("No AI agent configured")
            return None

        url = f"{config.ollama_host}/api/generate"
        payload = {
            'model': config.ollama_model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.1,  # Low temperature for deterministic analysis
                'num_predict': 2048,
            },
        }
        if system_prompt:
            payload['system'] = system_prompt

        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
        except requests.exceptions.ConnectionError:
            _logger.warning("Ollama is not running at %s", config.ollama_host)
            return None
        except Exception as e:
            _logger.error("Ollama query failed: %s", str(e))
            return None

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Threat Intelligence APIs (Open-Source)                       ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def _check_abuseipdb(self, ip_address):
        """Check IP reputation using AbuseIPDB (free tier: 1000 checks/day)."""
        config = self.search([], limit=1)
        if not config or not config.abuseipdb_api_key:
            return None

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': config.abuseipdb_api_key,
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True,
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json().get('data', {})
            return {
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode', ''),
                'isp': data.get('isp', ''),
                'usage_type': data.get('usageType', ''),
                'is_whitelisted': data.get('isWhitelisted', False),
                'domain': data.get('domain', ''),
                'last_reported': data.get('lastReportedAt', ''),
            }
        except Exception as e:
            _logger.warning("AbuseIPDB check failed for %s: %s", ip_address, str(e))
            return None

    def _check_otx(self, indicator, indicator_type=IndicatorTypes.IPv4):
        """
        Check indicator using OTXv2 Python SDK.
        indicator_type: IndicatorTypes.IPv4, IndicatorTypes.DOMAIN, etc.
        """
        config = self.search([], limit=1)
        if not config or not config.otx_api_key:
            return None

        try:
            otx = OTXv2(config.otx_api_key)
            result = otx.get_indicator_details_full(indicator_type, indicator)
            
            general = result.get('general', {})
            return {
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'reputation': general.get('reputation', 0),
                'country': general.get('country_code', ''),
                'validation': general.get('validation', []),
                'pulses': [
                    {
                        'name': p.get('name', ''),
                        'description': p.get('description', ''),
                        'tags': p.get('tags', []),
                    }
                    for p in general.get('pulse_info', {}).get('pulses', [])[:5]
                ],
            }
        except Exception as e:
            _logger.warning("OTX SDK check failed for %s: %s", indicator, str(e))
            return None

    def _check_virustotal(self, indicator, indicator_type='ip-address'):
        """
        Check indicator using VirusTotal API (vt-py) (free tier: 4 requests/min).
        indicator_type: ip_addresses, domains, urls, files
        """
        config = self.search([], limit=1)
        if not config or not config.virustotal_api_key:
            return None

        # Map generic indicators to vt-py specific paths
        path_map = {
            'ip-address': 'ip_addresses',
            'ip_address': 'ip_addresses',
            'ip_addresses': 'ip_addresses',
            'ip': 'ip_addresses',
            'domain': 'domains',
            'domains': 'domains',
            'url': 'urls',
            'urls': 'urls',
            'file': 'files',
            'files': 'files',
            'hash': 'files',
        }
        api_path = path_map.get(indicator_type, indicator_type)

        try:
            import vt
        except ImportError:
            _logger.warning("vt-py library not installed. Please run: pip install vt-py")
            return None

        try:
            client = vt.Client(config.virustotal_api_key)
            try:
                # url_id needs to be generated for urls
                if api_path == 'urls':
                    indicator = vt.url_id(indicator)
                
                # Fetch the object using vt-py
                obj = client.get_object(f"/{api_path}/{indicator}")
                
                stats = obj.last_analysis_stats
                
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': getattr(obj, 'reputation', 0),
                    'country': getattr(obj, 'country', ''),
                    'as_owner': getattr(obj, 'as_owner', ''),
                }
            finally:
                client.close()
        except Exception as e:
            _logger.warning("VirusTotal (vt-py) check failed for %s: %s", indicator, str(e))
            return None

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Alert Analysis                                               ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def analyze_alert(self, alert):
        """
        Comprehensive AI analysis of a security alert.
        Combines:
        1. Threat intelligence from open-source APIs
        2. LLM analysis for context and false positive detection
        3. Tunisia-specific threat assessment
        """
        threat_intel_data = {}

        # ── Step 1: Gather threat intelligence ─────────────────────
        if alert.source_ip:
            abuseipdb_result = self._check_abuseipdb(alert.source_ip)
            if abuseipdb_result:
                threat_intel_data['abuseipdb_src'] = abuseipdb_result

            otx_result = self._check_otx(alert.source_ip)
            if otx_result:
                threat_intel_data['otx_src'] = otx_result

            vt_result = self._check_virustotal(alert.source_ip)
            if vt_result:
                threat_intel_data['virustotal_src'] = vt_result

        if alert.destination_ip:
            abuseipdb_result = self._check_abuseipdb(alert.destination_ip)
            if abuseipdb_result:
                threat_intel_data['abuseipdb_dst'] = abuseipdb_result

        # Store threat intel results
        if threat_intel_data:
            self._store_threat_intel(alert, threat_intel_data)

        # ── Step 2: AI/LLM Analysis ───────────────────────────────
        system_prompt = """You are an expert SOC analyst specializing in cybersecurity threats 
in Tunisia and North Africa. Your task is to analyze security alerts and determine:
1. Whether the alert is a TRUE THREAT or a FALSE POSITIVE
2. The severity level (low, medium, high, critical)
3. The type of attack (if applicable)
4. Recommended response actions
5. Relevance to the Tunisia threat landscape

Tunisia is commonly targeted by:
- Brute force attacks against government and banking servers
- Phishing campaigns targeting Tunisian organizations
- DDoS attacks against critical infrastructure
- Web application attacks (SQL injection, XSS) on e-commerce and e-gov sites
- Ransomware targeting healthcare and education sectors
- APT groups interested in North African geopolitics

Respond ONLY in valid JSON format with these fields:
{
    "is_false_positive": true/false,
    "confidence_score": 0-100,
    "severity": "low/medium/high/critical",
    "attack_type": "string",
    "analysis": "detailed analysis text",
    "recommended_action": "what to do",
    "tunisia_relevance_score": 0-100,
    "false_positive_reason": "reason if false positive, otherwise null"
}"""

        alert_context = f"""
Alert Title: {alert.title}
Alert Description: {alert.description or 'N/A'}
Source IP: {alert.source_ip or 'N/A'}
Destination IP: {alert.destination_ip or 'N/A'}
Source Port: {alert.source_port or 'N/A'} 
Destination Port: {alert.destination_port or 'N/A'}
Protocol: {alert.protocol or 'N/A'}
Wazuh Rule ID: {alert.wazuh_rule_id or 'N/A'}
Wazuh Rule Level: {alert.severity_level or 'N/A'}
Wazuh Rule Description: {alert.wazuh_rule_description or 'N/A'}
Category: {alert.category or 'N/A'}
Raw Log (truncated): {(alert.raw_log or '')[:2000]}

Threat Intelligence Data:
{json.dumps(threat_intel_data, indent=2, default=str)[:3000]}

Analyze this alert and provide your assessment."""

        llm_response = self._query_ollama(alert_context, system_prompt)

        if llm_response:
            try:
                # Try to extract JSON from the response
                json_match = re.search(r'\{[\s\S]*\}', llm_response)
                if json_match:
                    analysis = json.loads(json_match.group())
                else:
                    analysis = {
                        'is_false_positive': False,
                        'confidence_score': 50,
                        'analysis': llm_response,
                        'recommended_action': 'Manual review required',
                        'tunisia_relevance_score': 50,
                    }
            except json.JSONDecodeError:
                analysis = {
                    'is_false_positive': False,
                    'confidence_score': 50,
                    'analysis': llm_response,
                    'recommended_action': 'Manual review required',
                    'tunisia_relevance_score': 50,
                }
        else:
            # Fallback: heuristic-based analysis when LLM is unavailable
            analysis = self._heuristic_analysis(alert, threat_intel_data)

        # ── Step 3: Update alert with analysis results ─────────────
        update_vals = {
            'ai_analysis': analysis.get('analysis', ''),
            'ai_confidence_score': analysis.get('confidence_score', 50),
            'ai_is_false_positive': analysis.get('is_false_positive', False),
            'ai_recommended_action': analysis.get('recommended_action', ''),
            'tunisia_relevance_score': analysis.get('tunisia_relevance_score', 50),
        }

        # Auto-mark as false positive if AI is very confident
        if analysis.get('is_false_positive') and analysis.get('confidence_score', 0) >= 85:
            update_vals['state'] = 'false_positive'
            update_vals['false_positive_reason'] = analysis.get(
                'false_positive_reason',
                'AI detected as false positive with high confidence',
            )
            config = self.search([], limit=1)
            if config:
                config.sudo().write({
                    'false_positives_detected': config.false_positives_detected + 1,
                })

        alert.sudo().write(update_vals)

        # Update statistics
        config = self.search([], limit=1)
        if config:
            config.sudo().write({
                'total_analyses': config.total_analyses + 1,
            })

        return analysis

    def _heuristic_analysis(self, alert, threat_intel_data):
        """
        Fallback heuristic analysis when LLM is unavailable.
        Uses threat intelligence data and rule-based logic.
        """
        is_false_positive = False
        confidence = 50
        analysis_parts = []
        tunisia_score = 50

        # Check AbuseIPDB data
        abuse_src = threat_intel_data.get('abuseipdb_src', {})
        if abuse_src:
            abuse_score = abuse_src.get('abuse_confidence_score', 0)
            if abuse_score > 80:
                analysis_parts.append(
                    f"Source IP has high abuse score ({abuse_score}%) on AbuseIPDB "
                    f"with {abuse_src.get('total_reports', 0)} reports."
                )
                confidence = max(confidence, 80)
            elif abuse_score == 0 and abuse_src.get('is_whitelisted'):
                analysis_parts.append("Source IP is whitelisted on AbuseIPDB.")
                is_false_positive = True
                confidence = 70

            # Check if source is from Tunisia
            if abuse_src.get('country_code') == 'TN':
                tunisia_score = min(tunisia_score + 30, 100)
                analysis_parts.append("Source IP is from Tunisia.")

        # Check OTX data
        otx_src = threat_intel_data.get('otx_src', {})
        if otx_src:
            pulse_count = otx_src.get('pulse_count', 0)
            if pulse_count > 0:
                analysis_parts.append(
                    f"Source IP found in {pulse_count} OTX threat pulses."
                )
                confidence = max(confidence, 75)
            else:
                analysis_parts.append("Source IP not found in OTX threat pulses.")

        # Check VirusTotal data
        vt_src = threat_intel_data.get('virustotal_src', {})
        if vt_src:
            malicious = vt_src.get('malicious', 0)
            if malicious > 5:
                analysis_parts.append(
                    f"VirusTotal: {malicious} engines flagged source IP as malicious."
                )
                confidence = max(confidence, 85)
            elif malicious == 0:
                analysis_parts.append("VirusTotal: No engines flagged source IP.")

        # Rule-level based assessment
        if alert.severity_level and alert.severity_level >= 12:
            analysis_parts.append(
                f"High Wazuh rule level ({alert.severity_level}) indicates serious threat."
            )
            confidence = max(confidence, 75)
            tunisia_score = min(tunisia_score + 20, 100)
        elif alert.severity_level and alert.severity_level <= 4:
            analysis_parts.append(
                f"Low Wazuh rule level ({alert.severity_level})."
            )
            if not threat_intel_data:
                is_false_positive = True
                confidence = 60

        # Check Tunisia IP
        if alert.is_tunisia_ip:
            tunisia_score = min(tunisia_score + 30, 100)

        if not analysis_parts:
            analysis_parts.append("Insufficient data for automated analysis. Manual review recommended.")

        return {
            'is_false_positive': is_false_positive,
            'confidence_score': confidence,
            'analysis': '\n'.join(analysis_parts),
            'recommended_action': 'Escalate to incident' if not is_false_positive and confidence >= 70
                                  else 'Monitor and review',
            'tunisia_relevance_score': tunisia_score,
            'false_positive_reason': 'Low threat indicators from threat intelligence sources'
                                     if is_false_positive else None,
        }

    def _store_threat_intel(self, alert, threat_data):
        """Store threat intelligence results linked to the alert."""
        threat_model = self.env['soc.threat.intel']
        for source, data in threat_data.items():
            threat_model.sudo().create({
                'alert_id': alert.id,
                'source': source.split('_')[0],  # abuseipdb, otx, virustotal
                'indicator': alert.source_ip if 'src' in source else alert.destination_ip,
                'indicator_type': 'ip',
                'raw_data': json.dumps(data, indent=2, default=str),
                'confidence_score': data.get('abuse_confidence_score',
                                   data.get('reputation',
                                   data.get('malicious', 0))),
            })

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Incident Analysis                                            ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def analyze_incident(self, incident):
        """AI analysis of a security incident with response recommendations."""
        system_prompt = """You are an expert SOC incident responder specializing in 
cybersecurity incidents in Tunisia and North Africa. Analyze the incident and provide:
1. Threat assessment
2. Recommended containment strategy
3. Eradication steps
4. Recovery plan
5. Lessons learned

Respond in JSON:
{
    "analysis": "detailed threat assessment",
    "containment_strategy": "containment steps",
    "eradication_steps": "eradication steps",
    "recovery_plan": "recovery steps",
    "severity_recommendation": "low/medium/high/critical",
    "lessons": "lessons learned"
}"""

        alert_summaries = []
        for alert in incident.alert_ids[:10]:
            alert_summaries.append(
                f"- {alert.title} | Severity: {alert.severity} | "
                f"Source IP: {alert.source_ip} | Category: {alert.category}"
            )

        prompt = f"""
Incident: {incident.title}
Description: {incident.description or 'N/A'}
Severity: {incident.severity}
Category: {incident.category or 'N/A'}
Source IP: {incident.source_ip or 'N/A'}
Destination IP: {incident.destination_ip or 'N/A'}
Number of related alerts: {incident.alert_count}

Related Alerts:
{chr(10).join(alert_summaries) if alert_summaries else 'No alerts linked'}

Affected Systems: {incident.affected_systems or 'N/A'}

Provide your incident analysis and response recommendations."""

        llm_response = self._query_ollama(prompt, system_prompt)

        if llm_response:
            try:
                json_match = re.search(r'\{[\s\S]*\}', llm_response)
                if json_match:
                    analysis = json.loads(json_match.group())
                else:
                    analysis = {'analysis': llm_response}
            except json.JSONDecodeError:
                analysis = {'analysis': llm_response}
        else:
            analysis = {
                'analysis': 'AI analysis unavailable. Please review manually.',
                'containment_strategy': 'Isolate affected systems from network.',
                'eradication_steps': 'Remove malicious artifacts, patch vulnerabilities.',
                'recovery_plan': 'Restore from clean backups, verify system integrity.',
            }

        incident.sudo().write({
            'ai_analysis': analysis.get('analysis', ''),
            'ai_response_suggestion': json.dumps(analysis, indent=2, default=str),
            'containment_actions': analysis.get('containment_strategy', ''),
            'eradication_actions': analysis.get('eradication_steps', ''),
            'recovery_actions': analysis.get('recovery_plan', ''),
        })

        return analysis

    def enrich_alert_ioc(self, alert):
        """Enrich alert IOCs with data from all threat intel sources."""
        enrichment_results = {}

        if alert.source_ip:
            enrichment_results['abuseipdb'] = self._check_abuseipdb(alert.source_ip)
            enrichment_results['otx'] = self._check_otx(alert.source_ip)
            enrichment_results['virustotal'] = self._check_virustotal(alert.source_ip)

        if alert.ioc_value:
            if alert.ioc_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
                enrichment_results['vt_hash'] = self._check_virustotal(
                    alert.ioc_value, 'files'
                )
            elif alert.ioc_type == 'domain':
                enrichment_results['otx_domain'] = self._check_otx(
                    alert.ioc_value, 'domain'
                )
                enrichment_results['vt_domain'] = self._check_virustotal(
                    alert.ioc_value, 'domains'
                )

        self._store_threat_intel(alert, {
            k: v for k, v in enrichment_results.items() if v
        })

        return enrichment_results
