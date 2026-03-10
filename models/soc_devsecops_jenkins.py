# -*- coding: utf-8 -*-
"""
Jenkins CI/CD Integration for SOC DevSecOps
Manages connection to Jenkins server and triggers/monitors security scan jobs.
"""
import json
import logging
import time

import requests
from requests.auth import HTTPBasicAuth

from odoo import models, fields, api, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class DevSecOpsJenkinsConfig(models.Model):
    """
    Jenkins + SonarQube connection configuration for DevSecOps pipelines.
    """
    _name = 'soc.devsecops.jenkins.config'
    _description = 'Jenkins & CI/CD Configuration'
    _rec_name = 'name'

    name = fields.Char(string='Configuration Name', default='Jenkins CI/CD', required=True)

    # ── Jenkins Settings ──────────────────────────────────────────────
    jenkins_url = fields.Char(
        string='Jenkins URL',
        default='http://localhost:8080',
        help='Jenkins server URL',
    )
    jenkins_user = fields.Char(string='Jenkins User')
    jenkins_api_token = fields.Char(string='Jenkins API Token')

    # ── SonarQube Settings ────────────────────────────────────────────
    sonarqube_url = fields.Char(
        string='SonarQube URL',
        default='http://localhost:9000',
    )
    sonarqube_token = fields.Char(string='SonarQube Token')

    # ── Docker Registry ───────────────────────────────────────────────
    docker_registry = fields.Char(
        string='Docker Registry',
        default='docker.io',
        help='Docker registry for image scanning',
    )
    docker_registry_user = fields.Char(string='Registry Username')
    docker_registry_password = fields.Char(string='Registry Password')

    # ── Kubernetes Settings ───────────────────────────────────────────
    k8s_context = fields.Char(
        string='K8s Context',
        default='default',
        help='Kubernetes context name for cluster scanning',
    )
    k8s_namespace = fields.Char(
        string='K8s Namespace',
        default='default',
    )
    k8s_kubeconfig_path = fields.Char(
        string='Kubeconfig Path',
        default='~/.kube/config',
    )

    # ── Cloud Credentials ─────────────────────────────────────────────
    aws_profile = fields.Char(string='AWS Profile', default='default')
    aws_region = fields.Char(string='AWS Region', default='eu-west-1')
    azure_subscription_id = fields.Char(string='Azure Subscription ID')
    gcp_project_id = fields.Char(string='GCP Project ID')

    # ── Policy Settings ───────────────────────────────────────────────
    fail_on_critical = fields.Boolean(
        string='Fail Pipeline on Critical',
        default=True,
        help='Block deployment if critical vulnerabilities are found',
    )
    fail_on_high = fields.Boolean(
        string='Fail Pipeline on High',
        default=False,
    )
    max_critical_allowed = fields.Integer(
        string='Max Critical Vulns Allowed',
        default=0,
    )
    max_high_allowed = fields.Integer(
        string='Max High Vulns Allowed',
        default=5,
    )

    # ── Status ────────────────────────────────────────────────────────
    state = fields.Selection([
        ('disconnected', 'Disconnected'),
        ('connected', 'Connected'),
        ('error', 'Error'),
    ], string='Jenkins Status', default='disconnected')
    last_error = fields.Text(string='Last Error')
    active = fields.Boolean(default=True)

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Jenkins API                                                  ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def _jenkins_auth(self):
        self.ensure_one()
        if self.jenkins_user and self.jenkins_api_token:
            return HTTPBasicAuth(self.jenkins_user, self.jenkins_api_token)
        return None

    def _jenkins_request(self, method, endpoint, **kwargs):
        self.ensure_one()
        url = f"{self.jenkins_url}{endpoint}"
        auth = self._jenkins_auth()
        try:
            resp = requests.request(method, url, auth=auth, timeout=30, **kwargs)
            resp.raise_for_status()
            return resp
        except Exception as e:
            _logger.error("Jenkins API error: %s", str(e))
            self.write({'last_error': str(e), 'state': 'error'})
            raise UserError(_(f"Jenkins error: {e}"))

    def action_test_jenkins(self):
        """Test Jenkins connection."""
        self.ensure_one()
        try:
            resp = self._jenkins_request('GET', '/api/json')
            if resp.ok:
                self.write({'state': 'connected', 'last_error': False})
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Success'),
                        'message': _('Successfully connected to Jenkins!'),
                        'type': 'success',
                    },
                }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Error'),
                    'message': str(e),
                    'type': 'danger',
                },
            }

    def trigger_jenkins_job(self, job_name, parameters=None):
        """Trigger a Jenkins job with optional parameters."""
        self.ensure_one()
        if parameters:
            endpoint = f"/job/{job_name}/buildWithParameters"
            self._jenkins_request('POST', endpoint, params=parameters)
        else:
            endpoint = f"/job/{job_name}/build"
            self._jenkins_request('POST', endpoint)
        _logger.info("Triggered Jenkins job: %s", job_name)

    def get_jenkins_build_status(self, job_name, build_number):
        """Get the status of a Jenkins build."""
        self.ensure_one()
        endpoint = f"/job/{job_name}/{build_number}/api/json"
        resp = self._jenkins_request('GET', endpoint)
        return resp.json()

    def get_jenkins_jobs(self):
        """List all Jenkins jobs."""
        self.ensure_one()
        resp = self._jenkins_request('GET', '/api/json?tree=jobs[name,color,lastBuild[number,result]]')
        return resp.json().get('jobs', [])

    # ╔═══════════════════════════════════════════════════════════════╗
    # ║  Pipeline Helper: Jenkinsfile Generator                       ║
    # ╚═══════════════════════════════════════════════════════════════╝

    def generate_jenkinsfile(self, scan_profile):
        """
        Generate a Jenkinsfile (declarative pipeline) for a given scan profile.
        Returns the Jenkinsfile content as a string.
        """
        stages = []

        if scan_profile.enable_trivy:
            stages.append("""
        stage('Trivy - Container Scan') {
            steps {
                sh 'trivy image --format json --output trivy-report.json --severity CRITICAL,HIGH,MEDIUM ${DOCKER_IMAGE}'
                archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_owasp_dc:
            stages.append("""
        stage('OWASP Dependency Check') {
            steps {
                sh 'dependency-check --scan . --format JSON --out dependency-check-report.json'
                archiveArtifacts artifacts: 'dependency-check-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_bandit:
            stages.append("""
        stage('Bandit - Python SAST') {
            steps {
                sh 'bandit -r . -f json -o bandit-report.json -ll || true'
                archiveArtifacts artifacts: 'bandit-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_semgrep:
            stages.append("""
        stage('Semgrep - SAST') {
            steps {
                sh 'semgrep scan --config auto --json --output semgrep-report.json . || true'
                archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_gitleaks:
            stages.append("""
        stage('Gitleaks - Secrets Detection') {
            steps {
                sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json || true'
                archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_checkov:
            stages.append("""
        stage('Checkov - IaC Security') {
            steps {
                sh 'checkov -d . -o json > checkov-report.json || true'
                archiveArtifacts artifacts: 'checkov-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_docker_bench:
            stages.append("""
        stage('Docker Bench Security') {
            steps {
                sh '''
                    docker run --rm --net host --pid host --userns host --cap-add audit_control \\
                        -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \\
                        -v /usr/lib/systemd:/usr/lib/systemd:ro -v /etc:/etc:ro \\
                        docker/docker-bench-security -l /dev/stdout -j > docker-bench-report.json || true
                '''
                archiveArtifacts artifacts: 'docker-bench-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_kube_bench:
            stages.append("""
        stage('kube-bench - K8s CIS Benchmark') {
            steps {
                sh 'kube-bench run --json > kube-bench-report.json || true'
                archiveArtifacts artifacts: 'kube-bench-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_kube_hunter:
            stages.append("""
        stage('kube-hunter - K8s Penetration Test') {
            steps {
                sh 'kube-hunter --pod --report json > kube-hunter-report.json || true'
                archiveArtifacts artifacts: 'kube-hunter-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_nuclei:
            stages.append("""
        stage('Nuclei - Vulnerability Scanner') {
            steps {
                sh 'nuclei -target ${TARGET_URL} -json -o nuclei-report.json -severity critical,high,medium || true'
                archiveArtifacts artifacts: 'nuclei-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_zap:
            stages.append("""
        stage('OWASP ZAP - DAST') {
            steps {
                sh '''
                    docker run --rm ghcr.io/zaproxy/zaproxy:stable \\
                        zap-baseline.py -t ${TARGET_URL} -J /dev/stdout > zap-report.json || true
                '''
                archiveArtifacts artifacts: 'zap-report.json', allowEmptyArchive: true
            }
        }""")

        if scan_profile.enable_sonarqube:
            stages.append("""
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner -Dsonar.projectBaseDir=.'
                }
            }
        }
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }""")

        # Webhook stage to send results back to Odoo
        stages.append("""
        stage('Report to SOC Platform') {
            steps {
                sh '''
                    curl -X POST ${ODOO_URL}/soc/devsecops/webhook \\
                        -H "Content-Type: application/json" \\
                        -d "{\\"scan_id\\": \\"${SCAN_ID}\\", \\"status\\": \\"completed\\", \\"build_number\\": ${BUILD_NUMBER}}"
                '''
            }
        }""")

        jenkinsfile = f"""// Auto-generated by SOC Management DevSecOps Module
// Profile: {scan_profile.name}
// Generated: {fields.Datetime.now()}

pipeline {{
    agent any

    environment {{
        DOCKER_IMAGE = '${{params.DOCKER_IMAGE ?: "myapp:latest"}}'
        TARGET_URL = '${{params.TARGET_URL ?: "http://localhost:8080"}}'
        SCAN_ID = '${{params.SCAN_ID ?: "manual"}}'
        ODOO_URL = '${{params.ODOO_URL ?: "http://localhost:8069"}}'
    }}

    parameters {{
        string(name: 'DOCKER_IMAGE', defaultValue: 'myapp:latest', description: 'Docker image to scan')
        string(name: 'TARGET_URL', defaultValue: 'http://localhost:8080', description: 'Web app URL for DAST')
        string(name: 'SCAN_ID', defaultValue: 'manual', description: 'SOC Scan ID')
        string(name: 'ODOO_URL', defaultValue: 'http://localhost:8069', description: 'Odoo SOC Platform URL')
    }}

    stages {{''.join(stages)
    }}

    post {{
        always {{
            publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: '*-report.json',
                reportName: 'Security Scan Reports'
            ])
        }}
        failure {{
            echo 'DevSecOps pipeline FAILED - Critical vulnerabilities detected!'
        }}
        success {{
            echo 'DevSecOps pipeline PASSED - No blocking vulnerabilities.'
        }}
    }}
}}
"""
        return jenkinsfile
