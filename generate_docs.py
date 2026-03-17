import os
import webbrowser

def generate_pdf_ready_html():
    raw_md_content = r"""
# Documentation Technique et Architecture : Odoo SOC Management

## 1. Introduction et Objectifs
Le module **Odoo SOC Management** est une plateforme centralisée développée dans le cadre d'un Projet de Fin d'Études (PFE). 
Ce système a pour but de fusionner les opérations de sécurité (Security Operations Center - SOC) et la gestion des pipelines DevSecOps. 
Il agit comme un agrégateur d'informations de sécurité, utilisant **Wazuh** comme SIEM principal, **Mistral/Ollama** pour l'intelligence artificielle d'analyse, et **Jenkins** pour l'orchestration CI/CD.

L'objectif majeur est de fournir à une équipe fonctionnant en Niveaux (1, 2, et 3) une vue complète et interactive de bout en bout des cyberattaques (via le dashboard OWL) et des vulnérabilités logicielles (via les rapports Trivy, SonarQube, etc.).

---

## 2. Architecture Globale du Système

Ce schéma décrit comment les données entrent, sont traitées, puis consommées.
Le pont (Webhook) est la porte d'entrée de la supervision SOC.

<div class="mermaid">
flowchart TD
    subgraph Sources_Externes [Sources de Données]
        Wazuh[Wazuh Manager (SIEM)]
        Jenkins[Jenkins CI/CD]
        ThreatFeeds[Outils Open-Source OTX, AbuseIPDB]
    end

    subgraph Odoo_Platform [Plateforme Centrale Odoo SOC]
        subgraph Ingestion [Contrôleurs (Endpoints Web)]
            WebhookWazuh[controllers/wazuh_webhook.py]
            WebhookDevSecOps[controllers/devsecops_webhook.py]
        end

        subgraph Logique_Traitements [Traitement Intelligent]
            FiltresPython[wazuh_filters.py (Critères de Tri)]
            IAEngine[Agent IA - soc.ai.agent.py]
            MitreMap[MITRE ATT&CK Mapping]
            IPChecker[Filtrage Géolocalisation (Tunisie)]
        end

        subgraph Entites [Modèles de Données Odoo]
            Alertes[(soc.alert)]
            Incidents[(soc.incident)]
            Tickets[(soc.ticket)]
            Vulns[(soc.devsecops.finding)]
            ScanProfiler[(soc.devsecops.scan)]
        end

        subgraph UI [Interface Utilisateur (OWL / XML)]
            Dashboard[Dashboard Interactif Temps Réel]
            Views[Vues Odoo Standards (Kanban, List, Form)]
        end
    end

    %% Connexions
    Wazuh -- "Alerte JSON (HTTP POST)" --> WebhookWazuh
    Jenkins -- "Rapport de Scan JSON" --> WebhookDevSecOps
    
    WebhookWazuh --> FiltresPython
    FiltresPython -- "Alerte Valide" --> Alertes
    FiltresPython -- "Faux Positif Local" --> IPChecker
    
    WebhookDevSecOps --> Vulns
    
    Alertes -- "Escalade Manuelle" --> Incidents
    Alertes <--> IAEngine
    Alertes <--> MitreMap
    ThreatFeeds -.-> Alertes
    
    Incidents --> Tickets
    
    Alertes --> Dashboard
    Incidents --> Dashboard
    Tickets --> Dashboard
    Vulns --> Views
    ScanProfiler --> Jenkins
</div>

---

## 3. Diagramme des Cas d'Utilisation

L'interaction des différents acteurs humains ou système avec les capacités du logiciel.

<div class="mermaid">
usecaseDiagram
    actor "Analyste N1 (Triage)" as N1
    actor "Analyste N2/N3 (Expert)" as Expert
    actor "Manager SOC" as Manager
    actor "Système Wazuh" as WazuhAgent

    usecase "Générer une alerte système" as UC1
    usecase "Consulter le Dashboard SOC" as UC2
    usecase "Analyser/Qualifier l'Alerte" as UC3
    usecase "Demander Investigation IA" as UC4
    usecase "Escalader en Incident" as UC5
    usecase "Affecter/Traiter un Ticket" as UC6
    usecase "Gérer la stratégie MITRE" as UC7
    usecase "Lancer Pipeline DevSecOps" as UC8
    usecase "Définir règles de Filtrage Python" as UC9

    WazuhAgent --> UC1

    N1 --> UC2
    N1 --> UC3
    N1 --> UC6

    Expert --> UC2
    Expert --> UC3
    Expert --> UC4
    Expert --> UC5
    Expert --> UC6

    Manager --> UC2
    Manager --> UC7
    Manager --> UC8
    Manager --> UC9
</div>

---

## 4. Diagramme de Classes Complet (Modèles Odoo)

La structure tabulaire sous-jacente gérée par l'ORM d'Odoo.

<div class="mermaid">
classDiagram
    class SocAlert {
        +Char name (ALR-202X-001)
        +Char title
        +Selection severity (low, medium, high, critical)
        +Char source_ip
        +Text wazuh_full_log
        +Many2one incident_id
        +action_escalate()
        +action_ai_analyze()
    }

    class SocIncident {
        +Char name (INC-202X-010)
        +Char title
        +Text description
        +Selection state (new, triage, investigate...)
        +Selection severity
        +Float time_to_resolve
        +Datetime detection_date
        +Many2one analyst_id
        +action_start_containment()
        +action_close()
    }

    class SocTicket {
        +Char name (TKT-202X-005)
        +Char first_name
        +Char last_name
        +Selection level (1, 2, 3)
        +Selection state (new, in_progress, resolved)
        +Text description
        +action_resolve()
    }

    class SocWazuhConnector {
        +Char wazuh_host
        +Char wazuh_user
        +Password wazuh_password
        +Float min_rule_level
        +Boolean filter_tunisia_only
        +test_connection()
    }

    class DevSecOpsScan {
        +Char name
        +Selection scan_type (sast, sca, dast, container)
        +Selection status (pending, running, success, failed)
        +Text target_repository
        +trigger_jenkins_job()
    }

    class DevSecOpsFinding {
        +Char title
        +Selection severity
        +Char cve_id
        +Char component
        +Many2one scan_id
    }
    
    class SocAiAgent {
        +Char ollama_host
        +Char ollama_model
        +analyze_incident()
        +analyze_alert()
    }

    SocAlert "1" -- "0..1" SocIncident : escaladé en
    SocAlert "1" -- "0..1" SocAiAgent : analysé par
    SocIncident "1" -- "*" SocTicket : décomposé_en tâches
    DevSecOpsScan "1" -- "*" DevSecOpsFinding : produit
</div>

---

## 5. Diagrammes de Séquence

### Séquence 1 : Capter, Filtrer et AI-Enrichir (Flux Automatique Wazuh)
La manière dont le système assure qu'aucune alerte faible n'impacte la base de données.

<div class="mermaid">
sequenceDiagram
    participant OS as Ordinateur Protégé
    participant WZ as Wazuh Server
    participant CTRL as Webhook Odoo (wazuh_webhook)
    participant FLT as Filtre Python (wazuh_filters)
    participant DB as ORM Odoo (soc.alert)
    participant AI as IA Locale (Ollama)

    OS->>WZ: Détection d'accès root non autorisé (Log)
    WZ->>WZ: Mapping sur la Règle Wazuh n° 5503 (Critique)
    WZ->>CTRL: Webhook (HTTP POST payload: JSON)
    
    CTRL->>CTRL: Validation JSON
    CTRL->>FLT: Verifier niveau/pertinence via apply_filters()
    
    alt Niveau < 3 ou règle ignorée
        FLT-->>CTRL: Return False
        CTRL-->>WZ: HTTP 200 (Alerte ignorée volontairement)
    else Niveau >= 3
        FLT-->>CTRL: Return True
        CTRL->>DB: create({"title":"Root login", "severity":"critical"})
        DB-->>CTRL: Record_ID: 45
        CTRL-->>WZ: HTTP 200 (Success)
        
        opt Tâche Cron planifiée
            DB->>AI: prompt("Analyse ce log Wazuh: [log]")
            AI-->>DB: Résumé IA et étapes (ex: "Bloquez l'IP 192.168.1.100")
        end
    end
</div>

### Séquence 2 : Lancement Manuel d'un Pipeline DevSecOps
Le flux qui relie l'utilisateur Odoo à l'infrastructure Jenkins CI/CD.

<div class="mermaid">
sequenceDiagram
    participant User as Utilisateur
    participant Odoo as Odoo (soc.devsecops.scan)
    participant JNK as Jenkins
    participant Scanner as Outils DevSecOps (Trivy)

    User->>Odoo: Clique sur "Lancer un scan Docker" (Bouton UI)
    Odoo->>Odoo: Génération Jenkinsfile Automatique
    Odoo->>JNK: API REST (Déclenchement Build + ID Scan)
    JNK-->>Odoo: HTTP 201 Created (Token Build)
    Odoo-->>User: Statut = "En Cours (Running)"
    
    JNK->>Scanner: Pipeline Stage 1: trivy image nginx:latest
    Scanner-->>JNK: Résultats Vulnérabilités en format JSON
    
    JNK->>Odoo: Payload JSON (devsecops_webhook)
    Odoo->>Odoo: Parsing & Création x N findings (soc.devsecops.finding)
    Odoo->>Odoo: Mise à jour Scan (Statut = Terminé)
</div>

---

## 6. Explications Détaillées par Module (Code)

### 6.1. Le Tableau de Bord Interactif (`static/src/` & `soc_dashboard.py`)
Le tableau de bord utilise **OWL (Odoo Web Library)**, le framework d'interface natif de la v16/v17, basé sur des composants (comme React/Vue).
1. **`dashboard_template.xml`** : Définit la structure HTML/XML. On y gère la carte des KPI (*New Alerts*, *False positive rate*, etc.), les graphiques en barres, en donuts, et surtout **les liens de navigations rapides (Quick Links)**.
2. **`dashboard.js`** : La logique côté client (JavaScript). Contient la classe `SocDashboard` qui étend `Component`. Elle effectue un `setInterval` pour recharger les données (par appel RPC à `/soc/api/dashboard`) et effectue le *routing* via l'objet Odoo `actionManger` lorsqu'on clique sur un bouton "Gestion Tickets" ou "Incidents".
3. **`soc_dashboard.py`** : Fournit un Endpoint JSON utilisé par OWL. C'est l'intelligence backend qui exécute du SQL complexe (`COUNT`, `GROUP BY severity`) pour servir les données optimisées au frontend.

### 6.2. La Réception des Alertes (`controllers/wazuh_webhook.py` & `wazuh_filters.py`)
Le webhook est défini avec `@http.route('/soc/wazuh/webhook', type='json', auth='public')`.
1. **Extraction de charge utile** : Décompose le JSON complexe de Wazuh en attributs lisibles (`rule.id`, `rule.level`, IPs).
2. **Le Pare-Feu `apply_filters`** : Nous avons mis en place `wazuh_filters.py`. Au lieu d'écrire des règles dures dans Odoo, l'administrateur peut juste modifier une liste en Python. Le webhook refuse l'insertion dans la base de données SQL si cette fonction renvoie `False`.

### 6.3. Modèle Alerte et Incident (`models/soc_alert.py` & `soc_incident.py`)
Ces modèles définissent des tables avec de nombreuses relations.
- **Sécurisation par Séquence :** Les Identifiants (ALR-2026-X, INC-2026-X) sont générés par le serveur pour garantir l'unicité et le format réglementaire.
- **MTTR Automatisé :** Dans l'objet `soc.incident`, le calcul du "Mean Time To Resolve" se fait de façon automatisée en calculant le float `delta = (closed_date - detection_date).total_seconds() / 3600`.

### 6.4. Nouveau Modèle : Les Tickets SOC (`models/soc_ticket.py`)
Un système d'attribution et de suivi de tâche pour N1 (Tri et observation basique), N2 (Investigation poussée et isolation) et N3 (Architectes de réponse, Forensic). Un incident majeur générera potentiellement de nombreux tickets.

### 6.5. Moteur d'Intelligence Artificielle (`models/soc_ai_agent.py`)
Pour un SOC moderne, il est impossible de traiter tous les logs manuellement.
Le module intègre un appel API REST standard vers un serveur local `Ollama` hébergeant un modèle `Mistral`. 
Il construit un Prompt intelligent en donnant le rôle à l'IA d'analyste de sécurité. Il demande à l'IA de lire `l'alerte Wazuh` issue de Odoo, d'expliquer l'attaque en termes simples, et liste une matrice de décisions correctives recommandée (quelles IPs bloquer, quels fichiers analyser).
"""

    html_template = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Documentation PFE SOC Management - Détaillée</title>
    <!-- Github Markdown CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.2.0/github-markdown.min.css">
    
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        
        document.getElementById('content').innerHTML = marked.parse(document.getElementById('raw-md').textContent);
        
        mermaid.initialize({{ 
            startOnLoad: true, 
            theme: 'default' 
        }});

        setTimeout(() => {{
            window.print();
        }}, 2500);
    </script>

    <style>
        body {{
            box-sizing: border-box;
            min-width: 200px;
            max-width: 1000px;
            margin: 0 auto;
            padding: 45px;
            font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif,"Apple Color Emoji","Segoe UI Emoji";
        }}
        .print-btn {{
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 24px;
            background-color: #2da44e;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: 0.2s ease-in-out;
            z-index: 1000;
        }}
        .print-btn:hover {{
            background-color: #2c974b;
            transform: scale(1.05);
        }}
        .mermaid {{
            background: #f6f8fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: flex;
            justify-content: center;
        }}
        h2 {{
            border-bottom: 2px solid #eaecef;
            padding-bottom: 10px;
            color: #24292f;
            margin-top: 40px;
        }}
        h3 {{
            color: #434c56;
        }}
        @media print {{
            .print-btn {{ display: none !important; }}
            .markdown-body {{ max-width: 100%; }}
            .mermaid {{ 
                page-break-inside: avoid; 
                margin-bottom: 2rem; 
                display: flex; 
                justify-content: center; 
                transform: scale(0.9);
                transform-origin: top center;
            }}
            h2 {{ page-break-before: always; border-bottom: none; }}
            body {{ padding: 0; }}
            pre {{ font-size: 12px !important; white-space: pre-wrap !important; }}
        }}
    </style>
</head>
<body class="markdown-body">
    <button class="print-btn" onclick="window.print()">🖨️ Sauvegarder en PDF</button>
    <div id="raw-md" style="display: none;">{raw_md_content.strip()}</div>
    
    <div id="content" style="margin-top:20px;">
        <h2 style="color: grey;">Génération de la documentation avancée en cours (Veuillez patienter 2 secondes...)</h2>
    </div>
</body>
</html>
    """
    
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Documentation_Technique_Avancee.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    
    print(f"[{file_path}] a été généré avec succès.")
    
    webbrowser.open(f"file:///{file_path.replace(chr(92), '/')}")

if __name__ == "__main__":
    generate_pdf_ready_html()
