/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, useState, onWillStart, onMounted } from "@odoo/owl";
import { useService } from "@web/core/utils/hooks";

/**
 * SOC Management Dashboard Component
 * Displays real-time security metrics, charts, alert summaries,
 * 5-layer architecture overview, and OpenCTI results.
 */
class SocDashboard extends Component {
    static template = "projetPfe-Soc_odoo.Dashboard";

    setup() {
        this.rpc = useService("rpc");
        this.action = useService("action");
        this.state = useState({
            data: null,
            loading: true,
            lastRefresh: new Date().toLocaleTimeString(),
        });

        onWillStart(async () => {
            await this.loadDashboardData();
        });

        onMounted(() => {
            // Auto-refresh every 60 seconds
            this.refreshInterval = setInterval(() => {
                this.loadDashboardData();
            }, 60000);
        });
    }

    async loadDashboardData() {
        try {
            this.state.loading = true;
            const result = await this.rpc("/soc/api/dashboard", {});
            this.state.data = result;
            this.state.lastRefresh = new Date().toLocaleTimeString();
            this.state.loading = false;
        } catch (error) {
            console.error("Failed to load dashboard data:", error);
            this.state.loading = false;
        }
    }

    async onRefresh() {
        await this.loadDashboardData();
    }

    // ── Navigation Actions ───────────────────────────────────────────────

    openAlerts() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_alert");
    }

    openCriticalAlerts() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_alert_critical");
    }

    openIncidents() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_incident");
    }

    openTunisiaAlerts() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_alert_tunisia");
    }

    openTickets() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_ticket");
    }

    openMitreTactics() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_mitre_tactic");
    }

    openMitreTechniques() {
        this.action.doAction("projetPfe-Soc_odoo.action_soc_mitre_technique");
    }

    openAlert(alertId) {
        this.action.doAction({
            type: "ir.actions.act_window",
            res_model: "soc.alert",
            res_id: alertId,
            views: [[false, "form"]],
            target: "current",
        });
    }

    // ── Chart Helpers ────────────────────────────────────────────────────

    getBarHeight(count) {
        if (!this.state.data || !this.state.data.daily_alerts) return "4px";
        const maxCount = Math.max(
            ...this.state.data.daily_alerts.map((d) => d.count),
            1
        );
        const pct = (count / maxCount) * 100;
        return `${Math.max(pct, 3)}%`;
    }

    getDonutStyle() {
        if (!this.state.data) return "";
        const d = this.state.data.severity_data;
        const total = (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0);
        if (total === 0) return "background: var(--soc-bg-secondary)";

        const critPct = ((d.critical || 0) / total) * 100;
        const highPct = ((d.high || 0) / total) * 100;
        const medPct = ((d.medium || 0) / total) * 100;

        const critEnd = critPct;
        const highEnd = critEnd + highPct;
        const medEnd = highEnd + medPct;

        return `background: conic-gradient(
            #ff5252 0% ${critEnd}%,
            #ffab40 ${critEnd}% ${highEnd}%,
            #4fc3f7 ${highEnd}% ${medEnd}%,
            #69f0ae ${medEnd}% 100%
        )`;
    }

    getSeverityTotal() {
        if (!this.state.data) return 0;
        const d = this.state.data.severity_data;
        return (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0);
    }

    getCategoryBarWidth(count) {
        if (!this.state.data || !this.state.data.category_data) return "0%";
        const maxCount = Math.max(
            ...this.state.data.category_data.map((c) => c.count),
            1
        );
        return `${Math.max((count / maxCount) * 100, 5)}%`;
    }

    getSeverityClass(severity) {
        return `soc-severity-${severity}`;
    }

    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        super.destroy?.();
    }
}

// Register dashboard action
registry.category("actions").add("projetPfe-Soc_odoo.dashboard", SocDashboard);
