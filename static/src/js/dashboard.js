/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, useState, onWillStart, onMounted, onWillUnmount, useRef } from "@odoo/owl";
import { useService } from "@web/core/utils/hooks";

/**
 * SOC Management Dashboard Component — Interactive Architecture
 * Displays real-time security metrics, interactive 5-layer architecture
 * with expandable alert panels, smooth scrolling navigation, and
 * OpenCTI results.
 */
class SocDashboard extends Component {
    static template = "projetPfe-Soc_odoo.Dashboard";

    setup() {
        this.rpc = useService("rpc");
        this.action = useService("action");

        // Refs for scroll-to-section
        this.dashboardRoot = useRef("dashboardRoot");

        this.state = useState({
            data: null,
            loading: true,
            lastRefresh: new Date().toLocaleTimeString(),
            // Interactive architecture state
            expandedLayer: null,
            layerAlerts: [],
            loadingLayerAlerts: false,
            // Scroll navigation
            activeSection: "header",
        });

        onWillStart(async () => {
            await this.loadDashboardData();
        });

        onMounted(() => {
            // Auto-refresh every 60 seconds
            this.refreshInterval = setInterval(() => {
                this.loadDashboardData();
            }, 60000);

            // Setup scroll spy for sidebar navigation
            this._setupScrollSpy();
        });

        onWillUnmount(() => {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
            }
            if (this._scrollHandler) {
                const scrollContainer = this._getScrollContainer();
                if (scrollContainer) {
                    scrollContainer.removeEventListener("scroll", this._scrollHandler);
                }
            }
        });
    }

    // ── Data Loading ─────────────────────────────────────────────────

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

    // ── Interactive Architecture — Layer Toggle ──────────────────────

    async toggleLayer(layerNum) {
        if (this.state.expandedLayer === layerNum) {
            // Collapse if already expanded
            this.state.expandedLayer = null;
            this.state.layerAlerts = [];
            return;
        }

        this.state.expandedLayer = layerNum;
        this.state.loadingLayerAlerts = true;
        this.state.layerAlerts = [];

        try {
            const result = await this.rpc("/soc/api/layer_alerts", {
                layer: layerNum,
            });
            this.state.layerAlerts = result.alerts || [];
        } catch (error) {
            console.error(`Failed to load layer ${layerNum} alerts:`, error);
            this.state.layerAlerts = [];
        } finally {
            this.state.loadingLayerAlerts = false;
        }
    }

    // ── Scroll Navigation ────────────────────────────────────────────

    _getScrollContainer() {
        // In Odoo, the main scrollable container is usually .o_action_manager or .o_content
        const el = this.dashboardRoot.el;
        if (!el) return null;
        let parent = el.closest(".o_action_manager") || el.closest(".o_content") || el.parentElement;
        // Walk up to find scrollable parent
        while (parent && parent !== document.body) {
            const style = window.getComputedStyle(parent);
            if (style.overflow === "auto" || style.overflow === "scroll" ||
                style.overflowY === "auto" || style.overflowY === "scroll") {
                return parent;
            }
            parent = parent.parentElement;
        }
        return window;
    }

    _setupScrollSpy() {
        const sectionIds = ["header", "architecture", "opencti", "operational", "charts", "tables"];

        this._scrollHandler = () => {
            const container = this._getScrollContainer();
            const scrollTop = container === window ? window.scrollY : container.scrollTop;
            const offset = 200;

            for (let i = sectionIds.length - 1; i >= 0; i--) {
                const sectionEl = document.getElementById(`section-${sectionIds[i]}`);
                if (sectionEl) {
                    const rect = sectionEl.getBoundingClientRect();
                    const containerRect = container === window
                        ? { top: 0 }
                        : container.getBoundingClientRect();
                    const relativeTop = rect.top - containerRect.top;

                    if (relativeTop <= offset) {
                        this.state.activeSection = sectionIds[i];
                        break;
                    }
                }
            }
        };

        const scrollContainer = this._getScrollContainer();
        if (scrollContainer) {
            scrollContainer.addEventListener("scroll", this._scrollHandler, { passive: true });
        }
    }

    scrollToSection(sectionId) {
        const sectionEl = document.getElementById(`section-${sectionId}`);
        if (sectionEl) {
            sectionEl.scrollIntoView({ behavior: "smooth", block: "start" });
            this.state.activeSection = sectionId;
        }
    }

    scrollToTop() {
        const container = this._getScrollContainer();
        if (container === window) {
            window.scrollTo({ top: 0, behavior: "smooth" });
        } else if (container) {
            container.scrollTo({ top: 0, behavior: "smooth" });
        }
        this.state.activeSection = "header";
    }

    // ── Navigation Actions ───────────────────────────────────────────

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

    openWazuhAlerts() {
        this.action.doAction({
            type: "ir.actions.act_window",
            name: "Alertes Wazuh",
            res_model: "soc.alert",
            views: [[false, "list"], [false, "form"]],
            domain: [["source", "=", "wazuh"]],
            target: "current",
        });
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

    // ── Chart Helpers ────────────────────────────────────────────────

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
}

// Register dashboard action
registry.category("actions").add("projetPfe-Soc_odoo.dashboard", SocDashboard);
