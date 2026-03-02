/* ═══════════════════════════════════════════════════════════
   NetGuard-ML Dashboard — app.js
   ══════════════════════════════════════════════════════════ */

// ─── Service URLs (routed through Nginx) ────────────────────
const API_URL = "/api";
const STATS_URL = "/stats";
const LOGS_URL = "/logs";
const ALERTS_URL = "/alerts";

// ─── State ──────────────────────────────────────────────────
let trafficChart = null;
let donutChart = null;
let pollInterval = null;
let currentPage = 1;
let socket = null;
let prevTotal = 0;
let prevThreats = 0;

// ─────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initNavigation();
    initCharts();
    initPredictForm();
    initBatchForm();
    initWebSocket();
    checkServices();
    loadDashboardData();
    loadLogs();
    loadAlertsHistory();

    // Poll every 6 seconds
    pollInterval = setInterval(() => {
        loadDashboardData();
        if (isTabActive("logs")) loadLogs();
        if (isTabActive("alerts")) loadAlertsHistory();
    }, 6000);

    document.getElementById("clearFeedBtn").addEventListener("click", () => {
        document.getElementById("liveFeed").innerHTML = '<div class="feed-empty">Waiting for traffic events…</div>';
    });

    document.getElementById("refreshLogsBtn").addEventListener("click", () => loadLogs(1));
    document.getElementById("logFilter").addEventListener("change", () => loadLogs(1));
    document.getElementById("menuToggle").addEventListener("click", () => {
        document.getElementById("sidebar").classList.toggle("open");
    });
});

// ─────────────────────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────────────────────
function initClock() {
    const el = document.getElementById("timeDisplay");
    const tick = () => {
        const now = new Date();
        el.textContent = now.toLocaleTimeString("en-US", { hour12: false });
    };
    tick();
    setInterval(tick, 1000);
}

// ─────────────────────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────────────────────
const TAB_TITLES = { dashboard: "Dashboard", predict: "Analyzer", logs: "Traffic Logs", alerts: "Alerts" };

function initNavigation() {
    document.querySelectorAll(".nav-item").forEach(item => {
        item.addEventListener("click", e => {
            e.preventDefault();
            const tab = item.dataset.tab;
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.getElementById(`nav-${tab}`).classList.add("active");
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    document.getElementById(`tab-${tab}`).classList.add("active");
    document.getElementById("pageTitle").textContent = TAB_TITLES[tab] || tab;
}

function isTabActive(tab) {
    return document.getElementById(`tab-${tab}`)?.classList.contains("active");
}

// ─────────────────────────────────────────────────────────────
// CHARTS
// ─────────────────────────────────────────────────────────────
const CHART_DEFAULTS = {
    animation: { duration: 600 },
    plugins: {
        legend: { display: false }, tooltip: {
            backgroundColor: "#111827",
            borderColor: "rgba(0,212,255,0.2)",
            borderWidth: 1,
            titleColor: "#f0f4ff",
            bodyColor: "#8b9bbb",
            padding: 10,
        }
    },
};

function initCharts() {
    // Traffic line chart
    const ctx1 = document.getElementById("trafficChart").getContext("2d");
    trafficChart = new Chart(ctx1, {
        type: "line",
        data: {
            labels: Array.from({ length: 24 }, (_, i) => `${23 - i}h ago`).reverse(),
            datasets: [
                {
                    label: "Benign",
                    data: new Array(24).fill(0),
                    borderColor: "#00d4ff",
                    backgroundColor: "rgba(0,212,255,0.08)",
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: "#00d4ff",
                },
                {
                    label: "Malicious",
                    data: new Array(24).fill(0),
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239,68,68,0.06)",
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: "#ef4444",
                },
            ],
        },
        options: {
            ...CHART_DEFAULTS,
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#4a5568", maxTicksLimit: 8 } },
                y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#4a5568" }, beginAtZero: true },
            },
        },
    });

    // Donut chart
    const ctx2 = document.getElementById("donutChart").getContext("2d");
    donutChart = new Chart(ctx2, {
        type: "doughnut",
        data: {
            labels: ["Benign", "Malicious"],
            datasets: [{
                data: [1, 0],
                backgroundColor: ["rgba(0,212,255,0.7)", "rgba(239,68,68,0.7)"],
                borderColor: ["#00d4ff", "#ef4444"],
                borderWidth: 2,
                hoverOffset: 6,
            }],
        },
        options: {
            ...CHART_DEFAULTS,
            responsive: true,
            maintainAspectRatio: false,
            cutout: "72%",
        },
    });
}

function updateCharts(stats, trafficData) {
    if (!stats) return;

    const benign = stats.benign || 0;
    const malicious = stats.malicious || 0;

    // Donut
    donutChart.data.datasets[0].data = [benign || 1, malicious];
    donutChart.update("none");
    const pct = stats.total ? Math.round(benign / stats.total * 100) : 0;
    document.getElementById("donutPct").textContent = pct + "%";

    // Traffic line chart with bucket data
    if (trafficData?.buckets) {
        const buckets = trafficData.buckets;
        const labels = [];
        const bData = [];
        const mData = [];
        for (let i = 23; i >= 0; i--) {
            labels.push(`${i}h ago`);
            const key = String(23 - i);
            bData.push(buckets[key]?.BENIGN || 0);
            mData.push(buckets[key]?.MALICIOUS || 0);
        }
        trafficChart.data.labels = labels.reverse();
        trafficChart.data.datasets[0].data = bData.reverse();
        trafficChart.data.datasets[1].data = mData.reverse();
        trafficChart.update("none");
    }
}

// ─────────────────────────────────────────────────────────────
// KPI CARDS
// ─────────────────────────────────────────────────────────────
function updateKPIs(stats) {
    if (!stats) return;
    const total = stats.total_packets || 0;
    const threats = stats.malicious || 0;
    const rate = stats.threat_rate || 0;
    const alerts = stats.active_alerts || 0;

    animateCount("kpi-total-val", prevTotal, total);
    animateCount("kpi-threats-val", prevThreats, threats);
    document.getElementById("kpi-rate-val").textContent = rate.toFixed(1) + "%";
    document.getElementById("kpi-alerts-val").textContent = alerts;
    document.getElementById("alert-badge").textContent = alerts;
    document.getElementById("log-badge").textContent = total;
    document.getElementById("alertCountBadge").textContent = `${alerts} alerts`;

    prevTotal = total;
    prevThreats = threats;
}

function animateCount(id, from, to, duration = 400) {
    const el = document.getElementById(id);
    if (!el) return;
    const step = (to - from) / (duration / 16);
    let current = from;
    const timer = setInterval(() => {
        current = Math.min(current + step, to);
        el.textContent = Math.round(current).toLocaleString();
        if (Math.round(current) >= to) clearInterval(timer);
    }, 16);
}

// ─────────────────────────────────────────────────────────────
// DATA LOADING
// ─────────────────────────────────────────────────────────────
async function loadDashboardData() {
    try {
        const [statsRes, trafficRes] = await Promise.all([
            fetch(`${STATS_URL}/stats`),
            fetch(`${STATS_URL}/traffic-over-time`),
        ]);
        const stats = statsRes.ok ? await statsRes.json() : null;
        const traffic = trafficRes.ok ? await trafficRes.json() : null;

        updateKPIs(stats);
        updateCharts(stats, traffic);
    } catch (err) {
        console.warn("Dashboard data fetch failed:", err);
    }
}

// ─────────────────────────────────────────────────────────────
// LOGS TABLE
// ─────────────────────────────────────────────────────────────
async function loadLogs(page = currentPage) {
    currentPage = page;
    const filter = document.getElementById("logFilter").value;
    const url = `${LOGS_URL}/logs?page=${page}&limit=20${filter ? "&label=" + filter : ""}`;

    try {
        const res = await fetch(url);
        const data = await res.json();
        renderLogsTable(data.logs || []);
        renderPagination(data.total || 0, 20, page);
    } catch (err) {
        document.getElementById("logsBody").innerHTML =
            '<tr><td colspan="9" class="empty-row">Could not load logs.</td></tr>';
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logsBody");
    if (!logs.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-row">No logs yet — run predictions first.</td></tr>';
        return;
    }
    tbody.innerHTML = logs.map((row, i) => {
        const t = new Date(row.timestamp * 1000).toLocaleTimeString();
        const proto = row.protocol_tcp ? "TCP" : "UDP";
        const cls = row.label === "MALICIOUS" ? "malicious" : "benign";
        return `<tr>
      <td>${row.id}</td>
      <td>${t}</td>
      <td><span class="label-pill ${cls}">${row.label}</span></td>
      <td>${(row.probability * 100).toFixed(1)}%</td>
      <td>${row.packet_length ?? "–"}</td>
      <td>${proto}</td>
      <td>${row.source_port ?? "–"}</td>
      <td>${row.dest_port ?? "–"}</td>
      <td>${row.source_ip ?? "–"}</td>
    </tr>`;
    }).join("");
}

function renderPagination(total, limit, page) {
    const pages = Math.ceil(total / limit);
    const el = document.getElementById("logsPagination");
    if (pages <= 1) { el.innerHTML = ""; return; }
    let html = "";
    for (let i = 1; i <= Math.min(pages, 8); i++) {
        html += `<button class="page-btn ${i === page ? "active" : ""}" onclick="loadLogs(${i})">${i}</button>`;
    }
    el.innerHTML = html;
}

// ─────────────────────────────────────────────────────────────
// ALERTS HISTORY
// ─────────────────────────────────────────────────────────────
async function loadAlertsHistory() {
    try {
        const res = await fetch(`${ALERTS_URL}/alerts/history?limit=50`);
        const data = await res.json();
        renderAlertsList(data.alerts || []);
    } catch { }
}

function renderAlertsList(alerts) {
    const el = document.getElementById("alertsList");
    if (!alerts.length) {
        el.innerHTML = '<div class="empty-state">No alerts recorded yet. Run predictions to generate traffic.</div>';
        return;
    }
    el.innerHTML = alerts.map(a => {
        const t = new Date(a.timestamp * 1000).toLocaleString();
        const f = a.features || {};
        return `<div class="alert-item">
      <div class="alert-icon">🚨</div>
      <div class="alert-body">
        <div class="alert-title">MALICIOUS Traffic Detected</div>
        <div class="alert-meta">
          ${t} · Len: ${f.packet_length ?? "?"}B · ${f.protocol_tcp ? "TCP" : "UDP"}
          · Port ${f.dest_port ?? "?"} · IP: ${a.source_ip ?? "?"}
        </div>
      </div>
      <div class="alert-prob">${(a.probability * 100).toFixed(1)}%</div>
    </div>`;
    }).join("");
}

// ─────────────────────────────────────────────────────────────
// WEBSOCKET (ALERTS)
// ─────────────────────────────────────────────────────────────
function initWebSocket() {
    try {
        socket = io(window.location.origin + "/alerts", {
            path: "/alerts/socket.io",
            transports: ["websocket", "polling"],
            reconnectionDelay: 2000,
            reconnectionAttempts: 10,
        });

        socket.on("connect", () => {
            document.getElementById("dot-alerts").className = "dot ok";
        });
        socket.on("disconnect", () => {
            document.getElementById("dot-alerts").className = "dot err";
        });
        socket.on("new_alert", alert => {
            addFeedItem(alert);
            showToast(`🚨 MALICIOUS traffic! ${(alert.probability * 100).toFixed(1)}% confidence`, "danger");
            loadAlertsHistory();
            loadDashboardData();
        });
        socket.on("history", data => {
            (data.alerts || []).slice(-5).forEach(a => addFeedItem(a, false));
        });
    } catch (err) {
        console.warn("WebSocket unavailable:", err);
    }
}

function addFeedItem(item, prepend = true) {
    const feed = document.getElementById("liveFeed");
    const empty = feed.querySelector(".feed-empty");
    if (empty) empty.remove();

    const isMal = item.label === "MALICIOUS";
    const t = new Date((item.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();
    const f = item.features || {};
    const el = document.createElement("div");
    el.className = `feed-item ${isMal ? "malicious" : "benign"}`;
    el.innerHTML = `
    <span class="feed-tag ${isMal ? "malicious" : "benign"}">${isMal ? "MALICIOUS" : "BENIGN"}</span>
    <span class="feed-meta">${t} · ${f.protocol_tcp ? "TCP" : "UDP"} · Len: ${f.packet_length ?? "?"}B · Port ${f.dest_port ?? "?"}</span>
    <span class="feed-prob">${(item.probability * 100).toFixed(1)}%</span>
  `;
    if (prepend && feed.firstChild) {
        feed.insertBefore(el, feed.firstChild);
    } else {
        feed.appendChild(el);
    }
    // Keep only last 50
    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

// ─────────────────────────────────────────────────────────────
// PREDICT FORM
// ─────────────────────────────────────────────────────────────
const PRESETS = {
    benign: { packet_length: 1200, inter_arrival_time: 0.5, protocol_tcp: 1, protocol_udp: 0, source_port: 54321, dest_port: 443 },
    ddos: { packet_length: 64, inter_arrival_time: 0.0001, protocol_tcp: 0, protocol_udp: 1, source_port: 50000, dest_port: 80 },
    scan: { packet_length: 40, inter_arrival_time: 0.01, protocol_tcp: 1, protocol_udp: 0, source_port: 12345, dest_port: 22 },
};

function initPredictForm() {
    document.querySelectorAll(".preset-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const p = PRESETS[btn.dataset.preset];
            if (!p) return;
            Object.entries(p).forEach(([k, v]) => {
                const el = document.getElementById(`f-${k}`);
                if (el) el.value = v;
            });
        });
    });

    document.getElementById("predictForm").addEventListener("submit", async e => {
        e.preventDefault();
        const btn = document.getElementById("analyzeBtn");
        btn.disabled = true;
        btn.textContent = "Analyzing…";

        const payload = {
            packet_length: parseFloat(document.getElementById("f-packet_length").value),
            inter_arrival_time: parseFloat(document.getElementById("f-inter_arrival_time").value),
            protocol_tcp: parseInt(document.getElementById("f-protocol_tcp").value),
            protocol_udp: parseInt(document.getElementById("f-protocol_udp").value),
            source_port: parseInt(document.getElementById("f-source_port").value),
            dest_port: parseInt(document.getElementById("f-dest_port").value),
        };

        try {
            const res = await fetch(`${API_URL}/predict`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            showPredictResult(data);
            addFeedItem({ ...data, timestamp: Date.now() / 1000, features: payload, source_ip: "dashboard" });
            showToast(data.label === "MALICIOUS" ? "🚨 Malicious traffic detected!" : "✅ Traffic appears benign", data.label === "MALICIOUS" ? "danger" : "success");
        } catch (err) {
            showToast("❌ API call failed — is the server running?", "danger");
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<span class="btn-icon">▶</span> Analyze Flow';
        }
    });
}

function showPredictResult(data) {
    const resultEl = document.getElementById("predictResult");
    const badge = document.getElementById("resultBadge");
    const probBar = document.getElementById("probBar");
    const probVal = document.getElementById("probValue");

    const isMal = data.label === "MALICIOUS";
    const pct = Math.round((data.probability || 0) * 100);

    badge.className = `result-badge ${isMal ? "malicious" : "benign"}`;
    badge.textContent = isMal ? "🚨 MALICIOUS" : "✅ BENIGN";
    probBar.style.width = `${pct}%`;
    probVal.textContent = `${pct}%`;

    resultEl.classList.remove("hidden");
}

// ─────────────────────────────────────────────────────────────
// BATCH FORM
// ─────────────────────────────────────────────────────────────
function initBatchForm() {
    document.getElementById("batchBtn").addEventListener("click", async () => {
        let flows;
        try {
            flows = JSON.parse(document.getElementById("batchInput").value);
        } catch {
            showToast("❌ Invalid JSON — check your input", "danger");
            return;
        }
        try {
            const res = await fetch(`${API_URL}/predict/batch`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ flows }),
            });
            const data = await res.json();
            renderBatchResults(data.results || []);
        } catch (err) {
            showToast("❌ Batch API call failed", "danger");
        }
    });
}

function renderBatchResults(results) {
    const el = document.getElementById("batchResults");
    el.classList.remove("hidden");
    el.innerHTML = `<h4 style="color:var(--text-secondary);font-size:12px;margin-bottom:10px;">Results (${results.length} flows)</h4>` +
        results.map((r, i) => {
            const isMal = r.prediction === "MALICIOUS";
            const pct = r.probability ? (r.probability * 100).toFixed(1) + "%" : "–";
            return `<div class="batch-result-item">
        <span style="color:var(--text-muted);font-size:11px;font-family:monospace">Flow ${i + 1}</span>
        <span class="label-pill ${isMal ? "malicious" : "benign"}">${r.prediction || "ERROR"}</span>
        <span style="margin-left:auto;color:var(--text-secondary);font-family:monospace;font-size:12px">${pct}</span>
      </div>`;
        }).join("");
}

// ─────────────────────────────────────────────────────────────
// SERVICE HEALTH CHECKS
// ─────────────────────────────────────────────────────────────
async function checkServices() {
    const checks = [
        { url: `${API_URL}/health`, dot: "dot-api" },
        { url: `${LOGS_URL}/health`, dot: "dot-logger" },
        { url: `${ALERTS_URL}/health`, dot: "dot-alerts" },
        { url: `${STATS_URL}/health`, dot: "dot-stats" },
    ];
    await Promise.allSettled(checks.map(async ({ url, dot }) => {
        try {
            const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
            document.getElementById(dot).className = r.ok ? "dot ok" : "dot err";
        } catch {
            document.getElementById(dot).className = "dot err";
        }
    }));
    setTimeout(checkServices, 15000);
}

// ─────────────────────────────────────────────────────────────
// TOAST
// ─────────────────────────────────────────────────────────────
function showToast(msg, type = "") {
    const container = document.getElementById("toastContainer");
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}
