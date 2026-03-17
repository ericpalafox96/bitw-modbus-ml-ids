const elHealth = document.getElementById("pill-health");
const elLog = document.getElementById("pill-log");
const elLast = document.getElementById("pill-last");

const elKpiEvents = document.getElementById("kpi-events");
const elKpiAttackRate = document.getElementById("kpi-attackrate");
const elKpiTopClass = document.getElementById("kpi-topclass");
const elKpiCritical = document.getElementById("kpi-critical");

const elReportConfidence = document.getElementById("report-confidence");
const elReportRecent = document.getElementById("report-recent");
const elReportSources = document.getElementById("report-sources");

const elBody = document.getElementById("events-body");
const elEmpty = document.getElementById("empty-state");

const selClass = document.getElementById("filter-class");
const selConf = document.getElementById("filter-conf");
const selSince = document.getElementById("filter-since");
const txtSearch = document.getElementById("filter-search");

const drawer = document.getElementById("drawer");
const analystNote = document.getElementById("analyst-note");
const noteStatus = document.getElementById("note-status");

document.getElementById("drawer-close").addEventListener("click", () => drawer.classList.remove("open"));
document.getElementById("btn-refresh").addEventListener("click", () => refreshAll(true));
document.getElementById("btn-export").addEventListener("click", exportCsv);

document.getElementById("btn-ack").addEventListener("click", () => setLocalStatus("acknowledged"));
document.getElementById("btn-investigating").addEventListener("click", () => setLocalStatus("investigating"));
document.getElementById("btn-resolved").addEventListener("click", () => setLocalStatus("resolved"));
document.getElementById("btn-save-note").addEventListener("click", saveLocalNote);

let currentEventId = null;
let currentEventStatus = "new";

const CLASS_TO_STYLE = {
  normal: "normal",
  timing_attack: "timing",
  replay_attack: "replay",
  command_injection: "inject",
};

const SEVERITY_TO_STYLE = {
  info: "sev-info",
  medium: "sev-medium",
  high: "sev-high",
  critical: "sev-critical",
};

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function pct(x) {
  return `${Math.round(x * 100)}%`;
}

function badge(cls) {
  const style = CLASS_TO_STYLE[cls] || "normal";
  return `<span class="badge"><span class="dot ${style}"></span>${cls}</span>`;
}

function severityBadge(sev) {
  const style = SEVERITY_TO_STYLE[sev] || "sev-info";
  return `<span class="sev-badge ${style}">${sev}</span>`;
}

function apiUrl(path, params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== "") q.set(k, v);
  }
  return q.toString() ? `${path}?${q.toString()}` : path;
}

async function api(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

let chart;

async function initChart() {
  const ctx = document.getElementById("chart");
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "normal", data: [] },
        { label: "timing_attack", data: [] },
        { label: "replay_attack", data: [] },
        { label: "command_injection", data: [] },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { color: "#e5e7eb" } } },
      scales: {
        x: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.05)" } },
      },
    },
  });
}

function noteKey(id) {
  return `ids_note_${id}`;
}

function statusKey(id) {
  return `ids_status_${id}`;
}

function getLocalStatus(id, fallback = "new") {
  return localStorage.getItem(statusKey(id)) || fallback;
}

function setLocalStatus(status) {
  if (!currentEventId) return;
  localStorage.setItem(statusKey(currentEventId), status);
  currentEventStatus = status;
  noteStatus.textContent = `Status saved locally: ${status}`;
  document.getElementById("d-action").textContent = document.getElementById("d-action").textContent;
  refreshEvents();
}

function saveLocalNote() {
  if (!currentEventId) return;
  localStorage.setItem(noteKey(currentEventId), analystNote.value || "");
  noteStatus.textContent = "Note saved locally in browser.";
}

async function refreshHealth() {
  try {
    await api("/api/health");
    elHealth.textContent = "Online";
    elHealth.style.borderColor = "rgba(34,197,94,0.35)";

    const s = await api("/api/log_status");

    elLog.textContent = s.log_exists
      ? `Log: ${Number(s.log_bytes || 0).toLocaleString()} bytes`
      : "Log: missing";

    if (s.last_event_age_sec == null) {
      elLast.textContent = "Last event: —";
      elLast.style.borderColor = "rgba(255,255,255,0.10)";
    } else {
      const age = Number(s.last_event_age_sec);
      const pred = s.last_prediction || "n/a";
      const conf = s.last_confidence == null ? "" : ` • ${Number(s.last_confidence).toFixed(2)}`;
      elLast.textContent = `Last event: ${age.toFixed(1)}s ago • ${pred}${conf}`;

      if (age < 2) elLast.style.borderColor = "rgba(34,197,94,0.35)";
      else if (age < 10) elLast.style.borderColor = "rgba(245,158,11,0.35)";
      else elLast.style.borderColor = "rgba(239,68,68,0.35)";
    }
  } catch {
    elHealth.textContent = "Offline";
    elHealth.style.borderColor = "rgba(239,68,68,0.35)";
    elLog.textContent = "Log: —";
    elLast.textContent = "Last event: —";
    elLast.style.borderColor = "rgba(255,255,255,0.10)";
  }
}

async function refreshSummary() {
  const s = await api("/api/summary");
  const one = s.last_1m;

  elKpiEvents.textContent = one.events;
  elKpiAttackRate.textContent = pct(one.attack_rate);
  elKpiTopClass.textContent = one.top_class;
  elKpiCritical.textContent = one.severity_counts.critical || 0;
}

async function refreshReport() {
  const r = await api("/api/report?window=900");
  elReportConfidence.textContent = Number(r.average_confidence || 0).toFixed(2);
  elReportRecent.textContent = r.most_recent_prediction || "—";

  if (!r.top_sources || r.top_sources.length === 0) {
    elReportSources.innerHTML = `<div class="empty-text">No source statistics available.</div>`;
    return;
  }

  elReportSources.innerHTML = r.top_sources
    .map((s) => `<div class="source-row"><span>${s.src_ip}</span><span>${s.count}</span></div>`)
    .join("");
}

function renderRows(items) {
  if (!items || items.length === 0) {
    elBody.innerHTML = "";
    elEmpty.classList.remove("hidden");
    return;
  }

  elEmpty.classList.add("hidden");

  elBody.innerHTML = items.map((e) => {
    const flow = `${e.src_ip || "?"}${e.src_port ? ":" + e.src_port : ""} → ${e.dst_ip || "?"}:${e.dst_port || 502}`;
    const localStatus = getLocalStatus(e.id, e.status || "new");

    return `
      <tr data-id="${e.id}">
        <td>${fmtTime(e.ts)}</td>
        <td>${badge(e.prediction)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td>${Number(e.confidence || 0).toFixed(2)}</td>
        <td>${e.policy_action || ""}</td>
        <td>${localStatus}</td>
        <td>${flow}</td>
      </tr>
    `;
  }).join("");

  [...elBody.querySelectorAll("tr")].forEach((tr) => {
    tr.addEventListener("click", () => openDetail(tr.getAttribute("data-id")));
  });
}

async function refreshEvents() {
  const params = {
    limit: 800,
    cls: selClass.value,
    min_conf: selConf.value,
    since_seconds: selSince.value,
    q: txtSearch.value.trim(),
  };

  const out = await api(apiUrl("/api/events", params));
  renderRows(out.items);
}

async function refreshTimeseries() {
  const t = await api("/api/timeseries?seconds=600&bucket=10");
  chart.data.labels = t.labels.map((x) => fmtTime(x));
  chart.data.datasets[0].data = t.series.normal;
  chart.data.datasets[1].data = t.series.timing_attack;
  chart.data.datasets[2].data = t.series.replay_attack;
  chart.data.datasets[3].data = t.series.command_injection;
  chart.update();
}

async function openDetail(id) {
  const d = await api(`/api/event/${id}`);
  currentEventId = id;
  currentEventStatus = getLocalStatus(id, d.status || "new");

  drawer.classList.add("open");

  const flow = `${d.src_ip || "?"}${d.src_port ? ":" + d.src_port : ""} → ${d.dst_ip || "?"}:${d.dst_port || 502}`;
  document.getElementById("drawer-sub").textContent = `${fmtTime(d.ts)} • ${flow}`;

  document.getElementById("d-class").textContent = d.prediction || "—";
  document.getElementById("d-severity").textContent = d.severity || "—";
  document.getElementById("d-conf").textContent = Number(d.confidence || 0).toFixed(2);
  document.getElementById("d-action").textContent = `${d.policy_action || "—"} • status: ${currentEventStatus}`;
  document.getElementById("d-protocol").textContent = d.protocol || "modbus_tcp";

  const modelName = d.model && (d.model.name || d.model.version)
    ? `${d.model.name || ""} ${d.model.version || ""}`.trim()
    : "—";
  document.getElementById("d-model").textContent = modelName;
  document.getElementById("d-response").textContent = d.recommended_response || "—";

  analystNote.value = localStorage.getItem(noteKey(id)) || "";
  noteStatus.textContent = analystNote.value ? "Loaded saved local note." : "No note saved.";

  const list = document.getElementById("feat-list");
  const feats = d.top_features || [];
  list.innerHTML = feats.length
    ? feats.map((f) => {
        const v = Number(f.value);
        const show = Number.isFinite(v) ? v.toFixed(6) : String(f.value);
        return `<div class="feat"><div class="feat-name">${f.name}</div><div class="feat-val">${show}</div></div>`;
      }).join("")
    : `<div class="empty-text">No feature data available for this event.</div>`;
}

function exportCsv() {
  const url = apiUrl("/api/export/events.csv", {
    limit: 5000,
    cls: selClass.value,
    min_conf: selConf.value,
    since_seconds: selSince.value,
    q: txtSearch.value.trim(),
  });
  window.open(url, "_blank");
}

async function refreshAll(full) {
  await refreshHealth();
  await refreshSummary();
  await refreshReport();
  await refreshEvents();
  if (full) await refreshTimeseries();
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);

  ws.onmessage = () => {
    refreshHealth();
    refreshSummary();
    refreshReport();
    refreshEvents();
  };

  ws.onclose = () => setTimeout(connectWs, 1000);
}

txtSearch.addEventListener("input", () => refreshEvents());
selClass.addEventListener("change", () => refreshEvents());
selConf.addEventListener("change", () => refreshEvents());
selSince.addEventListener("change", () => refreshEvents());

(async function main() {
  await initChart();
  await refreshAll(true);
  connectWs();
  setInterval(() => refreshTimeseries(), 5000);
})();