const elHealth = document.getElementById("pill-health");
const elLog = document.getElementById("pill-log");

const elKpiEvents = document.getElementById("kpi-events");
const elKpiAttackRate = document.getElementById("kpi-attackrate");
const elKpiTopClass = document.getElementById("kpi-topclass");

const elBody = document.getElementById("events-body");
const selClass = document.getElementById("filter-class");
const selConf = document.getElementById("filter-conf");
const selSince = document.getElementById("filter-since");

document.getElementById("btn-refresh").addEventListener("click", () => refreshAll(true));

const drawer = document.getElementById("drawer");
document.getElementById("drawer-close").addEventListener("click", () => drawer.classList.remove("open"));

const CLASS_TO_STYLE = {
  normal: "normal",
  timing_attack: "timing",
  replay_attack: "replay",
  command_injection: "inject",
};

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function badge(cls) {
  const style = CLASS_TO_STYLE[cls] || "normal";
  return `<span class="badge"><span class="dot ${style}"></span>${cls}</span>`;
}

function pct(x) {
  return `${Math.round(x * 100)}%`;
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

async function refreshHealth() {
  try {
    const h = await api("/api/health");
    elHealth.textContent = "Online";
    elHealth.style.borderColor = "rgba(34,197,94,0.35)";

    if (h.log_exists) {
      elLog.textContent = `Log: ${h.log_bytes.toLocaleString()} bytes`;
    } else {
      elLog.textContent = "Log: missing";
    }
  } catch {
    elHealth.textContent = "Offline";
    elHealth.style.borderColor = "rgba(239,68,68,0.35)";
    elLog.textContent = "Log: —";
  }
}

async function refreshSummary() {
  const s = await api("/api/summary");
  const one = s.last_1m;

  elKpiEvents.textContent = one.events;
  elKpiAttackRate.textContent = pct(one.attack_rate);
  elKpiTopClass.textContent = one.top_class;
}

function renderRows(items) {
  elBody.innerHTML = items
    .map((e) => {
      const flow = `${e.src_ip || "?"}${e.src_port ? ":" + e.src_port : ""} → ${e.dst_ip || "?"}:${e.dst_port || 502}`;
      return `
        <tr data-id="${e.id}">
          <td>${fmtTime(e.ts)}</td>
          <td>${badge(e.prediction)}</td>
          <td>${Number(e.confidence || 0).toFixed(2)}</td>
          <td>${e.policy_action || ""}</td>
          <td>${flow}</td>
        </tr>
      `;
    })
    .join("");

  [...elBody.querySelectorAll("tr")].forEach((tr) => {
    tr.addEventListener("click", () => openDetail(tr.getAttribute("data-id")));
  });
}

async function refreshEvents() {
  const cls = selClass.value;
  const minConf = selConf.value;
  const since = selSince.value;

  const q = new URLSearchParams();
  q.set("limit", "500");
  if (cls) q.set("cls", cls);
  q.set("min_conf", minConf);
  if (since) q.set("since_seconds", since);

  const out = await api(`/api/events?${q.toString()}`);
  renderRows(out.items);
}

async function refreshTimeseries() {
  const t = await api("/api/timeseries?seconds=600&bucket=10");
  const labels = t.labels.map((x) => fmtTime(x));

  chart.data.labels = labels;
  chart.data.datasets[0].data = t.series.normal;
  chart.data.datasets[1].data = t.series.timing_attack;
  chart.data.datasets[2].data = t.series.replay_attack;
  chart.data.datasets[3].data = t.series.command_injection;

  chart.update();
}

async function openDetail(id) {
  const d = await api(`/api/event/${id}`);
  drawer.classList.add("open");

  const flow = `${d.src_ip || "?"}${d.src_port ? ":" + d.src_port : ""} → ${d.dst_ip || "?"}:${d.dst_port || 502}`;
  document.getElementById("drawer-sub").textContent = `${fmtTime(d.ts)} • ${flow}`;

  document.getElementById("d-class").textContent = d.prediction;
  document.getElementById("d-conf").textContent = Number(d.confidence || 0).toFixed(2);
  document.getElementById("d-action").textContent = d.policy_action || "";

  const modelName = (d.model && (d.model.name || d.model.version)) ? `${d.model.name || ""} ${d.model.version || ""}`.trim() : "—";
  document.getElementById("d-model").textContent = modelName;

  const list = document.getElementById("feat-list");
  const feats = d.top_features || [];
  list.innerHTML = feats
    .map((f) => {
      const v = Number(f.value);
      const show = Number.isFinite(v) ? v.toFixed(6) : String(f.value);
      return `<div class="feat"><div class="feat-name">${f.name}</div><div class="feat-val">${show}</div></div>`;
    })
    .join("");
}

async function refreshAll(full) {
  await refreshHealth();
  await refreshSummary();
  await refreshEvents();
  if (full) await refreshTimeseries();
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);

  ws.onmessage = () => {
    // A new real event was appended to JSONL
    // Refresh lightweight pieces; chart refresh is throttled separately
    refreshHealth();
    refreshSummary();
    refreshEvents();
  };

  ws.onclose = () => setTimeout(connectWs, 1000);
}

(async function main() {
  await initChart();
  await refreshAll(true);
  connectWs();
  setInterval(() => refreshTimeseries(), 5000);
})();