"use strict";

const SEV = ["info", "low", "medium", "high", "critical"];
const SEV_COLOR = {
  info: "#6b7280", low: "#3b82f6", medium: "#f59e0b",
  high: "#f97316", critical: "#ef4444",
};
const RISK_COLOR = (s) =>
  s >= 80 ? "#ef4444" : s >= 55 ? "#f97316" : s >= 30 ? "#f59e0b" :
  s >= 10 ? "#3b82f6" : "#22c55e";

let activeSevFilter = "all";
let apSearch = "";
let lastState = null;

function el(id) { return document.getElementById(id); }
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function ago(ts) {
  if (!ts) return "-";
  const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (d < 60) return d + "s ago";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  return Math.floor(d / 3600) + "h ago";
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

function setStatus(live) {
  el("status-dot").className = "dot" + (live ? " live" : "");
  el("status-text").textContent = live ? "monitoring" : "offline";
}

function renderRisk(s) {
  const risk = s.risk || 0;
  el("risk-score").textContent = risk;
  el("risk-score").style.color = RISK_COLOR(risk);
  const label =
    risk >= 80 ? "critical" : risk >= 55 ? "high" : risk >= 30 ? "elevated" :
    risk >= 10 ? "guarded" : "clear";
  el("risk-label").textContent = label;
  el("risk-label").style.color = RISK_COLOR(risk);
  el("risk-fill").style.width = risk + "%";
  el("stat-aps").textContent = s.ap_count;
  const threats = (s.detections || []).filter((d) => d.severity_value >= 2).length;
  el("stat-threats").textContent = threats;
  el("stat-threats").style.color = threats ? "#f97316" : "var(--text)";
  el("stat-scans").textContent = s.scan_count;
}

function renderSevBreakdown(s) {
  const c = s.severity_counts || {};
  el("sev-breakdown").innerHTML = SEV.slice().reverse().map((k) =>
    `<div class="sev-row"><span class="swatch" style="background:${SEV_COLOR[k]}"></span>
     <span>${k}</span><span class="c">${c[k] || 0}</span></div>`).join("");
}

function renderFilters() {
  const opts = ["all"].concat(SEV.slice().reverse());
  el("sev-filters").innerHTML = opts.map((k) =>
    `<span class="chip ${activeSevFilter === k ? "active" : ""}" data-sev="${k}">${k}</span>`
  ).join("");
  el("sev-filters").querySelectorAll(".chip").forEach((ch) =>
    ch.addEventListener("click", () => {
      activeSevFilter = ch.dataset.sev;
      renderFilters();
      if (lastState) renderAlerts(lastState);
    }));
}

function renderAlerts(s) {
  let items = s.detections || [];
  if (activeSevFilter !== "all")
    items = items.filter((d) => d.severity === activeSevFilter);
  if (!items.length) {
    el("alerts").innerHTML = `<div class="empty">No ${
      activeSevFilter === "all" ? "" : activeSevFilter + " "}threats in the current scan.</div>`;
    return;
  }
  el("alerts").innerHTML = items.map((d) => {
    const col = SEV_COLOR[d.severity];
    return `<div class="alert" style="border-left-color:${col}">
      <div class="a-head">
        <span class="badge" style="background:${col}">${d.severity}</span>
        <span class="a-title">${esc(d.title)}</span>
        <span class="a-score">score ${d.score}</span>
      </div>
      <div class="a-target">${esc(d.ssid)} · ${esc(d.bssid)}</div>
      <div class="a-detail">${esc(d.detail)}</div>
      ${d.recommendation ? `<div class="a-rec">${esc(d.recommendation)}</div>` : ""}
    </div>`;
  }).join("");
}

function renderChannels(s) {
  const counts = {};
  (s.access_points || []).forEach((a) => {
    if (a.channel) counts[a.channel] = (counts[a.channel] || 0) + 1;
  });
  const entries = Object.entries(counts).sort((a, b) => Number(a[0]) - Number(b[0]));
  const max = Math.max(1, ...entries.map((e) => e[1]));
  if (!entries.length) { el("channels").innerHTML = `<div class="empty">No channel data.</div>`; return; }
  el("channels").innerHTML = entries.map(([ch, n]) =>
    `<div class="chan-row"><span class="chan-label">ch ${ch}</span>
      <div class="chan-bar"><div class="chan-fill" style="width:${(n / max) * 100}%"></div></div>
      <span class="chan-count">${n}</span></div>`).join("");
}

function threatBssids(s) {
  const set = new Set();
  (s.detections || []).forEach((d) => { if (d.severity_value >= 2) set.add(d.bssid); });
  return set;
}

function renderAps(s) {
  const threats = threatBssids(s);
  let rows = s.access_points || [];
  const q = apSearch.trim().toLowerCase();
  if (q) rows = rows.filter((a) =>
    (a.ssid + " " + a.bssid + " " + (a.vendor || "")).toLowerCase().includes(q));
  rows.sort((a, b) => (threats.has(b.bssid) - threats.has(a.bssid)) || (b.signal - a.signal));
  el("ap-rows").innerHTML = rows.map((a) => {
    const isThreat = threats.has(a.bssid);
    const sigCol = a.signal >= 60 ? "#22c55e" : a.signal >= 35 ? "#f59e0b" : "#ef4444";
    const secure = !a.open;
    return `<tr class="${isThreat ? "threat " : ""}${a.trusted ? "trusted" : ""}">
      <td>${esc(a.ssid)}${isThreat ? ' <span class="badge" style="background:#ef4444">threat</span>' : ""}</td>
      <td class="bssid">${esc(a.bssid)}</td>
      <td>${esc(a.vendor || "-")}</td>
      <td><span class="pill ${secure ? "secure" : "open"}">${esc(a.auth || "Open")}</span></td>
      <td class="mono">${esc(a.band || "-")}</td>
      <td class="mono">${a.channel || "-"}</td>
      <td><div class="sig"><div class="sig-bar"><div class="sig-fill"
        style="width:${a.signal}%;background:${sigCol}"></div></div>
        <span class="mono">${a.signal}%</span></div></td>
      <td>${a.trusted ? '<span class="pill secure">trusted</span>' : '<span class="muted small">unknown</span>'}</td>
      <td>${a.trusted
        ? `<button class="tbtn" data-act="remove" data-bssid="${esc(a.bssid)}">untrust</button>`
        : `<button class="tbtn" data-act="add" data-bssid="${esc(a.bssid)}">trust</button>`}</td>
    </tr>`;
  }).join("");
  el("ap-rows").querySelectorAll(".tbtn").forEach((b) =>
    b.addEventListener("click", async () => {
      await api("/api/baseline/" + b.dataset.act,
        { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bssid: b.dataset.bssid }) });
      refresh();
    }));
}

function render(s) {
  lastState = s;
  setStatus(true);
  renderRisk(s);
  renderSevBreakdown(s);
  renderAlerts(s);
  renderChannels(s);
  renderAps(s);
  el("source").textContent = (s.access_points[0] && "live") || "demo";
  el("last-scan").textContent = ago(s.last_scan_ts);
}

async function refresh() {
  try { render(await api("/api/state")); }
  catch (e) { setStatus(false); }
}

function wire() {
  el("btn-scan").addEventListener("click", async () => {
    el("btn-scan").textContent = "scanning…";
    render(await api("/api/scan"));
    el("btn-scan").textContent = "Rescan now";
  });
  el("btn-learn").addEventListener("click", async () => {
    await api("/api/baseline/learn", { method: "POST" });
    refresh();
  });
  el("btn-clear").addEventListener("click", async () => {
    await api("/api/baseline/clear", { method: "POST" });
    refresh();
  });
  el("ap-search").addEventListener("input", (e) => {
    apSearch = e.target.value;
    if (lastState) renderAps(lastState);
  });
  renderFilters();
}

wire();
refresh();
setInterval(refresh, 4000);
