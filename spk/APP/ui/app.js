const I18N = {};
const apiBase = location.pathname.endsWith(".cgi") ? location.pathname : "";

function t(key) {
  return I18N[key] || key;
}

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const text = t(el.dataset.i18nTitle);
    el.title = text;
    el.setAttribute("aria-label", text);
  });
  document.querySelectorAll("[data-help]").forEach((el) => {
    const text = t(el.dataset.help);
    el.dataset.tip = text;
    el.setAttribute("aria-label", text);
  });
  document.title = t("lang_app_title");
}

function fieldTip() {
  let tip = document.getElementById("field-tip");
  if (!tip) {
    tip = document.createElement("div");
    tip.id = "field-tip";
    tip.className = "field-tip";
    tip.setAttribute("role", "tooltip");
    document.body.append(tip);
  }
  return tip;
}

function placeFieldTip(btn) {
  const text = btn.dataset.tip || "";
  const tip = fieldTip();
  if (!text) {
    tip.classList.remove("show");
    return;
  }
  tip.textContent = text;
  tip.classList.add("show");
  tip.style.left = "0px";
  tip.style.top = "0px";
  const rect = btn.getBoundingClientRect();
  const margin = 8;
  const w = tip.offsetWidth;
  const h = tip.offsetHeight;
  let left = rect.left;
  let top = rect.top - h - margin;
  if (left + w > window.innerWidth - margin) left = window.innerWidth - margin - w;
  if (left < margin) left = margin;
  if (top < margin) top = rect.bottom + margin;
  if (top + h > window.innerHeight - margin) top = Math.max(margin, window.innerHeight - margin - h);
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;
}

function hideFieldTip() {
  fieldTip().classList.remove("show");
}

function bindFieldTips() {
  document.addEventListener("mouseover", (ev) => {
    const btn = ev.target.closest && ev.target.closest("button.info");
    if (btn) placeFieldTip(btn);
    else hideFieldTip();
  });
  document.addEventListener("focusin", (ev) => {
    const btn = ev.target.closest && ev.target.closest("button.info");
    if (btn) placeFieldTip(btn);
  });
  document.addEventListener("focusout", (ev) => {
    const btn = ev.target.closest && ev.target.closest("button.info");
    if (btn) hideFieldTip();
  });
  window.addEventListener("scroll", hideFieldTip, true);
}

async function api(action, opts) {
  let url = apiBase ? `${apiBase}?action=${encodeURIComponent(action)}` : `/api/${action}`;
  url += (url.includes("?") ? "&" : "?") + "_=" + Date.now();
  const res = await fetch(url, Object.assign({ cache: "no-store" }, opts));
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    err.status = res.status;
    throw err;
  }
  return data;
}

function notice(text) {
  document.getElementById("notice").textContent = text;
}

function linesToJson(text) {
  const list = text.split(/\n/).map((s) => s.trim()).filter(Boolean);
  return JSON.stringify(list);
}

function jsonToLines(raw) {
  try {
    const list = JSON.parse(raw || "[]");
    return Array.isArray(list) ? list.join("\n") : "";
  } catch {
    return raw || "";
  }
}

const INTERVALS = [1, 5, 10, 15, 20, 30, 60, 120];

function blocklistURL(typ) {
  return `https://lists.blocklist.de/lists/${typ || "all"}.txt`;
}

function shownSource(s) {
  const typ = s.blocklist_typ || "all";
  const url = (s.source_url || "").trim();
  if (!url) return blocklistURL(typ);
  return url;
}

function nearestInterval(raw) {
  const n = Number(raw);
  let best = INTERVALS[0];
  let diff = Infinity;
  for (const value of INTERVALS) {
    const d = Math.abs(value - n);
    if (d < diff) {
      best = value;
      diff = d;
    }
  }
  return best;
}

function intervalText(minutes) {
  return minutes === 1 ? `1 ${t("lang_minute")}` : `${minutes} ${t("lang_minutes")}`;
}

function setIntervalMinutes(raw) {
  const minutes = nearestInterval(raw);
  const index = INTERVALS.indexOf(minutes);
  document.getElementById("interval-range").value = String(index);
  document.querySelector("[name=interval_minutes]").value = String(minutes);
  document.getElementById("interval-label").textContent = intervalText(minutes);
}

function fillForm(s) {
  const form = document.getElementById("settings");
  for (const el of form.elements) {
    if (!el.name || !(el.name in s)) continue;
    if (el.type === "checkbox") el.checked = s[el.name] === "1";
    else if (el.name === "extra_sources") el.value = jsonToLines(s[el.name]);
    else if (el.name === "source_url") el.value = shownSource(s);
    else if (el.name === "geoip_countries") {
      try { el.value = JSON.parse(s[el.name]).join(", "); }
      catch { el.value = s[el.name]; }
    } else if (el.name === "interval_minutes") setIntervalMinutes(s[el.name]);
    else el.value = s[el.name];
  }
  if (!s.source_url) {
    const source = form.elements.source_url;
    if (source) source.value = shownSource(s);
  }
}

function readForm() {
  const form = document.getElementById("settings");
  const data = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === "checkbox") data[el.name] = el.checked ? "1" : "0";
    else if (el.name === "extra_sources") data[el.name] = linesToJson(el.value);
    else if (el.name === "geoip_countries") {
      const list = el.value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
      data[el.name] = JSON.stringify(list);
    } else data[el.name] = el.value.trim();
  }
  return data;
}

function fmtTime(unix) {
  if (!unix || unix < 86400) return t("lang_time_unknown");
  const d = new Date(unix * 1000);
  return d.toLocaleString();
}

function fmtDuration(ms) {
  ms = ms || 0;
  if (ms < 1000) return `${ms} ms`;
  const sec = Math.round(ms / 1000);
  const m = Math.floor(sec / 60);
  return m > 0 ? `${m}m ${sec % 60}s` : `${sec}s`;
}

function renderRuns(runs) {
  const body = document.getElementById("runs");
  body.replaceChildren();
  if (!runs || !runs.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 10;
    td.className = "empty";
    td.textContent = t("lang_stats_empty");
    tr.append(td);
    body.append(tr);
    return;
  }
  for (const run of runs) {
    const tr = document.createElement("tr");
    const cells = [
      fmtTime(run.started_at),
      t("lang_status_" + run.status) || run.status,
      fmtDuration(run.duration_ms),
      run.added, run.diffs, run.expired, run.online_count,
      run.count_before, run.count_after, run.geoip_skip,
    ];
    for (const value of cells) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    body.append(tr);
  }
}

function slotLabel(name) {
  return t("lang_slot_" + name) || name;
}

function renderBackups(slots) {
  const list = document.getElementById("backups");
  const restore = document.getElementById("restore");
  const previous = list.value;
  list.replaceChildren();
  if (!slots || !slots.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = t("lang_backup_empty");
    list.append(opt);
    list.disabled = true;
    restore.disabled = true;
    return;
  }
  list.disabled = false;
  restore.disabled = false;
  for (const slot of slots) {
    const opt = document.createElement("option");
    opt.value = slot.name;
    opt.textContent = `${slotLabel(slot.name)} · ${fmtTime(slot.unix)}`;
    list.append(opt);
  }
  if ([...list.options].some((opt) => opt.value === previous)) list.value = previous;
}

const CHART_SPANS = [7, 30, 90, 365, 0];

function chartSpan() {
  const index = Number(document.getElementById("chart-span").value);
  const span = CHART_SPANS[index];
  return span === undefined ? 30 : span;
}

function setChartLabel(span) {
  document.getElementById("chart-span-label").textContent = span
    ? `${span} ${t("lang_chart_days")}`
    : t("lang_chart_all");
}

let latestRuns = [];

function dayKey(unix) {
  const d = new Date(unix * 1000);
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

function pointFromRuns(runs) {
  if (!runs || !runs.length) return null;
  const sorted = [...runs].sort((a, b) => a.started_at - b.started_at);
  const today = dayKey(sorted[sorted.length - 1].started_at);
  const same = sorted.filter((run) => dayKey(run.started_at) === today);
  const last = same[same.length - 1];
  return {
    day: today,
    online: last.online_count || 0,
    added: same.reduce((sum, run) => sum + (run.added || 0), 0),
    total: last.count_after || 0,
  };
}

function svgEl(name, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
  return el;
}

function drawChart(points) {
  const host = document.getElementById("chart");
  host.replaceChildren();
  if (!points || !points.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = t("lang_chart_empty");
    host.append(p);
    return;
  }
  const w = 640;
  const h = 240;
  const left = 52;
  const right = 12;
  const top = 16;
  const bottom = 46;
  const plotW = w - left - right;
  const plotH = h - top - bottom;
  let max = 1;
  for (const point of points) {
    max = Math.max(max, point.total || 0, point.online || 0, point.added || 0);
  }
  const xAt = (i) => left + (points.length === 1 ? plotW / 2 : (plotW * i) / (points.length - 1));
  const yAt = (v) => top + plotH - (plotH * v) / max;
  const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, width: w, height: h, role: "img" });
  svg.append(svgEl("line", { x1: left, y1: top, x2: left, y2: top + plotH, stroke: "#d5deea" }));
  svg.append(svgEl("line", { x1: left, y1: top + plotH, x2: left + plotW, y2: top + plotH, stroke: "#d5deea" }));
  for (const frac of [0, 0.5, 1]) {
    const value = Math.round(max * frac);
    const y = yAt(value);
    svg.append(svgEl("line", { x1: left, y1: y, x2: left + plotW, y2: y, stroke: "#eef2f7" }));
    const label = svgEl("text", { x: left - 6, y: y + 4, "text-anchor": "end", fill: "#5c6b80", "font-size": "11" });
    label.textContent = value.toLocaleString();
    svg.append(label);
  }
  const series = [
    { key: "total", color: "#154889", name: t("lang_chart_total") },
    { key: "online", color: "#0f766e", name: t("lang_chart_online") },
    { key: "added", color: "#d97706", name: t("lang_chart_added") },
  ];
  for (const item of series) {
    const coords = points.map((point, i) => `${xAt(i)},${yAt(point[item.key] || 0)}`).join(" ");
    svg.append(svgEl("polyline", { points: coords, fill: "none", stroke: item.color, "stroke-width": "2" }));
    if (points.length > 120) continue;
    const radius = points.length === 1 ? 6 : 3;
    points.forEach((point, i) => {
      svg.append(svgEl("circle", { cx: xAt(i), cy: yAt(point[item.key] || 0), r: radius, fill: item.color }));
    });
  }
  const step = Math.max(1, Math.ceil(points.length / 6));
  const showYear = points[0].day.slice(0, 4) !== points[points.length - 1].day.slice(0, 4);
  points.forEach((point, i) => {
    if (i % step !== 0 && i !== points.length - 1) return;
    const label = svgEl("text", { x: xAt(i), y: top + plotH + 16, "text-anchor": "middle", fill: "#5c6b80", "font-size": "11" });
    label.textContent = showYear ? point.day.slice(2) : point.day.slice(5);
    svg.append(label);
  });
  series.forEach((item, i) => {
    const x = left + i * 150;
    const y = h - 12;
    svg.append(svgEl("line", { x1: x, y1: y - 4, x2: x + 16, y2: y - 4, stroke: item.color, "stroke-width": "3" }));
    const label = svgEl("text", { x: x + 20, y: y, fill: "#142033", "font-size": "12" });
    label.textContent = item.name;
    svg.append(label);
  });
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  tip.hidden = true;
  host.append(svg, tip);
  const nearest = (x) => {
    let best = 0;
    let bestDist = Infinity;
    for (let i = 0; i < points.length; i++) {
      const dist = Math.abs(xAt(i) - x);
      if (dist < bestDist) {
        bestDist = dist;
        best = i;
      }
    }
    return best;
  };
  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const x = ((ev.clientX - rect.left) / rect.width) * w;
    const y = ((ev.clientY - rect.top) / rect.height) * h;
    if (x < left || x > left + plotW || y < top || y > top + plotH) {
      tip.hidden = true;
      return;
    }
    const point = points[nearest(x)];
    tip.replaceChildren();
    const title = document.createElement("strong");
    title.textContent = point.day;
    tip.append(title);
    for (const item of series) {
      const row = document.createElement("div");
      const swatch = document.createElement("i");
      swatch.style.background = item.color;
      const label = document.createElement("span");
      label.textContent = `${item.name} ${(point[item.key] || 0).toLocaleString()}`;
      row.append(swatch, label);
      tip.append(row);
    }
    tip.hidden = false;
    const hostRect = host.getBoundingClientRect();
    let leftPx = ev.clientX - hostRect.left + 14;
    let topPx = ev.clientY - hostRect.top + 14;
    tip.style.left = "0px";
    tip.style.top = "0px";
    if (leftPx + tip.offsetWidth > host.clientWidth) leftPx = ev.clientX - hostRect.left - tip.offsetWidth - 10;
    if (topPx + tip.offsetHeight > host.clientHeight) topPx = ev.clientY - hostRect.top - tip.offsetHeight - 10;
    tip.style.left = `${Math.max(4, leftPx)}px`;
    tip.style.top = `${Math.max(4, topPx)}px`;
  });
  svg.addEventListener("mouseleave", () => {
    tip.hidden = true;
  });
}

async function loadChart() {
  const span = chartSpan();
  setChartLabel(span);
  let points = [];
  try {
    const url = apiBase ? `${apiBase}?action=history&days=${span}` : `/api/history?days=${span}`;
    const res = await fetch(url);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    points = data.days || [];
  } catch (err) {
    notice(t("lang_error") + ": " + err.message);
  }
  const today = pointFromRuns(latestRuns);
  if (today && !points.some((point) => point.day === today.day)) points.push(today);
  points.sort((a, b) => a.day < b.day ? -1 : a.day > b.day ? 1 : 0);
  drawChart(points);
}

let statusKey = "";
let lastRunning = false;

async function refreshAfterRun() {
  const [stats, backups] = await Promise.all([
    api("stats"),
    api("backups"),
  ]);
  latestRuns = stats.runs || [];
  renderRuns(latestRuns);
  renderBackups(backups.slots);
  await loadChart();
}

async function refreshStatus() {
  const st = await api("status");
  const status = document.getElementById("status");
  const progress = document.getElementById("run-progress");
  const running = !!st.running;
  const key = (running ? "1" : "0") + (st.scheduler ? "1" : "0");
  if (key !== statusKey) {
    statusKey = key;
    status.replaceChildren();
    const bits = [];
    if (running) bits.push(document.createTextNode(t("lang_running")));
    const sched = document.createElement("span");
    sched.textContent = st.scheduler ? t("lang_scheduler_on") : t("lang_scheduler_off");
    if (st.scheduler && !running) sched.className = "live";
    bits.push(sched);
    bits.forEach((bit, i) => {
      if (i) status.append(" · ");
      status.append(bit);
    });
  }
  if (progress) {
    progress.classList.toggle("active", running);
    progress.setAttribute("aria-hidden", running ? "false" : "true");
  }
  if (lastRunning && !running) refreshAfterRun().catch(() => {});
  lastRunning = running;
  return running;
}

async function refresh() {
  const [settings, stats, backups] = await Promise.all([
    api("settings"),
    api("stats"),
    api("backups"),
  ]);
  fillForm(settings);
  latestRuns = stats.runs || [];
  renderRuns(latestRuns);
  renderBackups(backups.slots);
  await loadChart();
  await refreshStatus();
}

document.getElementById("settings").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(readForm()),
    });
    notice(t("lang_saved"));
    await refreshStatus();
  } catch (err) {
    notice(t("lang_error") + ": " + err.message);
  }
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function watchRun() {
  let saw = false;
  for (let i = 0; i < 240; i++) {
    const running = await refreshStatus();
    if (running) saw = true;
    if (saw && !running) {
      await refresh();
      return;
    }
    if (!saw && i >= 4) {
      await refresh();
      return;
    }
    await sleep(500);
  }
}

document.getElementById("run").addEventListener("click", async () => {
  try {
    await api("run", { method: "POST" });
    notice(t("lang_run_started"));
    await watchRun();
  } catch (err) {
    notice(err.status === 409 ? t("lang_run_busy") : t("lang_error") + ": " + err.message);
  }
});

document.getElementById("showlog").addEventListener("click", async () => {
  const log = document.getElementById("log");
  const data = await api("log");
  log.hidden = false;
  log.textContent = data.text || t("lang_log_empty");
});

document.getElementById("clearlog").addEventListener("click", async () => {
  await api("log", { method: "POST" });
  const log = document.getElementById("log");
  log.hidden = false;
  log.textContent = t("lang_log_empty");
});

document.getElementById("restore").addEventListener("click", async () => {
  const slot = document.getElementById("backups").value;
  if (!slot) return;
  if (!confirm(t("lang_backup_confirm"))) return;
  try {
    await api("restore", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ slot }) });
    notice(t("lang_saved"));
    await refresh();
  } catch (err) {
    notice(t("lang_error") + ": " + err.message);
  }
});

document.getElementById("clearblock").addEventListener("click", async () => {
  if (!confirm(t("lang_clear_confirm"))) return;
  try {
    const data = await api("clear", { method: "POST" });
    let text = t("lang_cleared");
    if (typeof data.removed === "number") text += " (" + data.removed.toLocaleString() + ")";
    notice(text);
    await refresh();
  } catch (err) {
    notice(err.status === 409 ? t("lang_run_busy") : t("lang_error") + ": " + err.message);
  }
});

document.getElementById("reload").addEventListener("click", async () => {
  const btn = document.getElementById("reload");
  btn.disabled = true;
  btn.classList.add("spin");
  try {
    await refresh();
  } catch (err) {
    notice(t("lang_error") + ": " + err.message);
  } finally {
    btn.classList.remove("spin");
    btn.disabled = false;
  }
});

document.getElementById("chart-span").addEventListener("input", () => {
  setChartLabel(chartSpan());
  loadChart();
});

document.getElementById("interval-range").addEventListener("input", (ev) => {
  setIntervalMinutes(INTERVALS[Number(ev.target.value)]);
});

document.querySelector("[name=blocklist_typ]").addEventListener("change", (ev) => {
  const source = document.querySelector("[name=source_url]");
  const current = source.value.trim();
  if (!current || /^https:\/\/lists\.blocklist\.de\/lists\/[a-z]+\.txt$/.test(current)) {
    source.value = blocklistURL(ev.target.value);
  }
});

(async function boot() {
  try {
    const pack = await api("i18n");
    Object.assign(I18N, pack.strings || {});
    applyI18n();
    bindFieldTips();
    const support = document.getElementById("support");
    if (support) support.href = apiBase ? `${apiBase}?action=support` : "/api/support";
    const deny = document.querySelector("[name=deny]");
    if (deny && deny.options.length > 1) {
      deny.options[0].textContent = t("lang_deny_black");
      deny.options[1].textContent = t("lang_deny_white");
    }
    await refresh();
    setInterval(() => {
      refreshStatus().catch(() => {});
    }, 1000);
  } catch (err) {
    notice(String(err.message || err));
  }
})();
