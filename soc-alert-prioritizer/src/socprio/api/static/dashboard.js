(() => {
  "use strict";

  const COLORS = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };
  const PRIORITIES = ["critical", "high", "medium", "low"];
  const OPEN = ["new", "investigating", "monitoring"];
  const PAGE_SIZE = 25;
  const REFRESH_MS = 15000;

  const state = { priorities: new Set(), offset: 0, total: 0, timer: null };
  const $ = (id) => document.getElementById(id);

  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  const formatTime = (iso) => {
    const d = new Date(iso);
    return d.toLocaleString(undefined, { month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  const plotLayout = (extra = {}) => ({
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: "#8b93a7", size: 11 }, margin: { t: 10, r: 10, b: 30, l: 40 },
    xaxis: { gridcolor: "#232b3d" }, yaxis: { gridcolor: "#232b3d" },
    legend: { orientation: "h", y: -0.18 }, ...extra,
  });

  async function fetchJson(url) {
    const response = await fetch(url, { credentials: "same-origin" });
    if (response.status === 401) {
      window.location = "/login";  // session expired
      throw new Error("not authenticated");
    }
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    return response.json();
  }

  async function loadStats() {
    const hours = $("window").value;
    const stats = await fetchJson(`/api/stats?hours=${hours}`);
    for (const p of PRIORITIES) $(`k-${p}`).textContent = stats.by_priority[p] ?? 0;
    $("k-open").textContent = stats.open;
    $("k-events").textContent = stats.events.toLocaleString();
    $("k-noise").textContent = `${(stats.noise_reduction * 100).toFixed(1)}%`;

    const traces = PRIORITIES.map((p) => {
      const points = stats.timeline.filter((t) => t.priority === p);
      return { type: "bar", name: p, marker: { color: COLORS[p] },
        x: points.map((t) => t.time), y: points.map((t) => t.count) };
    });
    Plotly.react("chart-timeline", traces, plotLayout({ barmode: "stack" }),
      { displayModeBar: false, responsive: true });

    const types = Object.entries(stats.by_type).sort((a, b) => a[1] - b[1]);
    Plotly.react("chart-types", [{
      type: "bar", orientation: "h", marker: { color: "#3b82f6" },
      x: types.map((t) => t[1]), y: types.map((t) => t[0]),
    }], plotLayout({ margin: { t: 10, r: 10, b: 30, l: 130 }, showlegend: false }),
    { displayModeBar: false, responsive: true });

    $("top-sources").innerHTML = stats.top_sources.length
      ? stats.top_sources.map((s) => `
          <tr class="clickable" data-search="${escapeHtml(s.src_ip)}">
            <td class="mono">${escapeHtml(s.src_ip)}</td><td>${Number(s.alerts) || 0}</td>
            <td>${Number(s.max_score) || 0}</td></tr>`).join("")
      : `<tr><td colspan="3" class="empty">No data</td></tr>`;
  }

  function scoreCell(alert) {
    const color = COLORS[alert.priority] ?? "#8b93a7";
    const score = Math.max(0, Math.min(100, Number(alert.risk_score) || 0));
    return `<div class="score"><div class="bar"><span style="width:${score}%;
      background:${color}"></span></div><b>${score}</b></div>`;
  }

  async function loadAlerts() {
    const params = new URLSearchParams({
      limit: PAGE_SIZE, offset: state.offset, sort: $("sort").value, hours: $("window").value,
    });
    for (const p of state.priorities) params.append("priority", p);
    const status = $("status-filter").value;
    for (const s of status === "open" ? OPEN : status ? [status] : []) params.append("status", s);
    const q = $("search").value.trim();
    if (q) params.set("q", q);

    const page = await fetchJson(`/api/alerts?${params}`);
    state.total = page.total;
    $("alerts").innerHTML = page.items.length
      ? page.items.map((a) => `
        <tr class="clickable" data-id="${escapeHtml(a.id)}">
          <td>${formatTime(a.last_seen)}</td>
          <td><span class="badge ${PRIORITIES.includes(a.priority) ? a.priority : ""}">
            ${escapeHtml(a.priority)}</span></td>
          <td>${scoreCell(a)}</td>
          <td>${escapeHtml(a.alert_type)}</td>
          <td class="sig" title="${escapeHtml(a.signature)}">${escapeHtml(a.signature)}</td>
          <td class="mono">${escapeHtml(a.src_ip ?? "-")}</td>
          <td class="mono">${escapeHtml(a.dst_ip ?? "-")}</td>
          <td>${Number(a.occurrences) || 0}</td>
          <td class="status">${escapeHtml(a.status.replace("_", " "))}</td>
        </tr>`).join("")
      : `<tr><td colspan="9" class="empty">No alerts match the current filters.</td></tr>`;

    const first = page.total ? state.offset + 1 : 0;
    const last = Math.min(state.offset + PAGE_SIZE, page.total);
    $("page-info").textContent = `${first}-${last} of ${page.total}`;
    $("prev").disabled = state.offset === 0;
    $("next").disabled = last >= page.total;
  }

  async function refresh() {
    try {
      await Promise.all([loadStats(), loadAlerts()]);
    } catch (err) {
      console.error(err);
    }
  }

  function resetAndLoad() {
    state.offset = 0;
    loadAlerts().catch(console.error);
  }

  function scheduleRefresh() {
    clearInterval(state.timer);
    if ($("autorefresh").checked) state.timer = setInterval(refresh, REFRESH_MS);
  }

  function bind() {
    document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
      const p = chip.dataset.p;
      state.priorities.has(p) ? state.priorities.delete(p) : state.priorities.add(p);
      chip.classList.toggle("active");
      resetAndLoad();
    }));
    ["status-filter", "sort"].forEach((id) => $(id).addEventListener("change", resetAndLoad));
    $("window").addEventListener("change", () => {
      const hours = $("window").value;
      $("report-link").href = `/api/report.html?hours=${hours}`;
      $("csv-link").href = `/api/report.csv?hours=${hours}`;
      state.offset = 0;
      refresh();
    });
    let debounce;
    $("search").addEventListener("input", () => {
      clearTimeout(debounce);
      debounce = setTimeout(resetAndLoad, 250);
    });
    $("prev").addEventListener("click", () => {
      state.offset = Math.max(0, state.offset - PAGE_SIZE);
      loadAlerts().catch(console.error);
    });
    $("next").addEventListener("click", () => {
      state.offset += PAGE_SIZE;
      loadAlerts().catch(console.error);
    });
    $("alerts").addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-id]");
      if (row) window.location = `/alerts/${encodeURIComponent(row.dataset.id)}`;
    });
    $("top-sources").addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-search]");
      if (!row) return;
      $("search").value = row.dataset.search;
      resetAndLoad();
    });
    $("autorefresh").addEventListener("change", scheduleRefresh);
  }

  bind();
  refresh();
  scheduleRefresh();
})();
