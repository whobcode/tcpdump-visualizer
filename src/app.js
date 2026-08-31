/**
 * The page.
 *
 * Analysis runs once, over the whole capture, and the filter is a *display*
 * filter — it changes which rows you are shown, never what was analysed.
 * Filtering the input instead would be quietly wrong: a retransmission is only
 * a retransmission relative to the packets before it, so hiding half a capture
 * and re-running the analysis describes a capture that never existed.
 */
import { parseCapture, LINKTYPE_NAMES } from "./parse/index.js";
import { analyze, followStream, labelPort, EVENT } from "./analyze/index.js";
import * as fmt from "./format.js";

const PACKET_PAGE = 500;

const state = {
  capture: null,
  result: null,
  filter: { text: "", protocol: "", problemsOnly: false },
  tab: "overview",
  packetLimit: PACKET_PAGE,
  focusPacket: null,
  sort: {
    conversations: { key: "bytes", asc: false },
    endpoints: { key: "bytes", asc: false },
    streams: { key: "packets", asc: false },
  },
  charts: {},
};

const $ = (id) => document.getElementById(id);
const el = {
  uploadArea: $("uploadArea"), fileInput: $("fileInput"),
  loading: $("loadingSection"), results: $("resultsSection"),
  captureInfo: $("captureInfo"), captureError: $("captureError"),
  statsGrid: $("statsGrid"), tabs: $("tabs"),
  filterText: $("filterText"), filterProtocol: $("filterProtocol"),
  filterProblems: $("filterProblems"), clearFilter: $("clearFilter"),
  filterHint: $("filterHint"),
  packetTable: $("packetTable"), packetNote: $("packetNote"),
  loadMore: $("loadMorePackets"), findingList: $("findingList"),
  overviewSummary: $("overviewSummary"), streamModal: $("streamModal"),
};

/* ---------------------------------------------------------------- loading */

el.uploadArea.addEventListener("click", () => el.fileInput.click());
el.uploadArea.addEventListener("dragover", (e) => {
  e.preventDefault();
  el.uploadArea.classList.add("dragging");
});
el.uploadArea.addEventListener("dragleave", () => el.uploadArea.classList.remove("dragging"));
el.uploadArea.addEventListener("drop", (e) => {
  e.preventDefault();
  el.uploadArea.classList.remove("dragging");
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
});
el.fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) loadFile(file);
});

async function loadFile(file) {
  el.loading.classList.remove("hidden");
  el.results.classList.add("hidden");
  el.captureError.classList.add("hidden");
  // Yield once so the loading state paints before a large file blocks the thread.
  await new Promise((r) => setTimeout(r, 0));

  try {
    const buffer = await file.arrayBuffer();
    const capture = parseCapture(buffer);
    state.capture = capture;
    state.result = analyze(capture);
    state.packetLimit = PACKET_PAGE;
    state.focusPacket = null;
    state.tab = "overview";
    showCaptureInfo(file, capture);
    populateProtocolFilter();
    render();
    el.results.classList.remove("hidden");
  } catch (error) {
    showError(error.message);
    console.error(error);
  } finally {
    el.loading.classList.add("hidden");
  }
}

/**
 * Say what the file actually was. Format and link type change how every byte
 * is read, and a capture that is truncated or clipped by a snaplen answers a
 * different question than the one the reader thinks they asked.
 */
function showCaptureInfo(file, capture) {
  const bits = [
    file.name,
    capture.format === "pcapng" ? "pcapng" : "pcap (classic)",
    LINKTYPE_NAMES[capture.linktype] || `link type ${capture.linktype}`,
    `${fmt.count(capture.packets.length)} packets`,
  ];
  if (capture.header?.nanos) bits.push("nanosecond timestamps");
  if (capture.header && !capture.header.littleEndian) bits.push("big-endian");
  if (capture.header?.snaplen) bits.push(`snaplen ${capture.header.snaplen}`);
  if (capture.truncated) bits.push("FILE TRUNCATED");
  el.captureInfo.textContent = bits.join("  ·  ");
  el.captureInfo.classList.remove("hidden");
}

function showError(message) {
  el.captureError.textContent = message;
  el.captureError.classList.remove("hidden");
}

/* ---------------------------------------------------------------- filters */

function populateProtocolFilter() {
  const seen = Object.keys(state.result.summary.protocols).sort();
  el.filterProtocol.innerHTML = '<option value="">Any protocol</option>' +
    seen.map((p) => `<option value="${fmt.escapeHtml(p)}">${fmt.escapeHtml(p)}</option>`).join("");
  el.filterProtocol.value = state.filter.protocol;
}

const debounce = (fn, wait) => {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), wait); };
};

el.filterText.addEventListener("input", debounce((e) => {
  state.filter.text = e.target.value.trim().toLowerCase();
  state.packetLimit = PACKET_PAGE;
  render();
}, 180));

el.filterProtocol.addEventListener("change", (e) => {
  state.filter.protocol = e.target.value;
  state.packetLimit = PACKET_PAGE;
  render();
});

el.filterProblems.addEventListener("click", () => {
  state.filter.problemsOnly = !state.filter.problemsOnly;
  el.filterProblems.setAttribute("aria-pressed", String(state.filter.problemsOnly));
  state.packetLimit = PACKET_PAGE;
  render();
});

el.clearFilter.addEventListener("click", () => {
  resetFilter();
  state.packetLimit = PACKET_PAGE;
  state.focusPacket = null;
  render();
});

function resetFilter() {
  state.filter = { text: "", protocol: "", problemsOnly: false };
  el.filterText.value = "";
  el.filterProtocol.value = "";
  el.filterProblems.setAttribute("aria-pressed", "false");
}

const ICMP_ERROR_TYPES = new Set([3, 11, 12]);

function packetHasProblem(p) {
  if (p.tcp && p.tcp.events.length) {
    return p.tcp.events.some((e) => e !== EVENT.WINDOW_UPDATE);
  }
  if (p.snaplenTruncated) return true;
  if (p.protocol === "ICMP" && ICMP_ERROR_TYPES.has(p.icmpType)) return true;
  if (p.protocol === "ICMPv6" && p.icmpType != null && p.icmpType <= 4) return true;
  return false;
}

function haystack(p) {
  if (p._hay === undefined) {
    p._hay = [
      p.src, p.dst, p.srcPort, p.dstPort, p.protocol, p.info,
      p.app?.summary, p.app?.sni, p.app?.host, p.app?.question,
      labelPort(p.srcPort), labelPort(p.dstPort),
    ].filter(Boolean).join(" ").toLowerCase();
  }
  return p._hay;
}

function filteredPackets() {
  const { text, protocol, problemsOnly } = state.filter;
  return state.result.packets.filter((p) => {
    if (protocol && p.protocol !== protocol) return false;
    if (problemsOnly && !packetHasProblem(p)) return false;
    if (text && !haystack(p).includes(text)) return false;
    return true;
  });
}

function filteredConversations() {
  const { text, protocol } = state.filter;
  return state.result.conversations.filter((c) => {
    if (protocol && c.protocol !== protocol) return false;
    if (!text) return true;
    return [c.a, c.b, c.aPort, c.bPort, c.protocol, c.service]
      .filter(Boolean).join(" ").toLowerCase().includes(text);
  });
}

function filteredEndpoints() {
  const { text } = state.filter;
  if (!text) return state.result.endpoints;
  return state.result.endpoints.filter((e) => e.ip.toLowerCase().includes(text));
}

function streamHasProblem(s) {
  return Boolean(s.failed) || s.state === "reset" ||
    s.counts.retransmission + s.counts.fastRetransmission +
    s.counts.spuriousRetransmission + s.counts.zeroWindow +
    s.counts.lostSegment > 0;
}

function filteredStreams() {
  const { text, problemsOnly } = state.filter;
  return state.result.streams.filter((s) => {
    if (problemsOnly && !streamHasProblem(s)) return false;
    if (!text) return true;
    return [
      s.a.ip, s.b.ip, s.a.port, s.b.port, s.service,
      s.appProtocol, s.sni, s.host, s.state,
    ].filter(Boolean).join(" ").toLowerCase().includes(text);
  });
}

/* ------------------------------------------------------------------- tabs */

el.tabs.addEventListener("click", (e) => {
  const button = e.target.closest("[data-tab]");
  if (!button) return;
  state.tab = button.dataset.tab;
  render();
});

// Overview and Findings describe the whole capture, so a display filter there
// would either do nothing or quietly contradict the numbers above it.
const FILTERABLE_TABS = new Set(["conversations", "endpoints", "streams", "packets"]);

function renderTabs() {
  for (const button of el.tabs.querySelectorAll("[data-tab]")) {
    const active = button.dataset.tab === state.tab;
    button.setAttribute("aria-selected", String(active));
    $(`tab-${button.dataset.tab}`).classList.toggle("hidden", !active);
  }
  $("filterBar").classList.toggle("hidden", !FILTERABLE_TABS.has(state.tab));
}

/* --------------------------------------------------------------- renderer */

function render() {
  if (!state.result) return;
  renderTabs();
  renderStats();
  renderBadges();
  renderFilterHint();

  switch (state.tab) {
    case "overview": renderOverview(); break;
    case "conversations": renderConversations(); break;
    case "endpoints": renderEndpoints(); break;
    case "streams": renderStreams(); break;
    case "expert": renderFindings(); break;
    case "packets": renderPackets(); break;
  }
}

function renderFilterHint() {
  const { text, protocol, problemsOnly } = state.filter;
  if (!text && !protocol && !problemsOnly) {
    el.filterHint.textContent = "";
    return;
  }
  el.filterHint.textContent =
    `Showing ${fmt.count(filteredPackets().length)} of ` +
    `${fmt.count(state.result.packets.length)} packets. The filter changes what ` +
    `is listed, not what was analysed.`;
}

function renderBadges() {
  const r = state.result;
  $("badgeConversations").textContent = fmt.count(r.conversations.length);
  $("badgeEndpoints").textContent = fmt.count(r.endpoints.length);
  $("badgeStreams").textContent = fmt.count(r.streams.length);
  $("badgePackets").textContent = fmt.count(r.packets.length);
  const badge = $("badgeFindings");
  badge.textContent = fmt.count(r.findings.length);
  badge.classList.toggle("alert", r.findings.some((f) => f.severity === "error"));
}

function stat(label, value, note) {
  return `<div class="stat-card">
    <div class="stat-label">${fmt.escapeHtml(label)}</div>
    <div class="stat-value">${value}</div>
    ${note ? `<div class="stat-note">${note}</div>` : ""}
  </div>`;
}

function renderStats() {
  const s = state.result.summary;
  el.statsGrid.innerHTML = [
    stat("Packets", fmt.count(s.packets), fmt.bytes(s.bytes)),
    stat("Span", fmt.duration(s.duration), `avg ${fmt.bits(s.averageBitrate)}`),
    stat("Peak rate", fmt.bits(s.peakBitrate), "busiest bucket"),
    stat("Hosts", fmt.count(s.hosts), `${fmt.count(s.conversations)} conversations`),
    stat("TCP streams", fmt.count(s.tcpStreams),
      `${fmt.count(s.completedStreams)} established · ${fmt.count(s.failedStreams)} failed`),
    stat("Median handshake", fmt.ms(s.medianHandshakeRtt), "round trip to the peer"),
  ].join("");
}

/* --------------------------------------------------------------- overview */

function themeColors() {
  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();
  return {
    series: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => v(`--series-${i}`)),
    ink: v("--ink"), ink2: v("--ink-2"), muted: v("--ink-muted"),
    grid: v("--grid"), surface: v("--surface"),
  };
}

/* Gridlines and axes are solid hairlines one shade off the surface: present
   enough to read a value against, quiet enough not to compete with the data. */
function baseOptions(theme, { horizontal = false } = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: horizontal ? "y" : "x",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: theme.surface,
        titleColor: theme.ink,
        bodyColor: theme.ink2,
        borderColor: theme.grid,
        borderWidth: 1,
        padding: 10,
        displayColors: false,
      },
    },
    scales: {
      x: {
        grid: { color: theme.grid, drawTicks: false },
        border: { color: theme.grid },
        ticks: { color: theme.muted, font: { size: 11 } },
      },
      y: {
        beginAtZero: true,
        grid: { color: theme.grid, drawTicks: false },
        border: { color: theme.grid },
        ticks: { color: theme.muted, font: { size: 11 } },
      },
    },
  };
}

function destroyCharts() {
  for (const c of Object.values(state.charts)) c?.destroy();
  state.charts = {};
}

function renderOverview() {
  destroyCharts();
  const theme = themeColors();
  const r = state.result;

  // Throughput — a single series, so no legend: the card title names it.
  const buckets = r.timeline.buckets;
  const base = baseOptions(theme);
  state.charts.throughput = new Chart($("throughputChart"), {
    type: "line",
    data: {
      labels: buckets.map((b) => fmt.clockTime(b.t)),
      datasets: [{
        data: buckets.map((b) => b.bitsPerSecond),
        borderColor: theme.series[0],
        backgroundColor: `color-mix(in srgb, ${theme.series[0]} 14%, transparent)`,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        fill: true,
        tension: 0.25,
      }],
    },
    options: {
      ...base,
      interaction: { mode: "index", intersect: false },
      plugins: {
        ...base.plugins,
        tooltip: { ...base.plugins.tooltip, callbacks: { label: (c) => fmt.bits(c.parsed.y) } },
      },
      scales: {
        x: { ...base.scales.x, ticks: { ...base.scales.x.ticks, maxTicksLimit: 8, autoSkip: true } },
        y: { ...base.scales.y, ticks: { ...base.scales.y.ticks, callback: (v) => fmt.bits(v) } },
      },
    },
  });

  // Protocols — identity, so categorical hues in fixed slot order. Past eight
  // the tail folds into "Other" rather than inventing a ninth colour.
  const protocols = Object.entries(r.summary.protocols).sort((a, b) => b[1].bytes - a[1].bytes);
  const head = protocols.slice(0, 7);
  const tail = protocols.slice(7);
  if (tail.length) {
    head.push(["Other", {
      packets: tail.reduce((t, [, v]) => t + v.packets, 0),
      bytes: tail.reduce((t, [, v]) => t + v.bytes, 0),
    }]);
  }
  const hbase = baseOptions(theme, { horizontal: true });
  state.charts.protocol = new Chart($("protocolChart"), {
    type: "bar",
    data: {
      labels: head.map(([name]) => name),
      datasets: [{
        data: head.map(([, v]) => v.bytes),
        backgroundColor: head.map((_, i) => theme.series[i]),
        borderRadius: 4,
        borderSkipped: false,
        // A 2px gap of surface between bars, rather than an outline round each.
        borderWidth: 2,
        borderColor: theme.surface,
        // Thin marks: a bar that fills its whole band reads as a block of
        // colour rather than a measurement, and a chart with three categories
        // should not draw three times the ink of one with ten.
        barPercentage: 0.6,
        categoryPercentage: 0.8,
        maxBarThickness: 22,
      }],
    },
    options: {
      ...hbase,
      plugins: {
        ...hbase.plugins,
        tooltip: {
          ...hbase.plugins.tooltip,
          callbacks: {
            label: (c) => `${fmt.bytes(c.parsed.x)} · ${fmt.count(head[c.dataIndex][1].packets)} packets`,
          },
        },
      },
      scales: {
        x: { ...hbase.scales.x, ticks: { ...hbase.scales.x.ticks, callback: (v) => fmt.bytes(v) } },
        y: { grid: { display: false }, border: { color: theme.grid }, ticks: { color: theme.ink2, font: { size: 11 } } },
      },
    },
  });

  barChart("talkerChart", theme,
    r.endpoints.slice(0, 10).map((e) => [e.ip, e.bytes]), fmt.bytes);

  const services = new Map();
  for (const c of r.conversations) {
    if (c.serverPort == null) continue;
    const name = c.service ? `${c.service} (${c.serverPort})` : String(c.serverPort);
    services.set(name, (services.get(name) || 0) + c.bytes);
  }
  barChart("serviceChart", theme,
    [...services.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10), fmt.bytes);

  renderOverviewSummary();
}

/** One series, one colour — never a value-ramp across nominal categories. */
function barChart(canvasId, theme, rows, formatValue) {
  const base = baseOptions(theme, { horizontal: true });
  state.charts[canvasId] = new Chart($(canvasId), {
    type: "bar",
    data: {
      labels: rows.map(([label]) => label),
      datasets: [{
        data: rows.map(([, value]) => value),
        backgroundColor: theme.series[0],
        borderRadius: 4,
        borderSkipped: false,
        borderWidth: 2,
        borderColor: theme.surface,
        barPercentage: 0.6,
        categoryPercentage: 0.8,
        maxBarThickness: 22,
      }],
    },
    options: {
      ...base,
      plugins: {
        ...base.plugins,
        tooltip: { ...base.plugins.tooltip, callbacks: { label: (c) => formatValue(c.parsed.x) } },
      },
      scales: {
        x: { ...base.scales.x, ticks: { ...base.scales.x.ticks, callback: (v) => formatValue(v) } },
        y: { grid: { display: false }, border: { color: theme.grid }, ticks: { color: theme.ink2, font: { size: 11 } } },
      },
    },
  });
}

function renderOverviewSummary() {
  const r = state.result;
  const s = r.summary;
  const worst = r.findings.filter((f) => f.severity === "error").slice(0, 3);
  const parts = [
    `<div class="card-title">What this capture holds</div>`,
    `<p class="finding-detail">`,
    `${fmt.count(s.packets)} packets over ${fmt.duration(s.duration)}, `,
    `${fmt.count(s.hosts)} hosts, ${fmt.count(s.tcpStreams)} TCP connections `,
    `(${fmt.count(s.completedStreams)} established, ${fmt.count(s.failedStreams)} never answered, `,
    `${fmt.count(s.resetStreams)} reset).`,
    `</p>`,
  ];
  if (worst.length) {
    parts.push(`<p class="finding-detail" style="margin-top:8px">Worth looking at first: `,
      worst.map((f) => fmt.escapeHtml(f.title)).join("; "), `.</p>`);
  } else if (r.findings.length) {
    parts.push(`<p class="finding-detail" style="margin-top:8px">Nothing severe — `,
      `${r.findings.length} notes on the Findings tab.</p>`);
  } else {
    parts.push(`<p class="finding-detail" style="margin-top:8px">No problems detected.</p>`);
  }
  el.overviewSummary.innerHTML = parts.join("");
}

// A theme change swaps every chart colour, so charts are rebuilt rather than
// left painted for the previous surface.
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (state.result && state.tab === "overview") renderOverview();
});

/* ------------------------------------------------------------------ sort */

function sortRows(rows, table, accessors) {
  const { key, asc } = state.sort[table];
  const get = accessors[key];
  if (!get) return rows;
  return [...rows].sort((a, b) => {
    const x = get(a), y = get(b);
    if (typeof x === "string" || typeof y === "string") {
      return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
    }
    return asc ? (x ?? -1) - (y ?? -1) : (y ?? -1) - (x ?? -1);
  });
}

function wireSort(tableId, table) {
  const head = $(tableId).querySelector("thead");
  if (head.dataset.wired) return;
  head.dataset.wired = "1";
  head.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (!th) return;
    const key = th.dataset.sort;
    const current = state.sort[table];
    state.sort[table] = { key, asc: current.key === key ? !current.asc : false };
    render();
  });
}

function markSorted(tableId, table) {
  const { key, asc } = state.sort[table];
  for (const th of $(tableId).querySelectorAll("th[data-sort]")) {
    th.classList.toggle("sorted", th.dataset.sort === key);
    th.classList.toggle("asc", th.dataset.sort === key && asc);
  }
}

/* --------------------------------------------------------- conversations */

function renderConversations() {
  wireSort("conversationTable", "conversations");
  markSorted("conversationTable", "conversations");

  const rows = sortRows(filteredConversations(), "conversations", {
    a: (c) => c.a, b: (c) => c.b, protocol: (c) => c.protocol,
    service: (c) => c.service || "", packets: (c) => c.packets,
    bytes: (c) => c.bytes, bytesAB: (c) => c.bytesAB, bytesBA: (c) => c.bytesBA,
    duration: (c) => c.duration, bitrate: (c) => c.bitrate ?? -1,
  }).slice(0, 2000);

  const streamByKey = new Map();
  for (const s of state.result.streams) {
    if (!streamByKey.has(s.key)) streamByKey.set(s.key, s.id);
  }
  const lookup = (c) => {
    const x = `${c.a}|${c.aPort}`, y = `${c.b}|${c.bPort}`;
    return streamByKey.get(x <= y ? `${x}|${y}` : `${y}|${x}`);
  };

  const body = $("conversationTable").querySelector("tbody");
  body.innerHTML = rows.length ? rows.map((c) => {
    const streamId = c.protocol === "TCP" ? lookup(c) : undefined;
    return `<tr class="${streamId != null ? "clickable" : ""}"${streamId != null ? ` data-stream="${streamId}"` : ""}>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(c.a, c.aPort))}</td>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(c.b, c.bPort))}</td>
      <td class="proto proto-${c.protocol.toLowerCase().replace(/[^a-z0-9]/g, "")}">${fmt.escapeHtml(c.protocol)}</td>
      <td>${fmt.escapeHtml(c.service || "—")}</td>
      <td class="num">${fmt.count(c.packets)}</td>
      <td class="num">${fmt.bytes(c.bytes)}</td>
      <td class="num">${fmt.bytes(c.bytesAB)}</td>
      <td class="num">${fmt.bytes(c.bytesBA)}</td>
      <td class="num">${fmt.duration(c.duration)}</td>
      <td class="num">${c.bitrate == null ? "—" : fmt.bits(c.bitrate)}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="10" class="empty">No conversations match the filter.</td></tr>`;

  body.onclick = (e) => {
    const tr = e.target.closest("tr[data-stream]");
    if (tr) openStream(Number(tr.dataset.stream));
  };
}

/* -------------------------------------------------------------- endpoints */

function renderEndpoints() {
  wireSort("endpointTable", "endpoints");
  markSorted("endpointTable", "endpoints");

  const rows = sortRows(filteredEndpoints(), "endpoints", {
    ip: (e) => e.ip, packets: (e) => e.packets, bytes: (e) => e.bytes,
    bytesSent: (e) => e.bytesSent, bytesReceived: (e) => e.bytesReceived,
    peerCount: (e) => e.peerCount, portCount: (e) => e.portCount,
    ttl: (e) => e.ttlValues[0] ?? -1,
  }).slice(0, 2000);

  $("endpointTable").querySelector("tbody").innerHTML = rows.length ? rows.map((e) => `
    <tr>
      <td class="mono">${fmt.escapeHtml(e.ip)}</td>
      <td class="num">${fmt.count(e.packets)}</td>
      <td class="num">${fmt.bytes(e.bytes)}</td>
      <td class="num">${fmt.bytes(e.bytesSent)}</td>
      <td class="num">${fmt.bytes(e.bytesReceived)}</td>
      <td class="num">${fmt.count(e.peerCount)}</td>
      <td class="num">${fmt.count(e.portCount)}</td>
      <td class="mono">${e.ttlValues.slice(0, 4).join(", ") || "—"}</td>
    </tr>`).join("") : `<tr><td colspan="8" class="empty">No endpoints match the filter.</td></tr>`;
}

/* ---------------------------------------------------------------- streams */

const STATE_TAG = { reset: "bad", unanswered: "bad", closing: "warn" };

/** Name the protocol first, then whatever the connection said it was for. */
function streamLabel(s) {
  const protocol = s.appProtocol || s.service;
  const target = s.sni || s.host;
  if (protocol && target) return `${protocol} · ${target}`;
  return protocol || target || "—";
}

function renderStreams() {
  wireSort("streamTable", "streams");
  markSorted("streamTable", "streams");

  const rows = sortRows(filteredStreams(), "streams", {
    id: (s) => s.id, client: (s) => s.a.ip, server: (s) => s.b.ip,
    app: (s) => s.appProtocol || s.service || "",
    state: (s) => s.state, packets: (s) => s.packets,
    payloadBytes: (s) => s.payloadBytes,
    handshakeRtt: (s) => s.handshakeRtt ?? -1,
    retrans: (s) => s.counts.retransmission + s.counts.fastRetransmission +
                    s.counts.spuriousRetransmission,
    duration: (s) => s.duration,
  }).slice(0, 2000);

  const body = $("streamTable").querySelector("tbody");
  body.innerHTML = rows.length ? rows.map((s) => {
    const retrans = s.counts.retransmission + s.counts.fastRetransmission +
                    s.counts.spuriousRetransmission;
    const label = streamLabel(s);
    const stateText = s.failed ? `${s.state} · ${s.failed}` : s.state;
    return `<tr class="clickable" data-stream="${s.id}">
      <td class="num">${s.id}</td>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(s.a.ip, s.a.port))}</td>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(s.b.ip, s.b.port))}</td>
      <td>${fmt.escapeHtml(String(label))}</td>
      <td><span class="tag ${STATE_TAG[s.state] || ""}">${fmt.escapeHtml(stateText)}</span></td>
      <td class="num">${fmt.count(s.packets)}</td>
      <td class="num">${fmt.bytes(s.payloadBytes)}</td>
      <td class="num">${fmt.ms(s.handshakeRtt)}</td>
      <td class="num">${retrans ? `<span class="tag bad">${retrans}</span>` : "0"}</td>
      <td class="num">${fmt.duration(s.duration)}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="10" class="empty">No streams match the filter.</td></tr>`;

  body.onclick = (e) => {
    const tr = e.target.closest("tr[data-stream]");
    if (tr) openStream(Number(tr.dataset.stream));
  };
}

/* --------------------------------------------------------------- findings */

// Severity is carried by an icon and a word as well as by colour, so it never
// depends on hue alone.
const SEVERITY_ICON = { error: "●", warning: "▲", note: "○" };

function renderFindings() {
  const findings = state.result.findings;
  if (!findings.length) {
    el.findingList.innerHTML =
      `<p class="empty">Nothing stood out — no retransmissions, resets, refused
       connections or capture gaps were found.</p>`;
    return;
  }

  el.findingList.innerHTML = findings.map((f) => {
    const refs = f.packets.slice(0, 12);
    const more = f.totalPackets > refs.length ? ` +${f.totalPackets - refs.length} more` : "";
    const tagClass = f.severity === "error" ? "bad" : f.severity === "warning" ? "warn" : "";
    return `<div class="finding sev-${f.severity}">
      <div class="finding-icon" aria-hidden="true">${SEVERITY_ICON[f.severity]}</div>
      <div>
        <div class="finding-title">
          <span class="tag ${tagClass}">${f.severity}</span>
          ${fmt.escapeHtml(f.title)}
        </div>
        <div class="finding-detail">${fmt.escapeHtml(f.detail)}</div>
        ${refs.length ? `<div class="finding-refs">packets: ${
          refs.map((n) => `<button class="link-btn" data-packet="${n}">#${n}</button>`).join(" ")
        }${more}</div>` : ""}
      </div>
    </div>`;
  }).join("");

  el.findingList.onclick = (e) => {
    const button = e.target.closest("[data-packet]");
    if (button) showPacket(Number(button.dataset.packet));
  };
}

/* ---------------------------------------------------------------- packets */

function tcpInfo(p) {
  const t = p.tcp;
  const flags = (p.flagNames || []).join(", ") || "—";
  const parts = [`[${flags}]`, `Seq=${t ? t.relSeq : p.seq}`];
  if (t && t.relAck != null) parts.push(`Ack=${t.relAck}`);
  parts.push(`Win=${t ? t.scaledWindow : p.window}${t && t.scaled ? "*" : ""}`);
  parts.push(`Len=${p.payloadLength}`);
  return parts.join(" ");
}

function packetInfo(p) {
  const bits = [p.protocol === "TCP" ? tcpInfo(p) : (p.info || "")];
  if (p.app?.summary) bits.push(p.app.summary);
  return bits.filter(Boolean).join("  ·  ");
}

const BAD_EVENTS = new Set([
  EVENT.RETRANSMISSION, EVENT.FAST_RETRANSMISSION, EVENT.SPURIOUS_RETRANSMISSION,
  EVENT.ZERO_WINDOW, EVENT.RESET, EVENT.LOST_SEGMENT,
]);

function renderPackets() {
  const rows = filteredPackets();
  const shown = rows.slice(0, state.packetLimit);

  el.packetNote.textContent =
    `${fmt.count(rows.length)} packets match. A window marked * is scaled by the ` +
    `factor negotiated in the handshake; a length marked * was cut short by the snaplen.`;

  el.packetTable.innerHTML = shown.map((p) => {
    const events = (p.tcp?.events || []).filter((e) => e !== EVENT.WINDOW_UPDATE);
    const bad = events.some((e) => BAD_EVENTS.has(e));
    const tags = events
      .map((e) => `<span class="tag ${BAD_EVENTS.has(e) ? "bad" : "warn"}">${e}</span>`)
      .join("");
    const rowClass = events.length ? (bad ? "flagged-bad" : "flagged") : "";
    return `<tr id="pkt-${p.num}" class="${rowClass}">
      <td class="num">${p.num}</td>
      <td class="mono">${fmt.clockTime(p.timestamp)}</td>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(p.src, p.srcPort))}</td>
      <td class="mono">${fmt.escapeHtml(fmt.endpoint(p.dst, p.dstPort))}</td>
      <td class="proto proto-${p.protocol.toLowerCase().replace(/[^a-z0-9]/g, "")}">${fmt.escapeHtml(p.protocol)}</td>
      <td class="num">${p.length}${p.snaplenTruncated ? "*" : ""}</td>
      <td class="mono">${tags}${fmt.escapeHtml(packetInfo(p))}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="empty">No packets match the filter.</td></tr>`;

  el.loadMore.classList.toggle("hidden", rows.length <= state.packetLimit);
  el.loadMore.textContent = `Show more (${fmt.count(rows.length - shown.length)} remaining)`;

  if (state.focusPacket != null) {
    const row = $(`pkt-${state.focusPacket}`);
    if (row) {
      row.scrollIntoView({ block: "center", behavior: "smooth" });
      row.style.outline = "2px solid var(--series-1)";
      setTimeout(() => { row.style.outline = ""; }, 2000);
    }
    state.focusPacket = null;
  }
}

el.loadMore.addEventListener("click", () => {
  state.packetLimit += PACKET_PAGE;
  renderPackets();
});

/** Jump to a packet named by a finding, widening the page window if need be. */
function showPacket(num) {
  state.tab = "packets";
  let index = filteredPackets().findIndex((p) => p.num === num);
  if (index < 0) {
    // The packet exists but the filter hides it. Clearing the filter is
    // better than a click that appears to do nothing.
    resetFilter();
    index = state.result.packets.findIndex((p) => p.num === num);
  }
  if (index >= 0) state.packetLimit = Math.ceil((index + 1) / PACKET_PAGE) * PACKET_PAGE;
  state.focusPacket = num;
  render();
}

/* --------------------------------------------------------- stream viewer */

let viewerMode = "text";

function openStream(id) {
  const stream = state.result.streams.find((s) => s.id === id);
  if (!stream) return;
  renderStreamModal(stream, followStream(stream));
}

function renderStreamModal(stream, data) {
  const aLabel = fmt.endpoint(stream.a.ip, stream.a.port);
  const bLabel = fmt.endpoint(stream.b.ip, stream.b.port);
  const retrans = stream.counts.retransmission + stream.counts.fastRetransmission +
                  stream.counts.spuriousRetransmission;

  const meta = [
    ["State", stream.failed ? `${stream.state} · ${stream.failed}` : stream.state],
    ["Protocol", streamLabel(stream)],
    ["Handshake RTT", fmt.ms(stream.handshakeRtt)],
    ["Time to first byte", fmt.ms(stream.timeToFirstByte)],
    ["Round trip (median)", fmt.ms(stream.rtt?.median)],
    ["Payload out / in", `${fmt.bytes(stream.dirs[0].payloadBytes)} / ${fmt.bytes(stream.dirs[1].payloadBytes)}`],
    ["Retransmits", String(retrans)],
    ["Duplicate ACKs", String(stream.counts.dupAck)],
    ["Zero windows", String(stream.counts.zeroWindow)],
    ["Window scaling", stream.windowScalingInUse
      ? `×${2 ** (stream.dirs[0].windowScale || 0)} / ×${2 ** (stream.dirs[1].windowScale || 0)}`
      : "not negotiated"],
    ["Duration", fmt.duration(stream.duration)],
    ["Packets", fmt.count(stream.packets)],
  ];

  el.streamModal.innerHTML = `
    <div class="modal-backdrop" id="streamBackdrop">
      <div class="modal" role="dialog" aria-modal="true" aria-label="TCP stream ${stream.id}">
        <div class="modal-head">
          <h2>Stream ${stream.id} — ${fmt.escapeHtml(aLabel)} ⇄ ${fmt.escapeHtml(bLabel)}</h2>
          <button class="btn" id="viewText" aria-pressed="${viewerMode === "text"}">Text</button>
          <button class="btn" id="viewHex" aria-pressed="${viewerMode === "hex"}">Hex</button>
          <button class="btn" id="closeStream">Close</button>
        </div>
        <div class="stream-meta">
          ${meta.map(([k, v]) => `<div><span>${fmt.escapeHtml(k)}</span>${fmt.escapeHtml(String(v))}</div>`).join("")}
        </div>
        <div class="stream-legend">
          <span class="dir-a">■</span> ${fmt.escapeHtml(aLabel)} → ${fmt.escapeHtml(bLabel)}
          &nbsp;&nbsp;
          <span class="dir-b">■</span> ${fmt.escapeHtml(bLabel)} → ${fmt.escapeHtml(aLabel)}
          ${data.capped ? " — output capped" : ""}
        </div>
        <div class="modal-body"><pre class="stream-data" id="streamData"></pre></div>
      </div>
    </div>`;

  paintStreamData(stream, data);

  $("closeStream").onclick = closeStream;
  $("streamBackdrop").onclick = (e) => { if (e.target.id === "streamBackdrop") closeStream(); };
  $("viewText").onclick = () => { viewerMode = "text"; renderStreamModal(stream, data); };
  $("viewHex").onclick = () => { viewerMode = "hex"; renderStreamModal(stream, data); };
  document.addEventListener("keydown", escClose);
}

function paintStreamData(stream, data) {
  const target = $("streamData");
  if (!data.chunks.length) {
    target.innerHTML = `<span class="stream-gap">This connection carried no payload — ${
      stream.failed ? "it never completed." : "control packets only."}</span>`;
    return;
  }

  const html = [];
  for (const source of [
    { label: "client", gaps: data.aToB.gaps },
    { label: "server", gaps: data.bToA.gaps },
  ]) {
    if (source.gaps.length) {
      html.push(`<span class="stream-gap">${source.gaps.length} gap${
        source.gaps.length === 1 ? "" : "s"} in the ${source.label} direction — bytes ` +
        `missing from the capture, left as holes rather than closed up.</span>`);
    }
  }

  let offset = 0;
  for (const chunk of data.chunks) {
    const body = viewerMode === "hex"
      ? fmt.asHex(chunk.bytes, 16384, offset) + "\n"
      : fmt.asText(chunk.bytes);
    offset += chunk.bytes.length;
    html.push(`<span class="dir-${chunk.dir === 0 ? "a" : "b"}">${fmt.escapeHtml(body)}</span>`);
  }
  target.innerHTML = html.join("");
}

function escClose(e) { if (e.key === "Escape") closeStream(); }

function closeStream() {
  el.streamModal.innerHTML = "";
  document.removeEventListener("keydown", escClose);
}
