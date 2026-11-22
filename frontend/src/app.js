import {
  checkBackendHealth,
  assessNetworkAlpha,
  assessNetworkBeta,
  fetchDashboardStatistics,
  fetchEnvironmentStatistics,
  fetchNetworkAlpha,
  fetchNetworkBeta,
  fetchRuleCatalog,
  fetchRuntimeAssessment,
  fetchScanDetails,
  fetchScanHistory,
  startNetworkAlpha,
  startNetworkBeta,
  stopNetworkAlpha,
  stopNetworkBeta,
  updateRemediationStatus,
  uploadConfiguration
} from "./services/api.js";

const NFs = ["AMF", "SMF", "UPF", "NRF", "AUSF", "UDM", "PCF"];
const HISTORY_PAGE_SIZE = 100;
const SAMPLE_ROOT = "/sample_configs/";
const state = {
  health: null,
  history: [],
  historyTotal: 0,
  historyOffset: 0,
  historyLoaded: false,
  historyDetails: [],
  statistics: null,
  statisticsError: null,
  environment: null,
  betaEnvironment: null,
  environmentError: null,
  betaEnvironmentError: null,
  environmentStatistics: null,
  environmentStatisticsError: null,
  runtimeAssessment: null,
  betaRuntimeAssessment: null,
  environmentBusy: false,
  rules: [],
  samples: [],
  currentScan: null,
  currentPage: "overview",
  historyFilters: { search: "", nf: "", severity: "", sort: "date-desc" },
  findingFilters: { search: "", nf: "", severity: "", category: "" },
  ruleFilters: { search: "", nf: "", severity: "", category: "" },
  sampleFilters: { search: "", category: "", nf: "" },
  sampleLoadError: null,
  comparePrefill: null,
  selectedFile: null,
  selectedNode: null,
  mode: "network",
  zoom: 1,
  labels: true,
  severityView: "bars"
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 2600);
}

function formatTime(value) {
  if (!value) return "No scan data";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}

function animateCount(element, target) {
  if (!element) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    element.textContent = target;
    return;
  }
  const start = Number(element.textContent) || 0;
  const duration = 420;
  const started = performance.now();
  function update(now) {
    const progress = Math.min(1, (now - started) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = String(Math.round(start + (target - start) * eased));
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

async function checkBackend() {
  const status = $("#connectionStatus");
  try {
    await checkBackendHealth();
    status.className = "connection online";
    status.querySelector("span:last-child").textContent = "Backend Online";
  } catch (_) {
    status.className = "connection offline";
    status.querySelector("span:last-child").textContent = "Backend Disconnected";
  }
}

async function loadHistory() {
  try {
    const data = await fetchScanHistory({
      limit: HISTORY_PAGE_SIZE,
      offset: state.historyOffset,
      search: state.historyFilters.search,
      networkFunction: state.historyFilters.nf,
      severity: state.historyFilters.severity,
      sort: state.historyFilters.sort
    });
    state.history = data.scans;
    state.historyTotal = data.total;
    state.historyLoaded = true;
    const scanFilter = $("#scanFilter");
    const configurationScans = state.history.filter(
      (entry) => entry.assessment_type !== "runtime"
    );
    if (scanFilter) {
      scanFilter.innerHTML = `<option value="">LATEST CONFIGURATION SCAN</option>${configurationScans.map((entry) => `<option value="${escapeHtml(entry.scan_id)}">${escapeHtml(entry.filename)}</option>`).join("")}`;
      if (state.currentScan && configurationScans.some((entry) => entry.scan_id === state.currentScan.scan_id)) {
        scanFilter.value = state.currentScan.scan_id;
      }
    }
    renderHistory();
    renderRecentActivity();
    if (!state.currentScan && configurationScans.length) {
      try {
        const latest = await fetchScanDetails(configurationScans[0].scan_id);
        state.currentScan = latest;
        state.historyDetails = [latest];
        renderHealth(latest.summary);
      } catch {
        renderHealth(null);
      }
    } else if (state.currentScan) {
      renderHealth(state.currentScan.summary);
    } else {
      renderHealth(null);
    }
  } catch (error) {
    state.history = [];
    state.historyLoaded = false;
    state.historyTotal = 0;
    $("#activityTimeline").innerHTML = `<div class="analytics-empty"><strong>History unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
    if ($("#utilityContent") && state.currentPage === "history") {
      $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>History unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }
}

function renderHealth(summary) {
  const status = $("#selectedScanStatus");
  if (status) {
    status.textContent = summary
      ? `${summary.network_function || "Unknown NF"} · ${summary.security_score ?? "Score unavailable"}/100 · ${summary.total_findings ?? 0} findings`
      : "No scan selected";
  }
  updateTopology(summary);
}

function renderSeverity(summary) {
  const values = { CRITICAL: summary?.critical ?? 0, HIGH: summary?.high ?? 0, MEDIUM: summary?.medium ?? 0, LOW: summary?.low ?? 0 };
  const total = Object.values(values).reduce((sum, value) => sum + Number(value || 0), 0);
  if (!total) {
    const emptyTitle = summary ? "No recorded findings" : "Analytics unavailable";
    const emptyMessage = summary
      ? "The latest configuration scan reported no findings."
      : "Run a YAML or JSON scan to see its severity results.";
    $("#severityChart").innerHTML = `<div class="analytics-empty"><strong>${emptyTitle}</strong><span>${emptyMessage}</span></div>`;
    return;
  }
  if (state.severityView === "donut") {
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const colors = {
      CRITICAL: "var(--accent-coral)",
      HIGH: "var(--accent-amber)",
      MEDIUM: "var(--accent-yellow)",
      LOW: "var(--accent-teal)"
    };
    const segments = Object.entries(values).map(([severity, count]) => {
      const fraction = total ? count / total : 0;
      const segment = `<circle cx="54" cy="54" r="${radius}" fill="none" stroke="${colors[severity]}" stroke-width="8"
        stroke-dasharray="${fraction * circumference} ${circumference}"
        stroke-dashoffset="${-offset}" transform="rotate(-90 54 54)" title="${count} ${severity} · ${(fraction * 100).toFixed(1)}%"></circle>`;
      offset += fraction * circumference;
      return segment;
    }).join("");
    $("#severityChart").innerHTML = `<div class="donut-layout"><svg viewBox="0 0 108 108"><circle cx="54" cy="54" r="${radius}" fill="none" stroke="var(--border)" stroke-width="8"></circle>${segments}</svg>
      <div class="donut-legend">${Object.entries(values).map(([severity, count]) => `<div><span>${severity.charAt(0) + severity.slice(1).toLowerCase()}</span><strong>${count} · ${total ? ((count / total) * 100).toFixed(1) : "0"}%</strong></div>`).join("")}</div></div>`;
    return;
  }
  const max = Math.max(...Object.values(values), 1);
  $("#severityChart").innerHTML = Object.entries(values).map(([severity, count]) => `
    <div class="severity-row" data-severity="${severity}" title="${count} ${severity.toLowerCase()} findings · ${total ? ((count / total) * 100).toFixed(1) : "0"}%">
      <label>${severity.charAt(0) + severity.slice(1).toLowerCase()}</label>
      <div class="severity-track"><div class="severity-fill" style="width:${count ? Math.max((count / max) * 100, 8) : 0}%"></div></div>
      <b>${count}</b>
    </div>
  `).join("");
}

function latestConfigurationScan() {
  return state.statistics?.recent_scans?.[0] || null;
}

function renderDashboardStatistics() {
  const statistics = state.statistics;
  const stats = statistics?.stats;
  const latestScan = latestConfigurationScan();
  const latestSummary = latestScan?.summary || null;
  if (!stats) {
    ["metricTotalScans", "metricLatestScore", "metricLatestFindings", "metricRulesChecked"]
      .forEach((id) => $("#" + id).textContent = "—");
    ["scanCountMeta", "latestScanMeta", "latestFindingsMeta", "latestRulesMeta"]
      .forEach((id) => $("#" + id).textContent = "Analytics unavailable");
    renderSeverity(null);
    renderScoreTrend();
    renderVulnerabilitiesByNF();
    renderFrequentRules();
    renderRecentActivity();
    renderEnvironmentDashboardStatistics();
    if (state.currentPage === "analytics") renderAnalyticsPage();
    return;
  }

  $("#metricTotalScans").textContent = String(stats.total_scans ?? 0);
  $("#metricLatestScore").textContent = typeof latestSummary?.security_score === "number"
    ? String(latestSummary.security_score)
    : "—";
  $("#metricLatestFindings").textContent = Number.isInteger(latestSummary?.total_findings)
    ? String(latestSummary.total_findings)
    : "—";
  $("#metricRulesChecked").textContent = Number.isInteger(latestSummary?.total_rules_checked)
    ? String(latestSummary.total_rules_checked)
    : "—";
  $("#scanCountMeta").textContent = `${stats.total_scans} saved configuration scans`;
  $("#latestScanMeta").textContent = latestScan
    ? latestScan.filename
    : "No completed configuration scan";
  $("#latestFindingsMeta").textContent = latestSummary
    ? `${latestSummary.critical ?? 0} critical · ${latestSummary.high ?? 0} high · ${latestSummary.medium ?? 0} medium · ${latestSummary.low ?? 0} low`
    : "No scan result";
  $("#latestRulesMeta").textContent = latestSummary
    ? `${latestSummary.network_function || latestScan.network_function || "Unknown NF"} · ${formatTime(latestScan.scanned_at)}`
    : "No scan rule data";
  renderSeverity(latestSummary);
  renderScoreTrend();
  renderVulnerabilitiesByNF();
  renderFrequentRules();
  renderRecentActivity();
  renderEnvironmentDashboardStatistics();
  if (state.currentPage === "analytics") renderAnalyticsPage();
}

function renderRuntimeChart(containerId, entries, labelKey, unavailableMessage) {
  const chart = $("#" + containerId);
  if (!chart) return;
  if (!entries) {
    chart.innerHTML = `<div class="analytics-empty"><strong>Runtime data unavailable</strong><span>${escapeHtml(unavailableMessage)}</span></div>`;
    return;
  }
  if (!entries.length) {
    chart.innerHTML = `<div class="analytics-empty"><strong>No runtime data</strong><span>Saved runtime assessment records will appear here.</span></div>`;
    return;
  }
  const maximum = Math.max(...entries.map((entry) => Number(entry.count) || 0), 1);
  chart.innerHTML = entries.map((entry) => {
    const count = Number(entry.count) || 0;
    const width = count ? Math.max((count / maximum) * 100, 4) : 0;
    return `<div class="runtime-chart-row" title="${escapeHtml(entry[labelKey])}: ${count}">
      <strong>${escapeHtml(entry[labelKey])}</strong>
      <div class="runtime-chart-track"><i style="width:${width}%"></i></div>
      <span>${count}</span>
    </div>`;
  }).join("");
}

function renderEnvironmentDashboardStatistics() {
  const stats = state.environmentStatistics;
  if (!stats) {
    ["metricRunningNetworks", "metricRuntimeAssessments", "metricRuntimeFindings"]
      .forEach((id) => { if ($("#" + id)) $("#" + id).textContent = "—"; });
    ["runningNetworksMeta", "runtimeAssessmentsMeta", "runtimeFindingsMeta"]
      .forEach((id) => { if ($("#" + id)) $("#" + id).textContent = "Environment analytics unavailable"; });
    const message = state.environmentStatisticsError || "Waiting for environment status.";
    renderRuntimeChart("networkStatusChart", null, "status", message);
    renderRuntimeChart("runtimeSeverityChart", null, "severity", message);
    renderRuntimeChart("runtimeNetworkChart", null, "network_name", message);
    renderRuntimeChart("assessmentTypeChart", null, "label", message);
    return;
  }

  $("#metricRunningNetworks").textContent = String(stats.running_networks);
  $("#metricRuntimeAssessments").textContent = String(stats.runtime_assessments_completed);
  $("#metricRuntimeFindings").textContent = String(stats.total_runtime_findings);
  $("#runningNetworksMeta").textContent = "Live Docker Compose status";
  $("#runtimeAssessmentsMeta").textContent = "Persisted assessments";
  $("#runtimeFindingsMeta").textContent = "Security findings only";
  renderRuntimeChart(
    "networkStatusChart",
    stats.network_status_distribution,
    "status",
    "The backend could not read current Docker status."
  );
  renderRuntimeChart(
    "runtimeSeverityChart",
    stats.runtime_findings_by_severity,
    "severity",
    "Runtime finding summaries could not be loaded."
  );
  renderRuntimeChart(
    "runtimeNetworkChart",
    stats.runtime_findings_by_network,
    "network_name",
    "Runtime finding summaries could not be loaded."
  );
  renderRuntimeChart(
    "assessmentTypeChart",
    stats.findings_by_type,
    "label",
    "Assessment totals could not be loaded."
  );
}

async function loadEnvironmentDashboardStatistics() {
  try {
    state.environmentStatistics = await fetchEnvironmentStatistics();
    state.environmentStatisticsError = null;
  } catch (error) {
    state.environmentStatistics = null;
    state.environmentStatisticsError = error.message;
  }
  renderEnvironmentDashboardStatistics();
}

async function loadStatistics() {
  try {
    state.statistics = await fetchDashboardStatistics();
    state.statisticsError = null;
    renderDashboardStatistics();
  } catch (error) {
    state.statistics = null;
    state.statisticsError = error.message;
    renderDashboardStatistics();
  }
}

function renderScoreTrend() {
  const entries = state.statistics?.security_score_trend || [];
  const chart = $("#trendChart");
  if (!entries.length) {
    chart.innerHTML = `<div class="analytics-empty"><strong>No score history</strong><span>Completed scans with a stored score will appear here.</span></div>`;
    return;
  }

  const width = 620;
  const height = 210;
  const left = 34;
  const right = 12;
  const top = 12;
  const bottom = 36;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const points = entries.map((entry, index) => ({
    x: entries.length === 1 ? left + plotWidth / 2 : left + (index / (entries.length - 1)) * plotWidth,
    y: top + ((100 - Number(entry.security_score)) / 100) * plotHeight,
    entry,
    index
  }));
  const line = points.map((point) => `${point.x},${point.y}`).join(" ");
  const labels = points.filter((point) =>
    point.index === 0 ||
    point.index === points.length - 1 ||
    point.index % Math.max(1, Math.ceil(points.length / 5)) === 0
  );
  const grid = [0, 50, 100].map((score) => {
    const y = top + ((100 - score) / 100) * plotHeight;
    return `<line x1="${left}" y1="${y}" x2="${width - right}" y2="${y}" class="trend-gridline"></line><text x="2" y="${y + 3}" class="trend-axis-label">${score}</text>`;
  }).join("");
  const dots = points.map(({ x, y, entry }) =>
    `<circle cx="${x}" cy="${y}" r="3" class="trend-point"><title>${escapeHtml(entry.filename)} · ${formatTime(entry.scanned_at)} · ${entry.security_score}/100</title></circle>`
  ).join("");
  const xLabels = labels.map(({ x, entry, index }) =>
    `<text x="${x}" y="${height - 8}" text-anchor="middle" class="trend-axis-label">${escapeHtml(formatTime(entry.scanned_at).split(",")[0] || `#${index + 1}`)}</text>`
  ).join("");
  chart.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Security scores across recorded scans">
    ${grid}<polyline points="${line}" class="trend-line"></polyline>${dots}${xLabels}
  </svg>${state.statistics?.trend_truncated ? `<small class="chart-footnote">Showing the latest ${entries.length} scored scans.</small>` : ""}`;
}

function renderVulnerabilitiesByNF() {
  const chart = $("#vulnerabilitiesByNF");
  const entries = state.statistics?.vulnerabilities_by_network_function;
  if (!entries) {
    chart.innerHTML = `<div class="analytics-empty"><strong>Network function data unavailable</strong><span>Connect to the backend to load historical findings.</span></div>`;
    return;
  }
  const max = Math.max(...entries.map((entry) => Number(entry.count) || 0), 1);
  chart.innerHTML = entries.map((entry) => {
    const count = Number(entry.count) || 0;
    const width = count ? Math.max((count / max) * 100, 4) : 0;
    return `<div class="nf-bar-row" title="${escapeHtml(entry.network_function)}: ${count} findings">
      <strong>${escapeHtml(entry.network_function)}</strong>
      <div class="nf-bar-track"><i style="width:${width}%"></i></div>
      <span>${count}</span>
    </div>`;
  }).join("");
}

function renderFrequentRules() {
  const chart = $("#frequencyChart");
  const rules = state.statistics?.frequent_rules;
  if (!rules) {
    chart.innerHTML = `<div class="analytics-empty"><strong>Rule frequency unavailable</strong><span>Connect to the backend to load persisted findings.</span></div>`;
    return;
  }
  if (!rules.length) {
    chart.innerHTML = `<div class="analytics-empty"><strong>No findings recorded</strong><span>Rule counts will appear after scans produce findings.</span></div>`;
    return;
  }
  const max = Math.max(...rules.map((rule) => rule.count), 1);
  chart.innerHTML = rules.slice(0, 8).map((rule) => `
    <button class="frequency-row" data-rule-id="${escapeHtml(rule.rule_id)}" title="${escapeHtml(rule.title)} · ${rule.count} findings">
      <span><strong>${escapeHtml(rule.rule_id)}</strong><small>${escapeHtml(rule.title)}</small></span>
      <i><b style="width:${(rule.count / max) * 100}%"></b></i>
      <strong>${rule.count}</strong>
    </button>
  `).join("");
}

function renderRecentActivity() {
  const chart = $("#activityTimeline");
  const scans = state.statistics?.recent_scans;
  if (!scans) {
    chart.innerHTML = `<div class="analytics-empty"><strong>Scan activity unavailable</strong><span>Connect to the backend to load saved scan records.</span></div>`;
    return;
  }
  if (!scans.length) {
    chart.innerHTML = `<div class="analytics-empty"><strong>No scan activity yet</strong><span>Upload or scan a sample configuration to begin.</span></div>`;
    return;
  }
  chart.innerHTML = `
    <div class="activity-table-row activity-table-header"><strong>Filename</strong><strong>Network Function</strong><strong>Scan date</strong><strong>Score</strong><strong>Findings</strong><strong>Status</strong></div>
    ${scans.map((scan) => `
      <button class="activity-table-row" data-scan-id="${escapeHtml(scan.scan_id)}">
        <strong>${escapeHtml(scan.filename)}</strong>
        <span>${escapeHtml(scan.network_function || "Unavailable")}</span>
        <span>${formatTime(scan.scanned_at)}</span>
        <span>${scan.security_score ?? "—"}</span>
        <span>${scan.total_findings ?? 0}</span>
        <span class="activity-status">${escapeHtml(scan.result_status || scan.status || "UNKNOWN")}</span>
      </button>
    `).join("")}
  `;
  $$(".activity-table-row[data-scan-id]").forEach((row) =>
    row.addEventListener("click", () => loadScan(row.dataset.scanId))
  );
}

function renderMatrix(summary) {
  const activeNF = summary?.network_function;
  const currentFindings = state.currentScan?.findings || [];
  const categories = [...new Set(currentFindings.map((finding) => finding.category).filter(Boolean))].slice(0, 6);
  if (!categories.length) categories.push(...CATEGORIES);
  let header = `<div class="matrix-grid header"><span>NF</span>${categories.map((category) => `<span>${escapeHtml(category)}</span>`).join("")}</div>`;
  const rows = NFs.map((nf) => {
    const cells = categories.map((category) => {
      let className = "";
      if (nf === activeNF) {
        const categoryFindings = currentFindings.filter((finding) => finding.category === category);
        if (categoryFindings.some((finding) => finding.severity === "CRITICAL")) className = "red";
        else if (categoryFindings.some((finding) => ["HIGH", "MEDIUM"].includes(finding.severity))) className = "amber";
      }
      const categoryFindings = nf === activeNF ? currentFindings.filter((finding) => finding.category === category) : [];
      const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
      const highest = [...categoryFindings].sort((a, b) => (weights[b.severity] || 0) - (weights[a.severity] || 0))[0]?.severity || "None";
      const ruleIds = categoryFindings.map((finding) => finding.rule_id).join(", ") || "None";
      return `<i class="matrix-cell ${className}" data-nf="${nf}" data-category="${escapeHtml(category)}" title="${nf} · ${escapeHtml(category)} · ${categoryFindings.length} findings · Highest: ${highest} · Rules: ${escapeHtml(ruleIds)}"></i>`;
    }).join("");
    return `<div class="matrix-grid matrix-row" data-nf="${nf}"><strong>${nf}</strong>${cells}</div>`;
  }).join("");
  $("#nfMatrix").innerHTML = header + rows;
  $$(".matrix-row").forEach((row) => row.addEventListener("click", () => selectNode(row.dataset.nf)));
  $$(".matrix-cell").forEach((cell) => cell.addEventListener("click", (event) => {
    event.stopPropagation();
    const finding = (state.currentScan?.findings || []).find((item) =>
      item.target_nf === cell.dataset.nf && item.category === cell.dataset.category
    );
    if (finding) openFinding(finding);
    else selectNode(cell.dataset.nf);
  }));
}

function renderTrend() {
  const nf = state.currentScan?.summary?.network_function;
  const comparable = nf
    ? state.historyDetails.filter((entry) => entry.summary?.network_function === nf)
    : [];

  if (!comparable.length) {
    $("#trendChart").innerHTML = `<div class="analytics-empty"><strong>No comparable trend</strong><span>Load a scanned network function to begin a comparison.</span></div>`;
    return;
  }
  if (comparable.length < 2) {
    $("#trendChart").innerHTML = `<div class="analytics-empty"><strong>More scans required to display a trend.</strong><span>Comparable ${escapeHtml(nf)} scan history has 1 record.</span></div>`;
    return;
  }
  const values = comparable.map((entry) => Number(entry.summary.security_score));
  const width = 420, height = 105, pad = 8;
  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : pad + (index / (values.length - 1)) * (width - pad * 2);
    const y = height - pad - (value / 100) * (height - pad * 2);
    return [x, y];
  });
  const line = points.map((point) => point.join(",")).join(" ");
  const area = `${pad},${height} ${line} ${width - pad},${height}`;
  $("#trendChart").innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
    <polygon class="area" points="${area}"></polygon>
    <polyline points="${line}"></polyline>
  </svg>`;
}

function renderTopRisks() {
  const findings = state.currentScan?.findings || [];
  const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const ranked = [...findings].sort((a, b) =>
    (weights[b.severity] || 0) - (weights[a.severity] || 0) ||
    String(a.rule_id).localeCompare(String(b.rule_id))
  ).slice(0, 5);
  if (!ranked.length) {
    const detailsUnavailable = !state.currentScan && state.history.length > 0;
    $("#riskList").innerHTML = detailsUnavailable
      ? `<div class="analytics-empty"><strong>Finding details unavailable</strong><span>Saved history provides counts only. Run a scan in this session to view ranked risks.</span></div>`
      : `<div class="analytics-empty"><strong>No ranked risks</strong><span>${state.currentScan ? "The selected scan contains no findings." : "Run a scan to see ranked risks."}</span></div>`;
    return;
  }
  $("#riskList").innerHTML = ranked.map((finding, index) => `
    <button class="risk-row" data-rule-id="${escapeHtml(finding.rule_id)}">
      <span class="risk-index">${String(index + 1).padStart(2, "0")}</span>
      <span class="risk-copy"><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.target_nf)} · ${escapeHtml(finding.category)}</small></span>
      <span class="severity-pill ${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span>
    </button>
  `).join("");
  $$(".risk-row").forEach((row) => row.addEventListener("click", () =>
    openFinding(findings.find((finding) => finding.rule_id === row.dataset.ruleId))
  ));
}

function renderCategoryChart() {
  const findings = state.currentScan?.findings || [];
  if (!findings.length) {
    const detailsUnavailable = !state.currentScan && state.history.length > 0;
    $("#categoryChart").innerHTML = detailsUnavailable
      ? `<div class="analytics-empty"><strong>Finding details unavailable</strong><span>Saved history provides counts only. Run a scan in this session to view categories.</span></div>`
      : `<div class="analytics-empty"><strong>No categories flagged</strong><span>${state.currentScan ? "No findings in the selected scan." : "Run a scan to see finding categories."}</span></div>`;
    return;
  }
  const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const groups = {};
  findings.forEach((finding) => {
    const category = finding.category || "Uncategorized";
    if (!groups[category]) groups[category] = [];
    groups[category].push(finding);
  });
  const categories = Object.entries(groups).sort((a, b) =>
    b[1].length - a[1].length ||
    a[0].localeCompare(b[0])
  );
  const max = Math.max(...categories.map(([, items]) => items.length));
  $("#categoryChart").innerHTML = categories.map(([category, items]) => {
    const highest = [...items].sort((a, b) => (weights[b.severity] || 0) - (weights[a.severity] || 0))[0].severity;
    const percentage = (items.length / findings.length) * 100;
    return `<button class="category-row" data-category="${escapeHtml(category)}" title="${escapeHtml(category)}: ${items.length} findings · ${percentage.toFixed(1)}% · Highest ${highest}">
      <span class="category-name">${escapeHtml(category)}</span>
      <span class="category-track"><i style="width:${(items.length / max) * 100}%"></i></span>
      <strong>${items.length} · ${percentage.toFixed(0)}%</strong>
      <small>${highest}</small>
    </button>`;
  }).join("");
  $$(".category-row").forEach((row) => row.addEventListener("click", () => {
    const first = findings.find((finding) => finding.category === row.dataset.category);
    if (first) openFinding(first);
  }));
}

function renderRuleCoverage() {
  const evaluated = state.currentScan?.summary?.total_rules_checked;
  $("#coverageMeta").textContent = state.currentScan ? "BACKEND REPORTED" : "PER-SCAN DATA";
  if ($("#coverageCount")) $("#coverageCount").textContent = Number.isFinite(Number(evaluated)) ? `${evaluated} CHECKED` : "SCAN REQUIRED";
  if (!Number.isFinite(Number(evaluated))) {
    $("#coverageChart").innerHTML = `<div class="analytics-empty"><strong>Rule coverage unavailable</strong><span>Run a scan to see the number of rules evaluated.</span></div>`;
    return;
  }
  $("#coverageChart").innerHTML = `
    <div class="coverage-summary"><span><strong>${evaluated}</strong>Rules evaluated</span><span><strong>${state.currentScan.findings.length}</strong>Findings returned</span></div>
    <div class="analytics-empty"><strong>Evaluation count from backend</strong><span>The API does not expose the full rule catalog or per-rule pass results.</span></div>
  `;
}

function renderFrequencyChart() {
  const counts = {};
  state.historyDetails.forEach((scan) => {
    const unique = new Map();
    (scan.findings || []).forEach((finding) => unique.set(finding.rule_id, finding));
    unique.forEach((finding, ruleId) => {
      if (!counts[ruleId]) counts[ruleId] = { count: 0, title: finding.title, nfs: new Set() };
      counts[ruleId].count += 1;
      counts[ruleId].nfs.add(finding.target_nf);
    });
  });
  const ranked = Object.entries(counts).sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0])).slice(0, 5);
  if (!ranked.length) {
    $("#frequencyChart").innerHTML = `<div class="analytics-empty"><strong>No rule frequency data</strong><span>Only scans run in this session include finding-level history.</span></div>`;
    return;
  }
  const max = ranked[0][1].count;
  $("#frequencyChart").innerHTML = ranked.map(([ruleId, item]) => `
    <div class="frequency-row" title="Occurrences among scans run in this session">
      <span><strong>${escapeHtml(ruleId)}</strong><small>${escapeHtml([...item.nfs].join(", "))}</small></span>
      <i><b style="width:${(item.count / max) * 100}%"></b></i>
      <strong>${item.count}</strong>
    </div>
  `).join("");
}

function renderActivityTimeline() {
  if (!state.history.length) {
    $("#activityTimeline").innerHTML = `<div class="analytics-empty"><strong>No activity</strong><span>Scan completions appear here.</span></div>`;
    return;
  }
  $("#activityTimeline").innerHTML = state.history.slice(0, 8).map((entry) => {
    const detail = state.historyDetails.find((scan) => scan.scan_id === entry.scan_id);
    const nf = detail?.summary?.network_function || "NF unavailable";
    return `<button class="activity-row" data-scan-id="${escapeHtml(entry.scan_id)}">
      <i></i><span><strong>${escapeHtml(nf)}</strong><small>${escapeHtml(entry.filename)}</small></span>
      <span class="activity-metrics"><strong>${entry.total_findings ?? 0}</strong><small>${detail ? `${detail.summary.security_score}/100` : "Score unavailable"}</small></span>
      <time>${formatTime(entry.scanned_at)}</time>
    </button>`;
  }).join("");
  $$(".activity-row").forEach((row) => row.addEventListener("click", () => loadScan(row.dataset.scanId)));
}

function renderRemediationInto(container, scan) {
  if (!container) return;
  const findings = scan?.findings || [];
  if (!scan || scan.findings_available === false) {
    container.innerHTML = `<div class="analytics-empty"><strong>Finding details unavailable</strong><span>This saved record does not contain a complete finding list, so remediation status cannot be shown accurately.</span></div>`;
    return;
  }
  if (!findings.length) {
    container.innerHTML = `<div class="analytics-empty"><strong>No recommendations</strong><span>The selected scan contains no findings.</span></div>`;
    return;
  }

  container.innerHTML = findings.map((finding) => `
    <article class="finding-card">
      <div class="finding-card-top">
        <div><h3>${escapeHtml(finding.title)}</h3><span>${escapeHtml(finding.rule_id)} · ${escapeHtml(finding.target_nf)}</span></div>
        <span class="severity-pill ${escapeHtml(finding.severity).toLowerCase()}">${escapeHtml(finding.severity)}</span>
      </div>
      <p>${escapeHtml(finding.remediation)}</p>
      <label class="muted-note">Remediation status
        <select class="status-select" data-rule-id="${escapeHtml(finding.rule_id)}" data-target-nf="${escapeHtml(finding.target_nf)}">
          <option value="PENDING" ${finding.remediation_status === "PENDING" || !finding.remediation_status ? "selected" : ""}>Pending</option>
          <option value="FIXED" ${finding.remediation_status === "FIXED" ? "selected" : ""}>Fixed</option>
          <option value="ACCEPTED_RISK" ${finding.remediation_status === "ACCEPTED_RISK" ? "selected" : ""}>Accepted Risk</option>
        </select>
      </label>
    </article>
  `).join("");
  container.querySelectorAll(".status-select").forEach((select) =>
    select.addEventListener("change", () => saveFindingRemediation(select, scan))
  );
}

async function saveFindingRemediation(select, scan) {
  const finding = scan.findings.find((item) =>
    item.rule_id === select.dataset.ruleId &&
    item.target_nf === select.dataset.targetNf
  );
  if (!finding) return;
  const previousStatus = finding.remediation_status || "PENDING";
  select.disabled = true;
  try {
    const result = await updateRemediationStatus(
      scan.scan_id,
      finding.rule_id,
      finding.target_nf,
      select.value
    );
    finding.remediation_status = result.status;
    toast(`Remediation status saved: ${result.status.replace("_", " ")}`);
  } catch (error) {
    select.value = previousStatus;
    toast(error.message);
  } finally {
    select.disabled = false;
  }
}

function renderRemediation() {
  renderRemediationInto($("#remediationList"), state.currentScan);
  renderRemediationInto($("#remediationListUtility"), state.currentScan);
}

function renderHistory() {
  if (state.currentPage !== "history") return;
  const { search, nf, severity, sort } = state.historyFilters;
  const start = state.historyTotal ? state.historyOffset + 1 : 0;
  const end = Math.min(state.historyOffset + state.history.length, state.historyTotal);
  $("#utilityContent").innerHTML = `
    <div class="history-toolbar">
      <input id="historySearch" type="search" placeholder="Search filename" value="${escapeHtml(search)}" />
      <select id="historyNF"><option value="">All network functions</option>${NFs.map((item) => `<option value="${item}" ${nf === item ? "selected" : ""}>${item}</option>`).join("")}</select>
      <select id="historySeverity">
        <option value="">All severities</option>
        ${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((item) => `<option value="${item}" ${severity === item ? "selected" : ""}>${item}</option>`).join("")}
      </select>
      <select id="historySort">
        <option value="date-desc" ${sort === "date-desc" ? "selected" : ""}>Newest first</option>
        <option value="date-asc" ${sort === "date-asc" ? "selected" : ""}>Oldest first</option>
        <option value="score-desc" ${sort === "score-desc" ? "selected" : ""}>Score: high to low</option>
        <option value="score-asc" ${sort === "score-asc" ? "selected" : ""}>Score: low to high</option>
      </select>
    </div>
    ${state.history.length ? `
      <div class="history-list-table">
        <div class="history-list-row header"><strong>Assessment</strong><span>Type</span><span>Network</span><span>Date</span><span>Findings</span><span>Score</span><span>Status</span><span>Actions</span></div>
        ${state.history.map((entry) => `
          <div class="history-list-row">
            <strong title="${escapeHtml(entry.filename)}">${escapeHtml(entry.filename)}</strong>
            <span>${entry.assessment_type === "runtime" ? "Runtime" : "Configuration"}</span>
            <span>${escapeHtml(entry.network_function || "—")}</span>
            <span>${formatTime(entry.scanned_at)}</span>
            <span>${entry.total_findings ?? 0} · C${entry.critical_count || 0}/H${entry.high_count || 0}/M${entry.medium_count || 0}/L${entry.low_count || 0}</span>
            <span>${entry.security_score ?? "—"}</span>
            <span>${escapeHtml(entry.result_status || entry.status || "UNKNOWN")}</span>
            <span class="history-row-actions">${entry.assessment_type === "runtime"
              ? `<button data-history-runtime="${escapeHtml(entry.assessment_id || entry.scan_id)}" data-history-network="${escapeHtml(entry.network_id || "alpha")}">View</button>`
              : `<button data-history-open="${escapeHtml(entry.scan_id)}">Open</button><button data-history-compare="${escapeHtml(entry.scan_id)}">Compare</button>`
            }</span>
          </div>
        `).join("")}
      </div>
    ` : `<div class="analytics-empty"><strong>${state.historyTotal ? "No matching scans" : "No scan history"}</strong><span>${state.historyTotal ? "Adjust the filters to see matching records." : "Completed scans will appear here."}</span></div>`}
    <div class="history-pagination">
      <span>Showing ${start}–${end} of ${state.historyTotal}</span>
      <div><button id="historyPrevious" ${state.historyOffset <= 0 ? "disabled" : ""}>Previous</button> <button id="historyNext" ${end >= state.historyTotal ? "disabled" : ""}>Next</button></div>
    </div>
  `;
  $("#historySearch").addEventListener("input", (event) => {
    state.historyFilters.search = event.target.value;
    state.historyOffset = 0;
    clearTimeout(renderHistory.searchTimer);
    renderHistory.searchTimer = setTimeout(loadHistory, 250);
  });
  $("#historyNF").addEventListener("change", (event) => {
    state.historyFilters.nf = event.target.value;
    state.historyOffset = 0;
    loadHistory();
  });
  $("#historySeverity").addEventListener("change", (event) => {
    state.historyFilters.severity = event.target.value;
    state.historyOffset = 0;
    loadHistory();
  });
  $("#historySort").addEventListener("change", (event) => {
    state.historyFilters.sort = event.target.value;
    state.historyOffset = 0;
    loadHistory();
  });
  $("#historyPrevious").addEventListener("click", () => {
    state.historyOffset = Math.max(0, state.historyOffset - HISTORY_PAGE_SIZE);
    loadHistory();
  });
  $("#historyNext").addEventListener("click", () => {
    state.historyOffset += HISTORY_PAGE_SIZE;
    loadHistory();
  });
  $$("[data-history-open]").forEach((button) =>
    button.addEventListener("click", () => loadScan(button.dataset.historyOpen))
  );
  $$("[data-history-runtime]").forEach((button) =>
    button.addEventListener("click", () => loadRuntimeAssessment(
      button.dataset.historyRuntime,
      button.dataset.historyNetwork
    ))
  );
  $$("[data-history-compare]").forEach((button) =>
    button.addEventListener("click", () => {
      state.comparePrefill = button.dataset.historyCompare;
      showUtilityPage("comparison");
    })
  );
}

async function loadScan(scanId, options = {}) {
  let scan = state.historyDetails.find((entry) => entry.scan_id === scanId);
  if (!scan) {
    try {
      scan = await fetchScanDetails(scanId);
      state.historyDetails = [...state.historyDetails.filter((entry) => entry.scan_id !== scanId), scan];
    } catch (error) {
      toast(error.message);
      return null;
    }
  }
  state.currentScan = scan;
  renderHealth(scan.summary);
  if ($("#scanFilter") && state.history.some((entry) => entry.scan_id === scanId)) {
    $("#scanFilter").value = scanId;
  }
  if (state.currentPage === "findings") renderFindingsPage();
  if (state.currentPage === "remediation") renderRemediation();
  if (!options.silent) {
    closeModal();
    toast(`Loaded ${scan.filename}`);
  }
  return scan;
}

const topologyPositions = {
  AMF: [450, 150], SMF: [270, 320], UPF: [630, 320],
  NRF: [450, 350], AUSF: [245, 535], UDM: [630, 535], PCF: [790, 535]
};

function createTopology() {
  const nodeGroup = $("#nodes");
  const connectionGroup = $("#connections");
  const connections = [
    ["AMF", "NRF"], ["AMF", "SMF"], ["SMF", "UPF"], ["SMF", "NRF"],
    ["NRF", "AUSF"], ["NRF", "UDM"], ["NRF", "PCF"], ["AUSF", "AMF"],
    ["UDM", "SMF"], ["UPF", "UDM"], ["AUSF", "UDM"], ["PCF", "SMF"]
  ];
  connectionGroup.innerHTML = connections.map(([a, b]) => {
    const pa = topologyPositions[a], pb = topologyPositions[b];
    const d = `M${pa[0]} ${pa[1]} C${(pa[0] + pb[0]) / 2} ${pa[1]}, ${(pa[0] + pb[0]) / 2} ${pb[1]}, ${pb[0]} ${pb[1]}`;
    return `<path class="connection-line" data-a="${a}" data-b="${b}" d="${d}"></path>`;
  }).join("");

  nodeGroup.innerHTML = NFs.map((nf) => {
    const [x, y] = topologyPositions[nf];
    const points = Array.from({ length: 24 }, (_, i) => {
      const angle = (i / 24) * Math.PI * 2;
      const radius = i % 3 === 0 ? 39 : 31 + (i % 4) * 2;
      return `<circle cx="${(Math.cos(angle) * radius).toFixed(1)}" cy="${(Math.sin(angle) * radius).toFixed(1)}" r="${i % 4 === 0 ? 1.3 : 0.8}"></circle>`;
    }).join("");
    return `<g class="node-group" data-nf="${nf}" transform="translate(${x} ${y})">
      <circle class="node-selected-ring" r="58"></circle>
      <circle class="node-halo" r="48"></circle>
      <circle class="node-halo" r="43" stroke-dasharray="1 6"></circle>
      <circle class="node-core" r="34"></circle>
      <g class="node-points" transform="translate(0 0)">${points}</g>
      <text class="node-label" y="-3">${nf}</text>
      <text class="node-status" y="11">UNKNOWN</text>
      <circle class="node-indicator" cx="26" cy="-24" r="3"></circle>
      <text class="node-count" y="51">NO DATA</text>
    </g>`;
  }).join("");

  $$(".node-group").forEach((node) => {
    node.addEventListener("mouseenter", () => highlightNode(node.dataset.nf));
    node.addEventListener("mouseleave", () => clearHighlights());
    node.addEventListener("click", () => selectNode(node.dataset.nf));
  });
}

function highlightNode(nf) {
  $$(".connection-line").forEach((line) => line.classList.toggle("hot", line.dataset.a === nf || line.dataset.b === nf));
  showNodeTooltip(nf);
}

function clearHighlights() {
  $$(".connection-line").forEach((line) => line.classList.remove("hot"));
  hideNodeTooltip();
}

function showNodeTooltip(nf) {
  let tooltip = $(".node-tooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "node-tooltip";
    document.body.appendChild(tooltip);
  }
  const findings = state.currentScan?.findings?.filter((finding) =>
    finding.target_nf === nf ||
    (finding.target_nf === "ALL" && state.currentScan?.summary?.network_function === nf)
  ) || [];
  tooltip.innerHTML = `<strong>${nf}</strong><br>${findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"}` : "No findings in current scan"}`;
  tooltip.classList.add("visible");
  document.addEventListener("mousemove", positionTooltip);
  positionTooltip();
}

function positionTooltip(event) {
  const tooltip = $(".node-tooltip");
  if (!tooltip) return;
  const x = event?.clientX ?? innerWidth / 2;
  const y = event?.clientY ?? innerHeight / 2;
  tooltip.style.left = `${x + 12}px`;
  tooltip.style.top = `${y + 12}px`;
}

function hideNodeTooltip() {
  const tooltip = $(".node-tooltip");
  if (tooltip) tooltip.classList.remove("visible");
  document.removeEventListener("mousemove", positionTooltip);
}

function updateTopology(summary) {
  const nf = summary?.network_function;
  const findings = state.currentScan?.findings || [];
  $$(".node-group").forEach((node) => {
    const name = node.dataset.nf;
    const nodeFindings = findings.filter((finding) => finding.target_nf === name || (finding.target_nf === "ALL" && name === nf));
    const status = node.querySelector(".node-status");
    const count = node.querySelector(".node-count");
    const indicator = node.querySelector(".node-indicator");
    indicator.setAttribute("class", "node-indicator");
    indicator.style.fill = "var(--muted)";
    if (name === nf) {
      status.textContent = summary.status === "CLEAN" ? "NO FINDINGS" : "FINDINGS";
      count.textContent = `${summary.total_findings ?? 0} FINDINGS`;
      const hasCritical = (summary.critical || 0) > 0 || nodeFindings.some((finding) => finding.severity === "CRITICAL");
      const hasHigh = (summary.high || 0) > 0 || nodeFindings.some((finding) => finding.severity === "HIGH");
      const hasMedium = (summary.medium || 0) > 0 || nodeFindings.some((finding) => finding.severity === "MEDIUM");
      indicator.style.fill = hasCritical
        ? "var(--accent-coral)"
        : hasHigh
          ? "var(--accent-amber)"
          : hasMedium
            ? "var(--accent-yellow)"
            : "var(--muted)";
      const core = node.querySelector(".node-core");
      if (state.mode === "risk") {
        if (hasCritical) core.style.stroke = "var(--accent-coral)";
        else if (hasHigh) core.style.stroke = "var(--accent-amber)";
        else if (hasMedium) core.style.stroke = "var(--accent-yellow)";
        else core.style.stroke = "var(--muted)";
      } else {
        core.style.stroke = "";
      }
    } else {
      status.textContent = "NOT SCANNED";
      count.textContent = "NO DATA";
      node.querySelector(".node-core").style.stroke = "";
    }
  });
}

function selectNode(nf) {
  state.selectedNode = nf;
  $$(".node-group").forEach((node) => {
    node.classList.toggle("selected", node.dataset.nf === nf);
    node.classList.toggle("dimmed", node.dataset.nf !== nf);
  });
  openNodeInspector(nf);
}

function openNodeInspector(nf) {
  const findings = (state.currentScan?.findings || []).filter((finding) => finding.target_nf === nf || (finding.target_nf === "ALL" && state.currentScan?.summary?.network_function === nf));
  const isCurrent = state.currentScan?.summary?.network_function === nf;
  const severity = (name) => findings.filter((finding) => finding.severity === name).length;
  const applicableCount = isCurrent ? (state.currentScan.summary.total_rules_checked ?? "—") : "—";
  const topFinding = [...findings].sort((a, b) => ({CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1}[b.severity] || 0) - ({CRITICAL:10,HIGH:7,MEDIUM:4,LOW:1}[a.severity] || 0))[0];
  $("#inspectorEyebrow").textContent = "NETWORK FUNCTION";
  $("#inspectorTitle").textContent = nf;
  $("#inspectorContent").innerHTML = `
    <div class="inspector-body">
      <div class="finding-meta">
        <div><span>Security score</span><strong>${isCurrent ? (state.currentScan.summary.security_score ?? "—") + " / 100" : "NOT AVAILABLE"}</strong></div>
        <div><span>Detected findings</span><strong>${findings.length}</strong></div>
        <div><span>Applicable rules evaluated</span><strong>${applicableCount}</strong></div>
        <div><span>Status</span><strong>${isCurrent ? state.currentScan.summary.status : "NOT EVALUATED"}</strong></div>
        <div><span>Critical / High</span><strong>${severity("CRITICAL")} / ${severity("HIGH")}</strong></div>
        <div><span>Medium / Low</span><strong>${severity("MEDIUM")} / ${severity("LOW")}</strong></div>
      </div>
      ${topFinding ? `<div class="inspector-block"><label>Top vulnerability</label><p><strong>${escapeHtml(topFinding.title)}</strong><br>${escapeHtml(topFinding.description)}</p></div><div class="inspector-block"><label>Recommended action</label><p>${escapeHtml(topFinding.remediation)}</p></div>` : `<div class="inspector-block"><label>Top vulnerability</label><p>${isCurrent ? "No vulnerability flagged in the current scan." : "Not scanned."}</p></div>`}
      <div class="inspector-block">
        <label>Detected vulnerabilities</label>
        ${findings.length ? findings.map((finding) => `
          <button class="export-option finding-link" data-rule-id="${escapeHtml(finding.rule_id)}" style="width:100%;margin:0 0 8px;">
            <span>${escapeHtml(finding.rule_id)} · ${escapeHtml(finding.severity)}</span>
            <small>${escapeHtml(finding.title)}</small>
          </button>
        `).join("") : `<p>No per-component findings are available from the current scan.</p>`}
      </div>
    </div>
  `;
  $("#inspector").classList.add("open");
  $$(".finding-link").forEach((button) => button.addEventListener("click", () => openFinding(findings.find((finding) => finding.rule_id === button.dataset.ruleId))));
}

function openFinding(finding) {
  if (!finding) return;
  const displayNF = finding.target_nf === "ALL"
    ? `${state.currentScan?.summary?.network_function || "Current scan NF"} (rule applies to ALL)`
    : finding.target_nf;
  $("#inspectorEyebrow").textContent = escapeHtml(finding.rule_id);
  $("#inspectorTitle").textContent = escapeHtml(finding.title);
  $("#inspectorContent").innerHTML = `
    <div class="inspector-body">
      <div class="finding-meta">
        <div><span>Severity</span><strong>${escapeHtml(finding.severity)}</strong></div>
        <div><span>Network function</span><strong>${escapeHtml(displayNF)}</strong></div>
        <div><span>Category</span><strong>${escapeHtml(finding.category)}</strong></div>
        <div><span>Rule ID</span><strong>${escapeHtml(finding.rule_id)}</strong></div>
      </div>
      <div class="inspector-block"><label>Description / why it matters</label><p>${escapeHtml(finding.description)}</p></div>
      <div class="inspector-block"><label>Suggested fix</label><div class="fix-code">${escapeHtml(finding.remediation)}</div><button class="copy-button" id="copyFix">Copy Fix</button></div>
    </div>
  `;
  $("#inspector").classList.add("open");
  $("#copyFix").addEventListener("click", async () => {
    await navigator.clipboard?.writeText(finding.remediation);
    toast("Remediation copied");
  });
}

function renderRuleTable() {
  const nf = $("#ruleNF")?.value || "";
  const severity = $("#ruleSeverity")?.value || "";
  const search = ($("#ruleSearch")?.value || "").toLowerCase();
  const findings = state.currentScan?.findings || [];
  const nfSelect = $("#ruleNF");
  if (nfSelect && nfSelect.options.length === 1) {
    NFs.forEach((name) => nfSelect.add(new Option(name, name)));
  }
  const filtered = findings.filter((rule) =>
    (!nf || rule.target_nf === nf || rule.target_nf === "ALL") &&
    (!severity || rule.severity === severity) &&
    (!search || `${rule.rule_id} ${rule.title} ${rule.category} ${rule.description}`.toLowerCase().includes(search))
  );
  if (!filtered.length) {
    const message = findings.length
      ? "No findings match the selected filters."
      : "No scan findings are available. The backend does not expose a full rule catalog.";
    $("#ruleTable").innerHTML = `<div class="inspector-body">${message}</div>`;
    return;
  }
  $("#ruleTable").innerHTML = `
    <div class="rule-row header"><strong>Rule ID</strong><strong>Title</strong><strong>Severity</strong><strong>Target NF</strong><strong class="header-category">Description</strong></div>
    ${filtered.map((rule) => `
      <div class="rule-row">
        <strong>${escapeHtml(rule.rule_id)}</strong>
        <p><strong>${escapeHtml(rule.title)}</strong></p>
        <span class="severity-pill">${escapeHtml(rule.severity)}</span>
        <strong>${escapeHtml(rule.target_nf)}</strong>
        <p>${escapeHtml(rule.description)}</p>
      </div>
    `).join("")}
  `;
}

function renderFindingsPage() {
  const scan = state.currentScan;
  if (!scan) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>No scan selected</strong><span>Open a saved scan from Scan History to review its findings.</span></div>`;
    return;
  }
  if (scan.findings_available === false) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Historical finding details are incomplete</strong><span>This scan has ${scan.total_findings} recorded findings, but only ${scan.findings.length} detail records are available. The page will not present an incomplete list as complete.</span></div>`;
    return;
  }

  const findings = scan.findings || [];
  const filters = state.findingFilters;
  const categories = [...new Set(findings.map((item) => item.category).filter(Boolean))].sort();
  const filtered = findings.filter((finding) => {
    const targetNF = finding.target_nf === "ALL"
      ? scan.summary.network_function
      : finding.target_nf;
    const searchable = `${finding.rule_id} ${finding.title} ${targetNF} ${finding.category} ${finding.description} ${finding.remediation}`.toLowerCase();
    return (!filters.search || searchable.includes(filters.search.toLowerCase())) &&
      (!filters.nf || targetNF === filters.nf) &&
      (!filters.severity || finding.severity === filters.severity) &&
      (!filters.category || finding.category === filters.category);
  });

  $("#utilityContent").innerHTML = `
    <p class="muted-note">Showing findings for ${escapeHtml(scan.filename)} · ${escapeHtml(scan.summary.network_function || "Unknown NF")} · score ${scan.summary.security_score ?? "unavailable"}/100.</p>
    <div class="finding-toolbar">
      <input id="findingSearch" type="search" placeholder="Search title, rule, description, or remediation" value="${escapeHtml(filters.search)}" />
      <select id="findingNF"><option value="">All network functions</option>${NFs.map((item) => `<option value="${item}" ${filters.nf === item ? "selected" : ""}>${item}</option>`).join("")}</select>
      <select id="findingSeverity"><option value="">All severities</option>${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((item) => `<option value="${item}" ${filters.severity === item ? "selected" : ""}>${item}</option>`).join("")}</select>
      <select id="findingCategory"><option value="">All categories</option>${categories.map((item) => `<option value="${escapeHtml(item)}" ${filters.category === item ? "selected" : ""}>${escapeHtml(item)}</option>`).join("")}</select>
    </div>
    ${filtered.length ? `<div class="findings-list">${filtered.map((finding) => {
      const targetNF = finding.target_nf === "ALL"
        ? `${scan.summary.network_function || "Unknown"} (global rule)`
        : finding.target_nf;
      return `<article class="finding-card">
        <div class="finding-card-top">
          <div><h3>${escapeHtml(finding.title)}</h3><span>${escapeHtml(finding.rule_id)}</span></div>
          <span class="severity-pill ${escapeHtml(finding.severity).toLowerCase()}">${escapeHtml(finding.severity)}</span>
        </div>
        <div class="sample-card-meta"><span>${escapeHtml(targetNF)}</span><span>${escapeHtml(finding.category)}</span></div>
        <div class="finding-detail-grid">
          <div><label>Description / why it matters</label><p>${escapeHtml(finding.description)}</p></div>
          <div><label>Recommended remediation</label><p>${escapeHtml(finding.remediation)}</p></div>
        </div>
      </article>`;
    }).join("")}</div>` : `<div class="analytics-empty"><strong>${findings.length ? "No findings match these filters" : "No findings in this scan"}</strong><span>${findings.length ? "Adjust the filters or search terms." : "The backend reported no findings for the selected scan."}</span></div>`}
  `;
  $("#findingSearch").addEventListener("input", (event) => {
    state.findingFilters.search = event.target.value;
    renderFindingsPage();
    $("#findingSearch").focus();
    $("#findingSearch").setSelectionRange(event.target.value.length, event.target.value.length);
  });
  $("#findingNF").addEventListener("change", (event) => {
    state.findingFilters.nf = event.target.value;
    renderFindingsPage();
  });
  $("#findingSeverity").addEventListener("change", (event) => {
    state.findingFilters.severity = event.target.value;
    renderFindingsPage();
  });
  $("#findingCategory").addEventListener("change", (event) => {
    state.findingFilters.category = event.target.value;
    renderFindingsPage();
  });
}

function renderRuleCatalogPage() {
  const filters = state.ruleFilters;
  const categories = [...new Set(state.rules.map((rule) => rule.category))].sort();
  const filtered = state.rules.filter((rule) => {
    const searchable = `${rule.rule_id} ${rule.title} ${rule.category} ${rule.target_nf} ${rule.description} ${rule.remediation} ${rule.scope}`.toLowerCase();
    return (!filters.search || searchable.includes(filters.search.toLowerCase())) &&
      (!filters.nf || rule.target_nf === "ALL" || rule.target_nf === filters.nf) &&
      (!filters.severity || rule.severity === filters.severity) &&
      (!filters.category || rule.category === filters.category);
  });
  $("#utilityContent").innerHTML = `
    <div class="catalog-toolbar">
      <input id="catalogSearchUtility" type="search" placeholder="Search active rules" value="${escapeHtml(filters.search)}" />
      <select id="catalogNFUtility"><option value="">All network functions</option>${NFs.map((item) => `<option value="${item}" ${filters.nf === item ? "selected" : ""}>${item}</option>`).join("")}</select>
      <select id="catalogSeverityUtility"><option value="">All severities</option>${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((item) => `<option value="${item}" ${filters.severity === item ? "selected" : ""}>${item}</option>`).join("")}</select>
      <select id="catalogCategoryUtility"><option value="">All categories</option>${categories.map((item) => `<option value="${escapeHtml(item)}" ${filters.category === item ? "selected" : ""}>${escapeHtml(item)}</option>`).join("")}</select>
    </div>
    ${filtered.length ? `<div class="rule-catalog-list">${filtered.map((rule) => `
      <article class="rule-catalog-card">
        <div class="rule-catalog-top">
          <div><h3>${escapeHtml(rule.title)}</h3><strong>${escapeHtml(rule.rule_id)}</strong></div>
          <span class="severity-pill ${escapeHtml(rule.severity).toLowerCase()}">${escapeHtml(rule.severity)}</span>
        </div>
        <div class="sample-card-meta"><span>${escapeHtml(rule.target_nf)}</span><span>${escapeHtml(rule.category)}</span><span class="scope-badge">${escapeHtml(rule.scope)}</span></div>
        <p><strong>Description / why it matters:</strong> ${escapeHtml(rule.description)}</p>
        <p><strong>Remediation:</strong> ${escapeHtml(rule.remediation)}</p>
      </article>
    `).join("")}</div>` : `<div class="analytics-empty"><strong>${state.rules.length ? "No rules match these filters" : "Rule catalog unavailable"}</strong><span>${state.rules.length ? "Adjust your filters." : "Connect to the backend to load implemented rules."}</span></div>`}
  `;
  $("#catalogSearchUtility").addEventListener("input", (event) => {
    state.ruleFilters.search = event.target.value;
    renderRuleCatalogPage();
    $("#catalogSearchUtility").focus();
    $("#catalogSearchUtility").setSelectionRange(event.target.value.length, event.target.value.length);
  });
  $("#catalogNFUtility").addEventListener("change", (event) => {
    state.ruleFilters.nf = event.target.value;
    renderRuleCatalogPage();
  });
  $("#catalogSeverityUtility").addEventListener("change", (event) => {
    state.ruleFilters.severity = event.target.value;
    renderRuleCatalogPage();
  });
  $("#catalogCategoryUtility").addEventListener("change", (event) => {
    state.ruleFilters.category = event.target.value;
    renderRuleCatalogPage();
  });
}

async function loadRuleCatalog() {
  try {
    state.rules = await fetchRuleCatalog();
    if (state.currentPage === "rules") renderRuleCatalogPage();
  } catch (error) {
    state.rules = [];
    if (state.currentPage === "rules") {
      $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Rule catalog unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
    }
  }
}

async function loadSampleLibrary() {
  try {
    const response = await fetch(`${SAMPLE_ROOT}manifest.json`, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("The sample library could not be loaded.");
    const data = await response.json();
    if (!Array.isArray(data.samples) || !data.samples.every((sample) =>
      sample &&
      typeof sample.id === "string" &&
      typeof sample.path === "string" &&
      typeof sample.network_function === "string" &&
      typeof sample.category === "string" &&
      typeof sample.description === "string" &&
      Array.isArray(sample.expected_rule_ids)
    )) {
      throw new Error("The sample library manifest has an unexpected format.");
    }
    state.samples = data.samples.map((sample) => ({
      ...sample,
      filename: sample.path.split("/").pop(),
    }));
    state.sampleLoadError = null;
    $("#sampleSelect").innerHTML = `<option value="">SELECT CONFIGURATION</option>${state.samples.map((sample) =>
      `<option value="${escapeHtml(sample.id)}">${escapeHtml(sample.network_function)} · ${escapeHtml(sample.category)} · ${escapeHtml(sample.filename)}</option>`
    ).join("")}`;
    if (state.currentPage === "samples") renderSamplePage();
  } catch (error) {
    state.samples = [];
    state.sampleLoadError = error.message;
    if (state.currentPage === "samples") renderSamplePage();
  }
}

function renderSamplePage() {
  const filters = state.sampleFilters;
  const categories = [...new Set(state.samples.map((sample) => sample.category))].sort();
  const filtered = state.samples.filter((sample) =>
    (!filters.search || `${sample.filename} ${sample.network_function} ${sample.description}`.toLowerCase().includes(filters.search.toLowerCase())) &&
    (!filters.category || sample.category === filters.category) &&
    (!filters.nf || sample.network_function === filters.nf)
  );
  if (!state.samples.length) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Sample library ${state.sampleLoadError ? "unavailable" : "loading"}</strong><span>${escapeHtml(state.sampleLoadError || "Loading sample metadata.")}</span></div>`;
    return;
  }
  $("#utilityContent").innerHTML = `
    <p class="muted-note">Samples are tested against the currently implemented rules. A clean result means no configured rule matched; it is not a guarantee of complete security.</p>
    <div class="sample-toolbar">
      <input id="sampleSearch" type="search" placeholder="Search samples" value="${escapeHtml(filters.search)}" />
      <select id="sampleCategory"><option value="">All categories</option>${categories.map((item) => `<option value="${escapeHtml(item)}" ${filters.category === item ? "selected" : ""}>${escapeHtml(item)}</option>`).join("")}</select>
      <select id="sampleNF"><option value="">All network functions</option>${NFs.map((item) => `<option value="${item}" ${filters.nf === item ? "selected" : ""}>${item}</option>`).join("")}</select>
    </div>
    <div class="sample-grid">${filtered.map((sample) => `
      <article class="sample-card">
        <div class="sample-card-meta"><span>${escapeHtml(sample.network_function)}</span><span>${escapeHtml(sample.category)}</span></div>
        <h3>${escapeHtml(sample.filename)}</h3>
        <p>${escapeHtml(sample.description)}</p>
        <span class="sample-badge ${sample.contains_known_test_vulnerabilities ? "vulnerable" : "clean"}">${sample.contains_known_test_vulnerabilities ? "Known test findings" : "No known test findings"}</span>
        <div class="sample-actions">
          <a href="${SAMPLE_ROOT}${encodeURI(sample.path)}" download="${escapeHtml(sample.filename)}">Download</a>
          <button data-sample-preview="${escapeHtml(sample.id)}">Preview</button>
          <button data-sample-scan="${escapeHtml(sample.id)}">Scan This File</button>
        </div>
      </article>
    `).join("")}</div>
    ${filtered.length ? "" : `<div class="analytics-empty"><strong>No matching samples</strong><span>Adjust the category, network function, or search.</span></div>`}
  `;
  $("#sampleSearch").addEventListener("input", (event) => {
    state.sampleFilters.search = event.target.value;
    renderSamplePage();
    $("#sampleSearch").focus();
    $("#sampleSearch").setSelectionRange(event.target.value.length, event.target.value.length);
  });
  $("#sampleCategory").addEventListener("change", (event) => {
    state.sampleFilters.category = event.target.value;
    renderSamplePage();
  });
  $("#sampleNF").addEventListener("change", (event) => {
    state.sampleFilters.nf = event.target.value;
    renderSamplePage();
  });
  $$("[data-sample-preview]").forEach((button) =>
    button.addEventListener("click", () => previewSample(button.dataset.samplePreview))
  );
  $$("[data-sample-scan]").forEach((button) =>
    button.addEventListener("click", () => scanSample(button.dataset.sampleScan)
  ));
}

async function fetchSampleFile(sample) {
  const response = await fetch(`${SAMPLE_ROOT}${encodeURI(sample.path)}`);
  if (!response.ok) throw new Error(`Could not load ${sample.filename}.`);
  const content = await response.text();
  return new File(
    [content],
    sample.filename,
    { type: sample.filename.toLowerCase().endsWith(".json") ? "application/json" : "application/yaml" }
  );
}

async function previewSample(sampleId) {
  const sample = state.samples.find((entry) => entry.id === sampleId);
  if (!sample) return;
  try {
    const file = await fetchSampleFile(sample);
    $("#samplePreviewNF").textContent = `${sample.network_function} · ${sample.category}`;
    $("#samplePreviewTitle").textContent = sample.filename;
    $("#samplePreviewText").textContent = await file.text();
    openModal("samplePreviewModal");
  } catch (error) {
    toast(error.message);
  }
}

async function scanSample(sampleId) {
  const sample = state.samples.find((entry) => entry.id === sampleId);
  if (!sample) return;
  try {
    selectUpload(await fetchSampleFile(sample));
    $("#scanPanel").classList.add("open");
    await startScan();
  } catch (error) {
    $("#scanState").textContent = error.message;
    toast(error.message);
  }
}

async function loadAllHistoryRecords() {
  const records = [];
  let total = 0;
  do {
    const page = await fetchScanHistory({ limit: 500, offset: records.length });
    total = page.total;
    records.push(...page.scans);
    if (!page.scans.length) break;
  } while (records.length < total);
  return records;
}

async function renderComparisonPage() {
  $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Loading scan records</strong><span>Fetching saved scan summaries for comparison.</span></div>`;
  let records;
  try {
    records = await loadAllHistoryRecords();
  } catch (error) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Scan comparison unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
    return;
  }
  if (state.currentPage !== "comparison") return;
  if (records.length < 2) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Two scans are required</strong><span>Complete at least two scans before comparing historical results.</span></div>`;
    return;
  }
  const currentId = state.comparePrefill || records[0].scan_id;
  const current = records.find((scan) => scan.scan_id === currentId) || records[0];
  const previous = records.find((scan) =>
    scan.scan_id !== current.scan_id &&
    scan.network_function === current.network_function
  ) || records.find((scan) => scan.scan_id !== current.scan_id);
  const options = records.map((scan) =>
    `<option value="${escapeHtml(scan.scan_id)}">${escapeHtml(scan.filename)} · ${escapeHtml(scan.network_function || "Unknown NF")} · ${formatTime(scan.scanned_at)}</option>`
  ).join("");
  $("#utilityContent").innerHTML = `
    <div class="comparison-controls">
      <label>Previous scan<select id="comparePrevious">${options}</select></label>
      <label>Current scan<select id="compareCurrent">${options}</select></label>
    </div>
    <div id="comparisonResults" class="comparison-panel"><div class="analytics-empty"><strong>Select two scans</strong><span>Findings are compared by rule ID and target Network Function, not filename.</span></div></div>
  `;
  $("#comparePrevious").value = previous.scan_id;
  $("#compareCurrent").value = current.scan_id;
  $("#comparePrevious").addEventListener("change", runScanComparison);
  $("#compareCurrent").addEventListener("change", runScanComparison);
  state.comparePrefill = null;
  await runScanComparison();
}

async function runScanComparison() {
  const previousId = $("#comparePrevious")?.value;
  const currentId = $("#compareCurrent")?.value;
  const results = $("#comparisonResults");
  if (!previousId || !currentId || !results) return;
  if (previousId === currentId) {
    results.innerHTML = `<div class="analytics-empty"><strong>Choose two different scans</strong><span>A scan cannot be compared with itself.</span></div>`;
    return;
  }
  results.innerHTML = `<div class="analytics-empty"><strong>Comparing scans</strong><span>Loading complete finding records.</span></div>`;
  try {
    const [previous, current] = await Promise.all([
      fetchScanDetails(previousId),
      fetchScanDetails(currentId),
    ]);
    if (!previous.findings_available || !current.findings_available) {
      results.innerHTML = `<div class="analytics-empty"><strong>Comparison data is incomplete</strong><span>One or both stored scans do not contain all expected finding details. No resolution status has been inferred.</span></div>`;
      return;
    }
    const findingKey = (finding, scan) => {
      const targetNF = finding.target_nf === "ALL"
        ? scan.network_function || scan.summary.network_function || "UNKNOWN"
        : finding.target_nf || scan.network_function || "UNKNOWN";
      return `${finding.rule_id}|${targetNF}`;
    };
    const previousFindings = new Map(previous.findings.map((finding) => [findingKey(finding, previous), finding]));
    const currentFindings = new Map(current.findings.map((finding) => [findingKey(finding, current), finding]));
    const resolved = [...previousFindings].filter(([key]) => !currentFindings.has(key)).map(([, finding]) => finding);
    const newlyDetected = [...currentFindings].filter(([key]) => !previousFindings.has(key)).map(([, finding]) => finding);
    const remaining = [...currentFindings].filter(([key]) => previousFindings.has(key)).map(([, finding]) => finding);
    const previousScore = Number(previous.security_score ?? previous.summary.security_score);
    const currentScore = Number(current.security_score ?? current.summary.security_score);
    const scoreDifference = Number.isFinite(previousScore) && Number.isFinite(currentScore)
      ? currentScore - previousScore
      : null;
    const findingList = (label, items, className) => `
      <section class="comparison-result ${className}">
        <h3>${label} · ${items.length}</h3>
        ${items.length ? items.map((finding) => `
          <p><strong>${escapeHtml(finding.rule_id)}</strong> · ${escapeHtml(finding.target_nf)} — ${escapeHtml(finding.title)}</p>
        `).join("") : `<p>None</p>`}
      </section>
    `;
    results.innerHTML = `
      <div class="comparison-metrics">
        <div><span>Previous score</span><strong>${Number.isFinite(previousScore) ? `${previousScore}/100` : "Unavailable"}</strong></div>
        <div><span>Current score</span><strong>${Number.isFinite(currentScore) ? `${currentScore}/100` : "Unavailable"}</strong></div>
        <div><span>Score difference</span><strong>${scoreDifference === null ? "Unavailable" : `${scoreDifference > 0 ? "+" : ""}${scoreDifference}`}</strong></div>
        <div><span>Findings · previous → current</span><strong>${previous.findings.length} → ${current.findings.length}</strong></div>
      </div>
      ${previous.network_function !== current.network_function ? `<p class="muted-note">These scans cover different Network Functions. Finding matches remain NF-specific; the score difference is not a like-for-like comparison.</p>` : ""}
      ${findingList("Potentially resolved", resolved, "resolved")}
      ${findingList("Newly detected", newlyDetected, "new")}
      ${findingList("Remaining", remaining, "")}
      <p class="muted-note">“Potentially resolved” means the rule ID and target NF were absent from the selected current scan. Verify the configuration and remediation; this comparison does not confirm a fix.</p>
    `;
    state.historyDetails = [
      ...state.historyDetails.filter((scan) => ![previousId, currentId].includes(scan.scan_id)),
      previous,
      current,
    ];
  } catch (error) {
    results.innerHTML = `<div class="analytics-empty"><strong>Comparison failed</strong><span>${escapeHtml(error.message)}</span></div>`;
  }
}

function openModal(id) {
  $$(".modal.open").forEach((modal) => modal.classList.remove("open"));
  $("#" + id)?.classList.add("open");
}

function closeModal() {
  $$(".modal.open").forEach((modal) => modal.classList.remove("open"));
}

function setTheme(theme) {
  document.documentElement.classList.toggle("light", theme !== "dark");
  document.documentElement.classList.toggle("dark", theme === "dark");
  localStorage.setItem("susignal-theme", theme);
}

function setCamera() {
  $("#camera").style.transform = `scale(${state.zoom})`;
}

let selectedUpload = null;

function selectUpload(file) {
  if (!file) return;
  selectedUpload = null;
  $("#startScan").disabled = true;
  $("#selectedFilename").textContent = file.name;
  const ext = file.name.toLowerCase();
  if (!/\.(yaml|yml|json)$/.test(ext)) {
    const message = "Unsupported format. Use YAML or JSON.";
    $("#scanState").textContent = message;
    toast(message);
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    const message = "File exceeds the 5 MB limit.";
    $("#scanState").textContent = message;
    toast(message);
    return;
  }
  selectedUpload = file;
  $("#selectedFilename").textContent = file.name;
  if ($("#fileMeta")) $("#fileMeta").textContent = `${ext.split(".").pop().toUpperCase()} · ${(file.size / 1024).toFixed(1)} KB`;
  $("#startScan").disabled = false;
  $("#scanState").textContent = "Ready to analyze";
}

async function startScan() {
  if (!selectedUpload) return;
  const button = $("#startScan");
  button.disabled = true;
  button.textContent = "Scanning...";
  $("#progressTrack").classList.add("active");
  $("#canvasScanline").classList.add("scanning");
  $("#scanState").textContent = "Uploading configuration";
  try {
    const scan = await uploadConfiguration(selectedUpload);
    let detailWarning = null;
    state.currentScan = scan;
    state.historyDetails = state.historyDetails.filter((entry) => entry.scan_id !== scan.scan_id);
    state.historyDetails.push(scan);
    $("#scanState").textContent = `Complete · ${scan.summary.total_findings} findings`;
    renderHealth(scan.summary);
    $("#scanPanel").classList.remove("open");
    await Promise.all([
      loadHistory(),
      loadStatistics(),
      loadEnvironmentDashboardStatistics(),
    ]);
    try {
      const persistedScan = await fetchScanDetails(scan.scan_id);
      state.currentScan = persistedScan;
      state.historyDetails = [
        ...state.historyDetails.filter((entry) => entry.scan_id !== scan.scan_id),
        persistedScan,
      ];
      renderHealth(persistedScan.summary);
      if (state.currentPage === "findings") renderFindingsPage();
      if (state.currentPage === "remediation") renderRemediation();
    } catch (error) {
      detailWarning = error;
    }
    toast(detailWarning
      ? `Scan completed; saved details unavailable: ${detailWarning.message}`
      : `Scan complete · ${scan.summary.security_score}/100`);
  } catch (error) {
    $("#scanState").textContent = error.message;
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Start Scan";
    $("#progressTrack").classList.remove("active");
    $("#canvasScanline").classList.remove("scanning");
  }
}

async function selectSample(sampleId) {
  if (!sampleId) {
    selectedUpload = null;
    $("#startScan").disabled = true;
    $("#selectedFilename").textContent = "YAML OR JSON · 5 MB MAX";
    $("#scanState").textContent = "Ready to analyze";
    return;
  }
  try {
    const sample = state.samples.find((entry) => entry.id === sampleId);
    if (!sample) throw new Error("The selected sample is not in the sample library.");
    selectUpload(await fetchSampleFile(sample));
  } catch (error) {
    $("#scanState").textContent = error.message;
    toast(error.message);
  }
}

function printReport() {
  if (!state.currentScan) {
    toast("Select a saved scan or complete a scan before exporting a report.");
    return;
  }
  const scan = state.currentScan;
  const findings = scan.findings || [];
  const summary = scan.summary || {};
  const counts = {
    CRITICAL: summary.critical ?? scan.critical_count ?? 0,
    HIGH: summary.high ?? scan.high_count ?? 0,
    MEDIUM: summary.medium ?? scan.medium_count ?? 0,
    LOW: summary.low ?? scan.low_count ?? 0,
  };
  const networkFunction = scan.network_function || summary.network_function || "Unavailable";
  const scannedAt = scan.scanned_at ? formatTime(scan.scanned_at) : "Unavailable";
  const detailNote = scan.findings_available === false
    ? `<p>Finding details are incomplete: ${findings.length} detail records are available for ${scan.total_findings} recorded findings.</p>`
    : "";
  const html = `<!doctype html><html><head><title>SUSignal Report</title><style>
    body{font:14px/1.5 Arial,sans-serif;color:#171717;margin:44px}header{border-bottom:3px solid #e8c62b;padding-bottom:18px}
    h1{font-size:28px;margin:0}h2{font-size:16px;margin-top:30px;border-bottom:1px solid #bbb;padding-bottom:7px}
    table{width:100%;border-collapse:collapse;page-break-inside:auto}tr{page-break-inside:avoid}
    th,td{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top;font-size:11px}
    th{background:#f1f0e9}.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:20px}
    .meta div{border:1px solid #bbb;padding:11px}.severity{display:flex;gap:12px;flex-wrap:wrap}
    .severity span{padding:8px;border:1px solid #bbb}.note{color:#555;font-size:11px}
    @media print{body{margin:18mm}button{display:none}}
  </style></head><body><header><h1>SUSignal Security Assessment</h1><p>Configuration security analysis · based on implemented scanner rules</p></header>
  <div class="meta">
    <div><strong>Application</strong><br>SUSignal</div>
    <div><strong>Scan ID</strong><br>${escapeHtml(scan.scan_id)}</div>
    <div><strong>Filename</strong><br>${escapeHtml(scan.filename)}</div>
    <div><strong>Network Function</strong><br>${escapeHtml(networkFunction)}</div>
    <div><strong>Scan date</strong><br>${escapeHtml(scannedAt)}</div>
    <div><strong>Security score</strong><br>${summary.security_score ?? scan.security_score ?? "Unavailable"} / 100</div>
    <div><strong>Total findings</strong><br>${summary.total_findings ?? scan.total_findings ?? findings.length}</div>
    <div><strong>Rules checked</strong><br>${summary.total_rules_checked ?? "Unavailable"}</div>
    <div><strong>Assessment status</strong><br>${escapeHtml(summary.status || scan.result_status || scan.status || "Unavailable")}</div>
  </div>
  <h2>Severity breakdown</h2><div class="severity">${Object.entries(counts).map(([name, count]) => `<span><strong>${name}</strong> · ${count}</span>`).join("")}</div>
  <h2>Detailed findings and recommendations</h2>${detailNote}
  ${findings.length ? `<table><thead><tr><th>Rule ID</th><th>Vulnerability</th><th>Severity</th><th>Target NF</th><th>Category</th><th>Description / why it matters</th><th>Recommended remediation</th></tr></thead><tbody>
  ${findings.map((finding) => `<tr><td>${escapeHtml(finding.rule_id)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.target_nf)}</td><td>${escapeHtml(finding.category)}</td><td>${escapeHtml(finding.description)}</td><td>${escapeHtml(finding.remediation)}</td></tr>`).join("")}
  </tbody></table>` : `<p>No detailed findings are available for this scan.</p>`}
  <p class="note">This report reflects only the rules implemented in SUSignal at the time of this scan. A clean result is not a guarantee of complete security.</p>
  </body></html>`;
  const reportWindow = window.open("", "_blank");
  if (!reportWindow) {
    toast("The report window was blocked by the browser.");
    return;
  }
  reportWindow.document.write(html);
  reportWindow.document.close();
  reportWindow.print();
}

function renderReportPage() {
  const scan = state.currentScan;
  if (!scan) {
    $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>No scan selected</strong><span>Select a scan from history or complete a new scan to create a report.</span></div>`;
    return;
  }
  const summary = scan.summary || {};
  $("#utilityContent").innerHTML = `
    <article class="finding-card">
      <div class="finding-card-top"><div><h3>SUSignal Security Assessment</h3><span>${escapeHtml(scan.scan_id)}</span></div><strong>${summary.security_score ?? scan.security_score ?? "—"}/100</strong></div>
      <div class="finding-detail-grid">
        <div><label>Filename / type</label><p>${escapeHtml(scan.filename)} · ${escapeHtml(scan.file_type)}</p></div>
        <div><label>Network Function</label><p>${escapeHtml(scan.network_function || summary.network_function || "Unavailable")}</p></div>
        <div><label>Scan date</label><p>${escapeHtml(scan.scanned_at ? formatTime(scan.scanned_at) : "Unavailable")}</p></div>
        <div><label>Total findings</label><p>${summary.total_findings ?? scan.total_findings ?? scan.findings?.length ?? 0}</p></div>
        <div><label>Severity breakdown</label><p>Critical ${summary.critical ?? scan.critical_count ?? 0} · High ${summary.high ?? scan.high_count ?? 0} · Medium ${summary.medium ?? scan.medium_count ?? 0} · Low ${summary.low ?? scan.low_count ?? 0}</p></div>
        <div><label>Assessment status</label><p>${escapeHtml(summary.status || scan.result_status || scan.status || "Unavailable")}</p></div>
      </div>
      <p class="muted-note">${scan.findings_available === false ? "Finding details are incomplete for this historical scan." : `${scan.findings?.length || 0} detailed findings with backend-provided remediation recommendations.`}</p>
      <div class="sample-actions"><button id="printReportUtility">Print / Save PDF</button><button id="downloadJsonUtility">Download JSON</button></div>
    </article>
    <p class="muted-note">Reports reflect the rules implemented in SUSignal and do not claim a complete security assessment.</p>
  `;
  $("#printReportUtility").addEventListener("click", printReport);
  $("#downloadJsonUtility").addEventListener("click", downloadJson);
}

function downloadJson() {
  if (!state.currentScan) {
    toast("Select a saved scan or complete a scan before exporting JSON.");
    return;
  }
  const blob = new Blob([JSON.stringify(state.currentScan, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `susignal-${state.currentScan.scan_id}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function showPage(id) {
  $$(".page").forEach((page) => page.classList.remove("active"));
  $("#" + id)?.classList.add("active");
}

function renderAnalyticsPage() {
  $("#utilityContent").innerHTML = `
    ${state.statisticsError ? `<p class="muted-note">Analytics request failed: ${escapeHtml(state.statisticsError)}</p>` : ""}
    <div class="analytics-grid">
      <section class="chart-card"><div class="chart-header"><div><span>01</span><h3>SECURITY SCORE TREND</h3></div></div><div id="analyticsTrend"></div></section>
      <section class="chart-card"><div class="chart-header"><div><span>02</span><h3>VULNERABILITIES BY NETWORK FUNCTION</h3></div></div><div id="analyticsNF"></div></section>
      <section class="chart-card"><div class="chart-header"><div><span>03</span><h3>MOST FREQUENTLY TRIGGERED RULES</h3></div></div><div id="analyticsRules"></div></section>
      <section class="chart-card"><div class="chart-header"><div><span>04</span><h3>SEVERITY DISTRIBUTION</h3></div></div><div id="analyticsSeverity"></div></section>
    </div>
  `;
  $("#analyticsTrend").innerHTML = $("#trendChart").innerHTML;
  $("#analyticsNF").innerHTML = $("#vulnerabilitiesByNF").innerHTML;
  $("#analyticsRules").innerHTML = $("#frequencyChart").innerHTML;
  $("#analyticsSeverity").innerHTML = $("#severityChart").innerHTML;
}

function renderRuntimeAssessment(assessment) {
  const findings = assessment?.findings || [];
  const observations = assessment?.observations || [];
  const summary = assessment?.summary || {};
  const networkName = assessment?.network_name || "Test network";
  const findingsMarkup = findings.length
    ? findings.map((item) => `
      <article class="runtime-record finding">
        <div class="runtime-record-header">
          <strong>${escapeHtml(item.title)}</strong>
          <span class="severity-pill ${escapeHtml(item.severity).toLowerCase()}">${escapeHtml(item.severity)}</span>
        </div>
        <small>${escapeHtml(item.rule_id)} · ${escapeHtml(item.component || networkName)}</small>
        <p>${escapeHtml(item.description)}</p>
        <p><strong>Evidence:</strong> ${escapeHtml(item.evidence)}</p>
        <p><strong>Recommended action:</strong> ${escapeHtml(item.remediation)}</p>
      </article>
    `).join("")
    : `<div class="analytics-empty"><strong>No runtime security findings</strong><span>This ${escapeHtml(networkName)} assessment did not detect unavailable services, published host ports, or a non-internal Docker network.</span></div>`;
  const observationsMarkup = observations.length
    ? observations.map((item) => `
      <article class="runtime-record observation">
        <div class="runtime-record-header"><strong>${escapeHtml(item.title)}</strong><span>INFORMATIONAL</span></div>
        <small>${escapeHtml(item.rule_id)} · ${escapeHtml(item.component || networkName)}</small>
        <p>${escapeHtml(item.description)}</p>
        <p><strong>Evidence:</strong> ${escapeHtml(item.evidence)}</p>
      </article>
    `).join("")
    : `<div class="analytics-empty"><strong>No interface observations</strong><span>Interfaces are only observed when a service healthcheck can run.</span></div>`;

  return `
    <div class="runtime-assessment-summary">
      <span>${escapeHtml(assessment.assessment_status || "COMPLETED")}</span>
      <span>${formatTime(assessment.assessed_at)}</span>
      <span>${summary.services_healthy ?? 0}/${summary.services_configured ?? 0} services healthy</span>
      <span>${summary.total_findings ?? 0} findings · ${summary.total_observations ?? 0} observations</span>
    </div>
    <div class="runtime-results-grid">
      <section><h3>Security findings</h3>${findingsMarkup}</section>
      <section><h3>Informational observations</h3>${observationsMarkup}</section>
    </div>
  `;
}

function renderEnvironmentCard(environment, assessment, networkId, errorMessage = "") {
  const networkName = environment?.name || `Network ${networkId.toUpperCase()}`;
  if (!environment) {
    return `<section class="environment-card"><div class="analytics-empty"><strong>${escapeHtml(networkName)} status unavailable</strong><span>${escapeHtml(errorMessage || "The backend has not returned environment status.")}</span></div></section>`;
  }
  const serviceRows = environment.services.map((service) => `
    <div class="environment-service-row">
      <strong>${escapeHtml(service.name.toUpperCase())}</strong>
      <span>${escapeHtml(service.kind.replace("_", " "))}</span>
      <span class="environment-state ${escapeHtml(service.state)}">${escapeHtml(service.state.toUpperCase())}</span>
      <span class="environment-state ${escapeHtml(service.health)}">${escapeHtml(service.health.toUpperCase())}</span>
      <span>${service.published_ports?.length
        ? escapeHtml(service.published_ports.map((port) => `${port.host}:${port.host_port}`).join(", "))
        : "No host ports published"
      }</span>
    </div>
  `).join("");
  const latestSummary = assessment?.summary;

  return `
    <section class="environment-card">
      <div class="environment-heading">
        <div>
          <span class="environment-kicker">MANAGED 5G CORE LAB</span>
          <h3>${escapeHtml(environment.name)}</h3>
          <p>${escapeHtml(environment.description)}</p>
        </div>
        <span class="environment-state ${escapeHtml(environment.status)}">${escapeHtml(environment.status.replace("_", " ").toUpperCase())}</span>
      </div>
      <div class="environment-metrics">
        <div><span>Network Functions</span><strong>${environment.configured_network_functions}</strong></div>
        <div><span>Healthy Services</span><strong>${environment.healthy_services} / ${environment.service_count}</strong></div>
        <div><span>Last Assessment</span><strong>${assessment ? formatTime(assessment.assessed_at) : "Not assessed"}</strong></div>
        <div><span>Latest Findings</span><strong>${latestSummary?.total_findings ?? "—"}</strong></div>
      </div>
      <div class="environment-actions">
        <button class="primary-action" data-environment-id="${networkId}" data-environment-action="start" ${state.environmentBusy || environment.status === "running" ? "disabled" : ""}>START NETWORK</button>
        <button class="secondary-action" data-environment-id="${networkId}" data-environment-action="stop" ${state.environmentBusy || !environment.is_running ? "disabled" : ""}>STOP NETWORK</button>
        <button class="primary-action" data-environment-id="${networkId}" data-environment-action="scan" ${state.environmentBusy ? "disabled" : ""}>SCAN NETWORK</button>
        <button class="secondary-action" data-environment-id="${networkId}" data-environment-action="view-results" ${!assessment ? "disabled" : ""}>VIEW RESULTS</button>
      </div>
      ${errorMessage ? `<p class="environment-error">${escapeHtml(errorMessage)}</p>` : ""}
    </section>
    <section class="environment-card">
      <div class="environment-section-heading"><h3>Service health</h3><span>${environment.healthy_services} of ${environment.service_count} healthy</span></div>
      <div class="environment-service-list">
        <div class="environment-service-row header"><strong>Service</strong><span>Type</span><span>State</span><span>Health</span><span>Host exposure</span></div>
        ${serviceRows}
      </div>
      <p class="muted-note">SBI healthchecks perform TLS certificate and client-certificate verification. The UPF check confirms its process only; no UE connectivity is implied.</p>
    </section>
    <section class="environment-card" id="runtimeAssessmentResults-${networkId}">
      <div class="environment-section-heading"><h3>Latest runtime assessment</h3><span>${assessment ? escapeHtml(assessment.assessment_id) : "No saved assessment"}</span></div>
      ${assessment ? renderRuntimeAssessment(assessment) : `<div class="analytics-empty"><strong>No runtime assessment yet</strong><span>Use Scan Network to check service availability, health, host-port exposure, and observed SBI TLS health.</span></div>`}
    </section>
  `;
}

function renderNetworkAlphaPage() {
  const content = $("#utilityContent");
  content.innerHTML = [
    renderEnvironmentCard(
      state.environment,
      state.runtimeAssessment,
      "alpha",
      state.environmentError
    ),
    renderEnvironmentCard(
      state.betaEnvironment,
      state.betaRuntimeAssessment,
      "beta",
      state.betaEnvironmentError
    ),
  ].join("");
  content.querySelectorAll("[data-environment-action]").forEach((button) => {
    button.addEventListener("click", () => handleEnvironmentAction(
      button.dataset.environmentAction,
      button.dataset.environmentId
    ));
  });
}

async function loadNetworkAlphaPage({ preserveAssessment = false } = {}) {
  $("#utilityContent").innerHTML = `<div class="analytics-empty"><strong>Loading test environments</strong><span>Reading live service status from the backend.</span></div>`;
  const [alphaResult, betaResult] = await Promise.allSettled([
    fetchNetworkAlpha(),
    fetchNetworkBeta(),
  ]);
  if (alphaResult.status === "fulfilled") {
    state.environment = alphaResult.value.environment;
    state.environmentError = null;
    if (!preserveAssessment) {
      state.runtimeAssessment = alphaResult.value.last_runtime_assessment;
    }
  } else {
    state.environment = null;
    state.environmentError = alphaResult.reason.message;
  }
  if (betaResult.status === "fulfilled") {
    state.betaEnvironment = betaResult.value.environment;
    state.betaEnvironmentError = null;
    if (!preserveAssessment) {
      state.betaRuntimeAssessment = betaResult.value.last_runtime_assessment;
    }
  } else {
    state.betaEnvironment = null;
    state.betaEnvironmentError = betaResult.reason.message;
  }
  renderNetworkAlphaPage();
}

async function handleEnvironmentAction(action, networkId) {
  if (state.environmentBusy) return;
  const isBeta = networkId === "beta";
  const networkName = isBeta ? "Network Beta" : "Network Alpha";
  if (action === "view-results") {
    $(`#runtimeAssessmentResults-${networkId}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  state.environmentBusy = true;
  renderNetworkAlphaPage();
  try {
    if (action === "start") {
      const environment = isBeta
        ? await startNetworkBeta()
        : await startNetworkAlpha();
      if (isBeta) state.betaEnvironment = environment;
      else state.environment = environment;
      toast(`${networkName} started.`);
      await loadNetworkAlphaPage({ preserveAssessment: true });
    } else if (action === "stop") {
      const environment = isBeta
        ? await stopNetworkBeta()
        : await stopNetworkAlpha();
      if (isBeta) state.betaEnvironment = environment;
      else state.environment = environment;
      toast(`${networkName} stopped; persistent data was preserved.`);
      await loadNetworkAlphaPage({ preserveAssessment: true });
    } else if (action === "scan") {
      const assessment = isBeta
        ? await assessNetworkBeta()
        : await assessNetworkAlpha();
      if (isBeta) {
        state.betaRuntimeAssessment = assessment;
        state.betaEnvironment = assessment.environment_status;
      } else {
        state.runtimeAssessment = assessment;
        state.environment = assessment.environment_status;
      }
      toast(`${networkName} assessment completed: ${assessment.summary.total_findings} findings.`);
      await loadEnvironmentDashboardStatistics();
    }
    await loadHistory();
  } catch (error) {
    toast(error.message);
    await loadNetworkAlphaPage({ preserveAssessment: true });
  } finally {
    state.environmentBusy = false;
    renderNetworkAlphaPage();
  }
}

async function loadRuntimeAssessment(assessmentId, networkId = "alpha") {
  try {
    const assessment = await fetchRuntimeAssessment(assessmentId, networkId);
    if (networkId === "beta") state.betaRuntimeAssessment = assessment;
    else state.runtimeAssessment = assessment;
    state.currentPage = "environments";
    $$(".nav-item").forEach((item) => item.classList.toggle(
      "active",
      item.dataset.page === "environments"
    ));
    showPage("utilityPage");
    $("#utilityTitle").textContent = "5G TEST ENVIRONMENTS";
    $("#pageTitle").textContent = "5G TEST ENVIRONMENTS";
    await loadNetworkAlphaPage({ preserveAssessment: true });
  } catch (error) {
    toast(error.message);
  }
}

function showUtilityPage(page) {
  state.currentPage = page;
  showPage("utilityPage");
  const titles = {
    rules: "RULE CATALOG",
    findings: "SECURITY FINDINGS",
    remediation: "REMEDIATION CENTER",
    history: "SCAN HISTORY",
    comparison: "SCAN COMPARISON",
    samples: "SAMPLE CONFIGURATIONS",
    reports: "REPORTS",
    analytics: "RISK ANALYTICS",
    environments: "5G TEST ENVIRONMENTS",
    settings: "SETTINGS"
  };
  $("#utilityTitle").textContent = titles[page] || "SECURITY";
  $("#pageTitle").textContent = titles[page] || "SECURITY";

  if (page === "rules") {
    renderRuleCatalogPage();
    if (!state.rules.length) loadRuleCatalog();
  } else if (page === "samples") {
    renderSamplePage();
    if (!state.samples.length) loadSampleLibrary();
  } else if (page === "history") {
    renderHistory();
    loadHistory();
  } else if (page === "comparison") {
    renderComparisonPage();
  } else if (page === "reports") {
    renderReportPage();
  } else if (page === "findings") {
    renderFindingsPage();
  } else if (page === "remediation") {
    $("#utilityContent").innerHTML = `<p class="muted-note">Statuses are saved per finding and scan. SUSignal does not mark a finding fixed automatically when it disappears from a later scan.</p><div class="remediation-list" id="remediationListUtility"></div>`;
    renderRemediationInto($("#remediationListUtility"), state.currentScan);
  } else if (page === "analytics") {
    renderAnalyticsPage();
  } else if (page === "environments") {
    loadNetworkAlphaPage();
  } else if (page === "settings") {
    $("#utilityContent").innerHTML = `
      <section class="settings-section" aria-labelledby="settingsAppearanceTitle">
        <div class="settings-section-header">
          <span>DISPLAY PREFERENCE</span>
          <h3 id="settingsAppearanceTitle">Appearance</h3>
          <p>Choose the visual theme for the SUSignal interface.</p>
        </div>
        <div class="settings-option">
          <div>
            <strong>Dark Mode</strong>
            <p>Switch between light and dark themes at any time.</p>
          </div>
          <button class="primary-action" id="utilityTheme">TOGGLE DARK / LIGHT</button>
        </div>
      </section>`;
    $("#utilityTheme").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  }
}

function bindEvents() {
  $("#themeToggle").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  $("#openScan").addEventListener("click", () => $("#scanPanel").classList.add("open"));
  $("#browseButton").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", (event) => selectUpload(event.target.files[0]));
  $("#sampleSelect").addEventListener("change", (event) => selectSample(event.target.value));
  $("#startScan").addEventListener("click", startScan);
  const dropZone = $("#dropZone");
  ["dragenter", "dragover"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  }));
  dropZone.addEventListener("drop", (event) => selectUpload(event.dataTransfer.files[0]));

  $$("[data-close]").forEach((button) => button.addEventListener("click", () => {
    if (button.classList.contains("modal-backdrop")) {
      $("#" + button.dataset.close)?.classList.remove("open");
    } else {
      $("#" + button.dataset.close)?.classList.remove("open");
    }
  }));
  $$("[data-view]").forEach((button) => button.addEventListener("click", () => {
    const view = button.dataset.view;
    $$(".nav-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
    if (view === "rules") openModal("catalogModal");
    if (view === "history") openModal("historyModal");
  }));
  $$("[data-view-trigger]").forEach((button) => button.addEventListener("click", () => openModal("historyModal")));
  $("#exportButton").addEventListener("click", () => openModal("exportModal"));
  $("#downloadJson").addEventListener("click", downloadJson);
  $("#printReport").addEventListener("click", printReport);
  $("#ruleSearch").addEventListener("input", renderRuleTable);
  $("#ruleNF").addEventListener("change", renderRuleTable);
  $("#ruleSeverity").addEventListener("change", renderRuleTable);
  $("#severityView").querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    state.severityView = button.dataset.severityView;
    $$("#severityView button").forEach((item) => item.classList.toggle("active", item === button));
    renderSeverity(latestConfigurationScan()?.summary || null);
    if (state.currentPage === "analytics") renderAnalyticsPage();
  }));
  $("#zoomIn").addEventListener("click", () => { state.zoom = Math.min(1.8, state.zoom + .15); setCamera(); });
  $("#zoomOut").addEventListener("click", () => { state.zoom = Math.max(.7, state.zoom - .15); setCamera(); });
  $("#fitView").addEventListener("click", () => { state.zoom = 1; setCamera(); });
  $("#toggleLabels").addEventListener("click", () => {
    state.labels = !state.labels;
    $$(".node-label, .node-status, .node-count").forEach((label) => label.style.display = state.labels ? "" : "none");
  });
  $("#modeToolbar").querySelectorAll("button").forEach((button) => button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    $$("#modeToolbar button").forEach((item) => item.classList.toggle("active", item === button));
    $$(".connection-line").forEach((line) => line.style.opacity = state.mode === "connections" ? "1" : "");
    updateTopology(state.currentScan?.summary);
  }));
  $$("#canvasViews button").forEach((button) => button.addEventListener("click", () => {
    $$("#canvasViews button").forEach((item) => item.classList.toggle("active", item === button));
    if (button.textContent.includes("Finding")) openModal("historyModal");
  }));
  $("#sidebarCollapse").addEventListener("click", () => {
    $("#sidebar").classList.toggle("collapsed");
    $(".app-shell").classList.toggle("sidebar-collapsed");
  });
  $("#mobileMenu").addEventListener("click", () => $("#sidebar").classList.toggle("mobile-open"));
  $("#newScanButton").addEventListener("click", () => $("#scanPanel").classList.add("open"));
  $("#settingsButton").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => {
    $$(".nav-item").forEach((nav) => nav.classList.remove("active"));
    item.classList.add("active");
    const page = item.dataset.page;
    $("#sidebar").classList.remove("mobile-open");
    if (page === "topology") {
      state.currentPage = "topology";
      showPage("topologyPage");
      $("#pageTitle").textContent = "NETWORK TOPOLOGY";
    } else if (page === "scanner") {
      state.currentPage = "overview";
      $("#scanPanel").classList.add("open");
      showPage("overviewPage");
    } else if (["rules", "findings", "remediation", "history", "comparison", "samples", "reports", "analytics", "environments", "settings"].includes(page)) {
      showUtilityPage(page);
    } else {
      state.currentPage = "overview";
      showPage("overviewPage");
      $("#pageTitle").textContent = "SECURITY DASHBOARD";
    }
  }));
  $("#scanFilter").addEventListener("change", (event) => {
    if (event.target.value) {
      loadScan(event.target.value);
    } else {
      const latestConfiguration = state.history.find(
        (entry) => entry.assessment_type !== "runtime"
      );
      if (latestConfiguration) loadScan(latestConfiguration.scan_id);
      else renderHealth(null);
    }
  });
  window.addEventListener("resize", setCamera);
}

async function init() {
  setTheme(localStorage.getItem("susignal-theme") || "light");
  $("#scanPanel")?.classList.remove("open");
  $("#inspector")?.classList.remove("open");
  createTopology();
  bindEvents();
  renderHealth(null);
  renderDashboardStatistics();
  await Promise.all([
    checkBackend(),
    loadHistory(),
    loadStatistics(),
    loadEnvironmentDashboardStatistics(),
    loadRuleCatalog(),
    loadSampleLibrary(),
  ]);
}

init();
