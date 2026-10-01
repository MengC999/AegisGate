"use strict";

const workspaceViews = { home: "工作台", detect: "安全检测台", batch: "批量治理", rules: "词库与规则", audit: "统计与审计", system: "系统状态", ...Object.fromEntries(Object.entries(operationsPages).map(([view, page]) => [view, page.title])) };
const homeCharts = {};
let homeDashboard = null;
let dashboardRequest = null;
const riskColors = ["#f59ba8", "#e7b786", "#dbcfa0", "#91cbb5", "#a6bfdc"];
let dashboardAccent = { color: "rgb(140, 215, 198)", fill: "rgba(140, 215, 198, .12)" };

function refreshIcons() {
  if (window.lucide) lucide.createIcons({ attrs: { "aria-hidden": "true" } });
}

function closeSidebar() {
  document.body.classList.remove("sidebar-open");
  byId("sidebarOverlay").hidden = true;
  byId("sidebarToggle").setAttribute("aria-expanded", String(window.innerWidth > 700 && !document.body.classList.contains("sidebar-collapsed")));
  byId("appSidebar").inert = window.innerWidth <= 700;
}

function updateWorkspaceShell() {
  byId("currentViewTitle").textContent = workspaceViews[state.view];
  document.title = `${workspaceViews[state.view]} · AegisGate`;
  closeSidebar();
  byId("navSearchResults").hidden = true;
  byId("navSearch").setAttribute("aria-expanded", "false");
  if (state.view === "home") {
    loadHomeDashboard();
    requestAnimationFrame(() => Object.values(homeCharts).forEach(chart => chart.resize()));
  }
}

function openWorkspaceResource(resource, query) {
  selectEnterpriseResource(resource, query);
  byId("navSearch").value = "";
}

function updateHomeRuntime() {
  const connected = state.health?.status === "ok";
  const pending = !state.health && byId("healthText").textContent !== "服务异常";
  byId("homeGatewayState").dataset.status = connected ? "ready" : pending ? "loading" : "error";
  byId("homeGatewayLabel").textContent = connected ? "网关运行正常" : pending ? "正在连接网关" : "网关连接异常";
  byId("homeRequests").textContent = connected && state.stats ? String(state.stats.total_requests) : "--";
  byId("homeRequestsHint").textContent = connected && state.stats ? `干预 ${state.stats.violation_requests} 次` : "等待网关连接";
  const date = new Date();
  const hour = date.getHours();
  byId("homeGreeting").textContent = hour < 6 ? "夜深了" : hour < 12 ? "上午好" : hour < 18 ? "下午好" : "晚上好";
  byId("homeDate").textContent = date.toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric", weekday: "long" });
}

function replaceChart(id, configuration) {
  if (homeCharts[id]) homeCharts[id].destroy();
  if (!window.Chart) {
    byId(id).parentElement.textContent = "图表组件加载失败，请刷新页面";
    return;
  }
  homeCharts[id] = new Chart(byId(id), configuration);
}

function drawHomeTrend() {
  if (!homeDashboard) return;
  const days = Number(byId("homeTrendRange").value);
  const items = (homeDashboard.trends?.alerts || []).slice(-days);
  const total = items.reduce((sum, item) => sum + Number(item.total || 0), 0);
  const high = items.reduce((sum, item) => sum + Number(item.high_risk || 0), 0);
  byId("homeTrendSummary").textContent = `近 ${days} 天新增 ${total} 条告警，其中高风险 ${high} 条`;
  byId("homeTrendChart").setAttribute("aria-label", items.length ? items.map(item => `${item.date}：全部 ${item.total}，高风险 ${item.high_risk}`).join("；") : "暂无告警趋势数据");
  replaceChart("homeTrendChart", {
    type: "line",
    data: {
      labels: items.map(item => item.date.slice(5)),
      datasets: [
        { label: "全部告警", data: items.map(item => item.total), borderColor: dashboardAccent.color, backgroundColor: dashboardAccent.fill, fill: true, tension: .28, pointRadius: 3, pointHoverRadius: 5, pointBackgroundColor: dashboardAccent.color, borderWidth: 2 },
        { label: "高风险告警", data: items.map(item => item.high_risk), borderColor: "#f59ba8", backgroundColor: "transparent", borderDash: [5, 4], tension: .28, pointStyle: "rectRot", pointRadius: 3, pointHoverRadius: 5, pointBackgroundColor: "#f59ba8", borderWidth: 2 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 250 },
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: false }, tooltip: { backgroundColor: "rgba(25,25,25,.95)", titleColor: "#fff", bodyColor: "#ddd", borderColor: "#666", borderWidth: 1, padding: 12, displayColors: false } },
      scales: {
        x: { grid: { display: false }, border: { display: false }, ticks: { color: "#bbbbbb", maxTicksLimit: days === 7 ? 7 : 8, maxRotation: 0, font: { size: 9 } } },
        y: { beginAtZero: true, suggestedMax: 4, border: { display: false }, ticks: { precision: 0, color: "#bbbbbb", maxTicksLimit: 5, font: { size: 9 }, padding: 10 }, grid: { color: "rgba(255,255,255,.10)", drawTicks: false } },
      },
    },
  });
}

function drawDonut(id, labels, values, colors, cutout) {
  const empty = !values.some(value => value > 0);
  replaceChart(id, {
    type: "doughnut",
    data: { labels: empty ? ["暂无数据"] : labels, datasets: [{ data: empty ? [1] : values, backgroundColor: empty ? ["rgba(255,255,255,.12)"] : colors, borderWidth: 0, hoverOffset: 3, spacing: empty ? 0 : 2 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout, animation: false, plugins: { legend: { display: false }, tooltip: { enabled: !empty, backgroundColor: "rgba(25,25,25,.95)", displayColors: false } } },
  });
}

function renderHomeDashboard(dashboard) {
  const c = dashboard.counts || {};
  const metrics = { homeAssets: c.assets, homeAlerts: c.open_alerts, homeVulnerabilities: c.open_vulnerabilities, homeInspections: c.pending_inspections, homeIncidents: c.active_incidents, sidebarAlertCount: c.open_alerts, homeOpenVulnerabilities: c.open_vulnerabilities };
  Object.entries(metrics).forEach(([id, value]) => { byId(id).textContent = String(value ?? 0); });
  byId("homeAssetsHint").textContent = `${c.online_assets || 0} 台在线`;
  byId("homeAlertsHint").textContent = `${c.critical_alerts || 0} 项严重告警`;
  byId("homeVulnerabilitiesHint").textContent = `${c.overdue_vulnerabilities || 0} 项逾期待处理`;
  byId("homeRemediationHint").textContent = c.overdue_vulnerabilities ? `${c.overdue_vulnerabilities} 项漏洞已逾期` : "当前无逾期漏洞";
  byId("homeDataSource").textContent = dashboard.data_mode === "runtime_with_demo_seed" ? "本地工作空间 · 含演示数据" : "本地工作空间 · 实时数据";
  const severities = ["critical", "high", "medium", "low", "info"];
  const values = severities.map(key => Number(dashboard.alert_severity?.[key] || 0));
  const total = values.reduce((sum, value) => sum + value, 0);
  byId("homeAlertTotal").textContent = String(total);
  byId("homeRiskLegend").replaceChildren();
  severities.forEach((key, index) => {
    if (!values[index] && index > 2) return;
    const row = document.createElement("div");
    const dot = document.createElement("i"); dot.style.backgroundColor = riskColors[index];
    const label = document.createElement("span"); label.textContent = enterpriseSeverityNames[key];
    const count = document.createElement("strong"); count.textContent = String(values[index]);
    const share = document.createElement("small"); share.textContent = `${total ? Math.round(values[index] / total * 100) : 0}%`;
    row.append(dot, label, count, share); byId("homeRiskLegend").appendChild(row);
  });
  byId("homeRiskChart").setAttribute("aria-label", severities.map((key, i) => `${enterpriseSeverityNames[key]} ${values[i]} 条`).join("，"));
  drawDonut("homeRiskChart", severities.map(key => enterpriseSeverityNames[key]), values, riskColors, "75%");
  const closed = Number(dashboard.vulnerability_status?.closed || 0);
  const open = Number(c.open_vulnerabilities || 0);
  const rate = Math.round(Number(dashboard.remediation_completion_rate || 0));
  byId("homeCompletionRate").textContent = `${rate}%`;
  byId("homeClosedVulnerabilities").textContent = String(closed);
  byId("homeCompletionChart").setAttribute("aria-label", `整改完成率 ${rate}%，已关闭 ${closed} 项，待整改 ${open} 项`);
  drawDonut("homeCompletionChart", ["已关闭", "待整改"], [closed, open], ["#91d6ba", "rgba(255,255,255,.17)"], "85%");
  drawHomeTrend();
}

const todoTypes = { vulnerability: ["vulnerabilities", "漏洞整改", "shield-alert"], inspection: ["inspection-tasks", "基线巡检", "clipboard-check"], alert: ["alerts", "安全告警", "bell"], incident: ["incidents", "事件响应", "activity"], work_order: ["work-orders", "运维工单", "clipboard-list"] };

function appendIcon(container, name) {
  const icon = document.createElement("i"); icon.dataset.lucide = name; container.appendChild(icon);
}

function renderHomeTodos(todos) {
  byId("homeTodoCount").textContent = String(todos.total ?? todos.items?.length ?? 0);
  byId("notificationDot").hidden = !todos.total;
  byId("homeNotificationButton").title = `${todos.total || 0} 项运营待办`;
  const list = byId("homeTodoList"); list.replaceChildren();
  (todos.items || []).slice(0, 4).forEach(item => {
    const [resource, type, icon] = todoTypes[item.type] || ["work-orders", "运营工单", "clipboard-list"];
    const row = document.createElement("button"); row.type = "button"; row.className = "home-todo-row"; row.title = item.title;
    const mark = document.createElement("span"); mark.className = "todo-type-icon"; appendIcon(mark, icon);
    const copy = document.createElement("div"); copy.className = "todo-copy";
    const title = document.createElement("strong"); title.className = "todo-title"; title.textContent = item.title;
    const meta = document.createElement("span"); meta.className = "todo-meta";
    const label = document.createElement("span"); label.textContent = `${type} · ${enterpriseStatusNames[item.status] || item.status}`;
    const severity = document.createElement("span"); severity.className = `severity-tag ${item.severity}`; severity.textContent = enterpriseSeverityNames[item.severity] || "待处理";
    meta.append(label, severity); copy.append(title, meta);
    const deadline = document.createElement("span"); deadline.className = `todo-deadline${item.overdue ? " overdue" : ""}`; deadline.textContent = item.overdue ? "已逾期" : item.deadline ? item.deadline.slice(5, 10) : "待跟进";
    row.append(mark, copy, deadline); row.addEventListener("click", () => openEnterpriseDetail(resource, item.id)); list.appendChild(row);
  });
  if (!todos.items?.length) renderWidgetMessage("homeTodoList", "当前没有待办事项");
}

function renderHomeActivity(alerts) {
  const list = byId("homeActivityList"); list.replaceChildren();
  [...(alerts.items || [])].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 3).forEach(item => {
    const row = document.createElement("button"); row.type = "button"; row.className = "activity-row"; row.title = item.title;
    const mark = document.createElement("span"); mark.className = `activity-marker ${item.status === "false_positive" ? "tone-teal" : item.severity === "critical" ? "tone-coral" : "tone-amber"}`; appendIcon(mark, item.status === "false_positive" ? "check" : "shield-alert");
    const copy = document.createElement("div"); const title = document.createElement("strong"); title.textContent = item.title;
    const detail = document.createElement("p");
    const timestamp = item.created_at ? new Date(item.created_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "";
    detail.textContent = `${enterpriseStatusNames[item.status] || item.status} · ${timestamp}`;
    copy.append(title, detail); row.append(mark, copy); row.addEventListener("click", () => openEnterpriseDetail("alerts", item.id)); list.appendChild(row);
  });
  if (!alerts.items?.length) renderWidgetMessage("homeActivityList", "当前没有告警记录");
}

function renderWidgetMessage(id, message) {
  const empty = document.createElement("p"); empty.className = "widget-empty"; empty.textContent = message; byId(id).replaceChildren(empty);
}

async function loadHomeDashboard() {
  if (dashboardRequest) return dashboardRequest;
  byId("homeUpdated").textContent = "正在更新…";
  dashboardRequest = (async () => {
    const results = await Promise.allSettled([api("/api/v1/enterprise/dashboard"), api("/api/v1/enterprise/todos"), api("/api/v1/enterprise/alerts?page_size=100")]);
    const errors = [];
    const renderers = [dashboard => { homeDashboard = dashboard; renderHomeDashboard(dashboard); }, renderHomeTodos, renderHomeActivity];
    results.forEach((result, index) => {
      if (result.status === "fulfilled") renderers[index](result.value);
      else {
        errors.push(result.reason?.message || "数据加载失败");
        if (index === 1) { renderWidgetMessage("homeTodoList", "待办加载失败"); byId("homeTodoCount").textContent = "--"; }
        else if (index === 2) renderWidgetMessage("homeActivityList", "告警记录加载失败");
        else {
          homeDashboard = null;
          Object.values(homeCharts).forEach(chart => chart.destroy());
          Object.keys(homeCharts).forEach(key => delete homeCharts[key]);
          ["homeAssets", "homeAlerts", "homeVulnerabilities", "homeInspections", "homeIncidents", "sidebarAlertCount", "homeOpenVulnerabilities", "homeClosedVulnerabilities", "homeCompletionRate", "homeAlertTotal"].forEach(id => { byId(id).textContent = "--"; });
          byId("homeRiskLegend").replaceChildren();
          ["homeAssetsHint", "homeAlertsHint", "homeVulnerabilitiesHint", "homeRemediationHint"].forEach(id => { byId(id).textContent = "数据暂不可用"; });
          byId("homeTrendSummary").textContent = "趋势数据不可用";
          byId("homeDataSource").textContent = "运营数据暂不可用";
        }
      }
    });
    byId("homeError").hidden = !errors.length;
    byId("homeErrorText").textContent = errors.length ? `部分数据暂不可用：${[...new Set(errors)].join("；")}` : "";
    byId("homeUpdated").textContent = errors.length ? "更新未完成" : `更新于 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
    refreshIcons();
  })().finally(() => { dashboardRequest = null; });
  return dashboardRequest;
}

function searchWorkspace() {
  const query = byId("navSearch").value.trim();
  const results = byId("navSearchResults"); results.replaceChildren();
  results.hidden = !query;
  byId("navSearch").setAttribute("aria-expanded", String(Boolean(query)));
  if (!query) return;
  const addResult = (label, category, action) => {
    const button = document.createElement("button"); button.type = "button";
    const title = document.createElement("span"); title.textContent = label;
    const caption = document.createElement("small"); caption.textContent = category;
    button.append(title, caption); button.addEventListener("click", () => { action(); results.hidden = true; byId("navSearch").value = ""; byId("navSearch").setAttribute("aria-expanded", "false"); }); results.appendChild(button);
  };
  Object.entries(workspaceViews).filter(([, label]) => label.includes(query)).forEach(([view, label]) => addResult(label, "功能", () => setView(view)));
  Object.entries(enterpriseResourceMeta).filter(([, meta]) => meta.title.includes(query)).slice(0, 5).forEach(([resource, meta]) => addResult(meta.title, "运营管理", () => openWorkspaceResource(resource)));
  addResult(`在资产中搜索“${query}”`, "资产", () => openWorkspaceResource("assets", query));
  addResult(`在告警中搜索“${query}”`, "告警", () => openWorkspaceResource("alerts", query));
}

document.querySelectorAll("[data-open-view]").forEach(button => button.addEventListener("click", () => {
  if (button.dataset.openView === "ops") state.enterpriseResource = "dashboard";
  setView(button.dataset.openView);
}));
document.querySelectorAll("[data-open-resource]").forEach(button => button.addEventListener("click", () => openWorkspaceResource(button.dataset.openResource)));
byId("sidebarToggle").addEventListener("click", () => {
  if (window.innerWidth <= 700) {
    const open = document.body.classList.toggle("sidebar-open");
    byId("sidebarOverlay").hidden = !open;
    byId("sidebarToggle").setAttribute("aria-expanded", String(open));
    byId("appSidebar").inert = !open;
    if (open) document.querySelector(".view-tab.active").focus();
  } else {
    document.body.classList.toggle("sidebar-collapsed"); closeSidebar();
  }
});
byId("sidebarOverlay").addEventListener("click", closeSidebar);
window.addEventListener("resize", closeSidebar);
document.addEventListener("keydown", event => { if (event.key === "Escape") { closeSidebar(); byId("navSearchResults").hidden = true; byId("navSearch").setAttribute("aria-expanded", "false"); } });
document.querySelectorAll(".view-tabs").forEach(navigation => navigation.addEventListener("keydown", event => {
  const tabs = [...navigation.querySelectorAll(".view-tab")];
  const current = tabs.indexOf(event.target);
  if (current < 0 || !["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const index = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowDown" ? 1 : -1) + tabs.length) % tabs.length;
  tabs[index].focus(); tabs[index].click();
}));
byId("navSearch").addEventListener("input", searchWorkspace);
byId("navSearch").addEventListener("keydown", event => {
  if (["ArrowDown", "Enter"].includes(event.key) && !byId("navSearchResults").hidden) {
    event.preventDefault(); const button = byId("navSearchResults").querySelector("button");
    if (event.key === "Enter") button?.click(); else button?.focus();
  }
});
document.addEventListener("click", event => { if (!event.target.closest(".nav-search")) { byId("navSearchResults").hidden = true; byId("navSearch").setAttribute("aria-expanded", "false"); } });
byId("homeTrendRange").addEventListener("change", drawHomeTrend);
byId("homeNotificationButton").addEventListener("click", () => { setView("home"); byId("homeTodoHeading").scrollIntoView({ block: "center", behavior: "smooth" }); });
byId("homeRetryButton").addEventListener("click", () => { loadStats(); loadHomeDashboard(); });
byId("refreshButton").addEventListener("click", () => { if (state.view === "home") loadHomeDashboard(); else if (operationsPages[state.view]) loadOperations(); });
document.addEventListener("aegis:view-changed", updateWorkspaceShell);
document.addEventListener("aegis:accent-changed", event => {
  dashboardAccent = event.detail;
  drawHomeTrend();
});
document.addEventListener("aegis:stats-updated", () => {
  updateHomeRuntime();
  if (!homeDashboard) loadHomeDashboard();
});
window.addEventListener("popstate", restoreWorkspaceRoute);
refreshIcons();
updateHomeRuntime();
updateWorkspaceShell();
