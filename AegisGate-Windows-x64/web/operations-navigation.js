"use strict";

const operationsPages = {
  ops: { title: "运营总览", kicker: "OPERATIONS OVERVIEW", icon: "layout-dashboard", resources: [["dashboard", "运营待办"]] },
  "ops-assets": { title: "资产管理", kicker: "ASSET MANAGEMENT", icon: "server", resources: [["assets", "资产台账"], ["asset-groups", "资产分组"], ["asset-tags", "资产标签"], ["discovery-tasks", "主动发现"]] },
  "ops-response": { title: "告警与响应", kicker: "THREAT RESPONSE", icon: "bell-ring", resources: [["alerts", "告警中心"], ["incidents", "应急响应"], ["iocs", "IOC 情报"], ["alert-rules", "告警规则"]] },
  "ops-risks": { title: "漏洞整改", kicker: "RISK REMEDIATION", icon: "shield-alert", resources: [["vulnerabilities", "漏洞管理"], ["remediation-orders", "整改任务"], ["scan-tasks", "安全扫描"], ["test-projects", "安全测试"]] },
  "ops-maintenance": { title: "巡检与工单", kicker: "INSPECTION AND WORK ORDERS", icon: "clipboard-check", resources: [["inspection-tasks", "基线巡检"], ["work-orders", "运维工单"], ["baseline-rules", "基线规则"]] },
  "ops-reports": { title: "报表归档", kicker: "REPORT ARCHIVE", icon: "files", resources: [["reports", "报表归档"]] },
  "ops-access": { title: "权限管理", kicker: "ACCESS MANAGEMENT", icon: "users", resources: [["users", "用户管理"], ["roles", "角色权限"]] },
  "ops-settings": { title: "运营配置", kicker: "OPERATIONS SETTINGS", icon: "sliders-horizontal", resources: [["settings", "安全配置"], ["scheduled-jobs", "任务调度"], ["allowlist", "黑白名单"], ["integrations", "外部对接"], ["notifications", "站内消息"]] },
  "ops-history": { title: "历史台账", kicker: "HISTORICAL RECORDS", icon: "history", resources: [] },
};

function operationsPageForResource(resource) {
  return Object.keys(operationsPages).find(view => operationsPages[view].resources.some(([key]) => key === resource));
}

function resolveOperationsRoute(view, resource) {
  // Preserve links to the former all-in-one operations page.
  if (view === "ops" && resource) view = operationsPageForResource(resource) || view;
  const page = operationsPages[view];
  if (!page) return { view, resource: null };
  if (view === "ops-history") return { view, resource: ["overview", "assets", "alerts", "vulnerabilities", "incidents", "iocs"].includes(resource) ? resource : "overview" };
  return { view, resource: page.resources.some(([key]) => key === resource) ? resource : page.resources[0][0] };
}

function initializeOperationsPages() {
  const navigation = byId("operationsNavigation");
  Object.entries(operationsPages).forEach(([view, page]) => {
    const button = document.createElement("button");
    button.id = `tab-${view}`; button.className = "view-tab"; button.type = "button";
    button.dataset.view = view; button.title = page.title;
    button.setAttribute("role", "tab"); button.setAttribute("aria-selected", "false"); button.setAttribute("aria-controls", `view-${view}`);
    const icon = document.createElement("i"); icon.dataset.lucide = page.icon; icon.setAttribute("aria-hidden", "true");
    const label = document.createElement("span"); label.textContent = page.title;
    button.append(icon, label);
    if (view === "ops-response") { const count = document.createElement("b"); count.id = "sidebarAlertCount"; count.textContent = "--"; button.appendChild(count); }
    navigation.appendChild(button);
    if (!byId(`view-${view}`)) {
      const panel = document.createElement("section"); panel.id = `view-${view}`; panel.className = "view-panel"; panel.hidden = true;
      panel.setAttribute("role", "tabpanel"); panel.setAttribute("aria-labelledby", button.id);
      byId("mainContent").insertBefore(panel, byId("view-ops-history"));
    }
  });
  byId("enterpriseModuleNav").addEventListener("click", event => {
    const button = event.target.closest("[data-enterprise-resource]");
    if (button) selectEnterpriseResource(button.dataset.enterpriseResource);
  });
}

function mountOperationsPage(view) {
  const page = operationsPages[view];
  if (!page || view === "ops-history") return;
  byId(`view-${view}`).appendChild(byId("enterpriseWorkbench"));
  byId("enterpriseWorkbenchHeading").textContent = page.title;
  byId("enterprisePageKicker").textContent = page.kicker;
  byId("enterpriseOverviewMeta").hidden = view !== "ops";
  const nav = byId("enterpriseModuleNav"); nav.replaceChildren(); nav.hidden = page.resources.length < 2;
  page.resources.forEach(([resource, title]) => {
    const button = document.createElement("button"); button.className = "enterprise-module"; button.type = "button";
    button.dataset.enterpriseResource = resource; button.textContent = title;
    const active = resource === state.enterpriseResource;
    button.classList.toggle("active", active); button.setAttribute("aria-pressed", String(active));
    nav.appendChild(button);
  });
  const resource = state.enterpriseResource;
  byId("enterpriseCreateButton").hidden = resource === "dashboard" || resource === "settings" || Boolean(enterpriseResourceMeta[resource]?.noGenericCreate && resource !== "reports");
  byId("enterpriseCreateLabel").textContent = resource === "reports" ? "生成报告" : `新建${page.resources.find(([key]) => key === resource)?.[1] || "记录"}`;
}

function restoreWorkspaceRoute() {
  const params = new URLSearchParams(window.location.search);
  const requested = params.get("view");
  setView(byId(`view-${requested}`) ? requested : "home", false, params.get("resource"));
}
