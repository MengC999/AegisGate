from __future__ import annotations

import csv
import hashlib
import ipaddress
import io
import json
import re
import socket
import sqlite3
import threading
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


SCHEMA_VERSION = "1.0"
DEFAULT_TENANT_ID = "local"
DEFAULT_PROJECT_ID = "default"
DEFAULT_USER_ID = "local-admin"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{2,63}")
_RECORD_ID = re.compile(r"[a-z][a-z0-9_-]{2,95}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_HOSTNAME = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _today() -> str:
    return date.today().isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


class EnterpriseValidationError(ValueError):
    pass


class EnterpriseNotFoundError(LookupError):
    pass


class EnterpriseConflictError(RuntimeError):
    pass


COMMON_COLUMNS = """
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
"""


SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS enterprise_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    parent_id TEXT NOT NULL DEFAULT '',
    business_level TEXT NOT NULL DEFAULT 'normal',
    owner TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, name)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    environment TEXT NOT NULL DEFAULT 'production',
    business_level TEXT NOT NULL DEFAULT 'normal',
    importance_weight REAL NOT NULL DEFAULT 1.0,
    owner TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    group_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'offline',
    authorization_ticket TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    last_seen_at TEXT NOT NULL DEFAULT '',
    archived_at TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, address, port)
);

CREATE TABLE IF NOT EXISTS asset_tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT 'graphite',
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, name)
);

CREATE TABLE IF NOT EXISTS asset_tag_links (
    asset_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag_id),
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (tag_id) REFERENCES asset_tags(id)
);

CREATE TABLE IF NOT EXISTS asset_history (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    action TEXT NOT NULL,
    change_summary TEXT NOT NULL,
    change_sha256 TEXT NOT NULL,
    version INTEGER NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS discovery_tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    probe_type TEXT NOT NULL DEFAULT 'connectivity',
    target_port INTEGER NOT NULL DEFAULT 443,
    authorization_ticket TEXT NOT NULL,
    schedule TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'draft',
    result_summary TEXT NOT NULL DEFAULT '',
    resolved_addresses_json TEXT NOT NULL DEFAULT '[]',
    last_run_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    attack_type TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    target_asset_id TEXT NOT NULL DEFAULT '',
    payload_preview TEXT NOT NULL DEFAULT '',
    payload_sha256 TEXT NOT NULL DEFAULT '',
    raw_log_sha256 TEXT NOT NULL DEFAULT '',
    context_summary TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    repeat_count INTEGER NOT NULL DEFAULT 1,
    assignee TEXT NOT NULL DEFAULT '',
    false_positive_reason TEXT NOT NULL DEFAULT '',
    closed_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);
CREATE INDEX IF NOT EXISTS idx_alert_scope_status ON alerts(tenant_id, project_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_alert_fingerprint ON alerts(tenant_id, project_id, fingerprint);

CREATE TABLE IF NOT EXISTS alert_notes (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    note TEXT NOT NULL,
    note_sha256 TEXT NOT NULL,
    note_type TEXT NOT NULL DEFAULT 'handling',
    {COMMON_COLUMNS},
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE TABLE IF NOT EXISTS alert_filter_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_pattern TEXT NOT NULL DEFAULT '',
    attack_type_pattern TEXT NOT NULL DEFAULT '',
    minimum_severity TEXT NOT NULL DEFAULT 'info',
    action TEXT NOT NULL DEFAULT 'keep',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL DEFAULT 'in_app',
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unread',
    recipient TEXT NOT NULL DEFAULT '',
    read_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS scan_tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'configuration_review',
    intensity TEXT NOT NULL DEFAULT 'safe',
    target_asset_ids_json TEXT NOT NULL DEFAULT '[]',
    excluded_targets_json TEXT NOT NULL DEFAULT '[]',
    authorization_ticket TEXT NOT NULL,
    schedule TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'draft',
    progress INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    last_run_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    asset_id TEXT NOT NULL DEFAULT '',
    cve TEXT NOT NULL DEFAULT '',
    cvss REAL NOT NULL DEFAULT 0,
    severity TEXT NOT NULL,
    principle TEXT NOT NULL DEFAULT '',
    poc_reference TEXT NOT NULL DEFAULT '',
    reproduction_placeholder TEXT NOT NULL DEFAULT '仅限授权环境，由测试人员补充复现记录。',
    risk_impact TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending_fix',
    risk_priority REAL NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT '',
    deadline TEXT NOT NULL DEFAULT '',
    overdue INTEGER NOT NULL DEFAULT 0,
    source_scan_id TEXT NOT NULL DEFAULT '',
    closed_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);
CREATE INDEX IF NOT EXISTS idx_vuln_scope_status ON vulnerabilities(tenant_id, project_id, status, severity);

CREATE TABLE IF NOT EXISTS remediation_orders (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    title TEXT NOT NULL,
    assignee TEXT NOT NULL,
    department TEXT NOT NULL DEFAULT '',
    deadline TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    remediation_plan TEXT NOT NULL DEFAULT '',
    receipt_summary TEXT NOT NULL DEFAULT '',
    receipt_sha256 TEXT NOT NULL DEFAULT '',
    verified_by TEXT NOT NULL DEFAULT '',
    verified_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS},
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS retest_records (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    batch_id TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT 'pending',
    evidence_summary TEXT NOT NULL DEFAULT '',
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    tester TEXT NOT NULL,
    tested_at TEXT NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS security_test_projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    test_type TEXT NOT NULL DEFAULT 'authorized_security_assessment',
    asset_ids_json TEXT NOT NULL DEFAULT '[]',
    scope_summary TEXT NOT NULL,
    authorization_ticket TEXT NOT NULL,
    manager TEXT NOT NULL,
    start_date TEXT NOT NULL DEFAULT '',
    end_date TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planning',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS test_cases (
    id TEXT PRIMARY KEY,
    project_id_ref TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    safe_procedure TEXT NOT NULL,
    expected_result TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    {COMMON_COLUMNS},
    FOREIGN KEY (project_id_ref) REFERENCES security_test_projects(id)
);

CREATE TABLE IF NOT EXISTS test_records (
    id TEXT PRIMARY KEY,
    project_id_ref TEXT NOT NULL,
    test_case_id TEXT NOT NULL DEFAULT '',
    recorded_at TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT 'observed',
    process_summary TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    tester TEXT NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (project_id_ref) REFERENCES security_test_projects(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    impact_scope TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    deadline TEXT NOT NULL DEFAULT '',
    evidence_digest TEXT NOT NULL DEFAULT '',
    review_summary TEXT NOT NULL DEFAULT '',
    archived_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS incident_actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    action_summary TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    handler TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS incident_links (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS forensics_records (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    custody_summary TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    {COMMON_COLUMNS},
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50,
    status TEXT NOT NULL DEFAULT 'active',
    tags_json TEXT NOT NULL DEFAULT '[]',
    expires_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, type, value)
);

CREATE TABLE IF NOT EXISTS baseline_rules (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    check_method TEXT NOT NULL,
    expected_value TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, code)
);

CREATE TABLE IF NOT EXISTS inspection_tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_group_id TEXT NOT NULL DEFAULT '',
    asset_ids_json TEXT NOT NULL DEFAULT '[]',
    rule_ids_json TEXT NOT NULL DEFAULT '[]',
    schedule TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'pending',
    progress INTEGER NOT NULL DEFAULT 0,
    due_at TEXT NOT NULL DEFAULT '',
    last_run_at TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS baseline_findings (
    id TEXT PRIMARY KEY,
    inspection_task_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    actual_summary TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS},
    FOREIGN KEY (inspection_task_id) REFERENCES inspection_tasks(id)
);

CREATE TABLE IF NOT EXISTS work_orders (
    id TEXT PRIMARY KEY,
    order_type TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    title TEXT NOT NULL,
    assignee TEXT NOT NULL,
    department TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'medium',
    deadline TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requirement_summary TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS work_order_receipts (
    id TEXT PRIMARY KEY,
    work_order_id TEXT NOT NULL,
    receipt_summary TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT 'submitted',
    {COMMON_COLUMNS},
    FOREIGN KEY (work_order_id) REFERENCES work_orders(id)
);

CREATE TABLE IF NOT EXISTS report_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    report_type TEXT NOT NULL,
    sections_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS report_archives (
    id TEXT PRIMARY KEY,
    report_type TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    version INTEGER NOT NULL,
    template_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'generated',
    period_start TEXT NOT NULL DEFAULT '',
    period_end TEXT NOT NULL DEFAULT '',
    summary_json TEXT NOT NULL,
    content_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email_masked TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    last_login_at TEXT NOT NULL DEFAULT '',
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, username)
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    builtin INTEGER NOT NULL DEFAULT 0,
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, name)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_asset_groups (
    role_id TEXT NOT NULL,
    asset_group_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (role_id, asset_group_id)
);

CREATE TABLE IF NOT EXISTS login_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    success INTEGER NOT NULL,
    source_ip_hash TEXT NOT NULL,
    user_agent_hash TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operation_audit (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    change_summary TEXT NOT NULL,
    change_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS operation_audit_no_update
BEFORE UPDATE ON operation_audit BEGIN
    SELECT RAISE(ABORT, 'operation audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS operation_audit_no_delete
BEFORE DELETE ON operation_audit BEGIN
    SELECT RAISE(ABORT, 'operation audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS login_logs_no_update
BEFORE UPDATE ON login_logs BEGIN
    SELECT RAISE(ABORT, 'login log is immutable');
END;
CREATE TRIGGER IF NOT EXISTS login_logs_no_delete
BEFORE DELETE ON login_logs BEGIN
    SELECT RAISE(ABORT, 'login log is immutable');
END;

CREATE TABLE IF NOT EXISTS system_settings (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    sensitive INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, category, setting_key)
);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    schedule TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    target_resource_id TEXT NOT NULL DEFAULT '',
    last_run_at TEXT NOT NULL DEFAULT '',
    next_run_at TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT 'never',
    {COMMON_COLUMNS}
);

CREATE TABLE IF NOT EXISTS allowlist_entries (
    id TEXT PRIMARY KEY,
    entry_type TEXT NOT NULL,
    value TEXT NOT NULL,
    list_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    {COMMON_COLUMNS},
    UNIQUE (tenant_id, project_id, entry_type, value, list_type)
);

CREATE TABLE IF NOT EXISTS integration_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    integration_type TEXT NOT NULL,
    endpoint_origin TEXT NOT NULL DEFAULT '',
    credential_reference TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'not_tested',
    {COMMON_COLUMNS}
);
"""


RESOURCE_CONFIG: dict[str, dict[str, Any]] = {
    "assets": {
        "table": "assets",
        "prefix": "astx",
        "required": ("name", "kind", "address"),
        "fields": ("name", "kind", "address", "port", "environment", "business_level", "importance_weight", "owner", "department", "group_id", "status", "authorization_ticket", "source", "last_seen_at", "archived_at"),
        "search": ("name", "kind", "address", "owner", "department", "group_id"),
        "statuses": ("online", "offline", "archived"),
        "default_status": "offline",
    },
    "asset-groups": {
        "table": "asset_groups",
        "prefix": "grp",
        "required": ("name",),
        "fields": ("name", "description", "parent_id", "business_level", "owner", "department"),
        "search": ("name", "description", "owner", "department"),
    },
    "asset-tags": {
        "table": "asset_tags",
        "prefix": "tag",
        "required": ("name",),
        "fields": ("name", "color"),
        "search": ("name", "color"),
    },
    "discovery-tasks": {
        "table": "discovery_tasks",
        "prefix": "dsc",
        "required": ("name", "target_asset_id", "authorization_ticket"),
        "fields": ("name", "target_asset_id", "probe_type", "target_port", "authorization_ticket", "schedule", "status", "result_summary", "last_run_at"),
        "search": ("name", "target_asset_id", "authorization_ticket", "result_summary"),
        "statuses": ("draft", "scheduled", "running", "completed", "failed", "paused"),
        "default_status": "draft",
    },
    "alerts": {
        "table": "alerts",
        "prefix": "alx",
        "required": ("title", "source", "severity"),
        "fields": ("title", "source", "severity", "status", "attack_type", "source_ip", "target_asset_id", "context_summary", "repeat_count", "assignee", "false_positive_reason"),
        "search": ("title", "source", "attack_type", "source_ip", "target_asset_id", "context_summary", "assignee"),
        "statuses": ("open", "in_progress", "closed", "false_positive"),
        "default_status": "open",
    },
    "alert-rules": {
        "table": "alert_filter_rules",
        "prefix": "afr",
        "required": ("name",),
        "fields": ("name", "source_pattern", "attack_type_pattern", "minimum_severity", "action", "enabled", "priority"),
        "search": ("name", "source_pattern", "attack_type_pattern", "action"),
    },
    "scan-tasks": {
        "table": "scan_tasks",
        "prefix": "scn",
        "required": ("name", "authorization_ticket"),
        "fields": ("name", "scan_type", "intensity", "target_asset_ids_json", "excluded_targets_json", "authorization_ticket", "schedule", "status", "progress", "summary", "last_run_at"),
        "json_fields": ("target_asset_ids_json", "excluded_targets_json"),
        "search": ("name", "scan_type", "authorization_ticket", "summary"),
        "statuses": ("draft", "scheduled", "running", "paused", "completed", "failed"),
        "default_status": "draft",
    },
    "vulnerabilities": {
        "table": "vulnerabilities",
        "prefix": "vlx",
        "required": ("title", "severity"),
        "fields": ("title", "asset_id", "cve", "cvss", "severity", "principle", "poc_reference", "reproduction_placeholder", "risk_impact", "remediation", "status", "owner", "deadline", "source_scan_id"),
        "search": ("title", "asset_id", "cve", "principle", "risk_impact", "remediation", "owner"),
        "statuses": ("pending_fix", "risk_confirmed", "fixing", "retest", "closed", "accepted"),
        "default_status": "pending_fix",
    },
    "remediation-orders": {
        "table": "remediation_orders",
        "prefix": "rem",
        "required": ("vulnerability_id", "title", "assignee", "deadline"),
        "fields": ("vulnerability_id", "title", "assignee", "department", "deadline", "status", "remediation_plan", "receipt_summary", "verified_by", "verified_at"),
        "search": ("title", "vulnerability_id", "assignee", "department", "remediation_plan"),
        "statuses": ("pending", "in_progress", "submitted", "verified", "closed"),
        "default_status": "pending",
    },
    "test-projects": {
        "table": "security_test_projects",
        "prefix": "tst",
        "required": ("name", "scope_summary", "authorization_ticket", "manager"),
        "fields": ("name", "test_type", "asset_ids_json", "scope_summary", "authorization_ticket", "manager", "start_date", "end_date", "status"),
        "json_fields": ("asset_ids_json",),
        "search": ("name", "test_type", "scope_summary", "authorization_ticket", "manager"),
        "statuses": ("planning", "testing", "remediation", "retest", "completed", "archived"),
        "default_status": "planning",
    },
    "test-cases": {
        "table": "test_cases",
        "prefix": "tcs",
        "required": ("project_id_ref", "category", "title", "objective", "safe_procedure"),
        "fields": ("project_id_ref", "category", "title", "objective", "safe_procedure", "expected_result", "status"),
        "search": ("project_id_ref", "category", "title", "objective"),
        "statuses": ("pending", "running", "passed", "finding", "not_applicable"),
        "default_status": "pending",
    },
    "test-records": {
        "table": "test_records",
        "prefix": "trc",
        "required": ("project_id_ref", "process_summary", "tester"),
        "fields": ("project_id_ref", "test_case_id", "recorded_at", "result", "process_summary", "tester"),
        "search": ("project_id_ref", "test_case_id", "result", "process_summary", "tester"),
    },
    "incidents": {
        "table": "incidents",
        "prefix": "inx",
        "required": ("title", "category", "severity"),
        "fields": ("title", "category", "severity", "status", "impact_scope", "owner", "deadline", "review_summary", "archived_at"),
        "search": ("title", "category", "impact_scope", "owner", "review_summary"),
        "statuses": ("open", "contained", "eradicated", "recovered", "closed"),
        "default_status": "open",
    },
    "incident-actions": {
        "table": "incident_actions",
        "prefix": "iac",
        "required": ("incident_id", "stage", "action_summary", "handler"),
        "fields": ("incident_id", "stage", "action_summary", "handler", "occurred_at"),
        "search": ("incident_id", "stage", "action_summary", "handler"),
    },
    "incident-links": {
        "table": "incident_links",
        "prefix": "ilk",
        "required": ("incident_id", "resource_type", "resource_id"),
        "fields": ("incident_id", "resource_type", "resource_id"),
        "search": ("incident_id", "resource_type", "resource_id"),
    },
    "forensics-records": {
        "table": "forensics_records",
        "prefix": "for",
        "required": ("incident_id", "evidence_type", "evidence_digest", "custody_summary"),
        "fields": ("incident_id", "evidence_type", "evidence_digest", "custody_summary", "collected_at"),
        "search": ("incident_id", "evidence_type", "evidence_digest", "custody_summary"),
    },
    "iocs": {
        "table": "iocs",
        "prefix": "iocx",
        "required": ("type", "value", "source"),
        "fields": ("type", "value", "source", "confidence", "status", "tags_json", "expires_at"),
        "json_fields": ("tags_json",),
        "search": ("type", "value", "source", "tags_json"),
        "statuses": ("active", "expired", "false_positive"),
        "default_status": "active",
    },
    "baseline-rules": {
        "table": "baseline_rules",
        "prefix": "bsr",
        "required": ("code", "name", "category", "check_method"),
        "fields": ("code", "name", "category", "severity", "check_method", "expected_value", "remediation", "enabled"),
        "search": ("code", "name", "category", "check_method", "remediation"),
    },
    "inspection-tasks": {
        "table": "inspection_tasks",
        "prefix": "ins",
        "required": ("name",),
        "fields": ("name", "asset_group_id", "asset_ids_json", "rule_ids_json", "schedule", "status", "progress", "due_at", "last_run_at", "summary"),
        "json_fields": ("asset_ids_json", "rule_ids_json"),
        "search": ("name", "asset_group_id", "summary"),
        "statuses": ("pending", "scheduled", "running", "completed", "failed", "paused"),
        "default_status": "pending",
    },
    "baseline-findings": {
        "table": "baseline_findings",
        "prefix": "bfn",
        "required": ("inspection_task_id", "rule_id", "asset_id", "severity", "actual_summary"),
        "fields": ("inspection_task_id", "rule_id", "asset_id", "severity", "status", "actual_summary"),
        "search": ("inspection_task_id", "rule_id", "asset_id", "actual_summary"),
        "statuses": ("open", "remediating", "submitted", "verified", "closed", "accepted"),
        "default_status": "open",
    },
    "work-orders": {
        "table": "work_orders",
        "prefix": "wko",
        "required": ("order_type", "source_type", "source_id", "title", "assignee", "deadline"),
        "fields": ("order_type", "source_type", "source_id", "title", "assignee", "department", "priority", "deadline", "status", "requirement_summary"),
        "search": ("order_type", "source_type", "source_id", "title", "assignee", "department"),
        "statuses": ("pending", "in_progress", "submitted", "verified", "closed"),
        "default_status": "pending",
    },
    "report-templates": {
        "table": "report_templates",
        "prefix": "rptp",
        "required": ("name", "report_type", "sections_json"),
        "fields": ("name", "report_type", "sections_json", "enabled", "version"),
        "json_fields": ("sections_json",),
        "search": ("name", "report_type"),
    },
    "reports": {
        "table": "report_archives",
        "prefix": "rpta",
        "required": ("report_type", "source_type", "title", "summary_json", "content_json", "content_sha256", "version"),
        "fields": ("report_type", "source_type", "source_id", "title", "version", "template_id", "status", "period_start", "period_end", "summary_json", "content_json", "content_sha256"),
        "json_fields": ("summary_json", "content_json"),
        "search": ("report_type", "source_type", "source_id", "title"),
        "statuses": ("generated", "reviewed", "archived"),
        "default_status": "generated",
    },
    "users": {
        "table": "users",
        "prefix": "usr",
        "required": ("username", "display_name"),
        "fields": ("username", "display_name", "email_masked", "department", "status", "last_login_at"),
        "search": ("username", "display_name", "department", "email_masked"),
        "statuses": ("active", "locked", "disabled"),
        "default_status": "active",
    },
    "roles": {
        "table": "roles",
        "prefix": "rol",
        "required": ("name", "permissions_json"),
        "fields": ("name", "permissions_json", "description", "builtin"),
        "json_fields": ("permissions_json",),
        "search": ("name", "description"),
    },
    "notifications": {
        "table": "notifications",
        "prefix": "ntf",
        "required": ("title", "body"),
        "fields": ("channel", "severity", "title", "body", "resource_type", "resource_id", "status", "recipient", "read_at"),
        "search": ("title", "body", "resource_type", "resource_id", "recipient"),
        "statuses": ("unread", "read", "dismissed"),
        "default_status": "unread",
    },
    "scheduled-jobs": {
        "table": "scheduled_jobs",
        "prefix": "job",
        "required": ("name", "job_type", "schedule"),
        "fields": ("name", "job_type", "schedule", "enabled", "target_resource_id", "last_run_at", "next_run_at", "last_status"),
        "search": ("name", "job_type", "target_resource_id", "last_status"),
    },
    "allowlist": {
        "table": "allowlist_entries",
        "prefix": "lst",
        "required": ("entry_type", "value", "list_type", "reason"),
        "fields": ("entry_type", "value", "list_type", "reason", "expires_at", "enabled"),
        "search": ("entry_type", "value", "list_type", "reason"),
    },
    "integrations": {
        "table": "integration_configs",
        "prefix": "int",
        "required": ("name", "integration_type"),
        "fields": ("name", "integration_type", "endpoint_origin", "credential_reference", "enabled", "status"),
        "search": ("name", "integration_type", "endpoint_origin", "status"),
        "statuses": ("not_tested", "connected", "degraded", "disabled"),
        "default_status": "not_tested",
    },
}


SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}
ASSET_WEIGHT = {"core": 1.5, "high": 1.3, "normal": 1.0, "low": 0.8}


class EnterpriseOperationsStore:
    """SQLite-backed enterprise security operations domain.

    The store is additive to the legacy JSON operations layer. It keeps bounded,
    scoped business records and an immutable audit chain. Raw payloads, logs,
    credentials and forensic files are never stored by this module.
    """

    def __init__(self, database_path: Path, legacy_seed_path: Path | None = None) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(database_path), check_same_thread=False, timeout=10.0
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        with self._connection:
            self._connection.executescript(SCHEMA_SQL)
        self._migrate(legacy_seed_path)
        self._ensure_reference_data()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _migrate(self, legacy_seed_path: Path | None) -> None:
        with self._lock, self._connection:
            now = _now()
            self._connection.execute(
                "INSERT INTO enterprise_meta(key, value, updated_at) VALUES('schema_version', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (SCHEMA_VERSION, now),
            )
            seeded = self._connection.execute(
                "SELECT value FROM enterprise_meta WHERE key='seeded'"
            ).fetchone()
            if seeded:
                return
            self._seed(legacy_seed_path)
            self._connection.execute(
                "INSERT INTO enterprise_meta(key, value, updated_at) VALUES('seeded', 'demo_seed', ?)",
                (now,),
            )

    def _seed(self, legacy_seed_path: Path | None) -> None:
        now = _now()
        scope = {
            "tenant_id": DEFAULT_TENANT_ID,
            "project_id": DEFAULT_PROJECT_ID,
            "user_id": "demo-seed",
        }
        group = {
            "id": "grp_demo_core",
            "name": "核心安全平台",
            "description": "AegisGate 演示资产组",
            "business_level": "core",
            "owner": "SOC Team",
            "department": "Security Platform",
        }
        self._insert_seed("asset_groups", group, scope, now)

        legacy: dict[str, Any] = {}
        if legacy_seed_path and legacy_seed_path.exists():
            try:
                value = json.loads(legacy_seed_path.read_text(encoding="utf-8"))
                legacy = value if isinstance(value, dict) else {}
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                legacy = {}
        for item in legacy.get("assets", []):
            if not isinstance(item, dict):
                continue
            asset = {
                "id": str(item.get("id") or self._new_id("astx")),
                "name": str(item.get("name", "演示资产"))[:160],
                "kind": str(item.get("kind", "web"))[:32],
                "address": str(item.get("address", "local.invalid"))[:253],
                "port": 0,
                "environment": str(item.get("environment", "production"))[:32],
                "business_level": str(item.get("importance", "normal"))[:16],
                "importance_weight": ASSET_WEIGHT.get(str(item.get("importance", "normal")), 1.0),
                "owner": str(item.get("owner", ""))[:120],
                "department": str(item.get("department", ""))[:120],
                "group_id": group["id"],
                "status": "archived" if item.get("status") == "retired" else str(item.get("status", "offline")),
                "authorization_ticket": str(item.get("authorization_scope", "Demo inventory only"))[:160],
                "source": "legacy_demo",
                "last_seen_at": str(item.get("updated_at", ""))[:32],
                "archived_at": "",
                "version": 1,
            }
            self._insert_seed("assets", asset, scope, now)
            self._asset_history(asset["id"], "seed", "从现有演示台账迁移", 1, scope, commit=False)

        for item in legacy.get("alerts", []):
            if not isinstance(item, dict):
                continue
            fingerprint = str(item.get("fingerprint", "")) or _sha256(
                _json({
                    "source": item.get("source", ""),
                    "attack_type": item.get("attack_type", ""),
                    "asset_id": item.get("asset_id", ""),
                    "source_ip": item.get("source_indicator", ""),
                })
            )
            alert = {
                "id": str(item.get("id") or self._new_id("alx")),
                "title": str(item.get("title", "演示告警"))[:160],
                "source": str(item.get("source", "Legacy SOC"))[:120],
                "severity": str(item.get("severity", "medium")),
                "status": "in_progress" if item.get("status") == "investigating" else str(item.get("status", "open")),
                "attack_type": str(item.get("attack_type", ""))[:100],
                "source_ip": str(item.get("source_indicator", ""))[:128],
                "target_asset_id": str(item.get("asset_id", ""))[:96],
                "payload_preview": "",
                "payload_sha256": "",
                "raw_log_sha256": str(item.get("evidence_sha256", ""))[:64],
                "context_summary": "从现有演示运营数据迁移；不包含原始载荷与日志。",
                "fingerprint": fingerprint,
                "repeat_count": int(item.get("repeat_count", 1)),
                "assignee": "SOC Team",
                "false_positive_reason": "",
                "closed_at": "",
            }
            self._insert_seed("alerts", alert, scope, now)

        for item in legacy.get("vulnerabilities", []):
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "medium"))
            status_map = {
                "new": "pending_fix",
                "triaged": "risk_confirmed",
                "fixing": "fixing",
                "retesting": "retest",
                "closed": "closed",
                "accepted": "accepted",
            }
            vulnerability = {
                "id": str(item.get("id") or self._new_id("vlx")),
                "title": str(item.get("title", "演示漏洞"))[:180],
                "asset_id": str(item.get("asset_id", ""))[:96],
                "cve": str(item.get("cve", ""))[:24],
                "cvss": float(item.get("cvss", 0)),
                "severity": severity,
                "principle": "配置或组件风险，需要在授权环境中进一步验证。",
                "poc_reference": "",
                "reproduction_placeholder": "仅限授权环境，由测试人员补充复现记录。",
                "risk_impact": "可能影响系统机密性、完整性或可用性。",
                "remediation": str(item.get("remediation", ""))[:2000],
                "status": status_map.get(str(item.get("status", "new")), "pending_fix"),
                "risk_priority": self._risk_priority(severity, float(item.get("cvss", 0)), 1.0),
                "owner": str(item.get("owner", ""))[:120],
                "deadline": str(item.get("deadline", ""))[:10],
                "overdue": 0,
                "source_scan_id": "",
                "closed_at": "",
            }
            self._insert_seed("vulnerabilities", vulnerability, scope, now)

        for item in legacy.get("incidents", []):
            if not isinstance(item, dict):
                continue
            incident = {
                "id": str(item.get("id") or self._new_id("inx")),
                "title": str(item.get("title", "演示事件"))[:180],
                "category": str(item.get("category", "Security Event"))[:80],
                "severity": str(item.get("severity", "medium")),
                "status": str(item.get("stage", "open")).replace("detected", "open"),
                "impact_scope": str(item.get("impact_scope", ""))[:1000],
                "owner": str(item.get("owner", ""))[:120],
                "deadline": "",
                "evidence_digest": str(item.get("evidence_digest", ""))[:64],
                "review_summary": "",
                "archived_at": "",
            }
            self._insert_seed("incidents", incident, scope, now)

        for item in legacy.get("iocs", []):
            if not isinstance(item, dict):
                continue
            ioc = {
                "id": str(item.get("id") or self._new_id("iocx")),
                "type": str(item.get("type", "ip"))[:16],
                "value": str(item.get("value", ""))[:253],
                "source": str(item.get("source", "Demo feed"))[:120],
                "confidence": int(item.get("confidence", 50)),
                "status": str(item.get("status", "active")),
                "tags_json": _json(item.get("tags", [])),
                "expires_at": "",
            }
            self._insert_seed("iocs", ioc, scope, now)

        demo_rows = [
            (
                "baseline_rules",
                {
                    "id": "bsr_demo_headers",
                    "code": "WEB-HEADER-001",
                    "name": "Web 安全响应头基线",
                    "category": "Web",
                    "severity": "medium",
                    "check_method": "检查授权资产的响应头配置记录",
                    "expected_value": "CSP、HSTS、X-Content-Type-Options 已按环境启用",
                    "remediation": "在网关统一配置并通过集成测试验证",
                    "enabled": 1,
                },
            ),
            (
                "inspection_tasks",
                {
                    "id": "ins_demo_weekly",
                    "name": "核心平台周度基线巡检",
                    "asset_group_id": "grp_demo_core",
                    "asset_ids_json": "[]",
                    "rule_ids_json": '["bsr_demo_headers"]',
                    "schedule": "weekly",
                    "status": "pending",
                    "progress": 0,
                    "due_at": "2026-09-04",
                    "last_run_at": "",
                    "summary": "等待执行",
                },
            ),
            (
                "security_test_projects",
                {
                    "id": "tst_demo_gateway",
                    "name": "AegisGate 网关授权安全测试",
                    "test_type": "authorized_security_assessment",
                    "asset_ids_json": '["ast_demo_gateway"]',
                    "scope_summary": "仅验证演示网关的鉴权、输入校验和响应安全头",
                    "authorization_ticket": "DEMO-AUTH-2026-001",
                    "manager": "Security Lead",
                    "start_date": "2026-08-31",
                    "end_date": "2026-09-03",
                    "status": "testing",
                },
            ),
            (
                "report_templates",
                {
                    "id": "rptp_security_test",
                    "name": "标准安全测试报告",
                    "report_type": "security_test",
                    "sections_json": _json(["项目概述", "测试范围", "风险统计", "漏洞详情", "整改措施", "附录"]),
                    "enabled": 1,
                    "version": 1,
                },
            ),
            (
                "report_templates",
                {
                    "id": "rptp_vulnerability",
                    "name": "漏洞挖掘与整改报告",
                    "report_type": "vulnerability",
                    "sections_json": _json(["报告概述", "漏洞详情", "授权复现记录", "风险影响", "整改建议", "复测结论"]),
                    "enabled": 1,
                    "version": 1,
                },
            ),
        ]
        for table, row in demo_rows:
            self._insert_seed(table, row, scope, now)

        builtin_roles = [
            ("rol_admin", "管理员", ["enterprise:*"], "全部本地管理权限"),
            ("rol_operator", "安全运营", ["enterprise:read", "enterprise:write", "report:generate"], "安全运营与处置权限"),
            ("rol_reviewer", "复核人员", ["enterprise:read", "workflow:review"], "复核与验证权限"),
            ("rol_readonly", "只读查看", ["enterprise:read"], "只读审计权限"),
        ]
        for role_id, name, permissions, description in builtin_roles:
            self._insert_seed(
                "roles",
                {
                    "id": role_id,
                    "name": name,
                    "permissions_json": _json(permissions),
                    "description": description,
                    "builtin": 1,
                },
                scope,
                now,
            )
        self._insert_seed(
            "users",
            {
                "id": "usr_local_admin",
                "username": "local-admin",
                "display_name": "本地管理员",
                "email_masked": "",
                "department": "Security Platform",
                "status": "active",
                "last_login_at": "",
            },
            scope,
            now,
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id, tenant_id, project_id, created_by, created_at) VALUES(?,?,?,?,?,?)",
            ("usr_local_admin", "rol_admin", DEFAULT_TENANT_ID, DEFAULT_PROJECT_ID, "demo-seed", now),
        )
        settings = [
            ("alerting", "critical_threshold", {"severity": "critical", "notify": True}),
            ("notifications", "in_app", {"enabled": True}),
            ("security", "sensitive_action_confirmation", {"enabled": True}),
        ]
        for category, key, value in settings:
            self._insert_seed(
                "system_settings",
                {
                    "id": self._new_id("cfg"),
                    "category": category,
                    "setting_key": key,
                    "value_json": _json(value),
                    "sensitive": 0,
                    "version": 1,
                },
                scope,
                now,
            )

    def _ensure_reference_data(self) -> None:
        """Add stable built-in records without altering user-created workflow data."""
        scope = {
            "tenant_id": DEFAULT_TENANT_ID,
            "project_id": DEFAULT_PROJECT_ID,
            "user_id": "demo-seed",
        }
        with self._lock, self._connection:
            project = self._connection.execute(
                "SELECT id FROM security_test_projects WHERE id='tst_demo_gateway'"
            ).fetchone()
            if project:
                self._insert_builtin_test_cases("tst_demo_gateway", scope)
            for role_id in ("rol_operator", "rol_reviewer", "rol_readonly"):
                self._connection.execute(
                    "INSERT OR IGNORE INTO role_asset_groups(role_id, asset_group_id, tenant_id, project_id, created_by, created_at) VALUES(?,?,?,?,?,?)",
                    (role_id, "grp_demo_core", DEFAULT_TENANT_ID, DEFAULT_PROJECT_ID, "demo-seed", _now()),
                )

    def _insert_builtin_test_cases(
        self,
        project_id_ref: str,
        scope: dict[str, str],
    ) -> None:
        cases = [
            ("identity", "身份认证与会话边界", "验证未认证请求不能访问受保护接口。", "使用预置的无效测试凭据调用测试环境接口，记录状态码与请求摘要。", "返回统一未授权响应且不泄露内部信息。"),
            ("authorization", "角色与资产组授权", "验证角色只可访问被授权的资产组。", "使用只读和运营角色访问演示资产组，核对允许与拒绝结果。", "越权访问被拒绝并产生审计记录。"),
            ("input", "输入校验与内容安全", "验证结构、长度、PII 和提示注入策略。", "提交不含真实数据的边界样例，记录检测动作与证据摘要。", "输入被归一化、脱敏或拦截。"),
            ("headers", "Web 安全响应头", "验证控制台与 API 的基础安全响应头。", "读取授权测试响应头，不发送攻击载荷。", "CSP、X-Content-Type-Options 和点击劫持防护按基线返回。"),
            ("rate", "限流与异常处理", "验证请求速率和错误响应契约。", "在测试限额内发送重复无害请求，核对限流和 request_id。", "超限请求被拒绝，错误信息不回显输入原文。"),
        ]
        now = _now()
        for suffix, title, objective, procedure, expected in cases:
            row = {
                "id": f"tcs_{project_id_ref.removeprefix('tst_')}_{suffix}"[:95],
                "project_id_ref": project_id_ref,
                "category": suffix,
                "title": title,
                "objective": objective,
                "safe_procedure": procedure,
                "expected_result": expected,
                "status": "pending",
                "tenant_id": scope["tenant_id"],
                "project_id": scope["project_id"],
                "created_by": scope["user_id"],
                "created_at": now,
                "updated_at": now,
            }
            self._insert_seed("test_cases", row, scope, now)

    def _insert_seed(
        self,
        table: str,
        row: dict[str, Any],
        scope: dict[str, str],
        now: str,
    ) -> None:
        values = dict(row)
        values.setdefault("tenant_id", scope["tenant_id"])
        values.setdefault("project_id", scope["project_id"])
        values.setdefault("created_by", scope["user_id"])
        values.setdefault("created_at", now)
        values.setdefault("updated_at", now)
        columns = ",".join(values)
        placeholders = ",".join("?" for _ in values)
        self._connection.execute(
            f"INSERT OR IGNORE INTO {table} ({columns}) VALUES ({placeholders})",
            tuple(values.values()),
        )

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:16]}"

    @staticmethod
    def validate_scope(scope: dict[str, str] | None) -> tuple[str, str, str]:
        source = scope if isinstance(scope, dict) else {}
        tenant_id = str(source.get("tenant_id", DEFAULT_TENANT_ID)).strip().lower()
        project_id = str(source.get("project_id", DEFAULT_PROJECT_ID)).strip().lower()
        user_id = str(source.get("user_id", DEFAULT_USER_ID)).strip().lower()
        for field, value in (("tenant_id", tenant_id), ("project_id", project_id), ("user_id", user_id)):
            if not _IDENTIFIER.fullmatch(value):
                raise EnterpriseValidationError(f"{field} 格式无效")
        return tenant_id, project_id, user_id

    @staticmethod
    def _role_id(scope: dict[str, str] | None) -> str | None:
        """Return the persisted role id used for asset-group isolation.

        Direct trusted calls without a role keep the legacy tenant/project
        behavior. HTTP requests always attach a role; administrators bypass
        group filtering while other roles require explicit group mappings.
        """
        source = scope if isinstance(scope, dict) else {}
        value = str(source.get("role_id", "")).strip().lower()
        if not value or value in {"admin", "rol_admin"}:
            return None
        if not value.startswith("rol_"):
            value = f"rol_{value}"
        if not _RECORD_ID.fullmatch(value):
            raise EnterpriseValidationError("role_id 格式无效")
        return value

    def _visibility_clause(
        self,
        resource: str,
        scope: dict[str, str] | None,
        *,
        table_prefix: str = "",
    ) -> tuple[str, list[Any]]:
        """Build a parameterized asset-group visibility predicate."""
        role_id = self._role_id(scope)
        if role_id is None:
            return "", []
        tenant_id, project_id, user_id = self.validate_scope(scope)
        prefix = f"{table_prefix}." if table_prefix else ""

        def groups(column: str) -> tuple[str, list[Any]]:
            return (
                f"{column} IN (SELECT asset_group_id FROM role_asset_groups "
                "WHERE role_id=? AND tenant_id=? AND project_id=?)",
                [role_id, tenant_id, project_id],
            )

        def assets(column: str) -> tuple[str, list[Any]]:
            return (
                f"{column} IN (SELECT a.id FROM assets a JOIN role_asset_groups rag "
                "ON rag.asset_group_id=a.group_id AND rag.tenant_id=a.tenant_id "
                "AND rag.project_id=a.project_id WHERE rag.role_id=? "
                "AND a.tenant_id=? AND a.project_id=?)",
                [role_id, tenant_id, project_id],
            )

        if resource == "assets":
            return groups(f"{prefix}group_id")
        if resource == "asset-groups":
            return groups(f"{prefix}id")
        direct_asset_fields = {
            "discovery-tasks": "target_asset_id",
            "alerts": "target_asset_id",
            "vulnerabilities": "asset_id",
            "baseline-findings": "asset_id",
        }
        if resource in direct_asset_fields:
            return assets(f"{prefix}{direct_asset_fields[resource]}")

        allowed_assets, asset_params = assets("scope_asset.id")
        asset_ids_sql = allowed_assets.replace("scope_asset.id IN ", "")
        allowed_groups, group_params = groups("scope_group.id")
        group_ids_sql = allowed_groups.replace("scope_group.id IN ", "")

        if resource in {"scan-tasks", "test-projects"}:
            field = "target_asset_ids_json" if resource == "scan-tasks" else "asset_ids_json"
            return (
                f"EXISTS (SELECT 1 FROM json_each({prefix}{field}) j "
                f"WHERE j.value IN {asset_ids_sql})",
                asset_params,
            )
        if resource in {"test-cases", "test-records"}:
            return (
                f"{prefix}project_id_ref IN (SELECT p.id FROM security_test_projects p "
                f"WHERE EXISTS (SELECT 1 FROM json_each(p.asset_ids_json) j WHERE j.value IN {asset_ids_sql}))",
                asset_params,
            )
        if resource == "remediation-orders":
            return (
                f"{prefix}vulnerability_id IN (SELECT v.id FROM vulnerabilities v "
                f"WHERE v.asset_id IN {asset_ids_sql})",
                asset_params,
            )
        if resource == "inspection-tasks":
            return (
                f"({prefix}asset_group_id IN {group_ids_sql} OR EXISTS "
                f"(SELECT 1 FROM json_each({prefix}asset_ids_json) j WHERE j.value IN {asset_ids_sql}))",
                [*group_params, *asset_params],
            )

        accessible_incidents = (
            "SELECT i.id FROM incidents i WHERE i.tenant_id=? AND i.project_id=? AND i.created_by=? UNION "
            "SELECT il.incident_id FROM incident_links il WHERE il.tenant_id=? AND il.project_id=? AND ("
            f"(il.resource_type IN ('asset','assets') AND il.resource_id IN {asset_ids_sql}) OR "
            f"(il.resource_type IN ('alert','alerts') AND il.resource_id IN (SELECT al.id FROM alerts al WHERE al.target_asset_id IN {asset_ids_sql})) OR "
            f"(il.resource_type IN ('vulnerability','vulnerabilities') AND il.resource_id IN (SELECT vu.id FROM vulnerabilities vu WHERE vu.asset_id IN {asset_ids_sql})))"
        )
        incident_params = [tenant_id, project_id, user_id, tenant_id, project_id, *asset_params, *asset_params, *asset_params]
        if resource == "incidents":
            return f"{prefix}id IN ({accessible_incidents})", incident_params
        if resource in {"incident-actions", "incident-links", "forensics-records"}:
            return f"{prefix}incident_id IN ({accessible_incidents})", incident_params
        if resource == "work-orders":
            return (
                f"({prefix}source_id IN (SELECT v.id FROM vulnerabilities v WHERE v.asset_id IN {asset_ids_sql}) OR "
                f"{prefix}source_id IN (SELECT b.id FROM baseline_findings b WHERE b.asset_id IN {asset_ids_sql}) OR "
                f"{prefix}source_id IN (SELECT al.id FROM alerts al WHERE al.target_asset_id IN {asset_ids_sql}) OR "
                f"{prefix}source_id IN ({accessible_incidents}))",
                [*asset_params, *asset_params, *asset_params, *incident_params],
            )
        if resource == "reports":
            return (
                f"({prefix}created_by=? OR {prefix}source_id IN {asset_ids_sql} OR "
                f"{prefix}source_id IN (SELECT v.id FROM vulnerabilities v WHERE v.asset_id IN {asset_ids_sql}) OR "
                f"{prefix}source_id IN (SELECT p.id FROM security_test_projects p WHERE EXISTS "
                f"(SELECT 1 FROM json_each(p.asset_ids_json) j WHERE j.value IN {asset_ids_sql})) OR "
                f"{prefix}source_id IN ({accessible_incidents}))",
                [user_id, *asset_params, *asset_params, *asset_params, *incident_params],
            )
        return "", []

    def _validate_asset_scope(
        self,
        resource: str,
        values: dict[str, Any],
        scope: dict[str, str] | None,
    ) -> None:
        """Reject writes that would create an invisible cross-group record."""
        role_id = self._role_id(scope)
        if role_id is None:
            return
        tenant_id, project_id, _ = self.validate_scope(scope)

        def require_asset(asset_id: Any, field: str = "asset_id") -> None:
            value = str(asset_id or "")
            if not value:
                raise EnterpriseValidationError(f"{field} 必须绑定当前角色可访问的资产")
            self.get_record("assets", value, scope=scope)

        if resource == "assets":
            group_id = str(values.get("group_id", ""))
            if not group_id:
                raise EnterpriseValidationError("受限角色登记资产必须指定已授权资产组")
            row = self._connection.execute(
                "SELECT 1 FROM role_asset_groups WHERE role_id=? AND asset_group_id=? AND tenant_id=? AND project_id=?",
                (role_id, group_id, tenant_id, project_id),
            ).fetchone()
            if not row:
                raise EnterpriseValidationError("资产组不在当前角色授权范围内")
            return
        field_by_resource = {
            "discovery-tasks": "target_asset_id",
            "alerts": "target_asset_id",
            "vulnerabilities": "asset_id",
            "baseline-findings": "asset_id",
        }
        if resource in field_by_resource:
            field = field_by_resource[resource]
            require_asset(values.get(field), field)
            return
        def decode_ids(value: Any) -> list[Any]:
            return value if isinstance(value, list) else self._decode_json(value, [])

        if resource in {"scan-tasks", "test-projects"}:
            field = "target_asset_ids_json" if resource == "scan-tasks" else "asset_ids_json"
            asset_ids = decode_ids(values.get(field))
            if not asset_ids:
                raise EnterpriseValidationError(f"{field} 必须至少包含一个已授权资产")
            for asset_id in asset_ids:
                require_asset(asset_id, field)
            return
        if resource == "inspection-tasks":
            group_id = str(values.get("asset_group_id", ""))
            asset_ids = decode_ids(values.get("asset_ids_json"))
            if group_id:
                row = self._connection.execute(
                    "SELECT 1 FROM role_asset_groups WHERE role_id=? AND asset_group_id=? AND tenant_id=? AND project_id=?",
                    (role_id, group_id, tenant_id, project_id),
                ).fetchone()
                if not row:
                    raise EnterpriseValidationError("巡检资产组不在当前角色授权范围内")
            elif asset_ids:
                for asset_id in asset_ids:
                    require_asset(asset_id, "asset_ids_json")
            else:
                raise EnterpriseValidationError("巡检任务必须绑定已授权资产组或资产")
            return
        parent_resources = {
            "remediation-orders": ("vulnerabilities", "vulnerability_id"),
            "test-cases": ("test-projects", "project_id_ref"),
            "test-records": ("test-projects", "project_id_ref"),
            "incident-actions": ("incidents", "incident_id"),
            "forensics-records": ("incidents", "incident_id"),
        }
        if resource in parent_resources:
            parent_resource, field = parent_resources[resource]
            self.get_record(parent_resource, str(values.get(field, "")), scope=scope)
            return
        if resource == "incident-links":
            self.get_record("incidents", str(values.get("incident_id", "")), scope=scope)
            target_type = str(values.get("resource_type", "")).rstrip("s")
            target_map = {"asset": "assets", "alert": "alerts", "vulnerability": "vulnerabilities"}
            if target_type not in target_map:
                raise EnterpriseValidationError("事件只可关联资产、告警或漏洞")
            self.get_record(target_map[target_type], str(values.get("resource_id", "")), scope=scope)

    @staticmethod
    def _resource(resource: str) -> dict[str, Any]:
        config = RESOURCE_CONFIG.get(resource)
        if not config:
            raise EnterpriseValidationError("企业运营资源类型无效")
        return config

    @staticmethod
    def _bounded_text(value: Any, field: str, maximum: int, *, required: bool = False) -> str:
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise EnterpriseValidationError(f"{field} 必须是字符串")
        normalized = " ".join(value.replace("\x00", "").split()).strip()
        if required and not normalized:
            raise EnterpriseValidationError(f"{field} 不能为空")
        if len(normalized) > maximum:
            raise EnterpriseValidationError(f"{field} 最多 {maximum} 个字符")
        return normalized

    @staticmethod
    def _safe_preview(value: str, maximum: int = 240) -> str:
        cleaned = " ".join(value.replace("\x00", "").split())
        cleaned = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{8,}", r"\1[REDACTED]", cleaned)
        cleaned = re.sub(r"(?i)(api[_-]?key|token|password)\s*[:=]\s*\S+", r"\1=[REDACTED]", cleaned)
        cleaned = re.sub(r"\b1[3-9]\d{9}\b", "[PHONE]", cleaned)
        cleaned = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[EMAIL]", cleaned)
        return cleaned[:maximum]

    @staticmethod
    def _date(value: Any, field: str, *, allow_empty: bool = True) -> str:
        if value in (None, "") and allow_empty:
            return ""
        text = EnterpriseOperationsStore._bounded_text(value, field, 10, required=True)
        try:
            date.fromisoformat(text)
        except ValueError as exc:
            raise EnterpriseValidationError(f"{field} 必须是 YYYY-MM-DD") from exc
        return text

    @staticmethod
    def _json_array(value: Any, field: str, maximum: int = 200) -> str:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise EnterpriseValidationError(f"{field} 必须是数组") from exc
        if not isinstance(value, list) or len(value) > maximum:
            raise EnterpriseValidationError(f"{field} 必须是最多 {maximum} 项的数组")
        result: list[str] = []
        for item in value:
            if not isinstance(item, str) or len(item) > 160:
                raise EnterpriseValidationError(f"{field} 包含无效条目")
            result.append(item.strip())
        return _json(result)

    @staticmethod
    def _risk_priority(severity: str, cvss: float, asset_weight: float) -> float:
        base = max(float(cvss), SEVERITY_WEIGHT.get(severity, 1.0) * 2.0)
        return round(min(10.0, base * max(0.5, min(asset_weight, 2.0))), 2)

    def schema(self) -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        return {
            "schema_version": SCHEMA_VERSION,
            "database": self.database_path.name,
            "tables": [
                {"name": row["name"], "sql": row["sql"]}
                for row in rows
                if row["name"] not in {"enterprise_meta"}
            ],
            "privacy": {
                "raw_attack_payload_persisted": False,
                "raw_log_persisted": False,
                "credential_value_persisted": False,
                "audit_mutation_allowed": False,
            },
        }

    def list_records(
        self,
        resource: str,
        *,
        scope: dict[str, str] | None = None,
        page: int = 1,
        page_size: int = 50,
        query: str = "",
        filters: dict[str, str] | None = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> dict[str, Any]:
        config = self._resource(resource)
        tenant_id, project_id, _ = self.validate_scope(scope)
        if page < 1 or page_size < 1 or page_size > 200:
            raise EnterpriseValidationError("分页参数无效")
        allowed_sort = set(config["fields"]) | {"created_at", "updated_at", "id"}
        sort = sort if sort in allowed_sort else "updated_at"
        order = "ASC" if str(order).lower() == "asc" else "DESC"
        clauses = ["tenant_id=?", "project_id=?"]
        params: list[Any] = [tenant_id, project_id]
        normalized_query = self._bounded_text(query, "q", 120)
        if normalized_query:
            search_fields = config.get("search", ())
            if search_fields:
                clauses.append("(" + " OR ".join(f"LOWER({field}) LIKE ?" for field in search_fields) + ")")
                params.extend([f"%{normalized_query.casefold()}%"] * len(search_fields))
        requested_filters = filters if isinstance(filters, dict) else {}
        allowed_filters = {
            "status", "severity", "owner", "department", "group_id", "business_level",
            "assignee", "source", "category", "report_type", "source_type", "order_type",
            "enabled", "asset_id", "target_asset_id", "source_id", "project_id_ref",
        }
        table_columns = set(config["fields"]) | {"tenant_id", "project_id"}
        for field, value in requested_filters.items():
            if field not in allowed_filters or field not in table_columns or value in (None, ""):
                continue
            clauses.append(f"{field}=?")
            params.append(value)
        visibility, visibility_params = self._visibility_clause(resource, scope)
        if visibility:
            clauses.append(visibility)
            params.extend(visibility_params)
        where = " AND ".join(clauses)
        offset = (page - 1) * page_size
        table = config["table"]
        with self._lock:
            total = int(self._connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0])
            rows = self._connection.execute(
                f"SELECT * FROM {table} WHERE {where} ORDER BY {sort} {order}, id ASC LIMIT ? OFFSET ?",
                (*params, page_size, offset),
            ).fetchall()
        items = [self._decode_row(resource, row) for row in rows]
        if resource == "vulnerabilities":
            for item in items:
                item["overdue"] = self._is_overdue(item.get("deadline", ""), item.get("status", ""))
        return {
            "schema_version": SCHEMA_VERSION,
            "resource": resource,
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "scope": {"tenant_id": tenant_id, "project_id": project_id},
            "data_mode": "runtime" if self.database_path.exists() else "unavailable",
        }

    def get_record(
        self, resource: str, record_id: str, *, scope: dict[str, str] | None = None
    ) -> dict[str, Any]:
        config = self._resource(resource)
        tenant_id, project_id, _ = self.validate_scope(scope)
        if not _RECORD_ID.fullmatch(str(record_id)):
            raise EnterpriseValidationError("记录 ID 无效")
        visibility, visibility_params = self._visibility_clause(resource, scope)
        where = "id=? AND tenant_id=? AND project_id=?"
        params: list[Any] = [record_id, tenant_id, project_id]
        if visibility:
            where += f" AND {visibility}"
            params.extend(visibility_params)
        with self._lock:
            row = self._connection.execute(
                f"SELECT * FROM {config['table']} WHERE {where}",
                params,
            ).fetchone()
        if not row:
            raise EnterpriseNotFoundError("企业运营记录不存在")
        result = self._decode_row(resource, row)
        result["related"] = self._related(resource, record_id, tenant_id, project_id)
        return result

    def create(
        self,
        resource: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        config = self._resource(resource)
        if not isinstance(payload, dict):
            raise EnterpriseValidationError("请求数据必须是对象")
        tenant_id, project_id, user_id = self.validate_scope(scope)
        values = self._validate_payload(resource, payload, creating=True)
        self._validate_asset_scope(resource, values, scope)
        record_id = self._bounded_text(payload.get("id", ""), "id", 96) or self._new_id(config["prefix"])
        if not _RECORD_ID.fullmatch(record_id):
            raise EnterpriseValidationError("记录 ID 无效")
        now = _now()
        values.update(
            {
                "id": record_id,
                "tenant_id": tenant_id,
                "project_id": project_id,
                "created_by": user_id,
                "created_at": now,
                "updated_at": now,
            }
        )
        if resource == "alerts":
            return self._create_alert(values, payload, scope)
        if resource == "assets":
            values.setdefault("version", 1)
        if resource == "vulnerabilities":
            values["risk_priority"] = self._vulnerability_priority(values, tenant_id, project_id)
            values["overdue"] = int(self._is_overdue(values.get("deadline", ""), values.get("status", "")))
        if resource == "test-records":
            values.setdefault("recorded_at", now)
        if resource == "incident-actions":
            values.setdefault("occurred_at", now)
        try:
            with self._lock, self._connection:
                self._insert(config["table"], values)
                if resource == "assets":
                    self._asset_history(record_id, "create", "资产已登记", 1, scope, commit=False)
                self._append_audit("create", resource, record_id, user_id, values, tenant_id, project_id)
                self._post_create(resource, values, scope)
        except sqlite3.IntegrityError as exc:
            raise EnterpriseConflictError("记录与现有数据冲突") from exc
        return self.get_record(resource, record_id, scope=scope)

    def update(
        self,
        resource: str,
        record_id: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
        require_confirmation: bool = False,
    ) -> dict[str, Any]:
        config = self._resource(resource)
        if not isinstance(payload, dict):
            raise EnterpriseValidationError("请求数据必须是对象")
        tenant_id, project_id, user_id = self.validate_scope(scope)
        current = self.get_record(resource, record_id, scope=scope)
        if require_confirmation and payload.get("confirm") != "CONFIRM":
            raise EnterpriseValidationError("敏感操作需要二次确认")
        values = self._validate_payload(resource, payload, creating=False)
        if not values:
            raise EnterpriseValidationError("没有可更新字段")
        self._validate_asset_scope(resource, {**current, **values}, scope)
        if "status" in values:
            self._validate_transition(resource, str(current.get("status", "")), str(values["status"]))
        if resource == "assets":
            values["version"] = int(current.get("version", 1)) + 1
            if values.get("status") == "archived":
                values["archived_at"] = _now()
        if resource == "vulnerabilities":
            merged = {**current, **values}
            values["risk_priority"] = self._vulnerability_priority(merged, tenant_id, project_id)
            values["overdue"] = int(self._is_overdue(str(merged.get("deadline", "")), str(merged.get("status", ""))))
            if values.get("status") == "closed":
                values["closed_at"] = _now()
        if resource == "alerts" and values.get("status") == "closed":
            values["closed_at"] = _now()
        values["updated_at"] = _now()
        assignments = ",".join(f"{field}=?" for field in values)
        try:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    f"UPDATE {config['table']} SET {assignments} WHERE id=? AND tenant_id=? AND project_id=?",
                    (*values.values(), record_id, tenant_id, project_id),
                )
                if cursor.rowcount != 1:
                    raise EnterpriseNotFoundError("企业运营记录不存在")
                if resource == "assets":
                    summary = self._bounded_text(payload.get("note", "资产信息变更"), "note", 500) or "资产信息变更"
                    self._asset_history(record_id, "update", summary, int(values["version"]), scope, commit=False)
                note = self._bounded_text(payload.get("note", ""), "note", 500)
                if resource == "alerts" and note:
                    self._insert_alert_note(record_id, note, "handling", scope)
                self._append_audit("update", resource, record_id, user_id, values, tenant_id, project_id)
        except sqlite3.IntegrityError as exc:
            raise EnterpriseConflictError("更新与现有数据冲突") from exc
        return self.get_record(resource, record_id, scope=scope)

    def run_discovery(
        self, task_id: str, *, scope: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Perform one bounded DNS and TCP connectivity check for a registered asset."""
        task = self.get_record("discovery-tasks", task_id, scope=scope)
        if not task.get("authorization_ticket"):
            raise EnterpriseValidationError("主动探测必须绑定授权工单")
        asset = self.get_record("assets", str(task["target_asset_id"]), scope=scope)
        host = self._extract_host(str(asset.get("address", "")))
        port = int(task.get("target_port") or asset.get("port") or 443)
        if not 1 <= port <= 65535:
            raise EnterpriseValidationError("探测端口无效")
        addresses: list[str] = []
        reachable = False
        error_code = ""
        try:
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = sorted({entry[4][0] for entry in resolved})[:8]
            with socket.create_connection((host, port), timeout=1.5):
                reachable = True
        except socket.gaierror:
            error_code = "dns_resolution_failed"
        except (TimeoutError, OSError):
            error_code = "tcp_connect_failed"
        summary = "授权单点连通性检查成功" if reachable else f"授权单点连通性检查未连通：{error_code}"
        tenant_id, project_id, user_id = self.validate_scope(scope)
        now = _now()
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE discovery_tasks SET status='completed', result_summary=?, resolved_addresses_json=?, last_run_at=?, updated_at=? WHERE id=? AND tenant_id=? AND project_id=?",
                (summary, _json(addresses), now, now, task_id, tenant_id, project_id),
            )
            self._connection.execute(
                "UPDATE assets SET status=?, last_seen_at=?, updated_at=?, version=version+1 WHERE id=? AND tenant_id=? AND project_id=?",
                ("online" if reachable else "offline", now if reachable else str(asset.get("last_seen_at", "")), now, asset["id"], tenant_id, project_id),
            )
            self._asset_history(str(asset["id"]), "connectivity_probe", summary, int(asset.get("version", 1)) + 1, scope, commit=False)
            self._append_audit("run", "discovery-tasks", task_id, user_id, {"reachable": reachable, "result": error_code or "connected"}, tenant_id, project_id)
        return self.get_record("discovery-tasks", task_id, scope=scope)

    def create_retest(
        self,
        vulnerability_id: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        vulnerability = self.get_record("vulnerabilities", vulnerability_id, scope=scope)
        tenant_id, project_id, user_id = self.validate_scope(scope)
        result = self._bounded_text(payload.get("result", "pending"), "result", 32, required=True)
        if result not in {"pending", "passed", "failed", "inconclusive"}:
            raise EnterpriseValidationError("复测结果无效")
        summary = self._bounded_text(payload.get("evidence_summary", ""), "evidence_summary", 1000)
        evidence = self._bounded_text(payload.get("evidence", ""), "evidence", 10000)
        record_id = self._new_id("rts")
        now = _now()
        row = {
            "id": record_id,
            "vulnerability_id": vulnerability_id,
            "batch_id": self._bounded_text(payload.get("batch_id", ""), "batch_id", 96),
            "result": result,
            "evidence_summary": self._safe_preview(summary, 1000),
            "evidence_sha256": _sha256(evidence) if evidence else "",
            "tester": user_id,
            "tested_at": now,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
        }
        next_status = "closed" if result == "passed" else "fixing" if result == "failed" else "retest"
        with self._lock, self._connection:
            self._insert("retest_records", row)
            self._connection.execute(
                "UPDATE vulnerabilities SET status=?, closed_at=?, updated_at=? WHERE id=? AND tenant_id=? AND project_id=?",
                (next_status, now if next_status == "closed" else "", now, vulnerability_id, tenant_id, project_id),
            )
            self._append_audit("retest", "vulnerabilities", vulnerability_id, user_id, {"result": result, "previous_status": vulnerability.get("status"), "next_status": next_status, "evidence_sha256": row["evidence_sha256"]}, tenant_id, project_id)
        return {"retest": self._row_by_id("retest_records", record_id), "vulnerability": self.get_record("vulnerabilities", vulnerability_id, scope=scope)}

    def batch_retest(
        self,
        vulnerability_ids: list[str],
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(vulnerability_ids, list) or not 1 <= len(vulnerability_ids) <= 100:
            raise EnterpriseValidationError("批量复测必须包含 1 到 100 个漏洞 ID")
        batch_id = self._new_id("rtb")
        results = []
        for vulnerability_id in vulnerability_ids:
            if not isinstance(vulnerability_id, str):
                raise EnterpriseValidationError("漏洞 ID 无效")
            results.append(self.create_retest(vulnerability_id, {**payload, "batch_id": batch_id}, scope=scope))
        return {"batch_id": batch_id, "processed": len(results), "items": results}

    def add_incident_action(
        self,
        incident_id: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.get_record("incidents", incident_id, scope=scope)
        stage = self._bounded_text(payload.get("stage", ""), "stage", 32, required=True)
        if stage not in {"isolation", "trace", "eradication", "recovery", "forensics", "review"}:
            raise EnterpriseValidationError("事件处置阶段无效")
        evidence = self._bounded_text(payload.get("evidence", ""), "evidence", 10000)
        safe_payload = {
            "incident_id": incident_id,
            "stage": stage,
            "action_summary": self._bounded_text(payload.get("action_summary", ""), "action_summary", 1200, required=True),
            "handler": self.validate_scope(scope)[2],
            "occurred_at": _now(),
        }
        action = self.create("incident-actions", safe_payload, scope=scope)
        if evidence:
            with self._lock, self._connection:
                self._connection.execute(
                    "UPDATE incident_actions SET evidence_sha256=? WHERE id=?",
                    (_sha256(evidence), action["id"]),
                )
                if stage == "forensics":
                    tenant_id, project_id, user_id = self.validate_scope(scope)
                    now = _now()
                    self._connection.execute(
                        "INSERT INTO forensics_records(id, incident_id, evidence_type, evidence_digest, custody_summary, collected_at, tenant_id, project_id, created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            self._new_id("for"), incident_id, "digital_evidence_digest", _sha256(evidence),
                            "证据原文不落盘；由处置人保管原件，本系统仅记录摘要与时间。", now,
                            tenant_id, project_id, user_id, now, now,
                        ),
                    )
        status_by_stage = {"isolation": "contained", "eradication": "eradicated", "recovery": "recovered", "review": "closed"}
        if stage in status_by_stage:
            self.update("incidents", incident_id, {"status": status_by_stage[stage], "note": safe_payload["action_summary"]}, scope=scope)
        return self.get_record("incidents", incident_id, scope=scope)

    def submit_work_order_receipt(
        self,
        work_order_id: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        order = self.get_record("work-orders", work_order_id, scope=scope)
        summary = self._bounded_text(payload.get("receipt_summary", ""), "receipt_summary", 1500, required=True)
        evidence = self._bounded_text(payload.get("evidence", ""), "evidence", 10000)
        tenant_id, project_id, user_id = self.validate_scope(scope)
        now = _now()
        receipt_id = self._new_id("wrc")
        row = {
            "id": receipt_id,
            "work_order_id": work_order_id,
            "receipt_summary": summary,
            "evidence_sha256": _sha256(evidence) if evidence else "",
            "result": "submitted",
            "tenant_id": tenant_id,
            "project_id": project_id,
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._connection:
            self._insert("work_order_receipts", row)
            self._connection.execute(
                "UPDATE work_orders SET status='submitted', updated_at=? WHERE id=? AND tenant_id=? AND project_id=?",
                (now, work_order_id, tenant_id, project_id),
            )
            self._append_audit("receipt", "work-orders", work_order_id, user_id, {"previous_status": order.get("status"), "receipt_sha256": row["evidence_sha256"]}, tenant_id, project_id)
        return {"receipt": self._row_by_id("work_order_receipts", receipt_id), "work_order": self.get_record("work-orders", work_order_id, scope=scope)}

    def generate_report(
        self,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        report_type = self._bounded_text(payload.get("report_type", ""), "report_type", 32, required=True)
        if report_type not in {"security_test", "vulnerability", "daily", "weekly", "monthly", "inspection", "compliance"}:
            raise EnterpriseValidationError("报告类型无效")
        source_type = self._bounded_text(payload.get("source_type", report_type), "source_type", 32, required=True)
        source_id = self._bounded_text(payload.get("source_id", ""), "source_id", 96)
        period_start = self._date(payload.get("period_start", ""), "period_start")
        period_end = self._date(payload.get("period_end", ""), "period_end")
        title = self._bounded_text(payload.get("title", ""), "title", 180) or self._default_report_title(report_type)
        tenant_id, project_id, user_id = self.validate_scope(scope)
        content = self._report_content(report_type, source_id, scope, period_start, period_end)
        summary = content["summary"]
        with self._lock:
            version = int(
                self._connection.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM report_archives WHERE tenant_id=? AND project_id=? AND report_type=? AND source_type=? AND source_id=?",
                    (tenant_id, project_id, report_type, source_type, source_id),
                ).fetchone()[0]
            )
        content_json = _json(content)
        report = self.create(
            "reports",
            {
                "report_type": report_type,
                "source_type": source_type,
                "source_id": source_id,
                "title": title,
                "version": version,
                "template_id": self._template_for(report_type, tenant_id, project_id),
                "status": "generated",
                "period_start": period_start,
                "period_end": period_end,
                "summary_json": summary,
                "content_json": content,
                "content_sha256": _sha256(content_json),
            },
            scope=scope,
        )
        self._notify(
            title=f"报告已生成：{title}",
            body=f"版本 V{version} 已归档，可预览或导出。",
            severity="info",
            resource_type="reports",
            resource_id=str(report["id"]),
            scope=scope,
        )
        return report

    def export_report(
        self,
        report_id: str,
        export_format: str,
        *,
        scope: dict[str, str] | None = None,
    ) -> tuple[bytes, str, str]:
        report = self.get_record("reports", report_id, scope=scope)
        content = report.get("content_json")
        if not isinstance(content, dict):
            raise EnterpriseValidationError("报告内容无效")
        safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", str(report.get("title", "AegisGate_Report")))[:80] or "AegisGate_Report"
        if export_format == "docx":
            return self._build_docx(report, content), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", f"{safe_name}_V{report['version']}.docx"
        if export_format == "pdf":
            return self._build_pdf(report, content), "application/pdf", f"{safe_name}_V{report['version']}.pdf"
        if export_format in {"xlsx", "excel"}:
            return self._build_xlsx(report, content), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{safe_name}_V{report['version']}.xlsx"
        if export_format == "json":
            return json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8", f"{safe_name}_V{report['version']}.json"
        raise EnterpriseValidationError("导出格式仅支持 docx、pdf、xlsx 或 json")

    def export_collection(
        self,
        resource: str,
        export_format: str,
        *,
        scope: dict[str, str] | None = None,
    ) -> tuple[bytes, str, str]:
        result = self.list_records(resource, scope=scope, page=1, page_size=200, sort="created_at", order="asc")
        if export_format == "json":
            return json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8", f"aegisgate_{resource}.json"
        if export_format != "csv":
            raise EnterpriseValidationError("清单导出格式仅支持 csv 或 json")
        items = result["items"]
        columns = sorted({key for item in items for key in item if key != "related"})
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in items:
            writer.writerow({key: _json(value) if isinstance(value, (dict, list)) else value for key, value in item.items()})
        return b"\xef\xbb\xbf" + buffer.getvalue().encode("utf-8"), "text/csv; charset=utf-8", f"aegisgate_{resource}.csv"

    def bulk_import(
        self,
        resource: str,
        items: list[dict[str, Any]],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if resource not in {"assets", "iocs"}:
            raise EnterpriseValidationError("仅支持资产和 IOC 批量导入")
        if not isinstance(items, list) or not 1 <= len(items) <= 500:
            raise EnterpriseValidationError("批量导入必须包含 1 到 500 条记录")
        batch_sha256 = _sha256(_json(items))
        created: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append({"index": index, "error": "记录必须是对象"})
                continue
            try:
                created.append(self.create(resource, item, scope=scope))
            except (EnterpriseValidationError, EnterpriseConflictError) as exc:
                errors.append({"index": index, "error": str(exc)})
        return {
            "resource": resource,
            "received": len(items),
            "created": len(created),
            "failed": len(errors),
            "batch_sha256": batch_sha256,
            "items": created,
            "errors": errors[:50],
        }

    def import_payload(
        self,
        resource: str,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        items = payload.get("items")
        if isinstance(items, list):
            return self.bulk_import(resource, items, scope=scope)
        import_format = self._bounded_text(payload.get("format", ""), "format", 12, required=True).lower()
        content = payload.get("content")
        if not isinstance(content, str) or not content.strip() or len(content.encode("utf-8")) > 200_000:
            raise EnterpriseValidationError("导入内容为空或超过 200 KB")
        parsed: list[dict[str, Any]] = []
        if import_format == "csv":
            reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
            if not reader.fieldnames or len(reader.fieldnames) > 40:
                raise EnterpriseValidationError("CSV 表头无效")
            for row in reader:
                parsed.append({str(key).strip(): str(value or "").strip() for key, value in row.items() if key})
        elif import_format == "json":
            try:
                value = json.loads(content)
            except json.JSONDecodeError as exc:
                raise EnterpriseValidationError("JSON 导入格式无效") from exc
            if not isinstance(value, list):
                raise EnterpriseValidationError("JSON 导入内容必须是对象数组")
            parsed = value
        elif import_format in {"ndjson", "jsonl"}:
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EnterpriseValidationError("NDJSON 导入格式无效") from exc
                if not isinstance(value, dict):
                    raise EnterpriseValidationError("NDJSON 每行必须是对象")
                parsed.append(value)
        else:
            raise EnterpriseValidationError("导入格式仅支持 csv、json 或 ndjson")
        return self.bulk_import(resource, parsed, scope=scope)

    def set_asset_tags(
        self,
        asset_id: str,
        tag_ids: list[str],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        asset = self.get_record("assets", asset_id, scope=scope)
        if not isinstance(tag_ids, list) or len(tag_ids) > 50 or any(not isinstance(tag_id, str) or not _RECORD_ID.fullmatch(tag_id) for tag_id in tag_ids):
            raise EnterpriseValidationError("tag_ids 必须是最多 50 项的有效 ID 数组")
        tenant_id, project_id, user_id = self.validate_scope(scope)
        unique_ids = list(dict.fromkeys(tag_ids))
        with self._lock, self._connection:
            if unique_ids:
                placeholders = ",".join("?" for _ in unique_ids)
                found = self._connection.execute(
                    f"SELECT id FROM asset_tags WHERE tenant_id=? AND project_id=? AND id IN ({placeholders})",
                    (tenant_id, project_id, *unique_ids),
                ).fetchall()
                if {row["id"] for row in found} != set(unique_ids):
                    raise EnterpriseValidationError("存在不属于当前作用域的标签")
            self._connection.execute(
                "DELETE FROM asset_tag_links WHERE asset_id=? AND tenant_id=? AND project_id=?",
                (asset_id, tenant_id, project_id),
            )
            now = _now()
            for tag_id in unique_ids:
                self._connection.execute(
                    "INSERT INTO asset_tag_links(asset_id, tag_id, tenant_id, project_id, created_by, created_at) VALUES(?,?,?,?,?,?)",
                    (asset_id, tag_id, tenant_id, project_id, user_id, now),
                )
            self._append_audit("set_tags", "assets", asset_id, user_id, {"tag_ids": unique_ids, "asset_version": asset.get("version")}, tenant_id, project_id)
        return self.get_record("assets", asset_id, scope=scope)

    def set_role_asset_groups(
        self,
        role_id: str,
        group_ids: list[str],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.get_record("roles", role_id, scope=scope)
        if not isinstance(group_ids, list) or len(group_ids) > 100 or any(not isinstance(group_id, str) or not _RECORD_ID.fullmatch(group_id) for group_id in group_ids):
            raise EnterpriseValidationError("group_ids 必须是最多 100 项的有效 ID 数组")
        tenant_id, project_id, user_id = self.validate_scope(scope)
        unique_ids = list(dict.fromkeys(group_ids))
        with self._lock, self._connection:
            if unique_ids:
                placeholders = ",".join("?" for _ in unique_ids)
                found = self._connection.execute(
                    f"SELECT id FROM asset_groups WHERE tenant_id=? AND project_id=? AND id IN ({placeholders})",
                    (tenant_id, project_id, *unique_ids),
                ).fetchall()
                if {row["id"] for row in found} != set(unique_ids):
                    raise EnterpriseValidationError("存在不属于当前作用域的资产组")
            self._connection.execute(
                "DELETE FROM role_asset_groups WHERE role_id=? AND tenant_id=? AND project_id=?",
                (role_id, tenant_id, project_id),
            )
            now = _now()
            for group_id in unique_ids:
                self._connection.execute(
                    "INSERT INTO role_asset_groups(role_id, asset_group_id, tenant_id, project_id, created_by, created_at) VALUES(?,?,?,?,?,?)",
                    (role_id, group_id, tenant_id, project_id, user_id, now),
                )
            self._append_audit("set_asset_scope", "roles", role_id, user_id, {"asset_group_ids": unique_ids}, tenant_id, project_id)
        return self.get_record("roles", role_id, scope=scope)

    def record_login(
        self,
        *,
        success: bool,
        source_ip: str,
        user_agent: str,
        scope: dict[str, str] | None = None,
        reason: str = "",
    ) -> None:
        try:
            tenant_id, project_id, user_id = self.validate_scope(scope)
        except EnterpriseValidationError:
            tenant_id, project_id, user_id = DEFAULT_TENANT_ID, DEFAULT_PROJECT_ID, DEFAULT_USER_ID
        safe_reason = self._bounded_text(reason, "reason", 120)
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO login_logs(id, user_id, success, source_ip_hash, user_agent_hash, reason, tenant_id, project_id, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (self._new_id("log"), user_id, int(success), _sha256(source_ip), _sha256(user_agent), safe_reason, tenant_id, project_id, _now()),
            )

    def list_login_logs(
        self,
        *,
        scope: dict[str, str] | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        if page < 1 or not 1 <= page_size <= 200:
            raise EnterpriseValidationError("分页参数无效")
        with self._lock:
            total = int(self._connection.execute("SELECT COUNT(*) FROM login_logs WHERE tenant_id=? AND project_id=?", (tenant_id, project_id)).fetchone()[0])
            rows = self._connection.execute(
                "SELECT id, user_id, success, source_ip_hash, user_agent_hash, reason, created_at FROM login_logs WHERE tenant_id=? AND project_id=? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (tenant_id, project_id, page_size, (page - 1) * page_size),
            ).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size}

    def dashboard(self, *, scope: dict[str, str] | None = None) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        with self._lock:
            counts = {
                "assets": self._scoped_count("assets", scope),
                "online_assets": self._scoped_count("assets", scope, "status='online'"),
                "open_alerts": self._scoped_count("alerts", scope, "status IN ('open','in_progress')"),
                "critical_alerts": self._scoped_count("alerts", scope, "status IN ('open','in_progress') AND severity='critical'"),
                "open_vulnerabilities": self._scoped_count("vulnerabilities", scope, "status NOT IN ('closed','accepted')"),
                "overdue_vulnerabilities": self._scoped_count("vulnerabilities", scope, "deadline<>'' AND deadline<? AND status NOT IN ('closed','accepted')", (_today(),)),
                "active_incidents": self._scoped_count("incidents", scope, "status<>'closed'"),
                "pending_inspections": self._scoped_count("inspection-tasks", scope, "status IN ('pending','scheduled','running')"),
                "open_work_orders": self._scoped_count("work-orders", scope, "status NOT IN ('verified','closed')"),
                "reports": self._scoped_count("reports", scope),
            }
            alerts_by_severity = self._scoped_group_count("alerts", "severity", scope)
            vulnerabilities_by_status = self._scoped_group_count("vulnerabilities", "status", scope)
            events_by_status = self._scoped_group_count("incidents", "status", scope)
            asset_visibility, asset_visibility_params = self._visibility_clause("assets", scope, table_prefix="a")
            asset_where = "a.tenant_id=? AND a.project_id=?"
            asset_query_params: list[Any] = [tenant_id, project_id]
            if asset_visibility:
                asset_where += f" AND {asset_visibility}"
                asset_query_params.extend(asset_visibility_params)
            risk_assets = self._connection.execute(
                f"""
                SELECT a.id, a.name, a.business_level,
                       SUM(CASE WHEN v.status NOT IN ('closed','accepted') THEN v.risk_priority ELSE 0 END) AS risk_score,
                       COUNT(CASE WHEN v.status NOT IN ('closed','accepted') THEN 1 END) AS vulnerability_count
                FROM assets a LEFT JOIN vulnerabilities v
                  ON v.asset_id=a.id AND v.tenant_id=a.tenant_id AND v.project_id=a.project_id
                WHERE {asset_where}
                GROUP BY a.id, a.name, a.business_level
                ORDER BY risk_score DESC, vulnerability_count DESC, a.name ASC LIMIT 8
                """,
                asset_query_params,
            ).fetchall()
            alert_trend = self._daily_trend("alerts", scope, days=14)
            high_alert_trend = self._daily_trend("alerts", scope, days=14, extra="severity IN ('critical','high')")
            vulnerability_trend = self._daily_trend("vulnerabilities", scope, days=14)
            closed_vulnerability_trend = self._daily_trend("vulnerabilities", scope, days=14, date_field="closed_at", extra="closed_at<>''")
        completed = self._scoped_count("vulnerabilities", scope, "status='closed'")
        completion_total = counts["open_vulnerabilities"] + completed
        trend_dates = [(date.today() - timedelta(days=offset)).isoformat() for offset in range(13, -1, -1)]
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _now(),
            "scope": {"tenant_id": tenant_id, "project_id": project_id},
            "counts": counts,
            "alert_severity": alerts_by_severity,
            "vulnerability_status": vulnerabilities_by_status,
            "incident_status": events_by_status,
            "trends": {
                "alerts": [{"date": item, "total": alert_trend.get(item, 0), "high_risk": high_alert_trend.get(item, 0)} for item in trend_dates],
                "vulnerabilities": [{"date": item, "opened": vulnerability_trend.get(item, 0), "closed": closed_vulnerability_trend.get(item, 0)} for item in trend_dates],
            },
            "remediation_completion_rate": round(completed / completion_total * 100, 2) if completion_total else 100.0,
            "high_risk_assets": [dict(row) for row in risk_assets],
            "audit_integrity": self.verify_audit(scope=scope),
            "data_mode": "runtime_with_demo_seed",
        }

    def todos(self, *, scope: dict[str, str] | None = None, limit: int = 100) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        limit = max(1, min(int(limit), 200))
        queries = [
            ("alert", "alerts", "alerts", "status IN ('open','in_progress')", "title", "severity", "status", "updated_at", ""),
            ("vulnerability", "vulnerabilities", "vulnerabilities", "status NOT IN ('closed','accepted')", "title", "severity", "status", "deadline", "deadline"),
            ("incident", "incidents", "incidents", "status<>'closed'", "title", "severity", "status", "deadline", "deadline"),
            ("inspection", "inspection-tasks", "inspection_tasks", "status IN ('pending','scheduled','running')", "name", "'medium'", "status", "due_at", "due_at"),
            ("work_order", "work-orders", "work_orders", "status NOT IN ('verified','closed')", "title", "priority", "status", "deadline", "deadline"),
        ]
        items: list[dict[str, Any]] = []
        with self._lock:
            for todo_type, resource, table, where, title, severity, status, time_field, deadline_field in queries:
                deadline_expr = deadline_field if deadline_field else "''"
                visibility, visibility_params = self._visibility_clause(resource, scope)
                visibility_sql = f" AND {visibility}" if visibility else ""
                rows = self._connection.execute(
                    f"SELECT id, {title} AS title, {severity} AS severity, {status} AS status, {time_field} AS sort_time, {deadline_expr} AS deadline FROM {table} WHERE tenant_id=? AND project_id=? AND {where}{visibility_sql} LIMIT ?",
                    (tenant_id, project_id, *visibility_params, limit),
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    item["type"] = todo_type
                    item["overdue"] = self._is_overdue(str(item.get("deadline", "")), str(item.get("status", "")))
                    items.append(item)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        items.sort(key=lambda item: (not item["overdue"], severity_order.get(str(item.get("severity", "medium")), 3), str(item.get("deadline") or "9999-12-31"), str(item.get("title", ""))))
        return {"generated_at": _now(), "items": items[:limit], "total": len(items), "overdue": sum(bool(item["overdue"]) for item in items), "scope": {"tenant_id": tenant_id, "project_id": project_id}}

    def settings(self, *, scope: dict[str, str] | None = None) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, category, setting_key, value_json, sensitive, version, updated_at FROM system_settings WHERE tenant_id=? AND project_id=? ORDER BY category, setting_key",
                (tenant_id, project_id),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if item["sensitive"]:
                item["value"] = {"configured": bool(item["value_json"])}
            else:
                item["value"] = self._decode_json(item["value_json"], {})
            item.pop("value_json", None)
            items.append(item)
        return {"items": items, "total": len(items)}

    def update_setting(
        self,
        payload: dict[str, Any],
        *,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        tenant_id, project_id, user_id = self.validate_scope(scope)
        category = self._bounded_text(payload.get("category", ""), "category", 48, required=True)
        key = self._bounded_text(payload.get("key", ""), "key", 64, required=True)
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", category) or not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", key):
            raise EnterpriseValidationError("配置分类或键格式无效")
        value = payload.get("value")
        encoded = _json(value)
        if len(encoded) > 8000:
            raise EnterpriseValidationError("配置值过大")
        sensitive = bool(payload.get("sensitive", False))
        if sensitive and payload.get("confirm") != "CONFIRM":
            raise EnterpriseValidationError("敏感配置变更需要二次确认")
        now = _now()
        with self._lock, self._connection:
            current = self._connection.execute(
                "SELECT id, version FROM system_settings WHERE tenant_id=? AND project_id=? AND category=? AND setting_key=?",
                (tenant_id, project_id, category, key),
            ).fetchone()
            if current:
                record_id = str(current["id"])
                version = int(current["version"]) + 1
                self._connection.execute(
                    "UPDATE system_settings SET value_json=?, sensitive=?, version=?, updated_at=? WHERE id=?",
                    (encoded, int(sensitive), version, now, record_id),
                )
            else:
                record_id = self._new_id("cfg")
                version = 1
                self._connection.execute(
                    "INSERT INTO system_settings(id, category, setting_key, value_json, sensitive, version, tenant_id, project_id, created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (record_id, category, key, encoded, int(sensitive), version, tenant_id, project_id, user_id, now, now),
                )
            self._append_audit("configure", "system-settings", record_id, user_id, {"category": category, "key": key, "version": version, "value_sha256": _sha256(encoded), "sensitive": sensitive}, tenant_id, project_id)
        return {"id": record_id, "category": category, "key": key, "version": version, "sensitive": sensitive, "updated_at": now}

    def audit_records(
        self,
        *,
        scope: dict[str, str] | None = None,
        page: int = 1,
        page_size: int = 50,
        resource_type: str = "",
    ) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        if page < 1 or not 1 <= page_size <= 200:
            raise EnterpriseValidationError("分页参数无效")
        clauses = ["tenant_id=?", "project_id=?"]
        params: list[Any] = [tenant_id, project_id]
        if resource_type:
            clauses.append("resource_type=?")
            params.append(self._bounded_text(resource_type, "resource_type", 64, required=True))
        where = " AND ".join(clauses)
        with self._lock:
            total = int(self._connection.execute(f"SELECT COUNT(*) FROM operation_audit WHERE {where}", params).fetchone()[0])
            rows = self._connection.execute(
                f"SELECT * FROM operation_audit WHERE {where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (*params, page_size, (page - 1) * page_size),
            ).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size, "integrity": self.verify_audit(scope=scope)}

    def verify_audit(self, *, scope: dict[str, str] | None = None) -> dict[str, Any]:
        tenant_id, project_id, _ = self.validate_scope(scope)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM operation_audit WHERE tenant_id=? AND project_id=? ORDER BY created_at ASC, rowid ASC",
                (tenant_id, project_id),
            ).fetchall()
        expected = "0" * 64
        for index, row in enumerate(rows, start=1):
            item = dict(row)
            actual = item.pop("event_hash", "")
            if item.get("prev_hash") != expected or _sha256(_json(item)) != actual:
                return {"valid": False, "entries": index, "message": "审计链校验失败", "tail_hash": expected}
            expected = actual
        return {"valid": True, "entries": len(rows), "tail_hash": expected}

    def _validate_payload(self, resource: str, payload: dict[str, Any], *, creating: bool) -> dict[str, Any]:
        config = self._resource(resource)
        values: dict[str, Any] = {}
        for field in config["fields"]:
            if field not in payload:
                continue
            value = payload[field]
            if field in config.get("json_fields", ()):
                if field in {"summary_json", "content_json"}:
                    if not isinstance(value, dict):
                        raise EnterpriseValidationError(f"{field} 必须是对象")
                    encoded = _json(value)
                elif field == "sections_json" and isinstance(value, dict):
                    encoded = _json(value)
                else:
                    encoded = self._json_array(value, field)
                values[field] = encoded
            elif field in {"port", "target_port", "repeat_count", "confidence", "progress", "priority", "version"} and not (
                resource == "work-orders" and field == "priority"
            ):
                try:
                    number = int(value)
                except (TypeError, ValueError) as exc:
                    raise EnterpriseValidationError(f"{field} 必须是整数") from exc
                limits = {
                    "port": (0, 65535), "target_port": (1, 65535), "repeat_count": (1, 1_000_000),
                    "confidence": (0, 100), "progress": (0, 100), "priority": (1, 10000), "version": (1, 1_000_000),
                }
                low, high = limits[field]
                if not low <= number <= high:
                    raise EnterpriseValidationError(f"{field} 超出允许范围")
                values[field] = number
            elif field in {"enabled", "builtin"}:
                if not isinstance(value, (bool, int)):
                    raise EnterpriseValidationError(f"{field} 必须是布尔值")
                values[field] = int(bool(value))
            elif field in {"cvss", "importance_weight"}:
                try:
                    number = float(value)
                except (TypeError, ValueError) as exc:
                    raise EnterpriseValidationError(f"{field} 必须是数值") from exc
                if field == "cvss" and not 0 <= number <= 10:
                    raise EnterpriseValidationError("cvss 必须在 0 到 10 之间")
                if field == "importance_weight" and not 0.5 <= number <= 2:
                    raise EnterpriseValidationError("importance_weight 必须在 0.5 到 2 之间")
                values[field] = number
            elif field in {"deadline", "start_date", "end_date", "period_start", "period_end", "expires_at"}:
                values[field] = self._date(value, field)
            else:
                maximum = 2000 if field in {"description", "context_summary", "principle", "poc_reference", "reproduction_placeholder", "risk_impact", "remediation", "scope_summary", "safe_procedure", "objective", "expected_result", "process_summary", "impact_scope", "review_summary", "action_summary", "actual_summary", "requirement_summary", "receipt_summary", "remediation_plan", "summary"} else 253
                values[field] = self._bounded_text(value, field, maximum)
        if creating:
            for field in config.get("required", ()):
                if field not in values or values[field] in ("", [], None):
                    raise EnterpriseValidationError(f"{field} 不能为空")
            if "status" in config.get("fields", ()) and "status" not in values:
                values["status"] = config.get("default_status", "open")
        if "status" in values and values["status"] not in config.get("statuses", (values["status"],)):
            raise EnterpriseValidationError("状态值无效")
        if "severity" in values and values["severity"] not in SEVERITIES:
            raise EnterpriseValidationError("风险级别无效")
        if "cve" in values and values["cve"]:
            values["cve"] = values["cve"].upper()
            if not _CVE.fullmatch(values["cve"]):
                raise EnterpriseValidationError("CVE 编号格式无效")
        if resource == "assets":
            values.setdefault("business_level", "normal")
            values.setdefault("importance_weight", ASSET_WEIGHT.get(str(values.get("business_level", "normal")), 1.0))
            values.setdefault("port", 0)
            if "status" in values and values["status"] not in {"online", "offline", "archived"}:
                raise EnterpriseValidationError("资产状态无效")
        if resource == "alerts":
            values.setdefault("repeat_count", 1)
        if resource == "vulnerabilities":
            values.setdefault("cvss", 0.0)
            values.setdefault("reproduction_placeholder", "仅限授权环境，由测试人员补充复现记录。")
            if "poc_reference" in values and values["poc_reference"]:
                values["poc_reference"] = self._safe_preview(values["poc_reference"], 500)
        if resource == "discovery-tasks" and creating and not values.get("authorization_ticket"):
            raise EnterpriseValidationError("主动探测任务必须绑定授权工单")
        if resource == "scan-tasks":
            if values.get("intensity", "safe") not in {"safe", "standard"}:
                raise EnterpriseValidationError("扫描强度仅支持 safe 或 standard")
            if values.get("scan_type", "configuration_review") not in {"configuration_review", "dependency_inventory", "header_baseline", "tls_baseline"}:
                raise EnterpriseValidationError("扫描类型不在安全检查白名单内")
        if resource == "alert-rules" and "action" in values and values["action"] not in {"keep", "suppress_duplicate", "notify"}:
            raise EnterpriseValidationError("告警规则动作无效")
        if resource == "iocs" and creating:
            indicator_type = str(values.get("type", ""))
            indicator = str(values.get("value", ""))
            if indicator_type not in {"ip", "domain", "url", "sha256"}:
                raise EnterpriseValidationError("IOC 类型无效")
            try:
                if indicator_type == "ip":
                    ipaddress.ip_address(indicator)
                elif indicator_type == "domain":
                    if "." not in indicator or not _HOSTNAME.fullmatch(indicator):
                        raise ValueError
                elif indicator_type == "url":
                    parsed = urlparse(indicator)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                        raise ValueError
                elif not re.fullmatch(r"[0-9a-fA-F]{64}", indicator):
                    raise ValueError
            except ValueError as exc:
                raise EnterpriseValidationError("IOC 值与类型不匹配") from exc
        if resource == "allowlist" and creating:
            entry_type = str(values.get("entry_type", ""))
            entry_value = str(values.get("value", ""))
            try:
                if entry_type == "ip":
                    ipaddress.ip_address(entry_value)
                elif entry_type == "domain" and "." in entry_value and _HOSTNAME.fullmatch(entry_value):
                    pass
                else:
                    raise ValueError
            except ValueError as exc:
                raise EnterpriseValidationError("黑白名单值与类型不匹配") from exc
        return values

    def _create_alert(self, values: dict[str, Any], payload: dict[str, Any], scope: dict[str, str] | None) -> dict[str, Any]:
        tenant_id, project_id, user_id = self.validate_scope(scope)
        payload_text = self._bounded_text(payload.get("attack_payload", payload.get("payload", "")), "attack_payload", 10000)
        raw_log = self._bounded_text(payload.get("raw_log", ""), "raw_log", 20000)
        values["payload_preview"] = self._safe_preview(payload_text)
        values["payload_sha256"] = _sha256(payload_text) if payload_text else ""
        values["raw_log_sha256"] = _sha256(raw_log) if raw_log else ""
        values["fingerprint"] = _sha256(_json({
            "tenant_id": tenant_id,
            "project_id": project_id,
            "source": values.get("source", ""),
            "attack_type": values.get("attack_type", ""),
            "source_ip": values.get("source_ip", ""),
            "target_asset_id": values.get("target_asset_id", ""),
        }))
        now = _now()
        with self._lock, self._connection:
            applied_rules = self._matching_alert_rules(values, tenant_id, project_id)
            existing = self._connection.execute(
                "SELECT id, repeat_count FROM alerts WHERE tenant_id=? AND project_id=? AND fingerprint=? AND status IN ('open','in_progress') ORDER BY created_at DESC LIMIT 1",
                (tenant_id, project_id, values["fingerprint"]),
            ).fetchone()
            if existing:
                repeat_count = min(1_000_000, int(existing["repeat_count"]) + int(values.get("repeat_count", 1)))
                self._connection.execute(
                    "UPDATE alerts SET repeat_count=?, updated_at=? WHERE id=?",
                    (repeat_count, now, existing["id"]),
                )
                self._append_audit("deduplicate", "alerts", str(existing["id"]), user_id, {"repeat_count": repeat_count, "fingerprint": values["fingerprint"], "applied_rule_ids": [rule["id"] for rule in applied_rules]}, tenant_id, project_id)
                result = self.get_record("alerts", str(existing["id"]), scope=scope)
                result["deduplicated"] = True
                result["applied_rules"] = applied_rules
                return result
            self._insert("alerts", values)
            self._append_audit("create", "alerts", str(values["id"]), user_id, {**{key: value for key, value in values.items() if key not in {"payload_preview"}}, "applied_rule_ids": [rule["id"] for rule in applied_rules]}, tenant_id, project_id)
            if values.get("severity") == "critical":
                self._notify("高危告警待处置", str(values.get("title", "")), "critical", "alerts", str(values["id"]), scope, commit=False)
            elif any(rule["action"] == "notify" for rule in applied_rules):
                self._notify("告警规则触发通知", str(values.get("title", "")), str(values.get("severity", "info")), "alerts", str(values["id"]), scope, commit=False)
        result = self.get_record("alerts", str(values["id"]), scope=scope)
        result["applied_rules"] = applied_rules
        return result

    def _matching_alert_rules(
        self,
        values: dict[str, Any],
        tenant_id: str,
        project_id: str,
    ) -> list[dict[str, str]]:
        rows = self._connection.execute(
            "SELECT id, name, source_pattern, attack_type_pattern, minimum_severity, action FROM alert_filter_rules WHERE tenant_id=? AND project_id=? AND enabled=1 ORDER BY priority ASC, created_at ASC",
            (tenant_id, project_id),
        ).fetchall()
        source = str(values.get("source", "")).casefold()
        attack_type = str(values.get("attack_type", "")).casefold()
        severity_weight = SEVERITY_WEIGHT.get(str(values.get("severity", "info")), 1.0)
        matched: list[dict[str, str]] = []
        for row in rows:
            source_pattern = str(row["source_pattern"] or "").casefold()
            attack_pattern = str(row["attack_type_pattern"] or "").casefold()
            minimum = SEVERITY_WEIGHT.get(str(row["minimum_severity"] or "info"), 1.0)
            if severity_weight < minimum:
                continue
            if source_pattern and source_pattern not in source:
                continue
            if attack_pattern and attack_pattern not in attack_type:
                continue
            matched.append({"id": str(row["id"]), "name": str(row["name"]), "action": str(row["action"])})
        return matched[:20]

    def _insert(self, table: str, values: dict[str, Any]) -> None:
        if not re.fullmatch(r"[a-z_]+", table):
            raise EnterpriseValidationError("表名无效")
        columns = ",".join(values)
        placeholders = ",".join("?" for _ in values)
        self._connection.execute(
            f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values())
        )

    def _append_audit(
        self,
        operation: str,
        resource_type: str,
        resource_id: str,
        actor: str,
        changes: dict[str, Any],
        tenant_id: str,
        project_id: str,
    ) -> None:
        previous = self._connection.execute(
            "SELECT event_hash FROM operation_audit WHERE tenant_id=? AND project_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (tenant_id, project_id),
        ).fetchone()
        prev_hash = str(previous["event_hash"]) if previous else "0" * 64
        safe_changes = {
            key: value
            for key, value in changes.items()
            if key not in {"attack_payload", "raw_log", "evidence", "credential", "password", "token", "value_json", "content_json"}
        }
        change_summary = self._safe_preview(_json(safe_changes), 1000)
        event = {
            "id": self._new_id("aud"),
            "operation": operation,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "actor": actor,
            "change_summary": change_summary,
            "change_sha256": _sha256(_json(changes)),
            "prev_hash": prev_hash,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "created_at": _now(),
        }
        event["event_hash"] = _sha256(_json(event))
        self._connection.execute(
            "INSERT INTO operation_audit(id, operation, resource_type, resource_id, actor, change_summary, change_sha256, prev_hash, event_hash, tenant_id, project_id, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["id"], event["operation"], event["resource_type"], event["resource_id"],
                event["actor"], event["change_summary"], event["change_sha256"], event["prev_hash"],
                event["event_hash"], event["tenant_id"], event["project_id"], event["created_at"],
            ),
        )

    def _asset_history(
        self,
        asset_id: str,
        action: str,
        summary: str,
        version: int,
        scope: dict[str, str] | None,
        *,
        commit: bool,
    ) -> None:
        tenant_id, project_id, user_id = self.validate_scope(scope)
        now = _now()
        safe_summary = self._safe_preview(summary, 500)
        self._connection.execute(
            "INSERT INTO asset_history(id, asset_id, action, change_summary, change_sha256, version, tenant_id, project_id, created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (self._new_id("ash"), asset_id, action, safe_summary, _sha256(summary), version, tenant_id, project_id, user_id, now, now),
        )
        if commit:
            self._connection.commit()

    def _insert_alert_note(self, alert_id: str, note: str, note_type: str, scope: dict[str, str] | None) -> None:
        tenant_id, project_id, user_id = self.validate_scope(scope)
        now = _now()
        self._connection.execute(
            "INSERT INTO alert_notes(id, alert_id, note, note_sha256, note_type, tenant_id, project_id, created_by, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self._new_id("aln"), alert_id, self._safe_preview(note, 500), _sha256(note), note_type, tenant_id, project_id, user_id, now, now),
        )

    def _post_create(self, resource: str, values: dict[str, Any], scope: dict[str, str] | None) -> None:
        if resource == "vulnerabilities" and values.get("severity") in {"critical", "high"}:
            self._notify("高风险漏洞待整改", str(values.get("title", "")), str(values.get("severity")), "vulnerabilities", str(values["id"]), scope, commit=False)
        if resource == "baseline-findings":
            tenant_id, project_id, user_id = self.validate_scope(scope)
            now = _now()
            deadline = date.today().replace(day=date.today().day).isoformat()
            work_order = {
                "id": self._new_id("wko"),
                "order_type": "baseline_remediation",
                "source_type": "baseline-findings",
                "source_id": values["id"],
                "title": f"基线整改：{values.get('actual_summary', '')[:80]}",
                "assignee": user_id,
                "department": "",
                "priority": values.get("severity", "medium"),
                "deadline": deadline,
                "status": "pending",
                "requirement_summary": "按基线规则完成整改并提交不含敏感原文的回执。",
                "tenant_id": tenant_id,
                "project_id": project_id,
                "created_by": user_id,
                "created_at": now,
                "updated_at": now,
            }
            self._insert("work_orders", work_order)
        if resource == "test-projects":
            tenant_id, project_id, user_id = self.validate_scope(scope)
            self._insert_builtin_test_cases(
                str(values["id"]),
                {"tenant_id": tenant_id, "project_id": project_id, "user_id": user_id},
            )

    def _notify(
        self,
        title: str,
        body: str,
        severity: str,
        resource_type: str,
        resource_id: str,
        scope: dict[str, str] | None,
        *,
        commit: bool = True,
    ) -> None:
        tenant_id, project_id, user_id = self.validate_scope(scope)
        now = _now()
        row = {
            "id": self._new_id("ntf"),
            "channel": "in_app",
            "severity": severity if severity in SEVERITIES else "info",
            "title": self._safe_preview(title, 160),
            "body": self._safe_preview(body, 500),
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": "unread",
            "recipient": user_id,
            "read_at": "",
            "tenant_id": tenant_id,
            "project_id": project_id,
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
        }
        self._insert("notifications", row)
        if commit:
            self._connection.commit()

    def _related(self, resource: str, record_id: str, tenant_id: str, project_id: str) -> dict[str, Any]:
        relations: dict[str, list[tuple[str, str]]] = {
            "assets": [("asset_history", "asset_id")],
            "alerts": [("alert_notes", "alert_id")],
            "vulnerabilities": [("retest_records", "vulnerability_id"), ("remediation_orders", "vulnerability_id")],
            "test-projects": [("test_cases", "project_id_ref"), ("test_records", "project_id_ref")],
            "incidents": [("incident_actions", "incident_id"), ("incident_links", "incident_id"), ("forensics_records", "incident_id")],
            "work-orders": [("work_order_receipts", "work_order_id")],
        }
        result: dict[str, Any] = {}
        with self._lock:
            for table, field in relations.get(resource, []):
                rows = self._connection.execute(
                    f"SELECT * FROM {table} WHERE {field}=? AND tenant_id=? AND project_id=? ORDER BY created_at DESC LIMIT 100",
                    (record_id, tenant_id, project_id),
                ).fetchall()
                result[table] = [self._decode_plain_row(row) for row in rows]
            if resource == "assets":
                rows = self._connection.execute(
                    "SELECT t.id, t.name, t.color FROM asset_tags t JOIN asset_tag_links l ON l.tag_id=t.id WHERE l.asset_id=? AND l.tenant_id=? AND l.project_id=? ORDER BY t.name",
                    (record_id, tenant_id, project_id),
                ).fetchall()
                result["asset_tags"] = [dict(row) for row in rows]
            if resource == "roles":
                rows = self._connection.execute(
                    "SELECT g.id, g.name, g.business_level FROM asset_groups g JOIN role_asset_groups r ON r.asset_group_id=g.id WHERE r.role_id=? AND r.tenant_id=? AND r.project_id=? ORDER BY g.name",
                    (record_id, tenant_id, project_id),
                ).fetchall()
                result["asset_groups"] = [dict(row) for row in rows]
        return result

    def _decode_row(self, resource: str, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        for field in RESOURCE_CONFIG[resource].get("json_fields", ()):
            default: Any = [] if field != "summary_json" and field != "content_json" else {}
            result[field] = self._decode_json(result.get(field), default)
        return result

    def _decode_plain_row(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        for key, value in list(result.items()):
            if key.endswith("_json") and isinstance(value, str):
                result[key] = self._decode_json(value, [])
        return result

    @staticmethod
    def _decode_json(value: Any, default: Any) -> Any:
        if not isinstance(value, str):
            return default
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default

    def _row_by_id(self, table: str, record_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone()
        if not row:
            raise EnterpriseNotFoundError("记录不存在")
        return self._decode_plain_row(row)

    def _count(self, table: str, tenant_id: str, project_id: str, extra: str = "", extra_params: tuple[Any, ...] = ()) -> int:
        sql = f"SELECT COUNT(*) FROM {table} WHERE tenant_id=? AND project_id=?"
        if extra:
            sql += f" AND {extra}"
        return int(self._connection.execute(sql, (tenant_id, project_id, *extra_params)).fetchone()[0])

    def _group_count(self, table: str, field: str, tenant_id: str, project_id: str) -> dict[str, int]:
        rows = self._connection.execute(
            f"SELECT {field} AS value, COUNT(*) AS count FROM {table} WHERE tenant_id=? AND project_id=? GROUP BY {field}",
            (tenant_id, project_id),
        ).fetchall()
        return {str(row["value"]): int(row["count"]) for row in rows}

    def _scoped_count(
        self,
        resource: str,
        scope: dict[str, str] | None,
        extra: str = "",
        extra_params: tuple[Any, ...] = (),
    ) -> int:
        config = self._resource(resource)
        tenant_id, project_id, _ = self.validate_scope(scope)
        clauses = ["tenant_id=?", "project_id=?"]
        params: list[Any] = [tenant_id, project_id]
        if extra:
            clauses.append(extra)
            params.extend(extra_params)
        visibility, visibility_params = self._visibility_clause(resource, scope)
        if visibility:
            clauses.append(visibility)
            params.extend(visibility_params)
        return int(
            self._connection.execute(
                f"SELECT COUNT(*) FROM {config['table']} WHERE {' AND '.join(clauses)}",
                params,
            ).fetchone()[0]
        )

    def _scoped_group_count(
        self,
        resource: str,
        field: str,
        scope: dict[str, str] | None,
    ) -> dict[str, int]:
        config = self._resource(resource)
        if field not in set(config["fields"]):
            raise EnterpriseValidationError("分组字段无效")
        tenant_id, project_id, _ = self.validate_scope(scope)
        clauses = ["tenant_id=?", "project_id=?"]
        params: list[Any] = [tenant_id, project_id]
        visibility, visibility_params = self._visibility_clause(resource, scope)
        if visibility:
            clauses.append(visibility)
            params.extend(visibility_params)
        rows = self._connection.execute(
            f"SELECT {field} AS value, COUNT(*) AS count FROM {config['table']} "
            f"WHERE {' AND '.join(clauses)} GROUP BY {field}",
            params,
        ).fetchall()
        return {str(row["value"]): int(row["count"]) for row in rows}

    def _daily_trend(
        self,
        resource: str,
        scope: dict[str, str] | None,
        *,
        days: int,
        date_field: str = "created_at",
        extra: str = "",
    ) -> dict[str, int]:
        config = self._resource(resource)
        allowed_date_fields = {"created_at", "updated_at", "closed_at", "last_run_at"}
        if date_field not in allowed_date_fields:
            raise EnterpriseValidationError("趋势日期字段无效")
        start = (date.today() - timedelta(days=max(1, min(days, 90)) - 1)).isoformat()
        tenant_id, project_id, _ = self.validate_scope(scope)
        clauses = ["tenant_id=?", "project_id=?", f"substr({date_field},1,10)>=?"]
        params: list[Any] = [tenant_id, project_id, start]
        if extra:
            clauses.append(extra)
        visibility, visibility_params = self._visibility_clause(resource, scope)
        if visibility:
            clauses.append(visibility)
            params.extend(visibility_params)
        rows = self._connection.execute(
            f"SELECT substr({date_field},1,10) AS day, COUNT(*) AS count FROM {config['table']} "
            f"WHERE {' AND '.join(clauses)} GROUP BY day ORDER BY day",
            params,
        ).fetchall()
        return {str(row["day"]): int(row["count"]) for row in rows if row["day"]}

    @staticmethod
    def _is_overdue(deadline: str, status: str) -> bool:
        if not deadline or status in {"closed", "verified", "accepted", "completed", "archived"}:
            return False
        try:
            return date.fromisoformat(deadline) < date.today()
        except ValueError:
            return False

    def _vulnerability_priority(self, values: dict[str, Any], tenant_id: str, project_id: str) -> float:
        asset_weight = 1.0
        asset_id = str(values.get("asset_id", ""))
        if asset_id:
            row = self._connection.execute(
                "SELECT importance_weight FROM assets WHERE id=? AND tenant_id=? AND project_id=?",
                (asset_id, tenant_id, project_id),
            ).fetchone()
            if row:
                asset_weight = float(row["importance_weight"])
        return self._risk_priority(str(values.get("severity", "medium")), float(values.get("cvss", 0)), asset_weight)

    @staticmethod
    def _validate_transition(resource: str, current: str, target: str) -> None:
        transitions = {
            "alerts": {"open": {"in_progress", "closed", "false_positive"}, "in_progress": {"closed", "false_positive", "open"}, "false_positive": {"open"}, "closed": {"open"}},
            "vulnerabilities": {"pending_fix": {"risk_confirmed", "accepted"}, "risk_confirmed": {"fixing", "accepted"}, "fixing": {"retest", "accepted"}, "retest": {"closed", "fixing"}, "closed": {"fixing"}, "accepted": {"risk_confirmed"}},
            "incidents": {"open": {"contained", "closed"}, "contained": {"eradicated", "open"}, "eradicated": {"recovered", "contained"}, "recovered": {"closed", "eradicated"}, "closed": {"open"}},
            "work-orders": {"pending": {"in_progress", "closed"}, "in_progress": {"submitted", "pending"}, "submitted": {"verified", "in_progress"}, "verified": {"closed", "in_progress"}, "closed": {"in_progress"}},
        }
        if resource in transitions and target != current and target not in transitions[resource].get(current, set()):
            raise EnterpriseValidationError(f"不允许从 {current} 直接流转到 {target}")

    @staticmethod
    def _extract_host(address: str) -> str:
        candidate = address.strip()
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname or candidate.split(":", 1)[0]
        if not host or len(host) > 253 or not _HOSTNAME.fullmatch(host):
            try:
                socket.inet_pton(socket.AF_INET, host)
            except OSError as exc:
                raise EnterpriseValidationError("资产地址无法用于单点连通性检查") from exc
        return host

    def _template_for(self, report_type: str, tenant_id: str, project_id: str) -> str:
        row = self._connection.execute(
            "SELECT id FROM report_templates WHERE tenant_id=? AND project_id=? AND report_type=? AND enabled=1 ORDER BY version DESC LIMIT 1",
            (tenant_id, project_id, report_type),
        ).fetchone()
        return str(row["id"]) if row else ""

    @staticmethod
    def _default_report_title(report_type: str) -> str:
        labels = {
            "security_test": "安全测试报告", "vulnerability": "漏洞挖掘与整改报告",
            "daily": "安全运营日报", "weekly": "安全运营周报", "monthly": "安全运营月报",
            "inspection": "安全基线巡检报告", "compliance": "等保合规差距报告",
        }
        return f"AegisGate {labels.get(report_type, '安全运营报告')}"

    def _report_content(
        self,
        report_type: str,
        source_id: str,
        scope: dict[str, str] | None,
        period_start: str,
        period_end: str,
    ) -> dict[str, Any]:
        dashboard = self.dashboard(scope=scope)
        sections: list[dict[str, Any]] = []
        if report_type == "security_test":
            if not source_id:
                raise EnterpriseValidationError("安全测试报告必须绑定测试项目")
            project = self.get_record("test-projects", source_id, scope=scope)
            records = self.list_records("test-records", scope=scope, page_size=200, filters={"project_id_ref": source_id})["items"]
            vulnerabilities = self.list_records("vulnerabilities", scope=scope, page_size=200)["items"]
            sections = [
                {"title": "项目概述", "body": project},
                {"title": "测试范围", "body": {"scope": project.get("scope_summary"), "assets": project.get("asset_ids_json", []), "authorization_ticket": project.get("authorization_ticket")}},
                {"title": "风险统计", "body": self._risk_summary(vulnerabilities)},
                {"title": "漏洞详情", "body": vulnerabilities},
                {"title": "整改措施", "body": [{"id": item.get("id"), "title": item.get("title"), "remediation": item.get("remediation"), "deadline": item.get("deadline")} for item in vulnerabilities]},
                {"title": "附录", "body": {"test_records": records, "note": "仅包含授权测试过程摘要和证据哈希，不包含攻击载荷。"}},
            ]
        elif report_type == "vulnerability":
            vulnerabilities = [self.get_record("vulnerabilities", source_id, scope=scope)] if source_id else self.list_records("vulnerabilities", scope=scope, page_size=200)["items"]
            sections = [
                {"title": "报告概述", "body": self._risk_summary(vulnerabilities)},
                {"title": "漏洞详情", "body": vulnerabilities},
                {"title": "授权复现记录", "body": [{"id": item.get("id"), "placeholder": item.get("reproduction_placeholder"), "poc_reference": item.get("poc_reference")} for item in vulnerabilities]},
                {"title": "风险影响", "body": [{"id": item.get("id"), "impact": item.get("risk_impact")} for item in vulnerabilities]},
                {"title": "整改建议", "body": [{"id": item.get("id"), "remediation": item.get("remediation"), "deadline": item.get("deadline")} for item in vulnerabilities]},
                {"title": "复测结论", "body": [{"id": item.get("id"), "status": item.get("status"), "related": item.get("related", {})} for item in vulnerabilities]},
            ]
        elif report_type == "inspection":
            tasks = [self.get_record("inspection-tasks", source_id, scope=scope)] if source_id else self.list_records("inspection-tasks", scope=scope, page_size=200)["items"]
            findings = self.list_records("baseline-findings", scope=scope, page_size=200)["items"]
            sections = [
                {"title": "巡检概述", "body": {"tasks": len(tasks), "findings": len(findings)}},
                {"title": "巡检任务", "body": tasks},
                {"title": "不合规项", "body": findings},
                {"title": "整改跟踪", "body": self.list_records("work-orders", scope=scope, page_size=200, filters={"order_type": "baseline_remediation"})["items"]},
            ]
        else:
            sections = [
                {"title": "运营摘要", "body": dashboard["counts"]},
                {"title": "告警态势", "body": dashboard["alert_severity"]},
                {"title": "漏洞整改", "body": {"status": dashboard["vulnerability_status"], "completion_rate": dashboard["remediation_completion_rate"]}},
                {"title": "安全事件", "body": dashboard["incident_status"]},
                {"title": "高风险资产", "body": dashboard["high_risk_assets"]},
                {"title": "合规说明", "body": "本报告用于内部治理和差距分析，不构成等保测评结论、认证或法律意见。"},
            ]
        return {
            "generated_at": _now(),
            "period": {"start": period_start, "end": period_end},
            "summary": {"report_type": report_type, "section_count": len(sections), "dashboard": dashboard["counts"]},
            "sections": sections,
            "privacy_notice": "报告不包含原始攻击载荷、原始日志、凭据或真实敏感对话；证据以摘要保存。",
            "compliance_notice": "输出仅反映系统内已登记并验证的数据，不代表监管认证或生产合规结论。",
        }

    @staticmethod
    def _risk_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
        severities = {severity: 0 for severity in SEVERITIES}
        for item in items:
            severity = str(item.get("severity", "info"))
            severities[severity] = severities.get(severity, 0) + 1
        return {"total": len(items), "by_severity": severities, "open": sum(item.get("status") not in {"closed", "accepted"} for item in items)}

    @staticmethod
    def _flatten_report(report: dict[str, Any], content: dict[str, Any]) -> list[str]:
        lines = [str(report.get("title", "AegisGate Report")), f"版本：V{report.get('version', 1)}", f"生成时间：{report.get('created_at', '')}", ""]
        for section in content.get("sections", []):
            if not isinstance(section, dict):
                continue
            lines.append(str(section.get("title", "章节")))
            body = section.get("body", "")
            rendered = json.dumps(body, ensure_ascii=False, indent=2) if isinstance(body, (dict, list)) else str(body)
            lines.extend(rendered.splitlines())
            lines.append("")
        lines.extend([str(content.get("privacy_notice", "")), str(content.get("compliance_notice", ""))])
        return [line[:180] for line in lines]

    def _build_docx(self, report: dict[str, Any], content: dict[str, Any]) -> bytes:
        paragraphs = []
        for index, line in enumerate(self._flatten_report(report, content)):
            style = '<w:pStyle w:val="Title"/>' if index == 0 else ""
            paragraphs.append(f'<w:p><w:pPr>{style}</w:pPr><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>')
        document = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + "".join(paragraphs) + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>'
        styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:eastAsia="Microsoft YaHei"/><w:sz w:val="21"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:rFonts w:eastAsia="Microsoft YaHei"/><w:b/><w:sz w:val="34"/></w:rPr></w:style></w:styles>'
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
            archive.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
            archive.writestr("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
            archive.writestr("word/document.xml", document)
            archive.writestr("word/styles.xml", styles)
        return buffer.getvalue()

    def _build_pdf(self, report: dict[str, Any], content: dict[str, Any]) -> bytes:
        lines = self._flatten_report(report, content)
        wrapped: list[str] = []
        for line in lines:
            if not line:
                wrapped.append("")
                continue
            wrapped.extend(line[index:index + 52] for index in range(0, len(line), 52))
        pages = [wrapped[index:index + 46] for index in range(0, len(wrapped), 46)] or [[]]
        objects: dict[int, bytes] = {}
        page_ids = [5 + index * 2 for index in range(len(pages))]
        content_ids = [page_id + 1 for page_id in page_ids]
        objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
        objects[3] = b"<< /Type /Font /Subtype /Type0 /BaseFont /STSong-Light /Encoding /UniGB-UCS2-H /DescendantFonts [4 0 R] >>"
        objects[4] = b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /STSong-Light /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 4 >> >>"
        for page_id, content_id, page_lines in zip(page_ids, content_ids, pages):
            commands = ["BT", "/F1 10 Tf", "44 800 Td"]
            for line in page_lines:
                encoded = line.encode("utf-16-be").hex().upper()
                commands.append(f"<{encoded}> Tj")
                commands.append("0 -16 Td")
            commands.append("ET")
            stream = "\n".join(commands).encode("ascii")
            objects[page_id] = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
            objects[content_id] = f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        maximum = max(objects)
        for object_id in range(1, maximum + 1):
            offsets.append(len(output))
            output.extend(f"{object_id} 0 obj\n".encode("ascii"))
            output.extend(objects[object_id])
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {maximum + 1}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        output.extend(f"trailer\n<< /Size {maximum + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii"))
        return bytes(output)

    def _build_xlsx(self, report: dict[str, Any], content: dict[str, Any]) -> bytes:
        rows = self._flatten_report(report, content)
        sheet_rows = []
        for index, line in enumerate(rows, start=1):
            sheet_rows.append(f'<row r="{index}"><c r="A{index}" t="inlineStr"><is><t xml:space="preserve">{escape(line)}</t></is></c></row>')
        sheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="96" customWidth="1"/></cols><sheetData>' + "".join(sheet_rows) + '</sheetData></worksheet>'
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
            archive.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
            archive.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="AegisGate Report" sheetId="1" r:id="rId1"/></sheets></workbook>')
            archive.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
            archive.writestr("xl/worksheets/sheet1.xml", sheet)
        return buffer.getvalue()
