# AegisGate Architecture

## Product boundary

AegisGate is an enterprise-oriented LLM content safety and data governance gateway with a local SOC evidence workspace. It is designed for deterministic, privacy-minimized evaluation and authorized operational records, not autonomous offensive security execution.

## End-to-end request path

`Web workspace -> HTTP handler -> request validation and scope -> ConversationService -> normalization -> PII/DLP and rules -> ONNX/auxiliary model -> context and temporal calibration -> evidence fusion -> risk and action -> audit hash chain -> JSON response -> Web rendering`

Operations keep the original contract `Web -> /api/v1/ops -> scoped SecurityOperationsStore -> validation/deduplication -> append-only event hash -> response -> table/KPI view` and add `Web -> /api/v1/enterprise -> scoped EnterpriseOperationsStore -> SQLite transaction -> workflow relation/audit -> response -> workbench view`. Existing clients and tests continue using the original namespace.

## Components

- `src/aegisguard/engine.py`: policy, rules, evidence fusion, temporal correlation, and masking.
- `src/aegisguard/onnx_classifier.py`: local CPU ONNX inference with explicit `ready`, `unavailable`, and `invalid` states; install weights separately with `scripts/download_models.py`.
- `src/aegisguard/service.py`: conversation orchestration, batch governance, privacy scan, audit projection, and observability metrics.
- `src/aegisguard/audit.py`: privacy-minimized JSONL audit records and verification.
- `src/aegisguard/operations.py`: scoped SOC objects, field validation, alert deduplication, and a separate SHA-256 event chain.
- `src/aegisguard/enterprise.py`: additive SQLite domain for assets/groups/tags/history, authorized discovery, alerts/rules/notifications, safe scan tasks, vulnerabilities/remediation/retests, security test projects/cases/records, incidents/actions/links/forensics, IOC registry, baselines/inspections/findings/work orders, report templates/archives, RBAC users/roles/asset scopes, login logs, settings, schedules, allowlists and integrations. It provides idempotent migration, demo seeding, bounded import/export, report generation and immutable audit triggers.
- `src/aegisguard/web.py`: loopback-safe HTTP server, bearer authentication, role checks, rate limiting, security headers, and static file serving.
- `web/`: dependency-free responsive console with detection, batch, audit, system, legacy operations and the enterprise workbench. The workbench reuses existing tables, dialogs, glass surfaces, dark mode and responsive breakpoints.

## Data and trust boundaries

Original request text is hashed/represented by decision metadata in audit records. DLP previews require explicit opt-in and are restricted to pass/mask outputs. Operations evidence is stored as digests. Tenant and project identifiers are validated before reads or writes. Runtime JSON is separate from demo seed data.

The enterprise database is created lazily at `runtime/enterprise_operations.db`, uses foreign keys and bounded fields, and is returned with DDL/privacy metadata by `/api/v1/enterprise/schema`. Payloads, raw logs, credentials and private evidence are never stored as raw values. `operation_audit` and `login_logs` reject update/delete operations through SQLite triggers. Query-time `role_asset_groups` predicates are reused by pagination, detail reads, exports, dashboard counts, 14-day trends, unified todos and report content; missing mappings fail closed for non-admin roles. The full schema and domain mapping are documented in `docs/enterprise-operations-schema.md`.

## Scaling path

The local JSONL/JSON stores are intentionally replaceable by PostgreSQL, object storage, Redis, and a queue. The HTTP schemas, scope fields, idempotent fingerprints, trace digests, and append-only event semantics should remain stable during that migration.
