# AegisGate API Reference

This document describes the versioned HTTP contract implemented by the local Python gateway.

## Runtime

- Base URL: `http://127.0.0.1:8765`
- Content type: `application/json`
- Every API response includes `X-Aegis-Request-Id` and `X-Aegis-Backend`.
- Remote binding requires `AEGIS_API_TOKEN` and a `Bearer` token.
- Optional scope headers: `X-Aegis-Tenant`, `X-Aegis-Project`, `X-Aegis-User`, `X-Aegis-Role` (`admin`, `operator`, `reviewer`, `readonly`).

## Detection

`POST /api/v1/detect`, `POST /api/v1/chat`, `POST /api/v1/sequence`, and `POST /api/v1/batch/detect` share the same normalization, rule, model, context, decision, and audit path. Responses expose decisions and digests; original sensitive text is not persisted by default.

## Privacy DLP

`POST /api/v1/privacy/scan`

```json
{"text":"contact 13800138000 or demo@example.com","strategy":"hash"}
```

`strategy` is `mask`, `replace`, or `hash`. The response contains `safe_text`, match categories, risk metadata, policy version, and a trace digest. Raw matches are held only for the request and are never returned as evidence fields.

## Security operations

- `GET /api/v1/ops/overview`
- `GET /api/v1/ops/{resource}` where resource is `assets`, `alerts`, `vulnerabilities`, `incidents`, or `iocs`
- `POST /api/v1/ops/{resource}`
- `PATCH /api/v1/ops/{resource}/{id}`
- `GET /api/v1/ops/events/verify`

List requests support `page`, `page_size`, `status`, `severity`, and `q`. Records are isolated by tenant/project scope. Alert fingerprints suppress repeated open/investigating alerts and increment `repeat_count`; the operation is appended to the SHA-256 event chain.

## Metrics and governance

- `GET /api/v1/stats`
- `GET /api/v1/observability/metrics`
- `GET /api/v1/governance/status`
- `GET /api/v1/policy`
- `GET /api/v1/reviews`
- `POST /api/v1/reviews/status`

Metrics include request/intervention totals, average/P95/P99 latency, model failure rate, action counters, and audit integrity. No metric endpoint returns original request content.

## Enterprise operations (additive)

The `/api/v1/enterprise` namespace is backed by `runtime/enterprise_operations.db`; the legacy `/api/v1/ops/*` namespace remains unchanged. All reads and writes accept `X-Aegis-Tenant`, `X-Aegis-Project` and `X-Aegis-User`. Token mode reuses the existing `admin`, `operator`, `reviewer` and `readonly` roles. Non-admin roles are filtered by persisted `role_asset_groups`; an absent mapping returns no asset-bound records.

- `GET /api/v1/enterprise/dashboard`, `/todos`, `/schema` provide the scoped dashboard, 14-day alert/vulnerability trends, unified pending queue and current SQLite DDL/privacy contract.
- `GET|POST /api/v1/enterprise/{resource}`, `GET|PATCH /api/v1/enterprise/{resource}/{id}` cover assets, groups, tags, discovery tasks, alerts/rules, scan tasks, vulnerabilities/remediation, test projects/cases/records, incidents/actions/links, IOCs, baselines, inspections/findings, work orders, report templates/archives, users, roles, notifications, schedules, allowlists and integrations.
- `POST /api/v1/enterprise/{resource}/import` accepts up to 500 assets or IOCs as JSON `items`, CSV `content`, or NDJSON `content`; the response contains `batch_sha256`, success counts and bounded row errors. `GET /api/v1/enterprise/{resource}/export?format=csv|json` exports the same role-scoped list.
- `POST /api/v1/enterprise/assets/{id}/tags` replaces scoped asset tags; `POST /api/v1/enterprise/roles/{id}/asset-groups` requires `CONFIRM` and changes the query-time asset boundary.
- `POST /api/v1/enterprise/discovery-tasks/{id}/run` requires `{"confirm":"CONFIRM"}` and performs one registered-host, one-port DNS/TCP connectivity check. It does not enumerate, exploit or execute payloads.
- `POST /api/v1/enterprise/vulnerabilities/{id}/retest` and `/vulnerabilities/retest/batch` append evidence digests and advance lifecycle; incident actions and work-order receipts append similar workflow records.
- `POST /api/v1/enterprise/reports/generate` archives versioned operations, vulnerability, security-test, inspection and compliance-difference reports. `GET /api/v1/enterprise/reports/{id}/export?format=docx|pdf|xlsx|json` returns a real file response.
- `GET|POST /api/v1/enterprise/settings`, `GET /api/v1/enterprise/audit`, `GET /api/v1/enterprise/audit/verify`, and `GET /api/v1/enterprise/login-logs` expose redacted configuration and append-only evidence. Settings, full audit/login records, users, roles, integrations and schedules require administrator permission; sensitive writes also require second confirmation.

List parameters are `page`, `page_size` (maximum 200), `q`, `status`, `severity`, `sort` and `order`. Raw attack payloads, raw logs, credentials and private evidence are never returned or persisted. Errors add `INVALID_ENTERPRISE_REQUEST`, `ENTERPRISE_NOT_FOUND` and `ENTERPRISE_CONFLICT` where applicable.

## Error model

```json
{"error":{"code":"INVALID_REQUEST","message":"request validation failed"}}
```

Common status codes are `400`, `401`, `403`, `404`, `413`, `429`, and `500`. Error messages are bounded and do not echo attacker-controlled payloads.

## Safety boundary

The operations APIs register and analyze authorized assets, alerts, vulnerabilities, incidents, and IOCs. They do not execute unauthorized scanning, exploit payloads, lateral movement, privilege escalation, persistence, or destructive actions.
