# Threat Model

## Assets

Protected assets are request/response confidentiality, policy and model integrity, audit-chain integrity, tenant isolation, operator credentials, and availability of the gateway.

## Threats and controls

- Prompt injection, jailbreak, and instruction smuggling: Unicode normalization, bounded history, rules, model evidence, temporal calibration, and output re-check.
- PII and secret leakage: pattern detection, mask/replace/hash strategies, safe previews, and audit redaction.
- Cross-tenant and cross-group disclosure: validated tenant/project scope plus query-time `role_asset_groups` predicates on asset-bound lists, details, exports, dashboards, todos and reports. Control-plane records and full login/audit logs require the administrator permission.
- Duplicate alert floods: stable alert fingerprints, configurable source/type/severity rules, bounded repeat counters and in-app notification policy.
- Audit tampering: append-only records with previous-hash links and verification endpoints.
- HTTP abuse: loopback default, bearer token for remote bind, rate limiting, request-size limits, CSP, and path traversal checks.
- Supply-chain drift: pinned runtime requirements, model cards, SHA-256 manifests, and third-party notices.

## Out of scope

The product does not perform autonomous exploitation, unauthorized scanning, lateral movement, privilege escalation, persistence, malware execution, or destructive incident response. Active discovery is limited to one registered asset and one port under an authorization ticket. Other testing is represented as scoped tasks, records, evidence digests, retests and remediation workflow.

## Residual risk

Rule and model thresholds require calibration against each tenant's labeled data. Header-provided identity is a local integration contract, not a replacement for an external identity provider. SQLite/JSON persistence is not a high-availability datastore. TLS, backup, queue durability, retention enforcement and external alert delivery must be supplied by deployment infrastructure.
