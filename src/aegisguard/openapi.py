from __future__ import annotations

from typing import Any


def build_openapi(version: str = "3.1.0") -> dict[str, Any]:
    error = {
        "type": "object",
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {"code": {"type": "string"}, "message": {"type": "string"}},
            }
        },
    }
    response = {"200": {"description": "Success"}, "400": {"description": "Invalid request"}}
    scoped_headers = [
        {"name": "X-Aegis-Tenant", "in": "header", "schema": {"type": "string", "default": "local"}},
        {"name": "X-Aegis-Project", "in": "header", "schema": {"type": "string", "default": "default"}},
        {"name": "X-Aegis-User", "in": "header", "schema": {"type": "string", "default": "local-admin"}},
        {"name": "X-Aegis-Role", "in": "header", "schema": {"type": "string", "enum": ["admin", "operator", "reviewer", "readonly"], "default": "admin"}},
    ]
    paths: dict[str, Any] = {
        "/api/health": {"get": {"summary": "Health and model status", "responses": response}},
        "/api/v1/detect": {
            "post": {
                "summary": "Detect one input or output",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/DetectRequest"}}}},
                "responses": response,
            }
        },
        "/api/v1/privacy/scan": {
            "post": {
                "summary": "Privacy-minimized PII and DLP transformation",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PrivacyScanRequest"}}}},
                "responses": response,
            }
        },
        "/api/v1/batch/detect": {
            "post": {
                "summary": "Synchronous bounded batch detection",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BatchRequest"}}}},
                "responses": response,
            }
        },
        "/api/v1/observability/metrics": {"get": {"summary": "Privacy-safe operational metrics", "responses": response}},
        "/api/v2/gateway/preflight": {
            "post": {
                "summary": "Compute a privacy-minimised preflight projection and issue a short-lived route ticket",
                "parameters": scoped_headers,
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GatewayPreflightRequest"}}}},
                "responses": {"200": {"description": "Preflight projection and signed ticket"}, "400": {"description": "Invalid request"}},
            }
        },
        "/api/v2/gateway/route": {
            "post": {
                "summary": "Validate a route ticket and perform server-side deep detection",
                "parameters": scoped_headers,
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GatewayRouteRequest"}}}},
                "responses": {"200": {"description": "Route decision with audit digest"}, "400": {"description": "Invalid request"}, "409": {"description": "Replay or stale policy"}},
            }
        },
        "/api/v2/telemetry/routing": {
            "get": {
                "summary": "Read privacy-minimised routing telemetry for the caller scope",
                "description": "Returns route counts and safe request metadata derived from the append-only audit chain. Raw text, PII values and match values are never returned.",
                "parameters": [
                    *scoped_headers,
                    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
                    {"name": "page_size", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}},
                    {"name": "route", "in": "query", "schema": {"type": "string", "enum": ["local_block", "deep_check", "local_observe"]}},
                ],
                "responses": {"200": {"description": "Scoped routing telemetry without source content", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RoutingTelemetry"}}}}, "400": {"description": "Invalid scope or pagination"}, "403": {"description": "Permission denied"}},
            }
        },
        "/api/v2/invention/evidence": {
            "get": {
                "summary": "Read the privacy-minimised evidence graph",
                "description": "Projects policy, route, rule, model, temporal, output-review and human-review relationships from immutable audit metadata. Raw source and PII values are excluded.",
                "parameters": [
                    *scoped_headers,
                    {"name": "request_id", "in": "query", "schema": {"type": "string", "maxLength": 128}},
                    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
                    {"name": "page_size", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}},
                ],
                "responses": {"200": {"description": "Scoped evidence graph without source content", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/InventionEvidenceGraph"}}}}, "400": {"description": "Invalid scope, request id or pagination"}, "403": {"description": "Permission denied"}},
            }
        },
        "/api/v1/ops/overview": {
            "get": {"summary": "Scoped security operations overview", "parameters": scoped_headers, "responses": response}
        },
        "/api/v1/ops/{resource}": {
            "get": {
                "summary": "List scoped security operations records",
                "parameters": [
                    {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/OpsResource"}},
                    *scoped_headers,
                ],
                "responses": response,
            },
            "post": {
                "summary": "Create a scoped security operations record",
                "parameters": [{"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/OpsResource"}}, *scoped_headers],
                "responses": {"201": {"description": "Created"}, "400": {"description": "Invalid request"}},
            },
        },
        "/api/v1/ops/{resource}/{id}": {
            "patch": {
                "summary": "Append a scoped state transition",
                "parameters": [
                    {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/OpsResource"}},
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                    *scoped_headers,
                ],
                "responses": response,
            }
        },
    }
    enterprise_resources = [
        "assets",
        "asset-groups",
        "asset-tags",
        "discovery-tasks",
        "alerts",
        "alert-rules",
        "scan-tasks",
        "vulnerabilities",
        "remediation-orders",
        "test-projects",
        "test-cases",
        "test-records",
        "incidents",
        "incident-actions",
        "incident-links",
        "forensics-records",
        "iocs",
        "baseline-rules",
        "inspection-tasks",
        "baseline-findings",
        "work-orders",
        "report-templates",
        "reports",
        "users",
        "roles",
        "notifications",
        "scheduled-jobs",
        "allowlist",
        "integrations",
    ]
    enterprise_query = [
        *scoped_headers,
        {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
        {"name": "page_size", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}},
        {"name": "q", "in": "query", "schema": {"type": "string", "maxLength": 120}},
        {"name": "status", "in": "query", "schema": {"type": "string"}},
        {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}},
        {"name": "sort", "in": "query", "schema": {"type": "string", "default": "updated_at"}},
        {"name": "order", "in": "query", "schema": {"type": "string", "enum": ["asc", "desc"], "default": "desc"}},
    ]
    paths.update(
        {
            "/api/v1/enterprise": {
                "get": {
                    "summary": "Enterprise security operations capabilities",
                    "parameters": scoped_headers,
                    "responses": response,
                }
            },
            "/api/v1/enterprise/schema": {
                "get": {
                    "summary": "SQLite business schema and privacy properties",
                    "parameters": scoped_headers,
                    "responses": response,
                }
            },
            "/api/v1/enterprise/dashboard": {
                "get": {
                    "summary": "Scoped SOC dashboard backed by operational records",
                    "parameters": scoped_headers,
                    "responses": response,
                }
            },
            "/api/v1/enterprise/todos": {
                "get": {
                    "summary": "Unified pending alerts, vulnerabilities, incidents, inspections and work orders",
                    "parameters": [
                        *scoped_headers,
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100}},
                    ],
                    "responses": response,
                }
            },
            "/api/v1/enterprise/{resource}": {
                "get": {
                    "summary": "List a scoped enterprise operations resource",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/EnterpriseResource"}},
                        *enterprise_query,
                    ],
                    "responses": response,
                },
                "post": {
                    "summary": "Create a scoped enterprise operations record",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/EnterpriseResource"}},
                        *scoped_headers,
                    ],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EnterpriseRecordWrite"}}}},
                    "responses": {"201": {"description": "Created"}, "400": {"description": "Invalid request"}, "409": {"description": "Conflict"}},
                },
            },
            "/api/v1/enterprise/{resource}/{id}": {
                "get": {
                    "summary": "Get one scoped enterprise record with related workflow entries",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/EnterpriseResource"}},
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        *scoped_headers,
                    ],
                    "responses": response,
                },
                "patch": {
                    "summary": "Update fields or append a validated workflow state transition",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/EnterpriseResource"}},
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        *scoped_headers,
                    ],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EnterpriseRecordWrite"}}}},
                    "responses": response,
                },
            },
            "/api/v1/enterprise/{resource}/import": {
                "post": {
                    "summary": "Import up to 500 assets or IOC records",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"type": "string", "enum": ["assets", "iocs"]}},
                        *scoped_headers,
                    ],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"oneOf": [
                        {"type": "object", "required": ["items"], "properties": {"items": {"type": "array", "minItems": 1, "maxItems": 500, "items": {"type": "object", "additionalProperties": True}}}},
                        {"type": "object", "required": ["format", "content"], "properties": {"format": {"type": "string", "enum": ["csv", "json", "ndjson", "jsonl"]}, "content": {"type": "string", "maxLength": 200000}}},
                    ]}}}},
                    "responses": {"201": {"description": "Import processed"}, "400": {"description": "Invalid import"}},
                }
            },
            "/api/v1/enterprise/{resource}/export": {
                "get": {
                    "summary": "Export assets or IOC registry as CSV or JSON",
                    "parameters": [
                        {"name": "resource", "in": "path", "required": True, "schema": {"type": "string", "enum": ["assets", "iocs"]}},
                        {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["csv", "json"], "default": "csv"}},
                        *scoped_headers,
                    ],
                    "responses": {"200": {"description": "File download"}, "400": {"description": "Invalid export"}},
                }
            },
            "/api/v1/enterprise/discovery-tasks/{id}/run": {
                "post": {
                    "summary": "Run one authorized bounded DNS and TCP connectivity check",
                    "description": "Checks one registered asset and one port. It does not enumerate ports, exploit vulnerabilities or execute payloads.",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["confirm"], "properties": {"confirm": {"type": "string", "const": "CONFIRM"}}}}}},
                    "responses": response,
                }
            },
            "/api/v1/enterprise/assets/{id}/tags": {
                "post": {
                    "summary": "Replace an asset's scoped tag assignments",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["tag_ids"], "properties": {"tag_ids": {"type": "array", "maxItems": 50, "items": {"type": "string"}}}}}}},
                    "responses": response,
                }
            },
            "/api/v1/enterprise/roles/{id}/asset-groups": {
                "post": {
                    "summary": "Replace a role's asset-group scope after explicit confirmation",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["group_ids", "confirm"], "properties": {"group_ids": {"type": "array", "maxItems": 100, "items": {"type": "string"}}, "confirm": {"type": "string", "const": "CONFIRM"}}}}}},
                    "responses": response,
                }
            },
            "/api/v1/enterprise/vulnerabilities/{id}/retest": {
                "post": {
                    "summary": "Append a vulnerability retest result and update lifecycle state",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RetestRequest"}}}},
                    "responses": {"201": {"description": "Retest recorded"}, "400": {"description": "Invalid result"}},
                }
            },
            "/api/v1/enterprise/vulnerabilities/retest/batch": {
                "post": {
                    "summary": "Append one bounded batch of vulnerability retest results",
                    "parameters": scoped_headers,
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["vulnerability_ids", "result"], "properties": {"vulnerability_ids": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "string"}}, "result": {"type": "string", "enum": ["pending", "passed", "failed", "inconclusive"]}, "evidence_summary": {"type": "string", "maxLength": 1000}, "evidence": {"type": "string", "maxLength": 10000}}}}}},
                    "responses": {"201": {"description": "Batch recorded"}, "400": {"description": "Invalid request"}},
                }
            },
            "/api/v1/enterprise/incidents/{id}/actions": {
                "post": {
                    "summary": "Append an incident response action and advance the validated workflow",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "responses": {"201": {"description": "Action recorded"}, "400": {"description": "Invalid action"}},
                }
            },
            "/api/v1/enterprise/work-orders/{id}/receipts": {
                "post": {
                    "summary": "Submit a remediation receipt with optional evidence digest",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}, *scoped_headers],
                    "responses": {"201": {"description": "Receipt recorded"}, "400": {"description": "Invalid receipt"}},
                }
            },
            "/api/v1/enterprise/reports/generate": {
                "post": {
                    "summary": "Generate and archive a versioned operations, vulnerability, inspection or security test report",
                    "parameters": scoped_headers,
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReportGenerateRequest"}}}},
                    "responses": {"201": {"description": "Report generated"}, "400": {"description": "Invalid report request"}},
                }
            },
            "/api/v1/enterprise/reports/{id}/export": {
                "get": {
                    "summary": "Export an archived report as DOCX, PDF, XLSX or JSON",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["docx", "pdf", "xlsx", "json"], "default": "pdf"}},
                        *scoped_headers,
                    ],
                    "responses": {"200": {"description": "File download"}, "404": {"description": "Report not found"}},
                }
            },
            "/api/v1/enterprise/settings": {
                "get": {"summary": "List redacted system settings", "parameters": scoped_headers, "responses": response},
                "post": {"summary": "Create or version a system setting", "parameters": scoped_headers, "responses": response},
            },
            "/api/v1/enterprise/audit": {
                "get": {"summary": "List immutable enterprise operation audit records", "parameters": enterprise_query, "responses": response}
            },
            "/api/v1/enterprise/audit/verify": {
                "get": {"summary": "Verify the scoped enterprise audit hash chain", "parameters": scoped_headers, "responses": response}
            },
            "/api/v1/enterprise/login-logs": {
                "get": {
                    "summary": "List immutable privacy-minimized authentication logs",
                    "parameters": enterprise_query,
                    "responses": response,
                }
            },
        }
    )
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "AegisGate API",
            "version": version,
            "description": "LLM content safety, privacy DLP, governance and authorized security operations.",
        },
        "servers": [{"url": "http://127.0.0.1:8765"}],
        "paths": paths,
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "Error": error,
                "OpsResource": {"type": "string", "enum": ["assets", "alerts", "vulnerabilities", "incidents", "iocs"]},
                "EnterpriseResource": {"type": "string", "enum": enterprise_resources},
                "EnterpriseRecordWrite": {
                    "type": "object",
                    "description": "Resource-specific bounded fields. Unknown fields are ignored and raw secrets are never persisted.",
                    "additionalProperties": True,
                    "properties": {
                        "status": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "note": {"type": "string", "maxLength": 500},
                        "confirm": {"type": "string", "description": "Set to CONFIRM for sensitive administration changes."},
                    },
                },
                "RetestRequest": {
                    "type": "object",
                    "required": ["result"],
                    "properties": {
                        "result": {"type": "string", "enum": ["pending", "passed", "failed", "inconclusive"]},
                        "evidence_summary": {"type": "string", "maxLength": 1000},
                        "evidence": {"type": "string", "maxLength": 10000, "description": "Hashed only; raw value is not retained."},
                    },
                },
                "ReportGenerateRequest": {
                    "type": "object",
                    "required": ["report_type"],
                    "properties": {
                        "report_type": {"type": "string", "enum": ["security_test", "vulnerability", "daily", "weekly", "monthly", "inspection", "compliance"]},
                        "source_type": {"type": "string"},
                        "source_id": {"type": "string"},
                        "title": {"type": "string", "maxLength": 180},
                        "period_start": {"type": "string", "format": "date"},
                        "period_end": {"type": "string", "format": "date"},
                    },
                },
                "DetectRequest": {
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": {"type": "string", "minLength": 1},
                        "direction": {"type": "string", "enum": ["input", "output"], "default": "input"},
                        "session_id": {"type": "string", "maxLength": 128, "description": "Optional bounded identifier for privacy-minimised session risk state."},
                    },
                },
                "PrivacyScanRequest": {
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": {"type": "string", "minLength": 1},
                        "strategy": {"type": "string", "enum": ["mask", "replace", "hash"], "default": "mask"},
                    },
                },
                "BatchRequest": {
                    "type": "object",
                    "required": ["records"],
                    "properties": {
                        "direction": {"type": "string", "enum": ["input", "output"], "default": "input"},
                        "include_safe_text": {"type": "boolean", "default": False},
                        "records": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 500,
                            "items": {
                                "type": "object",
                                "required": ["id", "text"],
                                "properties": {"id": {"type": "string"}, "text": {"type": "string"}},
                            },
                        },
                    },
                },
                "GatewayPreflightRequest": {
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": {"type": "string", "minLength": 1, "maxLength": 16000, "description": "Used only for server-side feature extraction; raw text is not persisted."},
                        "history": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 16000}},
                        "client_capability": {"type": "string", "maxLength": 64},
                        "session_id": {"type": "string", "maxLength": 128},
                        "request_id": {"type": "string", "maxLength": 128},
                        "nonce": {"type": "string", "maxLength": 128},
                    },
                },
                "GatewayRouteRequest": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "maxLength": 16000, "description": "Required for deep_check; omitted for source-free conservative local_block."},
                        "history": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 16000}},
                        "direction": {"type": "string", "enum": ["input", "output"], "default": "input"},
                        "ticket": {"type": "object", "description": "Signed ticket returned by gateway/preflight."},
                        "client_capability": {"type": "string", "maxLength": 64},
                        "session_id": {"type": "string", "maxLength": 128},
                    },
                },
                "RoutingTelemetry": {
                    "type": "object",
                    "description": "Content-free route telemetry restricted to the authenticated tenant/project scope.",
                    "properties": {
                        "schema_version": {"type": "string"},
                        "scope": {"type": "object", "properties": {"tenant_id": {"type": "string"}, "project_id": {"type": "string"}}},
                        "page": {"type": "integer"},
                        "page_size": {"type": "integer"},
                        "total": {"type": "integer"},
                        "route_counts": {"type": "object"},
                        "action_counts": {"type": "object"},
                        "average_risk_score": {"type": "number"},
                        "scope_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "tenant_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "items": {"type": "array", "items": {"type": "object"}},
                    },
                },
                "InventionEvidenceGraph": {
                    "type": "object",
                    "description": "Privacy-minimised evidence graph; raw source and PII values are excluded.",
                    "properties": {
                        "schema_version": {"type": "string"},
                        "scope": {"type": "object", "properties": {"tenant_id": {"type": "string"}, "project_id": {"type": "string"}}},
                        "total_events": {"type": "integer"},
                        "nodes": {"type": "array", "items": {"type": "object"}},
                        "edges": {"type": "array", "items": {"type": "object"}},
                        "scope_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "tenant_fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "privacy": {"type": "object"},
                    },
                },
            },
        },
    }
