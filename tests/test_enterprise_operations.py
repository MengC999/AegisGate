from __future__ import annotations

import io
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.enterprise import (  # noqa: E402
    EnterpriseNotFoundError,
    EnterpriseOperationsStore,
    EnterpriseValidationError,
)
from src.aegisguard.web import AegisServer  # noqa: E402


class EnterpriseOperationsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-enterprise-")
        self.database = Path(self.temp.name) / "enterprise.db"
        self.store = EnterpriseOperationsStore(
            self.database,
            ROOT / "data" / "security_operations_demo.json",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_schema_has_required_domains_and_immutable_audit(self) -> None:
        schema = self.store.schema()
        names = {item["name"] for item in schema["tables"]}
        self.assertTrue(
            {
                "assets",
                "asset_history",
                "alerts",
                "vulnerabilities",
                "remediation_orders",
                "security_test_projects",
                "incident_actions",
                "inspection_tasks",
                "work_orders",
                "report_archives",
                "operation_audit",
                "system_settings",
            }.issubset(names)
        )
        self.assertFalse(schema["privacy"]["raw_attack_payload_persisted"])
        created = self.store.create(
            "assets",
            {"name": "Audit Asset", "kind": "api", "address": "audit.example", "authorization_ticket": "AUTH-001"},
        )
        self.assertTrue(created["id"].startswith("astx_"))
        connection = sqlite3.connect(self.database)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("UPDATE operation_audit SET actor='changed'")
        connection.close()
        self.assertTrue(self.store.verify_audit()["valid"])

    def test_asset_history_scope_search_and_archive(self) -> None:
        scope = {"tenant_id": "tenant_a", "project_id": "project_a", "user_id": "operator_a"}
        asset = self.store.create(
            "assets",
            {
                "name": "Customer Portal",
                "kind": "web",
                "address": "portal.authorized.example",
                "business_level": "core",
                "owner": "Owner A",
                "department": "Digital",
                "authorization_ticket": "AUTH-PORTAL",
            },
            scope=scope,
        )
        updated = self.store.update(
            "assets",
            asset["id"],
            {"status": "archived", "note": "业务下线归档"},
            scope=scope,
        )
        self.assertEqual(updated["status"], "archived")
        self.assertTrue(updated["archived_at"])
        self.assertGreaterEqual(len(updated["related"]["asset_history"]), 2)
        result = self.store.list_records(
            "assets",
            scope=scope,
            query="portal",
            filters={"department": "Digital", "status": "archived"},
        )
        self.assertEqual(result["total"], 1)
        other = self.store.list_records(
            "assets",
            scope={"tenant_id": "tenant_b", "project_id": "project_a", "user_id": "operator_b"},
        )
        self.assertEqual(other["total"], 0)

    def test_alert_deduplication_stores_only_redacted_preview_and_hashes(self) -> None:
        payload = {
            "title": "Gateway signal",
            "source": "WAF",
            "severity": "critical",
            "attack_type": "SQL Injection",
            "source_ip": "198.51.100.10",
            "target_asset_id": "ast_demo_gateway",
            "attack_payload": "email demo@example.com token=secret-value SELECT * FROM users",
            "raw_log": "Authorization: Bearer unit-secret",
        }
        first = self.store.create("alerts", payload)
        second = self.store.create("alerts", payload)
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(second["repeat_count"], 2)
        serialized = json.dumps(second, ensure_ascii=False)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("unit-secret", serialized)
        self.assertNotIn("demo@example.com", first["payload_preview"])
        self.assertEqual(len(first["payload_sha256"]), 64)
        notifications = self.store.list_records("notifications")
        self.assertGreaterEqual(notifications["total"], 1)

    def test_vulnerability_lifecycle_risk_retest_and_report_exports(self) -> None:
        asset = self.store.create(
            "assets",
            {
                "name": "Core API",
                "kind": "api",
                "address": "core-api.example",
                "business_level": "core",
                "importance_weight": 1.5,
                "authorization_ticket": "AUTH-CORE",
            },
        )
        vulnerability = self.store.create(
            "vulnerabilities",
            {
                "title": "Authorization boundary incomplete",
                "asset_id": asset["id"],
                "cve": "CVE-2026-12345",
                "cvss": 8.2,
                "severity": "high",
                "principle": "Authorization decision is not applied consistently.",
                "risk_impact": "May expose protected functions.",
                "remediation": "Centralize authorization and add regression tests.",
                "deadline": "2026-09-30",
            },
        )
        self.assertEqual(vulnerability["risk_priority"], 10.0)
        with self.assertRaises(EnterpriseValidationError):
            self.store.update("vulnerabilities", vulnerability["id"], {"status": "closed"})
        self.store.update("vulnerabilities", vulnerability["id"], {"status": "risk_confirmed"})
        self.store.update("vulnerabilities", vulnerability["id"], {"status": "fixing"})
        self.store.update("vulnerabilities", vulnerability["id"], {"status": "retest"})
        result = self.store.create_retest(
            vulnerability["id"],
            {"result": "passed", "evidence_summary": "Authorization regression suite passed", "evidence": "private evidence body"},
        )
        self.assertEqual(result["vulnerability"]["status"], "closed")
        self.assertNotIn("private evidence body", json.dumps(result))
        report = self.store.generate_report(
            {
                "report_type": "vulnerability",
                "source_type": "vulnerability",
                "source_id": vulnerability["id"],
                "title": "Authorized Vulnerability Report",
            }
        )
        for export_format, magic in (("docx", b"PK"), ("pdf", b"%PDF"), ("xlsx", b"PK")):
            content, _, filename = self.store.export_report(report["id"], export_format)
            self.assertTrue(content.startswith(magic))
            self.assertTrue(filename.endswith(f".{export_format}"))
            if export_format in {"docx", "xlsx"}:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    self.assertIsNone(archive.testzip())

    def test_authorized_discovery_is_bounded_to_one_registered_asset_and_port(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            asset = self.store.create(
                "assets",
                {"name": "Local Authorized Service", "kind": "service", "address": "127.0.0.1", "port": port, "authorization_ticket": "AUTH-LOCAL"},
            )
            task = self.store.create(
                "discovery-tasks",
                {"name": "Single service connectivity", "target_asset_id": asset["id"], "target_port": port, "authorization_ticket": "AUTH-LOCAL"},
            )
            result = self.store.run_discovery(task["id"])
            self.assertEqual(result["status"], "completed")
            self.assertIn("成功", result["result_summary"])
            self.assertEqual(self.store.get_record("assets", asset["id"])["status"], "online")
        finally:
            listener.close()

    def test_incident_actions_baseline_work_order_receipt_and_todos(self) -> None:
        incident = self.store.create(
            "incidents",
            {"title": "Unauthorized access review", "category": "Intrusion", "severity": "high", "impact_scope": "Demo asset only"},
        )
        incident = self.store.add_incident_action(
            incident["id"],
            {"stage": "isolation", "action_summary": "Isolated the demo endpoint", "evidence": "case evidence"},
        )
        self.assertEqual(incident["status"], "contained")
        finding = self.store.create(
            "baseline-findings",
            {
                "inspection_task_id": "ins_demo_weekly",
                "rule_id": "bsr_demo_headers",
                "asset_id": "ast_demo_gateway",
                "severity": "medium",
                "actual_summary": "Header evidence is incomplete",
            },
        )
        orders = self.store.list_records("work-orders", filters={"source_id": finding["id"]})
        self.assertEqual(orders["total"], 1)
        receipt = self.store.submit_work_order_receipt(
            orders["items"][0]["id"],
            {"receipt_summary": "Configuration updated and reviewed", "evidence": "internal screenshot bytes"},
        )
        self.assertEqual(receipt["work_order"]["status"], "submitted")
        todos = self.store.todos()
        self.assertGreater(todos["total"], 0)
        self.assertIn("overdue", todos)

    def test_bulk_import_and_export_are_bounded(self) -> None:
        result = self.store.bulk_import(
            "assets",
            [
                {"name": "Imported A", "kind": "host", "address": "imported-a.example", "authorization_ticket": "AUTH-IMPORT"},
                {"name": "Imported B", "kind": "host", "address": "imported-b.example", "authorization_ticket": "AUTH-IMPORT"},
            ],
        )
        self.assertEqual(result["created"], 2)
        content, content_type, filename = self.store.export_collection("assets", "csv")
        self.assertTrue(content.startswith(b"\xef\xbb\xbf"))
        self.assertIn("text/csv", content_type)
        self.assertTrue(filename.endswith(".csv"))

    def test_csv_ndjson_import_ioc_validation_and_batch_digest(self) -> None:
        csv_result = self.store.import_payload(
            "assets",
            {
                "format": "csv",
                "content": "name,kind,address,authorization_ticket\nCSV Gateway,web,csv-gateway.example,AUTH-CSV\n",
            },
        )
        self.assertEqual(csv_result["created"], 1)
        self.assertEqual(len(csv_result["batch_sha256"]), 64)
        ndjson_result = self.store.import_payload(
            "iocs",
            {
                "format": "ndjson",
                "content": '{"type":"domain","value":"ioc-import.example","source":"unit-test"}\n'
                '{"type":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":"unit-test"}',
            },
        )
        self.assertEqual(ndjson_result["created"], 2)
        with self.assertRaises(EnterpriseValidationError):
            self.store.create("iocs", {"type": "ip", "value": "999.2.3.4", "source": "unit-test"})

    def test_asset_tags_role_group_scope_and_dashboard_trends(self) -> None:
        second_group = self.store.create(
            "asset-groups",
            {"name": "Restricted Lab", "business_level": "normal"},
        )
        restricted_asset = self.store.create(
            "assets",
            {
                "name": "Restricted Asset",
                "kind": "web",
                "address": "restricted.example",
                "group_id": second_group["id"],
                "authorization_ticket": "AUTH-RESTRICTED",
            },
        )
        tag = self.store.create("asset-tags", {"name": "Internet", "color": "blue"})
        tagged = self.store.set_asset_tags(restricted_asset["id"], [tag["id"]])
        self.assertEqual(tagged["related"]["asset_tags"][0]["id"], tag["id"])
        restricted_alert = self.store.create(
            "alerts",
            {"title": "Restricted alert", "source": "WAF", "severity": "high", "target_asset_id": restricted_asset["id"]},
        )
        restricted_vulnerability = self.store.create(
            "vulnerabilities",
            {"title": "Restricted finding", "severity": "high", "asset_id": restricted_asset["id"], "cvss": 7.5},
        )
        restricted_test = self.store.create(
            "test-projects",
            {
                "name": "Restricted assessment",
                "asset_ids_json": [restricted_asset["id"]],
                "scope_summary": "Restricted lab only",
                "authorization_ticket": "AUTH-LAB",
                "manager": "security-team",
            },
        )
        baseline_finding = self.store.create(
            "baseline-findings",
            {
                "inspection_task_id": "ins_demo_weekly",
                "rule_id": "bsr_demo_headers",
                "asset_id": restricted_asset["id"],
                "severity": "medium",
                "actual_summary": "Restricted baseline finding",
            },
        )

        self.store.set_role_asset_groups("rol_reviewer", [second_group["id"]])
        reviewer_scope = {
            "tenant_id": "local",
            "project_id": "default",
            "user_id": "reviewer-user",
            "role_id": "rol_reviewer",
        }
        visible = self.store.list_records("assets", scope=reviewer_scope)
        self.assertEqual([item["id"] for item in visible["items"]], [restricted_asset["id"]])
        self.assertEqual(self.store.list_records("alerts", scope=reviewer_scope)["items"][0]["id"], restricted_alert["id"])
        self.assertEqual(self.store.list_records("vulnerabilities", scope=reviewer_scope)["items"][0]["id"], restricted_vulnerability["id"])
        self.assertEqual(self.store.list_records("test-projects", scope=reviewer_scope)["items"][0]["id"], restricted_test["id"])
        scoped_orders = self.store.list_records("work-orders", scope=reviewer_scope, filters={"source_id": baseline_finding["id"]})
        self.assertEqual(scoped_orders["total"], 1)
        with self.assertRaises(EnterpriseNotFoundError):
            self.store.get_record("assets", "ast_demo_gateway", scope=reviewer_scope)
        incident = self.store.create(
            "incidents",
            {"title": "Restricted incident", "category": "Intrusion", "severity": "high"},
            scope=reviewer_scope,
        )
        self.store.create(
            "incident-links",
            {"incident_id": incident["id"], "resource_type": "alert", "resource_id": restricted_alert["id"]},
            scope=reviewer_scope,
        )
        self.assertEqual(self.store.list_records("incidents", scope=reviewer_scope)["items"][0]["id"], incident["id"])
        report = self.store.generate_report(
            {"report_type": "weekly", "source_type": "operations", "title": "Reviewer scoped report"},
            scope=reviewer_scope,
        )
        self.assertEqual(self.store.get_record("reports", report["id"], scope=reviewer_scope)["id"], report["id"])
        dashboard = self.store.dashboard(scope=reviewer_scope)
        self.assertEqual(dashboard["counts"]["assets"], 1)
        self.assertEqual(len(dashboard["trends"]["alerts"]), 14)
        self.assertEqual(len(dashboard["trends"]["vulnerabilities"]), 14)

    def test_alert_filter_rule_builtin_cases_and_immutable_login_log(self) -> None:
        rule = self.store.create(
            "alert-rules",
            {
                "name": "Critical WAF notification",
                "source_pattern": "waf",
                "attack_type_pattern": "injection",
                "minimum_severity": "high",
                "action": "notify",
                "priority": 10,
            },
        )
        alert = self.store.create(
            "alerts",
            {
                "title": "Rule matched alert",
                "source": "Edge WAF",
                "severity": "high",
                "attack_type": "Template Injection",
                "target_asset_id": "ast_demo_gateway",
                "source_ip": "203.0.113.77",
            },
        )
        self.assertIn(rule["id"], [item["id"] for item in alert["applied_rules"]])

        project = self.store.create(
            "test-projects",
            {
                "name": "Authorized regression",
                "asset_ids_json": ["ast_demo_gateway"],
                "scope_summary": "Demo gateway only",
                "authorization_ticket": "AUTH-TEST",
                "manager": "unit-tester",
            },
        )
        cases = self.store.list_records("test-cases", filters={"project_id_ref": project["id"]}, page_size=20)
        self.assertGreaterEqual(cases["total"], 5)

        self.store.record_login(success=True, source_ip="127.0.0.1", user_agent="unit-test")
        logs = self.store.list_login_logs()
        self.assertGreaterEqual(logs["total"], 1)
        connection = sqlite3.connect(self.database)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM login_logs")
        connection.close()


class EnterpriseOperationsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="aegis-enterprise-api-")
        cls.server = AegisServer(
            ("127.0.0.1", 0), ROOT, runtime_dir=Path(cls.temp.name) / "runtime"
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(
        self,
        path: str,
        payload: dict[str, object] | None = None,
        method: str = "GET",
    ) -> tuple[dict[str, object], urllib.response.addinfourl]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        response = urllib.request.urlopen(request, timeout=5)
        parsed = json.loads(response.read().decode("utf-8"))
        return parsed, response

    def test_dashboard_todos_schema_and_openapi(self) -> None:
        dashboard, _ = self.request("/api/v1/enterprise/dashboard")
        self.assertGreaterEqual(dashboard["counts"]["assets"], 3)
        todos, _ = self.request("/api/v1/enterprise/todos")
        self.assertGreater(todos["total"], 0)
        schema, _ = self.request("/api/v1/enterprise/schema")
        self.assertGreaterEqual(len(schema["tables"]), 30)
        document, _ = self.request("/api/v1/openapi.json")
        self.assertIn("/api/v1/enterprise/{resource}", document["paths"])
        self.assertIn("/api/v1/enterprise/reports/{id}/export", document["paths"])
        self.assertIn("/api/v1/enterprise/assets/{id}/tags", document["paths"])
        self.assertIn("/api/v1/enterprise/roles/{id}/asset-groups", document["paths"])
        self.assertIn("/api/v1/enterprise/login-logs", document["paths"])
        self.assertEqual(len(dashboard["trends"]["alerts"]), 14)

    def test_create_patch_get_and_audit_api(self) -> None:
        asset, response = self.request(
            "/api/v1/enterprise/assets",
            {"name": "API Managed Asset", "kind": "api", "address": "managed-api.example", "authorization_ticket": "AUTH-API"},
            "POST",
        )
        self.assertEqual(response.status, 201)
        updated, _ = self.request(
            f"/api/v1/enterprise/assets/{asset['id']}",
            {"status": "online", "note": "Health evidence received"},
            "PATCH",
        )
        self.assertEqual(updated["status"], "online")
        detail, _ = self.request(f"/api/v1/enterprise/assets/{asset['id']}")
        self.assertIn("asset_history", detail["related"])
        audit, _ = self.request("/api/v1/enterprise/audit/verify")
        self.assertTrue(audit["valid"])

    def test_report_generation_and_binary_export_api(self) -> None:
        report, response = self.request(
            "/api/v1/enterprise/reports/generate",
            {"report_type": "weekly", "source_type": "operations", "title": "Weekly SOC Report"},
            "POST",
        )
        self.assertEqual(response.status, 201)
        request = urllib.request.Request(
            self.base + f"/api/v1/enterprise/reports/{report['id']}/export?format=pdf"
        )
        with urllib.request.urlopen(request, timeout=5) as exported:
            content = exported.read()
            self.assertEqual(exported.headers.get_content_type(), "application/pdf")
            self.assertTrue(content.startswith(b"%PDF"))
            self.assertIn("attachment", exported.headers.get("Content-Disposition", ""))


class EnterpriseOperationsAuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="aegis-enterprise-auth-")
        cls.previous_token = os.environ.get("AEGIS_API_TOKEN")
        os.environ["AEGIS_API_TOKEN"] = "enterprise-unit-token"
        cls.server = AegisServer(
            ("127.0.0.1", 0), ROOT, runtime_dir=Path(cls.temp.name) / "runtime"
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()
        if cls.previous_token is None:
            os.environ.pop("AEGIS_API_TOKEN", None)
        else:
            os.environ["AEGIS_API_TOKEN"] = cls.previous_token

    def test_readonly_scope_can_read_but_cannot_write(self) -> None:
        headers = {
            "Authorization": f"{'Bearer'} enterprise-unit-token",
            "X-Aegis-Role": "readonly",
            "X-Aegis-Tenant": "tenant_auth",
            "X-Aegis-Project": "project_auth",
        }
        request = urllib.request.Request(self.base + "/api/v1/enterprise/dashboard", headers=headers)
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(payload["counts"]["assets"], 0)
        write_headers = {**headers, "Content-Type": "application/json"}
        request = urllib.request.Request(
            self.base + "/api/v1/enterprise/assets",
            data=json.dumps({"name": "Blocked", "kind": "api", "address": "blocked.example"}).encode("utf-8"),
            headers=write_headers,
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)
        raised.exception.close()
        request = urllib.request.Request(self.base + "/api/v1/enterprise/login-logs", headers=headers)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
