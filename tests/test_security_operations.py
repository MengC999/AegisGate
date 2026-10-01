from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.operations import OperationsValidationError, SecurityOperationsStore  # noqa: E402
from src.aegisguard.web import AegisServer  # noqa: E402


class SecurityOperationsStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-ops-")
        root = Path(self.temp.name)
        self.store = SecurityOperationsStore(
            ROOT / "data" / "security_operations_demo.json",
            root / "runtime.json",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_seed_overview_is_content_safe_and_counts_resources(self) -> None:
        overview = self.store.overview()
        self.assertEqual(overview["data_mode"], "demo_seed")
        self.assertEqual(overview["counts"]["assets"], 3)
        self.assertEqual(overview["counts"]["critical_alerts"], 1)
        self.assertFalse(overview["audit_integrity"]["valid"] is False)
        self.assertNotIn("raw_evidence", json.dumps(overview).replace("raw_evidence_persisted", ""))

    def test_create_and_state_change_are_hash_chained(self) -> None:
        item = self.store.create(
            "assets",
            {
                "name": "Authorized Test API",
                "kind": "api",
                "address": "api.test.example",
                "authorization_scope": "ticket-123",
            },
        )
        self.assertTrue(item["id"].startswith("ast_"))
        updated = self.store.update_state("assets", item["id"], "offline", note="maintenance")
        self.assertEqual(updated["status"], "offline")
        verification = self.store.verify_events()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["entries"], 2)

    def test_ioc_validation_rejects_mismatched_value(self) -> None:
        with self.assertRaises(OperationsValidationError):
            self.store.create("iocs", {"type": "ip", "value": "not-an-ip", "source": "test"})

    def test_vulnerability_cve_and_cvss_are_validated(self) -> None:
        with self.assertRaises(OperationsValidationError):
            self.store.create(
                "vulnerabilities",
                {"title": "invalid", "cve": "CVE-nope", "cvss": 5},
            )
        with self.assertRaises(OperationsValidationError):
            self.store.create(
                "vulnerabilities",
                {"title": "invalid", "cve": "CVE-2026-1234", "cvss": 12},
            )

    def test_scope_isolation_and_alert_deduplication(self) -> None:
        first = self.store.create(
            "alerts",
            {
                "title": "Repeated signal",
                "source": "gateway",
                "severity": "high",
                "attack_type": "prompt_injection",
                "source_indicator": "198.51.100.8",
                "repeat_count": 2,
            },
            scope={"tenant_id": "tenant_a", "project_id": "project_x", "user_id": "analyst_a"},
        )
        second = self.store.create(
            "alerts",
            {
                "title": "Repeated signal",
                "source": "gateway",
                "severity": "high",
                "attack_type": "prompt_injection",
                "source_indicator": "198.51.100.8",
                "repeat_count": 3,
            },
            scope={"tenant_id": "tenant_a", "project_id": "project_x", "user_id": "analyst_a"},
        )
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(second["repeat_count"], 5)
        self.assertEqual(self.store.list_records("alerts", tenant_id="tenant_a", project_id="project_x")["total"], 1)
        self.assertEqual(self.store.list_records("alerts", tenant_id="tenant_b", project_id="project_x")["total"], 0)

    def test_alert_indicator_rejects_payload_like_values(self) -> None:
        with self.assertRaises(OperationsValidationError):
            self.store.create(
                "alerts",
                {
                    "title": "unsafe",
                    "source": "test",
                    "attack_type": "x",
                    "source_indicator": "198.51.100.8; whoami",
                },
            )


class SecurityOperationsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="aegis-ops-web-")
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

    def request(self, path: str, payload: dict[str, object] | None = None, method: str = "GET") -> dict[str, object]:
        body = None
        headers = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=4) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_overview_and_lists_are_available(self) -> None:
        overview = self.request("/api/v1/ops/overview")
        self.assertEqual(overview["counts"]["assets"], 3)
        alerts = self.request("/api/v1/ops/alerts?severity=critical")
        self.assertEqual(alerts["total"], 1)
        self.assertEqual(alerts["items"][0]["severity"], "critical")

    def test_observability_metrics_contract(self) -> None:
        metrics = self.request("/api/v1/observability/metrics")
        self.assertEqual(metrics["schema_version"], "1.0")
        self.assertIn("p95_latency_ms", metrics)
        self.assertIn("model_failure_rate", metrics)

    def test_openapi_contains_new_contracts(self) -> None:
        document = self.request("/api/v1/openapi.json")
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertIn("/api/v1/privacy/scan", document["paths"])
        self.assertIn("/api/v1/ops/{resource}", document["paths"])

    def test_privacy_scan_returns_only_transformed_text(self) -> None:
        payload = self.request(
            "/api/v1/privacy/scan",
            {"text": "contact 13800138000 or demo@example.com", "strategy": "hash"},
            method="POST",
        )
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertGreaterEqual(payload["match_count"], 1)
        self.assertNotIn("13800138000", payload["safe_text"])
        self.assertNotIn("demo@example.com", payload["safe_text"])

    def test_create_patch_and_verify(self) -> None:
        created = self.request(
            "/api/v1/ops/incidents",
            {"title": "Authorized review event", "category": "Review", "severity": "low"},
            method="POST",
        )
        self.assertTrue(created["id"].startswith("inc_"))
        updated = self.request(
            f"/api/v1/ops/incidents/{created['id']}",
            {"state": "contained", "note": "ticket-ops-1"},
            method="PATCH",
        )
        self.assertEqual(updated["stage"], "contained")
        verified = self.request("/api/v1/ops/events/verify")
        self.assertTrue(verified["valid"])

    def test_tenant_header_isolation(self) -> None:
        request = urllib.request.Request(
            self.base + "/api/v1/ops/overview",
            headers={"X-Aegis-Tenant": "tenant_missing", "X-Aegis-Project": "default"},
        )
        with urllib.request.urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(payload["counts"]["assets"], 0)


class SecurityOperationsAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="aegis-ops-auth-")
        cls.previous_token = os.environ.get("AEGIS_API_TOKEN")
        os.environ["AEGIS_API_TOKEN"] = "unit-test-token"
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

    def request(self, path: str, payload: dict[str, object] | None = None, method: str = "GET", role: str = "admin") -> dict[str, object]:
        body = None
        headers = {
            "Authorization": "Bearer unit-test-token",
            "X-Aegis-Role": role,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=4) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_readonly_can_read_but_cannot_create(self) -> None:
        overview = self.request("/api/v1/ops/overview", role="readonly")
        self.assertIn("counts", overview)
        request = urllib.request.Request(
            self.base + "/api/v1/ops/incidents",
            data=json.dumps({"title": "blocked", "category": "test"}).encode("utf-8"),
            headers={
                "Authorization": "Bearer unit-test-token",
                "X-Aegis-Role": "readonly",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=4)
        self.assertEqual(raised.exception.code, 403)
        raised.exception.close()

    def test_unknown_resource_returns_json_400(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/v1/ops/unknown")
        self.assertEqual(raised.exception.code, 400)
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
