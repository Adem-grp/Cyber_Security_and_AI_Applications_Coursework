import sys
import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import web_app


class TestWebInterface(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.data_dir = Path(self.temp_dir.name) / "web_data"
        self.app = web_app.create_app(
            {
                "TESTING": True,
                "CRYPTOAUDIT_DATA_DIR": str(self.data_dir),
                "SECRET_KEY": "unit-test-secret",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _csrf_token_for(self, path: str) -> str:
        self.client.get(path)
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def test_root_redirects_to_welcome(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/welcome", response.location)

    def test_encrypt_page_uses_plain_algorithm_labels(self):
        response = self.client.get("/app/encrypt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AES-256-GCM", response.data)
        self.assertNotIn(b"(recommended)", response.data)
        self.assertNotIn(b"(deprecated)", response.data)

    def test_audit_page_without_data_shows_empty_message(self):
        response = self.client.get("/app/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No audit data yet. Run an encryption first.", response.data)

    def test_encrypt_requires_legacy_confirmation_for_3des(self):
        csrf = self._csrf_token_for("/app/encrypt")

        response = self.client.post(
            "/encrypt",
            data={
                "csrf_token": csrf,
                "input_mode": "text",
                "input_text": "hello",
                "password": "VeryStrongPassword!123",
                "algorithm": "3des-ofb",
                "confirm_legacy": "no",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"requires explicit confirmation", response.data)

    @mock.patch("cryptoaudit.frontend.web.execute_pipeline")
    def test_encrypt_text_success_path(self, mock_execute_pipeline):
        csrf = self._csrf_token_for("/app/encrypt")

        report_path = Path(self.temp_dir.name) / "report.json"
        report_path.write_text(
            json.dumps(
                {
                    "run_id": "run-123",
                    "timestamp_utc": "2026-04-18T12:00:00Z",
                    "algorithms": [
                        {
                            "name": "aes-256-gcm",
                            "audit": {
                                "verdict": "PASS",
                                "findings": ["AEAD mode validated"],
                                "recommendation": "Keep current settings",
                                "standard_reference": "NIST SP 800-131A Rev.2",
                            },
                            "avalanche": {"difference_percent": 51.23},
                            "benchmark": {"avg_encrypt_ms": 1.2, "throughput_mb_s": 120.5},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        mock_execute_pipeline.return_value = type(
            "Result",
            (),
            {
                "output_dir": "outputs_web",
                "report_json_path": str(report_path),
                "report_html_path": "outputs_web/report.html",
                "encrypted_artifact_paths": ["outputs_web/aes.enc.json"],
                "run_id": "run-123",
            },
        )()

        response = self.client.post(
            "/encrypt",
            data={
                "csrf_token": csrf,
                "input_mode": "text",
                "input_text": "hello",
                "password": "VeryStrongPassword!123",
                "algorithm": "aes-256-gcm",
                "confirm_legacy": "no",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encryption successful", response.data)
        self.assertIn(b"Audit Summary", response.data)
        self.assertIn(b"AEAD mode validated", response.data)
        self.assertIn(b"Generated Output Files", response.data)
        mock_execute_pipeline.assert_called_once()

        with self.client.session_transaction() as sess:
            self.assertIn("last_audit", sess)
            self.assertEqual(sess["last_audit"]["run_id"], "run-123")

    @mock.patch("cryptoaudit.frontend.web.execute_manual_decrypt_pipeline")
    def test_decrypt_warning_is_standards_cited(self, mock_manual_decrypt):
        csrf = self._csrf_token_for("/app/decrypt")
        mock_manual_decrypt.return_value = type(
            "DecryptResult",
            (),
            {
                "output_dir": "outputs_web",
                "artifact_path": "",
                "decrypted_file_path": "outputs_web/restored.bin",
                "warning": "3des-ofb is a compatibility option; decrypted output was produced.",
            },
        )()

        response = self.client.post(
            "/decrypt",
            data={
                "csrf_token": csrf,
                "decrypt_mode": "manual",
                "manual_algorithm": "3des-ofb",
                "manual_pbkdf2_iterations": "600000",
                "manual_salt_b64": "MDEyMzQ1Njc4OWFiY2RlZg==",
                "manual_nonce_b64": "MDEyMzQ1Njc=",
                "manual_ciphertext_b64": "AA==",
                "password": "VeryStrongPassword!123",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023.", response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)



