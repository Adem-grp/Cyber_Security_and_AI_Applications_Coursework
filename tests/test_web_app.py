import sys
import tempfile
import unittest
import json
import io
from pathlib import Path
from unittest import mock
from cryptoaudit.frontend.web import create_app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class TestWebInterface(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.data_dir = Path(self.temp_dir.name) / "web_data"
        self.app = create_app(
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

    def test_start_redirects_to_app_when_csrf_valid(self):
        csrf = self._csrf_token_for("/welcome")
        response = self.client.post(
            "/start",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/app", response.location)

    def test_start_invalid_csrf_redirects_back_to_welcome(self):
        self.client.get("/welcome")
        response = self.client.post(
            "/start",
            data={"csrf_token": "invalid-token"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome to CryptoAudit", response.data)
        self.assertIn(b"Invalid CSRF token", response.data)

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

    def test_decrypt_page_shows_required_output_filename_input(self):
        response = self.client.get("/app/decrypt")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Output filename (required)", response.data)
        self.assertIn(b"e.g. document.pdf, video.mp4, notes.txt", response.data)
        self.assertIn(
            b"Enter the original filename with its extension so the decrypted file downloads correctly.",
            response.data,
        )

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
        html_path = Path(self.temp_dir.name) / "report.html"
        artifact_path = Path(self.temp_dir.name) / "aes.enc.json"
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
        html_path.write_text("<html><body>report</body></html>", encoding="utf-8")
        artifact_path.write_text('{"artifact":"ok"}', encoding="utf-8")

        mock_execute_pipeline.return_value = type(
            "Result",
            (),
            {
                "output_dir": "outputs_web",
                "report_json_path": str(report_path),
                "report_html_path": str(html_path),
                "encrypted_artifact_paths": [str(artifact_path)],
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
        self.assertIn(b"Download Results (ZIP)", response.data)
        self.assertIn(b"run-123", response.data)
        self.assertIn(b"2026-04-18T12:00:00Z", response.data)
        mock_execute_pipeline.assert_called_once()

        with self.client.session_transaction() as sess:
            self.assertIn("audit_history", sess)
            self.assertEqual(sess["audit_history"][0]["run_id"], "run-123")

        download_path = Path(tempfile.gettempdir()) / "cryptoaudit_downloads" / "cryptoaudit_run-123.zip"
        self.assertTrue(download_path.exists())

        download_response = self.client.get("/app/download/run-123", follow_redirects=False)
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.mimetype, "application/zip")
        self.assertIn("cryptoaudit_run-123.zip", download_response.headers.get("Content-Disposition", ""))
        self.assertGreater(len(download_response.data), 0)
        self.assertFalse(download_path.exists())

    @mock.patch("cryptoaudit.frontend.web.execute_manual_decrypt_pipeline")
    def test_decrypt_warning_is_standards_cited(self, mock_manual_decrypt):
        csrf = self._csrf_token_for("/app/decrypt")
        restored_path = Path(self.temp_dir.name) / "restored.bin"
        restored_path.write_bytes(b"restored")
        mock_manual_decrypt.return_value = type(
            "DecryptResult",
            (),
            {
                "output_dir": "outputs_web",
                "artifact_path": "",
                "decrypted_file_path": str(restored_path),
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
                "output_file_name": "restored.bin",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Decryption Result", response.data)
        self.assertIn(
            b"NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023.",
            response.data,
        )

        with self.client.session_transaction() as sess:
            run_id = next(iter(sess.get("decrypt_results", {})))

        download_path = Path(tempfile.gettempdir()) / "cryptoaudit_downloads"
        matches = list(download_path.glob(f"{run_id}_decrypted_*"))
        self.assertTrue(matches)

        download_response = self.client.get(f"/app/download_decrypted/{run_id}", follow_redirects=False)
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.mimetype, "application/octet-stream")
        self.assertIn("filename=restored.bin", download_response.headers.get("Content-Disposition", ""))
        self.assertEqual(download_response.data, b"restored")
        self.assertFalse(matches[0].exists())

    @mock.patch("cryptoaudit.frontend.web.execute_decrypt_pipeline")
    def test_decrypt_download_uses_user_filename_when_provided(self, mock_decrypt_pipeline):
        csrf = self._csrf_token_for("/app/decrypt")
        restored_path = Path(self.temp_dir.name) / "restored.bin"
        restored_path.write_bytes(b"restored")
        mock_decrypt_pipeline.return_value = type(
            "DecryptResult",
            (),
            {
                "output_dir": "outputs_web",
                "artifact_path": "",
                "decrypted_file_path": str(restored_path),
                "warning": None,
            },
        )()

        response = self.client.post(
            "/decrypt",
            data={
                "csrf_token": csrf,
                "decrypt_mode": "artifact",
                "password": "VeryStrongPassword!123",
                "output_file_name": "document.pdf",
                "artifact_file": (io.BytesIO(b"{}"), "20260419T100000Z_invoice.pdf_enc.json"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Decryption Result", response.data)

        with self.client.session_transaction() as sess:
            run_id = next(iter(sess.get("decrypt_results", {})))

        download_response = self.client.get(f"/app/download_decrypted/{run_id}", follow_redirects=False)
        self.assertEqual(download_response.status_code, 200)
        self.assertIn("filename=document.pdf", download_response.headers.get("Content-Disposition", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)

