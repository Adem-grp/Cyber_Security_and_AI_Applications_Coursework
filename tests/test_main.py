import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main


class TestCliParsing(unittest.TestCase):
    def test_parse_args_with_text(self):
        with mock.patch.object(sys, "argv", ["main.py", "--text", "hello"]):
            args = main.parse_args()
        self.assertEqual(args.input_text, "hello")
        self.assertIsNone(args.input_file)

    def test_main_without_args_launches_interface(self):
        with mock.patch.object(sys, "argv", ["main.py"]):
            with mock.patch(
                "cryptoaudit.backend.core.launch_interface",
                return_value=0,
            ) as mocked_launch:
                rc = main.main()
        self.assertEqual(rc, 0)
        mocked_launch.assert_called_once()

    def test_validate_cli_mode_args_encrypt_requires_input(self):
        args = argparse.Namespace(
            mode="encrypt",
            input_file=None,
            input_text=None,
            artifact_file=None,
        )
        with self.assertRaises(ValueError):
            main.validate_cli_mode_args(args)

    def test_validate_cli_mode_args_decrypt_requires_artifact(self):
        args = argparse.Namespace(
            mode="decrypt",
            input_file=None,
            input_text=None,
            artifact_file=None,
        )
        with self.assertRaises(ValueError):
            main.validate_cli_mode_args(args)


class TestConfigAndInputValidation(unittest.TestCase):
    def test_load_config_defaults(self):
        cfg = main.load_config(None)
        self.assertIn(main.ALGO_AES_GCM, cfg.algorithms)
        self.assertEqual(cfg.pbkdf2_iterations, main.DEFAULT_PBKDF2_ITERATIONS)

    def test_load_config_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cfg.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "algorithms": [main.ALGO_AES_GCM],
                        "pbkdf2_iterations": 600000,
                        "benchmark_iterations": 10,
                        "benchmark_payload_size": 1048576,
                        "max_file_size_bytes": 104857600,
                        "output_dir": "outputs",
                    }
                ),
                encoding="utf-8",
            )
            cfg = main.load_config(str(cfg_path))
            self.assertEqual(cfg.algorithms, [main.ALGO_AES_GCM])

    def test_validate_config_rejects_bad_ranges(self):
        cfg = main.AppConfig(pbkdf2_iterations=99999)
        with self.assertRaises(ValueError):
            main.validate_config(cfg)

    def test_validate_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = main.validate_output_dir(tmp)
            self.assertTrue(out.exists())
            self.assertTrue(out.is_dir())

    def test_load_input_from_text(self):
        payload, meta = main.load_input(None, "abc", 1024 * 1024)
        self.assertEqual(payload, b"abc")
        self.assertEqual(meta["source"], "text")

    def test_load_input_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "data.txt"
            p.write_text("hello", encoding="utf-8")
            payload, meta = main.load_input(str(p), None, 1024 * 1024)
            self.assertEqual(payload, b"hello")
            self.assertEqual(meta["source"], "file")


class TestPasswordHandling(unittest.TestCase):
    def test_get_password_from_env(self):
        with mock.patch.dict(os.environ, {"CRYPTOAUDIT_TEST_PASS": "MySecret"}, clear=False):
            value = main.get_password("CRYPTOAUDIT_TEST_PASS")
        self.assertIsInstance(value, bytearray)
        self.assertEqual(bytes(value), b"MySecret")

    def test_get_password_from_prompt(self):
        with mock.patch("getpass.getpass", return_value="PromptSecret"):
            value = main.get_password(None)
        self.assertEqual(bytes(value), b"PromptSecret")

    def test_wipe_bytearray(self):
        buf = bytearray(b"sensitive")
        main.wipe_bytearray(buf)
        self.assertTrue(all(b == 0 for b in buf))


class TestCryptoFunctions(unittest.TestCase):
    def test_derive_key_deterministic(self):
        password = bytearray(b"pass")
        salt = b"1234567890abcdef"
        k1 = main.derive_key(password, salt, 100000, 32)
        k2 = main.derive_key(password, salt, 100000, 32)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_encrypt_payload_supported_algorithms(self):
        plaintext = b"payload"
        aes = main.encrypt_payload(main.ALGO_AES_GCM, os.urandom(32), os.urandom(12), plaintext)
        aes_192 = main.encrypt_payload(main.ALGO_AES_192_GCM, os.urandom(24), os.urandom(12), plaintext)
        aes_128 = main.encrypt_payload(main.ALGO_AES_128_GCM, os.urandom(16), os.urandom(12), plaintext)
        cha = main.encrypt_payload(main.ALGO_CHACHA, os.urandom(32), os.urandom(12), plaintext)
        des = main.encrypt_payload(main.ALGO_3DES, os.urandom(24), os.urandom(8), plaintext)
        self.assertNotEqual(aes, plaintext)
        self.assertNotEqual(aes_192, plaintext)
        self.assertNotEqual(aes_128, plaintext)
        self.assertNotEqual(cha, plaintext)
        self.assertNotEqual(des, plaintext)

    def test_hamming_distance_bits(self):
        # 0b00000000 vs 0b11111111 differs by 8 bits.
        diff = main.hamming_distance_bits(b"\x00", b"\xff")
        self.assertEqual(diff, 8)

    def test_avalanche_test_shape(self):
        result = main.avalanche_test(main.ALGO_AES_GCM, os.urandom(32), b"hello world")
        self.assertIn("difference_percent", result)
        self.assertGreaterEqual(result["difference_percent"], 0.0)

    def test_benchmark_algorithm_shape(self):
        result = main.benchmark_algorithm(main.ALGO_AES_GCM, os.urandom(32), b"A" * 4096, 2)
        self.assertIn("avg_encrypt_ms", result)
        self.assertIn("throughput_mb_s", result)


class TestAuditAndReporting(unittest.TestCase):
    def test_run_audit_warns_for_3des(self):
        cfg = main.AppConfig()
        verdict = main.run_audit(main.ALGO_3DES, cfg, 50.0)
        self.assertEqual(verdict.verdict, "WARN")

    def test_run_audit_fails_for_ecb_override(self):
        cfg = main.AppConfig(mode_overrides={main.ALGO_AES_GCM: "ECB"})
        verdict = main.run_audit(main.ALGO_AES_GCM, cfg, 50.0)
        self.assertEqual(verdict.verdict, "FAIL")

    def test_b64(self):
        self.assertEqual(main.b64(b"abc"), "YWJj")

    def test_build_html_report_escapes_findings(self):
        report = {
            "run_id": "run1",
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "input_metadata": {"source": "text"},
            "algorithms": [
                {
                    "name": "aes-256-gcm",
                    "audit": {
                        "verdict": "PASS",
                        "standard_reference": "NIST",
                        "findings": ["<script>alert(1)</script>"],
                    },
                    "benchmark": {"avg_encrypt_ms": 1.1, "throughput_mb_s": 2.2},
                }
            ],
        }
        html = main.build_html_report(report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)


class TestIntegration(unittest.TestCase):
    def test_execute_pipeline_generates_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = main.AppConfig(
                algorithms=[main.ALGO_AES_GCM],
                pbkdf2_iterations=100000,
                benchmark_iterations=1,
                benchmark_payload_size=4096,
                max_file_size_bytes=1024 * 1024,
                output_dir=str(Path(tmp) / "out"),
            )
            password = bytearray(b"test-password")
            result = main.execute_pipeline(config=cfg, input_file=None, input_text="integration", password=password)
            main.wipe_bytearray(password)

            self.assertTrue(Path(result.report_json_path).exists())
            self.assertTrue(Path(result.report_html_path).exists())
            self.assertEqual(len(result.encrypted_artifact_paths), 1)

            report_obj = json.loads(Path(result.report_json_path).read_text(encoding="utf-8"))
            self.assertNotIn("integration", json.dumps(report_obj))

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["CRYPTOAUDIT_PASSWORD"] = "CliPass!123"
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "main.py"),
                "--text",
                "cli integration payload",
                "--password-env",
                "CRYPTOAUDIT_PASSWORD",
                "--output-dir",
                str(Path(tmp) / "out"),
            ]
            completed = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, msg=completed.stderr)
            self.assertIn("Success: encrypted artifacts written", completed.stdout)

    def test_execute_decrypt_pipeline_roundtrip_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "out"
            cfg = main.AppConfig(
                algorithms=[main.ALGO_AES_GCM],
                pbkdf2_iterations=100000,
                benchmark_iterations=1,
                benchmark_payload_size=4096,
                max_file_size_bytes=20 * 1024 * 1024,
                output_dir=str(output_dir),
            )

            video_like_bytes = os.urandom(512 * 1024)
            input_file = Path(tmp) / "clip.mp4"
            input_file.write_bytes(video_like_bytes)

            password = bytearray(b"RoundTripPass!123")
            encrypt_result = main.execute_pipeline(
                config=cfg,
                input_file=str(input_file),
                input_text=None,
                password=password,
            )

            artifact_path = encrypt_result.encrypted_artifact_paths[0]
            decrypt_result = main.execute_decrypt_pipeline(
                artifact_file=artifact_path,
                password=password,
                output_dir=str(output_dir),
                output_file_name="clip_restored.mp4",
                allow_overwrite=False,
            )
            main.wipe_bytearray(password)

            restored = Path(decrypt_result.decrypted_file_path).read_bytes()
            self.assertEqual(restored, video_like_bytes)

    def test_execute_decrypt_pipeline_fails_with_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "out"
            cfg = main.AppConfig(
                algorithms=[main.ALGO_AES_GCM],
                pbkdf2_iterations=100000,
                benchmark_iterations=1,
                benchmark_payload_size=4096,
                max_file_size_bytes=1024 * 1024,
                output_dir=str(output_dir),
            )

            password = bytearray(b"CorrectPassword!")
            encrypt_result = main.execute_pipeline(
                config=cfg,
                input_file=None,
                input_text="decrypt me",
                password=password,
            )

            wrong_password = bytearray(b"WrongPassword!")
            with self.assertRaises(ValueError):
                main.execute_decrypt_pipeline(
                    artifact_file=encrypt_result.encrypted_artifact_paths[0],
                    password=wrong_password,
                    output_dir=str(output_dir),
                    output_file_name="wrong.bin",
                    allow_overwrite=False,
                )
            main.wipe_bytearray(password)
            main.wipe_bytearray(wrong_password)


if __name__ == "__main__":
    unittest.main(verbosity=2)
