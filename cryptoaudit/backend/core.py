from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import html
import json
import os
import subprocess
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024
DEFAULT_PBKDF2_ITERATIONS = 600_000
DEFAULT_BENCHMARK_ITERATIONS = 10
DEFAULT_BENCHMARK_PAYLOAD_SIZE = 1 * 1024 * 1024

ALGO_AES_GCM = "aes-256-gcm"
ALGO_AES_192_GCM = "aes-192-gcm"
ALGO_AES_128_GCM = "aes-128-gcm"
ALGO_CHACHA = "chacha20-poly1305"
ALGO_3DES = "3des-ofb"
ALGO_DES_CBC = "des-cbc"
ALGO_RC4 = "rc4"

ALGORITHM_SPECS: Dict[str, Dict[str, Any]] = {
    ALGO_AES_GCM: {
        "key_len": 32,
        "nonce_len": 12,
        "status": "recommended",
        "mode": "GCM",
        "standard_ref": "NIST SP 800-131A Rev.2, FIPS 140-3",
    },
    ALGO_AES_192_GCM: {
        "key_len": 24,
        "nonce_len": 12,
        "status": "recommended",
        "mode": "GCM",
        "standard_ref": "NIST SP 800-131A Rev.2, FIPS 140-3",
    },
    ALGO_AES_128_GCM: {
        "key_len": 16,
        "nonce_len": 12,
        "status": "recommended",
        "mode": "GCM",
        "standard_ref": "NIST SP 800-131A Rev.2, FIPS 140-3",
    },
    ALGO_CHACHA: {
        "key_len": 32,
        "nonce_len": 12,
        "status": "recommended",
        "mode": "Poly1305",
        "standard_ref": "RFC 8439 (ChaCha20-Poly1305 Internet Standard), FIPS 140-3 context-dependent",
    },
    ALGO_3DES: {
        "key_len": 24,
        "nonce_len": 8,
        "status": "compatible",
        "mode": "OFB",
        "standard_ref": "NIST SP 800-131A Rev.2 transition guidance, FIPS 140-3 transition concerns",
    },
    ALGO_DES_CBC: {
        "key_len": 8,
        "nonce_len": 8,
        "status": "deprecated-blocked",
        "mode": "CBC",
        "standard_ref": "Deprecated; blocked for security policy compliance",
    },
    ALGO_RC4: {
        "key_len": 16,
        "nonce_len": 0,
        "status": "deprecated-blocked",
        "mode": "stream",
        "standard_ref": "Deprecated; blocked for security policy compliance",
    },
}


BLOCKED_DEPRECATED_ALGORITHMS = {
    ALGO_DES_CBC: "DES-CBC is deprecated and blocked.",
    ALGO_RC4: "RC4 is deprecated and blocked.",
}


@dataclass
class AppConfig:
    algorithms: List[str] = field(default_factory=lambda: [ALGO_AES_GCM, ALGO_CHACHA, ALGO_3DES])
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS
    benchmark_iterations: int = DEFAULT_BENCHMARK_ITERATIONS
    benchmark_payload_size: int = DEFAULT_BENCHMARK_PAYLOAD_SIZE
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE
    output_dir: str = "outputs"
    mode_overrides: Dict[str, str] = field(default_factory=dict)
    detect_reused_iv_in_config: bool = False


@dataclass
class AuditVerdict:
    algorithm: str
    verdict: str
    standard_reference: str
    findings: List[str]
    recommendation: str


@dataclass
class BenchmarkResult:
    algorithm: str
    kdf_ms: float
    avg_encrypt_ms: float
    min_encrypt_ms: float
    max_encrypt_ms: float
    stddev_encrypt_ms: float
    throughput_mb_s: float
    iterations: int


@dataclass
class RunArtifacts:
    """Return paths from a completed run for UI and CLI consumers."""
    output_dir: str
    report_json_path: str
    report_html_path: str
    encrypted_artifact_paths: List[str]
    run_id: str


@dataclass
class DecryptArtifacts:
    """Return paths and metadata from a completed decrypt operation."""
    output_dir: str
    artifact_path: str
    decrypted_file_path: str
    algorithm: str
    warning: Optional[str]


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments and enforce mutually exclusive input sources."""
    parser = argparse.ArgumentParser(description="CryptoAudit - local cryptographic benchmark and audit tool")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], default="encrypt", help="Operation mode")

    source_group = parser.add_mutually_exclusive_group(required=False)
    source_group.add_argument("--file", dest="input_file", help="Path to input file")
    source_group.add_argument("--text", dest="input_text", help="Raw text input")

    parser.add_argument("--artifact", dest="artifact_file", help="Path to encrypted artifact JSON (decrypt mode)")
    parser.add_argument("--decrypt-output-file", dest="decrypt_output_file", help="Optional output filename for decrypted bytes")
    parser.add_argument("--allow-overwrite", action="store_true", help="Allow overwrite of existing decrypt output file")

    parser.add_argument("--config", dest="config_file", help="Path to JSON config file")
    parser.add_argument("--output-dir", dest="output_dir", help="Output directory")
    parser.add_argument(
        "--password-env",
        dest="password_env",
        help="Optional environment variable name to read password from (for automation)",
    )
    return parser.parse_args()


def validate_cli_mode_args(args: argparse.Namespace) -> None:
    """Validate mode-specific required and forbidden CLI argument combinations."""
    has_encrypt_input = bool(args.input_file) ^ bool(args.input_text)
    if args.mode == "encrypt":
        if not has_encrypt_input:
            raise ValueError("Encrypt mode requires exactly one input source: --file or --text")
        if args.artifact_file:
            raise ValueError("--artifact is only valid in decrypt mode")
        return

    if not args.artifact_file:
        raise ValueError("Decrypt mode requires --artifact")
    if args.input_file or args.input_text:
        raise ValueError("Decrypt mode does not accept --file/--text inputs")


def load_config(config_path: Optional[str]) -> AppConfig:
    """Load JSON configuration from disk or return secure defaults."""
    if not config_path:
        return AppConfig()

    path = Path(config_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Config file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in config: {exc}") from exc

    config = AppConfig(
        algorithms=data.get("algorithms", [ALGO_AES_GCM, ALGO_CHACHA, ALGO_3DES]),
        pbkdf2_iterations=data.get("pbkdf2_iterations", DEFAULT_PBKDF2_ITERATIONS),
        benchmark_iterations=data.get("benchmark_iterations", DEFAULT_BENCHMARK_ITERATIONS),
        benchmark_payload_size=data.get("benchmark_payload_size", DEFAULT_BENCHMARK_PAYLOAD_SIZE),
        max_file_size_bytes=data.get("max_file_size_bytes", DEFAULT_MAX_FILE_SIZE),
        output_dir=data.get("output_dir", "outputs"),
        mode_overrides=data.get("mode_overrides", {}),
        detect_reused_iv_in_config=data.get("detect_reused_iv_in_config", False),
    )
    validate_config(config)
    return config


def validate_config(config: AppConfig) -> None:
    """Validate config values against allowed algorithm and numeric ranges."""
    allowed_algorithms = set(ALGORITHM_SPECS)
    if not config.algorithms:
        raise ValueError("At least one algorithm must be selected")
    if any(alg not in allowed_algorithms for alg in config.algorithms):
        raise ValueError(f"Unsupported algorithm configured: {config.algorithms}")

    blocked_selected = [alg for alg in config.algorithms if alg in BLOCKED_DEPRECATED_ALGORITHMS]
    if blocked_selected:
        details = "; ".join(BLOCKED_DEPRECATED_ALGORITHMS[alg] for alg in blocked_selected)
        raise ValueError(
            "Blocked deprecated algorithms selected: "
            f"{', '.join(blocked_selected)}. {details} Choose AES-GCM, ChaCha20-Poly1305, or 3DES-OFB for compatibility testing."
        )

    if not (100_000 <= int(config.pbkdf2_iterations) <= 5_000_000):
        raise ValueError("pbkdf2_iterations must be between 100000 and 5000000")

    if not (1 <= int(config.benchmark_iterations) <= 1000):
        raise ValueError("benchmark_iterations must be between 1 and 1000")

    if not (1 * 1024 * 1024 <= int(config.max_file_size_bytes) <= 1 * 1024 * 1024 * 1024):
        raise ValueError("max_file_size_bytes must be between 1MB and 1GB")

    if not (4 * 1024 <= int(config.benchmark_payload_size) <= 64 * 1024 * 1024):
        raise ValueError("benchmark_payload_size must be between 4KB and 64MB")


def validate_output_dir(path_str: str) -> Path:
    """Resolve, create, and verify the output directory is writable."""
    output_dir = Path(path_str).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.exists() or not output_dir.is_dir():
        raise ValueError(f"Invalid output directory: {output_dir}")

    probe = output_dir / ".write_test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise ValueError(f"Output directory is not writable: {output_dir}") from exc
    return output_dir


def load_input(input_file: Optional[str], input_text: Optional[str], max_size: int) -> Tuple[bytes, Dict[str, Any]]:
    """Load input bytes from file or text and return metadata for reporting."""
    if input_file:
        path = Path(input_file).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise ValueError(f"Input file not found: {path}")
        if not os.access(path, os.R_OK):
            raise ValueError(f"Input file is not readable: {path}")

        size = path.stat().st_size
        if size > max_size:
            raise ValueError(f"Input file exceeds size limit ({size} > {max_size} bytes)")

        data = path.read_bytes()
        meta = {
            "source": "file",
            "file_name": path.name,
            "file_size": size,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return data, meta

    if input_text is None:
        raise ValueError("Either input file or input text must be provided")

    data = input_text.encode("utf-8")
    if len(data) > max_size:
        raise ValueError(f"Text input exceeds size limit ({len(data)} > {max_size} bytes)")

    meta = {
        "source": "text",
        "text_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, meta


def get_password(password_env: Optional[str]) -> bytearray:
    """Read password from environment variable or secure terminal prompt."""
    if password_env:
        value = os.environ.get(password_env)
        if not value:
            raise ValueError(f"Environment variable '{password_env}' is not set or empty")
        return bytearray(value.encode("utf-8"))

    prompt_password = getpass.getpass("Enter password: ")
    if not prompt_password:
        raise ValueError("Password cannot be empty")
    return bytearray(prompt_password.encode("utf-8"))


def wipe_bytearray(buf: bytearray) -> None:
    """Best-effort in-place overwrite of sensitive bytearray contents."""
    for i in range(len(buf)):
        buf[i] = 0


def derive_key(password: bytearray, salt: bytes, iterations: int, key_len: int) -> bytes:
    """Derive a symmetric key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", bytes(password), salt, iterations, dklen=key_len)


def encrypt_payload(algorithm: str, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with the selected algorithm and nonce/IV."""
    if algorithm in {ALGO_AES_GCM, ALGO_AES_192_GCM, ALGO_AES_128_GCM}:
        return AESGCM(key).encrypt(nonce, plaintext, None)
    if algorithm == ALGO_CHACHA:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    if algorithm == ALGO_3DES:
        padder = padding.PKCS7(64).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.OFB(nonce))
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def decrypt_payload(algorithm: str, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with the selected algorithm and nonce/IV."""
    if algorithm in {ALGO_AES_GCM, ALGO_AES_192_GCM, ALGO_AES_128_GCM}:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    if algorithm == ALGO_CHACHA:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    if algorithm == ALGO_3DES:
        cipher = Cipher(algorithms.TripleDES(key), modes.OFB(nonce))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    """Compute bit-level Hamming distance between two byte strings."""
    max_len = max(len(a), len(b))
    a2 = a.ljust(max_len, b"\x00")
    b2 = b.ljust(max_len, b"\x00")
    return sum((x ^ y).bit_count() for x, y in zip(a2, b2))


def avalanche_test(algorithm: str, key: bytes, plaintext: bytes) -> Dict[str, float]:
    """Measure avalanche effect by flipping one input bit and comparing ciphertexts."""
    baseline = plaintext if plaintext else b"\x00"
    modified = bytearray(baseline)
    modified[0] ^= 0x01

    nonce_len = ALGORITHM_SPECS[algorithm]["nonce_len"]
    fixed_nonce = bytes([0xA5] * nonce_len)

    ct1 = encrypt_payload(algorithm, key, fixed_nonce, baseline)
    ct2 = encrypt_payload(algorithm, key, fixed_nonce, bytes(modified))

    bit_diff = hamming_distance_bits(ct1, ct2)
    total_bits = max(len(ct1), len(ct2)) * 8
    ratio = (bit_diff / total_bits * 100.0) if total_bits else 0.0

    return {
        "bit_difference": float(bit_diff),
        "total_bits": float(total_bits),
        "difference_percent": round(ratio, 3),
    }


def benchmark_algorithm(algorithm: str, key: bytes, payload: bytes, iterations: int) -> Dict[str, float]:
    """Benchmark encryption latency and throughput across multiple iterations."""
    samples_ms: List[float] = []
    nonce_len = ALGORITHM_SPECS[algorithm]["nonce_len"]

    for _ in range(iterations):
        nonce = os.urandom(nonce_len)
        t0 = time.perf_counter()
        _ = encrypt_payload(algorithm, key, nonce, payload)
        t1 = time.perf_counter()
        samples_ms.append((t1 - t0) * 1000.0)

    avg_ms = statistics.mean(samples_ms)
    avg_sec = avg_ms / 1000.0
    throughput = (len(payload) / (1024 * 1024) / avg_sec) if avg_sec > 0 else 0.0

    return {
        "avg_encrypt_ms": round(avg_ms, 4),
        "min_encrypt_ms": round(min(samples_ms), 4),
        "max_encrypt_ms": round(max(samples_ms), 4),
        "stddev_encrypt_ms": round(statistics.pstdev(samples_ms), 4),
        "throughput_mb_s": round(throughput, 4),
    }


def run_audit(algorithm: str, config: AppConfig, avalanche_percent: float) -> AuditVerdict:
    """Produce standards-oriented pass/warn/fail verdicts and recommendations."""
    spec = ALGORITHM_SPECS[algorithm]
    findings: List[str] = []
    verdict = "PASS"
    recommendation = "Configuration is aligned with modern secure defaults."

    if spec["status"] != "recommended":
        verdict = "WARN"
        findings.append(f"{algorithm} is a compatibility option and is not recommended for new systems.")
        recommendation = "Prefer modern authenticated algorithms such as AES-GCM or ChaCha20-Poly1305."

    mode_override = config.mode_overrides.get(algorithm, "").strip().upper()
    if mode_override == "ECB":
        verdict = "FAIL"
        findings.append("ECB mode configured; ECB is unsafe and leaks plaintext patterns.")
        recommendation = "Disable ECB and use authenticated modes such as GCM or Poly1305."

    if config.detect_reused_iv_in_config:
        if verdict != "FAIL":
            verdict = "WARN"
        findings.append("Config indicates possible IV/nonce reuse; this can break confidentiality/integrity.")
        recommendation = "Ensure a fresh random IV/nonce for every encryption operation."

    pbkdf2_n = int(config.pbkdf2_iterations)
    if pbkdf2_n < 200000:
        verdict = "FAIL"
        findings.append(
            f"PBKDF2 iteration count ({pbkdf2_n}) is critically low. "
            "NIST SP 800-132 recommends a minimum of 210,000 iterations as "
            "of 2023. Current setting is insufficient for secure key "
            "derivation."
        )
        recommendation = "Increase PBKDF2 iterations to 600000 or above."
    elif pbkdf2_n < 600000:
        if verdict == "PASS":
            verdict = "WARN"
        findings.append(
            f"PBKDF2 iteration count ({pbkdf2_n}) meets the minimum but falls below the recommended value of 600,000 "
            "per NIST SP 800-132 guidance."
        )
        recommendation = "Increase PBKDF2 iterations to 600000 or above."

    if avalanche_percent < 40.0 or avalanche_percent > 60.0:
        aead_algorithms = {ALGO_AES_GCM, ALGO_AES_192_GCM, ALGO_AES_128_GCM, ALGO_CHACHA}
        if avalanche_percent < 40.0 and algorithm in aead_algorithms:
            verdict = "PASS"
            findings.append(
                "Avalanche measured at "
                f"{avalanche_percent:.2f}%. "
                "AEAD modes (GCM, ChaCha20-Poly1305) use CTR/stream XOR construction — "
                "single-bit input changes produce localised output changes by design. "
                "This is expected behaviour and does not indicate a weakness."
            )
        elif avalanche_percent < 40.0 and algorithm == ALGO_3DES:
            if verdict == "PASS":
                verdict = "WARN"
            findings.append(
                "Avalanche measured at "
                f"{avalanche_percent:.2f}%. "
                "AEAD modes (GCM, ChaCha20-Poly1305) use CTR/stream XOR construction — "
                "single-bit input changes produce localised output changes by design. "
                "This is expected behaviour and does not indicate a weakness."
            )
        else:
            if verdict == "PASS":
                verdict = "WARN"
            findings.append(
                "Avalanche effect outside expected range "
                f"(measured {avalanche_percent:.2f}%). "
                "Note: this metric is statistically unreliable for short inputs (under 64 bytes). "
                "Re-test with larger payloads before drawing conclusions."
            )

    if not findings:
        findings.append("No issues detected.")

    return AuditVerdict(
        algorithm=algorithm,
        verdict=verdict,
        standard_reference=spec["standard_ref"],
        findings=findings,
        recommendation=recommendation,
    )


def b64(data: bytes) -> str:
    """Encode bytes to ASCII Base64 for JSON-safe output fields."""
    return base64.b64encode(data).decode("ascii")


def build_html_report(report: Dict[str, Any]) -> str:
    """Render a compact human-readable HTML report from run data."""
    rows = []
    for entry in report["algorithms"]:
        findings = "<br>".join(html.escape(item) for item in entry["audit"]["findings"])
        rows.append(
            "<tr>"
            f"<td>{html.escape(entry['name'])}</td>"
            f"<td>{html.escape(entry['audit']['verdict'])}</td>"
            f"<td>{html.escape(entry['audit']['standard_reference'])}</td>"
            f"<td>{findings}</td>"
            f"<td>{entry['benchmark']['avg_encrypt_ms']}</td>"
            f"<td>{entry['benchmark']['throughput_mb_s']}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>CryptoAudit Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f5f5f5; }}
    .meta {{ margin-bottom: 16px; }}
  </style>
</head>
<body>
  <h1>CryptoAudit Report</h1>
  <div class=\"meta\">
    <p><strong>Run ID:</strong> {html.escape(report['run_id'])}</p>
    <p><strong>Timestamp (UTC):</strong> {html.escape(report['timestamp_utc'])}</p>
    <p><strong>Input Source:</strong> {html.escape(report['input_metadata']['source'])}</p>
  </div>
  <table>
    <thead>
      <tr>
        <th>Algorithm</th>
        <th>Verdict</th>
        <th>Standard Reference</th>
        <th>Findings</th>
        <th>Avg Encrypt (ms)</th>
        <th>Throughput (MB/s)</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""


def load_artifact(artifact_path: str) -> Dict[str, Any]:
    """Load and validate a CryptoAudit artifact JSON file."""
    path = Path(artifact_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Artifact file not found: {path}")

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid artifact JSON: {exc}") from exc

    required_top = {"algorithm", "pbkdf2", "nonce_or_iv_b64", "ciphertext_b64"}
    missing = [field for field in required_top if field not in artifact]
    if missing:
        raise ValueError(f"Artifact missing required fields: {missing}")

    algorithm = artifact.get("algorithm")
    if algorithm not in ALGORITHM_SPECS:
        raise ValueError(f"Unsupported algorithm in artifact: {algorithm}")

    pbkdf2 = artifact.get("pbkdf2", {})
    for field in ["hash", "iterations", "salt_b64"]:
        if field not in pbkdf2:
            raise ValueError(f"Artifact pbkdf2 missing field: {field}")
    if str(pbkdf2.get("hash")).lower() != "sha256":
        raise ValueError("Only PBKDF2-HMAC-SHA256 artifacts are supported")
    return artifact


def resolve_decrypt_output_path(
    *,
    artifact_path: Path,
    output_dir: Path,
    output_file_name: Optional[str],
    original_filename: Optional[str] = None,
    allow_overwrite: bool,
) -> Path:
    """Build and validate a safe output path for decrypted bytes."""
    recognized_exts = {
        ".txt",
        ".pdf",
        ".mp4",
        ".png",
        ".csv",
        ".docx",
        ".doc",
        ".xlsx",
        ".xls",
        ".pptx",
        ".ppt",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".json",
        ".xml",
        ".html",
        ".md",
        ".rtf",
        ".zip",
        ".7z",
        ".tar",
        ".gz",
        ".mp3",
        ".wav",
        ".mkv",
        ".avi",
        ".mov",
    }

    def _recognized_ext(filename: Optional[str]) -> Optional[str]:
        if not filename:
            return None
        candidate = Path(filename)
        if candidate.is_absolute() or candidate.parent != Path("."):
            raise ValueError("--decrypt-output-file must be a filename only (no directories)")
        ext = candidate.suffix.lower()
        return ext if ext in recognized_exts else None

    if output_file_name:
        candidate = Path(output_file_name)
        if candidate.is_absolute() or candidate.parent != Path("."):
            raise ValueError("--decrypt-output-file must be a filename only (no directories)")
        out_path = output_dir / candidate.name
    else:
        base_name = artifact_path.stem.replace(".enc", "")
        ext = _recognized_ext(original_filename) or ".bin"
        out_path = output_dir / f"{base_name}.decrypted{ext}"

    if out_path.exists() and not allow_overwrite:
        raise ValueError(f"Decrypt output already exists: {out_path}. Use --allow-overwrite to replace it.")
    return out_path


def resolve_manual_decrypt_output_path(
    *,
    output_dir: Path,
    output_file_name: Optional[str],
    original_filename: Optional[str] = None,
    allow_overwrite: bool,
    algorithm: str,
) -> Path:
    """Build and validate output path for manual decrypt mode."""
    recognized_exts = {
        ".txt",
        ".pdf",
        ".mp4",
        ".png",
        ".csv",
        ".docx",
        ".doc",
        ".xlsx",
        ".xls",
        ".pptx",
        ".ppt",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".json",
        ".xml",
        ".html",
        ".md",
        ".rtf",
        ".zip",
        ".7z",
        ".tar",
        ".gz",
        ".mp3",
        ".wav",
        ".mkv",
        ".avi",
        ".mov",
    }

    def _recognized_ext(filename: Optional[str]) -> Optional[str]:
        if not filename:
            return None
        candidate = Path(filename)
        if candidate.is_absolute() or candidate.parent != Path("."):
            raise ValueError("Output file name must be a filename only (no directories)")
        ext = candidate.suffix.lower()
        return ext if ext in recognized_exts else None

    if output_file_name:
        candidate = Path(output_file_name)
        if candidate.is_absolute() or candidate.parent != Path("."):
            raise ValueError("Output file name must be a filename only (no directories)")
        out_path = output_dir / candidate.name
    else:
        run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ext = _recognized_ext(original_filename) or ".bin"
        out_path = output_dir / f"{run_id}_{algorithm}.manual.decrypted{ext}"

    if out_path.exists() and not allow_overwrite:
        raise ValueError(f"Decrypt output already exists: {out_path}. Enable overwrite to replace it.")
    return out_path


def _decode_b64_strict(field_name: str, value: str, max_size: int) -> bytes:
    """Decode Base64 with strict validation and a bounded decoded size."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")

    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be valid Base64") from exc

    if len(decoded) > max_size:
        raise ValueError(f"{field_name} exceeds allowed size")
    return decoded


def execute_pipeline(
    *,
    config: AppConfig,
    input_file: Optional[str],
    input_text: Optional[str],
    password: bytearray,
) -> RunArtifacts:
    """Run the full encryption/audit/report flow and return artifact paths."""
    validate_config(config)
    plaintext, input_meta = load_input(input_file, input_text, config.max_file_size_bytes)
    output_dir = validate_output_dir(config.output_dir)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    benchmark_payload = os.urandom(config.benchmark_payload_size)
    algorithm_entries: List[Dict[str, Any]] = []
    artifacts_written: List[str] = []

    for algorithm in config.algorithms:
        spec = ALGORITHM_SPECS[algorithm]
        key_len = spec["key_len"]
        nonce_len = spec["nonce_len"]

        salt = os.urandom(16)
        kdf_t0 = time.perf_counter()
        key = derive_key(password, salt, config.pbkdf2_iterations, key_len)
        kdf_ms = (time.perf_counter() - kdf_t0) * 1000.0

        nonce = os.urandom(nonce_len)
        ciphertext = encrypt_payload(algorithm, key, nonce, plaintext)

        avalanche = avalanche_test(algorithm, key, plaintext)
        audit = run_audit(algorithm, config, avalanche["difference_percent"])
        bench = benchmark_algorithm(algorithm, key, benchmark_payload, config.benchmark_iterations)

        artifact = {
            "run_id": run_id,
            "algorithm": algorithm,
            "status": spec["status"],
            "pbkdf2": {
                "hash": "sha256",
                "iterations": config.pbkdf2_iterations,
                "salt_b64": b64(salt),
            },
            "nonce_or_iv_b64": b64(nonce),
            "ciphertext_b64": b64(ciphertext),
        }
        artifact_path = output_dir / f"{run_id}_{algorithm}.enc.json"
        artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        artifacts_written.append(str(artifact_path))

        entry = {
            "name": algorithm,
            "status": spec["status"],
            "audit": asdict(audit),
            "avalanche": avalanche,
            "benchmark": {
                "kdf_ms": round(kdf_ms, 4),
                **bench,
                "iterations": config.benchmark_iterations,
            },
        }
        algorithm_entries.append(entry)

        key_buf = bytearray(key)
        wipe_bytearray(key_buf)

    report = {
        "tool": "CryptoAudit",
        "run_id": run_id,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input_metadata": input_meta,
        "config": {
            "algorithms": config.algorithms,
            "pbkdf2_iterations": config.pbkdf2_iterations,
            "benchmark_iterations": config.benchmark_iterations,
            "benchmark_payload_size": config.benchmark_payload_size,
            "max_file_size_bytes": config.max_file_size_bytes,
        },
        "algorithms": algorithm_entries,
        "artifacts": artifacts_written,
        "notes": [
            "No plaintext, keys, or passwords are persisted in outputs.",
            "3DES is included for compatibility/audit comparison and is not recommended for new deployments.",
        ],
    }

    report_json_path = output_dir / f"{run_id}_report.json"
    report_html_path = output_dir / f"{run_id}_report.html"
    report_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_html_path.write_text(build_html_report(report), encoding="utf-8")

    return RunArtifacts(
        output_dir=str(output_dir),
        report_json_path=str(report_json_path),
        report_html_path=str(report_html_path),
        encrypted_artifact_paths=artifacts_written,
        run_id=run_id,
    )


def execute_decrypt_pipeline(
    *,
    artifact_file: str,
    password: bytearray,
    output_dir: str,
    output_file_name: Optional[str] = None,
    original_filename: Optional[str] = None,
    allow_overwrite: bool = False,
) -> DecryptArtifacts:
    """Decrypt one CryptoAudit artifact and write recovered bytes locally."""
    artifact = load_artifact(artifact_file)
    algorithm = artifact["algorithm"]
    spec = ALGORITHM_SPECS[algorithm]
    pbkdf2_meta = artifact["pbkdf2"]

    try:
        salt = base64.b64decode(pbkdf2_meta["salt_b64"])
        nonce = base64.b64decode(artifact["nonce_or_iv_b64"])
        ciphertext = base64.b64decode(artifact["ciphertext_b64"])
    except Exception as exc:
        raise ValueError("Artifact encoding is invalid") from exc

    if len(salt) != 16:
        raise ValueError("Artifact salt length is invalid")
    if len(nonce) != spec["nonce_len"]:
        raise ValueError("Artifact nonce/IV length is invalid for algorithm")

    output_dir_path = validate_output_dir(output_dir)
    artifact_path = Path(artifact_file).expanduser().resolve()
    output_path = resolve_decrypt_output_path(
        artifact_path=artifact_path,
        output_dir=output_dir_path,
        output_file_name=output_file_name,
        original_filename=original_filename,
        allow_overwrite=allow_overwrite,
    )

    iterations = int(pbkdf2_meta["iterations"])
    key = derive_key(password, salt, iterations, spec["key_len"])
    warning: Optional[str] = None

    try:
        plaintext = decrypt_payload(algorithm, key, nonce, ciphertext)
    except InvalidTag as exc:
        raise ValueError("Integrity check failed: wrong password or tampered ciphertext") from exc
    except ValueError as exc:
        raise ValueError("Decryption failed: ciphertext may be corrupted or password is incorrect") from exc
    finally:
        key_buf = bytearray(key)
        wipe_bytearray(key_buf)

    output_path.write_bytes(plaintext)

    if spec["status"] != "recommended":
        warning = (
            f"{algorithm} is a compatibility option; decrypted output was produced, "
            "but integrity guarantees may be weaker than modern AEAD modes."
        )

    return DecryptArtifacts(
        output_dir=str(output_dir_path),
        artifact_path=str(artifact_path),
        decrypted_file_path=str(output_path),
        algorithm=algorithm,
        warning=warning,
    )


def execute_manual_decrypt_pipeline(
    *,
    algorithm: str,
    pbkdf2_iterations: int,
    salt_b64: str,
    nonce_or_iv_b64: str,
    ciphertext_b64: str,
    password: bytearray,
    output_dir: str,
    output_file_name: Optional[str] = None,
    original_filename: Optional[str] = None,
    allow_overwrite: bool = False,
) -> DecryptArtifacts:
    """Decrypt externally supplied ciphertext parameters with strict local validation."""
    if algorithm not in ALGORITHM_SPECS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if algorithm in BLOCKED_DEPRECATED_ALGORITHMS:
        raise ValueError(BLOCKED_DEPRECATED_ALGORITHMS[algorithm])
    if not (100_000 <= int(pbkdf2_iterations) <= 5_000_000):
        raise ValueError("PBKDF2 iterations must be between 100000 and 5000000")

    spec = ALGORITHM_SPECS[algorithm]
    salt = _decode_b64_strict("Salt", salt_b64, 64)
    nonce = _decode_b64_strict("Nonce/IV", nonce_or_iv_b64, 64)
    ciphertext = _decode_b64_strict("Ciphertext", ciphertext_b64, 1 * 1024 * 1024 * 1024)

    if len(salt) != 16:
        raise ValueError("Salt must decode to exactly 16 bytes")
    if len(nonce) != int(spec["nonce_len"]):
        raise ValueError("Nonce/IV length is invalid for the selected algorithm")
    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty")

    output_dir_path = validate_output_dir(output_dir)
    output_path = resolve_manual_decrypt_output_path(
        output_dir=output_dir_path,
        output_file_name=output_file_name,
        original_filename=original_filename,
        allow_overwrite=allow_overwrite,
        algorithm=algorithm,
    )

    key = derive_key(password, salt, int(pbkdf2_iterations), int(spec["key_len"]))
    warning: Optional[str] = None
    try:
        plaintext = decrypt_payload(algorithm, key, nonce, ciphertext)
    except InvalidTag as exc:
        raise ValueError("Integrity check failed: wrong password or tampered ciphertext") from exc
    except ValueError as exc:
        raise ValueError("Decryption failed: parameters may be mismatched or ciphertext is invalid") from exc
    finally:
        key_buf = bytearray(key)
        wipe_bytearray(key_buf)

    output_path.write_bytes(plaintext)

    if spec["status"] != "recommended":
        warning = (
            f"{algorithm} is a compatibility option; decrypted output was produced, "
            "but integrity guarantees may be weaker than modern AEAD modes."
        )

    return DecryptArtifacts(
        output_dir=str(output_dir_path),
        artifact_path="manual-input",
        decrypted_file_path=str(output_path),
        algorithm=algorithm,
        warning=warning,
    )


def launch_interface() -> int:
    """Launch the preferred local interface (web first, desktop fallback)."""
    try:
        from cryptoaudit.frontend.web import run_web_interface

        return int(run_web_interface())
    except Exception as exc:
        print(f"Web interface launch failed: {exc}", file=sys.stderr)

    try:
        from prototype.ui_tkinter import main as tk_main

        return int(tk_main())
    except Exception as exc:
        print(f"Error: no interface launcher found ({exc})", file=sys.stderr)
        return 1


def main() -> int:
    """Execute the full CryptoAudit pipeline and write artifacts/reports."""
    if len(sys.argv) == 1:
        return launch_interface()

    args = parse_args()
    password: Optional[bytearray] = None

    try:
        validate_cli_mode_args(args)
        password = get_password(args.password_env)

        if args.mode == "encrypt":
            config = load_config(args.config_file)
            if args.output_dir:
                config.output_dir = args.output_dir
            result = execute_pipeline(
                config=config,
                input_file=args.input_file,
                input_text=args.input_text,
                password=password,
            )

            print(f"Success: encrypted artifacts written to {result.output_dir}")
            print(f"JSON report: {result.report_json_path}")
            print(f"HTML report: {result.report_html_path}")
        else:
            decrypt_output_dir = args.output_dir
            if not decrypt_output_dir and args.config_file:
                decrypt_output_dir = load_config(args.config_file).output_dir
            if not decrypt_output_dir:
                decrypt_output_dir = "outputs"

            result = execute_decrypt_pipeline(
                artifact_file=args.artifact_file,
                password=password,
                output_dir=decrypt_output_dir,
                output_file_name=args.decrypt_output_file,
                allow_overwrite=bool(args.allow_overwrite),
            )
            print(f"Success: decrypted output written to {result.decrypted_file_path}")
            if result.warning:
                print(f"Warning: {result.warning}")

        return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if password is not None:
            wipe_bytearray(password)


if __name__ == "__main__":
    raise SystemExit(main())


