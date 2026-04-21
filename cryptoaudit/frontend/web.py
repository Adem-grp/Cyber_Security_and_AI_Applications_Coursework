from __future__ import annotations

import io
import json
import os
import secrets
import sqlite3
import tempfile
import threading
import webbrowser
import zipfile
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from flask import (
    Flask,
    current_app,
    flash,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from cryptoaudit.backend.core import (
    ALGO_3DES,
    ALGO_DES_CBC,
    ALGO_RC4,
    ALGO_AES_128_GCM,
    ALGO_AES_192_GCM,
    ALGO_AES_GCM,
    ALGO_CHACHA,
    ALGORITHM_SPECS,
    AppConfig,
    DEFAULT_BENCHMARK_ITERATIONS,
    DEFAULT_BENCHMARK_PAYLOAD_SIZE,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_PBKDF2_ITERATIONS,
    execute_decrypt_pipeline,
    execute_manual_decrypt_pipeline,
    execute_pipeline,
    validate_config,
    wipe_bytearray,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
FEATURE_AUTH_ACCOUNTS = False

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CryptoAudit Web</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f8fafc; color: #1f2937; }
    .container { max-width: 980px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    .col { flex: 1; min-width: 280px; }
    label { display: block; margin: 8px 0 4px; font-weight: 600; }
    input[type=text], input[type=password], input[type=number], textarea, select { width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 6px; box-sizing: border-box; }
    textarea { min-height: 120px; resize: vertical; }
    .muted { color: #6b7280; font-size: 0.92rem; }
    .actions { margin-top: 14px; display: flex; gap: 8px; align-items: center; }
    button { padding: 9px 14px; border: 0; border-radius: 6px; background: #2563eb; color: #ffffff; cursor: pointer; }
    button.secondary { background: #4b5563; }
    .chip { display: inline-block; border: 1px solid #d1d5db; border-radius: 999px; padding: 3px 10px; margin-right: 6px; margin-bottom: 6px; }
    .flash-error { border: 1px solid #fca5a5; background: #fef2f2; color: #991b1b; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
    .flash-success { border: 1px solid #86efac; background: #f0fdf4; color: #166534; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
    .flash-warn { border: 1px solid #fcd34d; background: #fffbeb; color: #92400e; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
    .badge { display: inline-block; border-radius: 999px; padding: 2px 10px; font-size: 0.82rem; font-weight: 700; }
    .badge-pass { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
    .badge-warn { background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
    .badge-fail { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f8fafc; }
    details { border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; margin-top: 10px; }
    .dropzone { border: 2px dashed #93c5fd; border-radius: 8px; padding: 16px; text-align: center; background: #eff6ff; margin-top: 8px; }
    .dropzone.dragover { background: #dbeafe; border-color: #2563eb; }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .nav-row { justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .nav-links { display: flex; gap: 8px; align-items: center; }
    .nav-link { display: inline-block; text-decoration: none; color: #1f2937; border: 1px solid #d1d5db; border-radius: 6px; padding: 8px 12px; }
    .nav-link.active { background: #2563eb; color: #ffffff; border-color: #2563eb; }
    .modal-backdrop { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.55); display: none; align-items: center; justify-content: center; z-index: 2000; }
    .modal-backdrop.show { display: flex; }
    .modal { width: min(520px, calc(100vw - 32px)); background: #ffffff; border-radius: 10px; border: 1px solid #d1d5db; padding: 16px; box-shadow: 0 16px 40px rgba(0, 0, 0, 0.18); }
    .modal h3 { margin: 0 0 8px; }
    .hidden { display: none; }
    @media (max-width: 760px) { .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="flash-{{ category }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {{ body|safe }}
  </div>
</body>
</html>
"""


LOGIN_BODY = """
<h1>CryptoAudit Login</h1>
<p class="muted">Local-only secure web interface. No external network calls are made by the app.</p>
<form method="post" action="{{ url_for('login') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <label>Username</label>
  <input type="text" name="username" autocomplete="username" required>
  <label>Password</label>
  <input type="password" name="password" autocomplete="current-password" required>
  <div class="actions">
    <button type="submit">Sign In</button>
  </div>
</form>
"""


SETUP_BODY = """
<h1>CryptoAudit First-Time Setup</h1>
<p class="muted">Create the first local account. Credentials remain on this machine only.</p>
<form method="post" action="{{ url_for('setup') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <label>Username</label>
  <input type="text" name="username" minlength="3" maxlength="40" required>
  <label>Password</label>
  <input type="password" name="password" minlength="12" autocomplete="new-password" required>
  <label>Confirm Password</label>
  <input type="password" name="confirm_password" minlength="12" autocomplete="new-password" required>
  <div class="actions">
    <button type="submit">Create Account</button>
  </div>
</form>
"""


WELCOME_BODY = """
<h1>Welcome to CryptoAudit</h1>
<p class="muted">A local-only cryptographic benchmarking and audit tool for security-focused encryption workflows.</p>

<h2>What this tool does</h2>
<ul>
  <li>Encrypts raw text or uploaded files (including large binary files such as videos) using selected algorithms.</li>
  <li>Runs an audit layer and benchmark measurements per algorithm.</li>
  <li>Generates local HTML and JSON reports without sending data to external services.</li>
</ul>

<h2>Usage guidelines</h2>
<ul>
  <li>Use a strong password and keep it private; it is not stored by the application.</li>
  <li>Prefer recommended algorithms (AES-GCM or ChaCha20-Poly1305) for new deployments.</li>
  <li>Store output artifacts in trusted local folders with appropriate OS access controls.</li>
</ul>

<form method="post" action="{{ url_for('start') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <div class="actions">
    <button type="submit">Start</button>
  </div>
</form>
"""


APP_NAV = """
<div class="row nav-row">
  <h1 style="margin: 0;">CryptoAudit Web</h1>
  <div class="nav-links">
    <a class="nav-link {% if active_page == 'encrypt' %}active{% endif %}" href="{{ url_for('encrypt_page') }}">Encrypt</a>
    <a class="nav-link {% if active_page == 'decrypt' %}active{% endif %}" href="{{ url_for('decrypt_page') }}">Decrypt</a>
    <a class="nav-link {% if active_page == 'audit' %}active{% endif %}" href="{{ url_for('audit_page') }}">Audit</a>
  </div>
  {% if auth_enabled %}
  <form method="post" action="{{ url_for('logout') }}" style="margin: 0;">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <button type="submit" class="secondary">Logout</button>
  </form>
  {% endif %}
</div>
{% if auth_enabled %}
  <p class="muted">Signed in as <strong>{{ username }}</strong>. All data processing and outputs stay local.</p>
{% else %}
  <p class="muted">Guest mode enabled. All data processing and outputs stay local.</p>
{% endif %}
"""

ENCRYPT_BODY = """
<h2>Encrypt + Audit</h2>
<form method="post" action="{{ url_for('encrypt') }}" enctype="multipart/form-data" id="encryptForm">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="hidden" name="confirm_legacy" id="confirmLegacy" value="no">

      <label>Input Mode</label>
      <div>
        <label style="display:inline; font-weight:normal;"><input type="radio" name="input_mode" value="text" checked> Raw Text</label>
        <label style="display:inline; font-weight:normal; margin-left: 10px;"><input type="radio" name="input_mode" value="file"> File Upload</label>
      </div>

      <label>Raw Text (used when Input Mode = Raw Text)</label>
      <textarea name="input_text" placeholder="Type plaintext to encrypt"></textarea>

      <label>File Upload (used when Input Mode = File Upload)</label>
      <input type="file" id="inputFile" name="input_file">
      <div class="dropzone" id="dropzone">Drag and drop a file here (including videos), or use file chooser.</div>

      <label>Algorithm</label>
      <select name="algorithm" id="algorithmSelect" required>
        {% for alg in algorithms %}
          <option value="{{ alg.name }}" {% if alg.default_checked %}selected{% endif %}>{{ alg.label }}</option>
        {% endfor %}
      </select>
      <p class="muted">One algorithm is applied per run. Use separate runs if you want to compare outputs.</p>

      <label>Password</label>
      <input type="password" name="password" autocomplete="new-password" required>

      <details>
        <summary><strong>Advanced Settings (optional)</strong></summary>
        <label>Output Directory</label>
        <input type="text" name="output_dir" value="outputs_web">
        <label>PBKDF2 Iterations</label>
        <input type="number" name="pbkdf2_iterations" value="{{ defaults.pbkdf2 }}" min="100000" max="5000000">
        <label>Benchmark Iterations</label>
        <input type="number" name="benchmark_iterations" value="{{ defaults.bench_iter }}" min="1" max="1000">
        <label>Benchmark Payload Size (bytes)</label>
        <input type="number" name="benchmark_payload_size" value="{{ defaults.bench_payload }}" min="4096" max="67108864">
        <label>Max File Size (bytes)</label>
        <input type="number" name="max_file_size_bytes" value="{{ defaults.max_file }}" min="1048576" max="1073741824">
        <label>Optional Config JSON Upload</label>
        <input type="file" name="config_file" accept=".json,application/json">
      </details>

  <div class="actions">
    <button type="submit">Run Encryption Pipeline</button>
  </div>
</form>

<h3>Why this is safe-by-default</h3>
<div class="chip">No plaintext persisted</div>
<div class="chip">No password/key logging</div>
<div class="chip">Per-run random salt + nonce/IV</div>
<div class="chip">Output path checks</div>
<div class="chip">Local-only host binding</div>

<div class="modal-backdrop" id="legacyModalBackdrop" role="dialog" aria-modal="true" aria-labelledby="legacyModalTitle">
  <div class="modal">
    <h3 id="legacyModalTitle">Compatibility Warning</h3>
    <p>3DES-OFB is classified as a legacy compatibility cipher. NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023. FIPS 140-3 transition guidance recommends migration to AES-GCM or ChaCha20-Poly1305.</p>
    <p class="muted">You can continue anyway or retry to adjust your algorithm selection.</p>
    <div class="actions">
      <button type="button" id="legacyContinueBtn">Continue Anyway</button>
      <button type="button" class="secondary" id="legacyRetryBtn">Retry</button>
    </div>
  </div>
</div>

<script>
(function () {
  const dropzone = document.getElementById("dropzone");
  const inputFile = document.getElementById("inputFile");
  const encryptForm = document.getElementById("encryptForm");
  const confirmLegacy = document.getElementById("confirmLegacy");
  const legacyModalBackdrop = document.getElementById("legacyModalBackdrop");
  const legacyContinueBtn = document.getElementById("legacyContinueBtn");
  const legacyRetryBtn = document.getElementById("legacyRetryBtn");
  let bypassLegacyCheck = false;

  function hasLegacySelected() {
    const selected = document.getElementById("algorithmSelect");
    return selected && selected.value === "3des-ofb";
  }

  encryptForm.addEventListener("submit", function (event) {
    confirmLegacy.value = "no";
    if (bypassLegacyCheck) {
      confirmLegacy.value = "yes";
      bypassLegacyCheck = false;
      return;
    }

    if (hasLegacySelected()) {
      event.preventDefault();
      legacyModalBackdrop.classList.add("show");
    }
  });

  legacyContinueBtn.addEventListener("click", function () {
    legacyModalBackdrop.classList.remove("show");
    bypassLegacyCheck = true;
    encryptForm.requestSubmit();
  });

  legacyRetryBtn.addEventListener("click", function () {
    legacyModalBackdrop.classList.remove("show");
    bypassLegacyCheck = false;
    confirmLegacy.value = "no";
  });

  function setDragState(active) {
    if (active) {
      dropzone.classList.add("dragover");
    } else {
      dropzone.classList.remove("dragover");
    }
  }

  dropzone.addEventListener("dragover", function (event) {
    event.preventDefault();
    setDragState(true);
  });

  dropzone.addEventListener("dragleave", function () {
    setDragState(false);
  });

  dropzone.addEventListener("drop", function (event) {
    event.preventDefault();
    setDragState(false);
    if (event.dataTransfer.files.length > 0) {
      inputFile.files = event.dataTransfer.files;
    }
  });
})();
</script>
"""


DECRYPT_BODY = """
<h2>Decrypt Artifact</h2>
<form method="post" action="{{ url_for('decrypt') }}" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <label>Decrypt Mode</label>
  <div>
    <label style="display:inline; font-weight:normal;"><input type="radio" name="decrypt_mode" value="artifact" checked> CryptoAudit Artifact (recommended)</label>
    <label style="display:inline; font-weight:normal; margin-left: 10px;"><input type="radio" name="decrypt_mode" value="manual"> External/Manual Parameters</label>
  </div>

  <div id="artifactSection">
    <label>Artifact JSON</label>
    <input type="file" name="artifact_file" id="artifactFile" accept=".json,application/json">
    <p class="muted">This mode reads algorithm, PBKDF2 iterations, salt, and nonce/IV from your artifact file.</p>
    <details>
      <summary><strong>Artifact Metadata Preview (local only)</strong></summary>
      <p class="muted" id="artifactMeta">Select an artifact to preview metadata.</p>
    </details>
  </div>

  <div id="manualSection" class="hidden">
    <label>Algorithm</label>
    <select name="manual_algorithm" id="manualAlgorithm">
      {% for alg in decrypt_algorithms %}
        <option value="{{ alg.name }}">{{ alg.label }}</option>
      {% endfor %}
    </select>

    <label>PBKDF2 Iterations</label>
    <input type="number" name="manual_pbkdf2_iterations" value="{{ defaults.pbkdf2 }}" min="100000" max="5000000">

    <label>Salt (Base64, 16 bytes decoded)</label>
    <textarea name="manual_salt_b64" placeholder="Base64 salt"></textarea>

    <label>Nonce/IV (Base64)</label>
    <textarea name="manual_nonce_b64" placeholder="Base64 nonce or IV"></textarea>

    <label>Ciphertext (Base64)</label>
    <textarea name="manual_ciphertext_b64" placeholder="Base64 ciphertext"></textarea>
    <p class="muted">Use this mode only when ciphertext was generated by a compatible implementation.</p>
  </div>

  <label>Password</label>
  <input type="password" name="password" autocomplete="new-password" required>

  <label>Output filename (required)</label>
  <input type="text" name="output_file_name" placeholder="e.g. document.pdf, video.mp4, notes.txt" required>
  <p class="muted">Enter the original filename with its extension so the decrypted file downloads correctly.</p>

  <details>
    <summary><strong>Advanced Settings (optional)</strong></summary>
    <label>Output Directory</label>
    <input type="text" name="output_dir" value="outputs_web">
  </details>

  <div class="actions">
    <button type="submit">Run Decryption</button>
  </div>
</form>

<script>
(function () {
  const modeInputs = document.querySelectorAll('input[name="decrypt_mode"]');
  const artifactSection = document.getElementById("artifactSection");
  const manualSection = document.getElementById("manualSection");
  const artifactFile = document.getElementById("artifactFile");
  const artifactMeta = document.getElementById("artifactMeta");

  function updateMode() {
    const selected = Array.from(modeInputs).find(x => x.checked)?.value || "artifact";
    const isArtifact = selected === "artifact";
    artifactSection.classList.toggle("hidden", !isArtifact);
    manualSection.classList.toggle("hidden", isArtifact);
  }

  modeInputs.forEach((input) => input.addEventListener("change", updateMode));
  updateMode();

  artifactFile.addEventListener("change", function () {
    if (!artifactFile.files || artifactFile.files.length === 0) {
      artifactMeta.textContent = "Select an artifact to preview metadata.";
      return;
    }
    const file = artifactFile.files[0];
    const reader = new FileReader();
    reader.onload = function () {
      try {
        const data = JSON.parse(String(reader.result || ""));
        const alg = data.algorithm || "(missing)";
        const iters = (data.pbkdf2 && data.pbkdf2.iterations) || "(missing)";
        const hashName = (data.pbkdf2 && data.pbkdf2.hash) || "(missing)";
        artifactMeta.textContent = "Algorithm: " + alg + " | PBKDF2 hash: " + hashName + " | Iterations: " + iters;
      } catch (e) {
        artifactMeta.textContent = "Unable to parse artifact JSON metadata.";
      }
    };
    reader.readAsText(file);
  });
})();
</script>
"""


AUDIT_BODY = """
<h2>Audit Information</h2>
{% if last_audit %}
  <p class="muted"><strong>Run ID:</strong> <code>{{ last_audit.run_id }}</code> | <strong>Timestamp:</strong> <code>{{ last_audit.timestamp }}</code></p>
  <table>
    <thead>
      <tr>
        <th>Algorithm</th>
        <th>Verdict</th>
        <th>Findings</th>
        <th>Recommendation</th>
        <th>Standard</th>
        <th>Avalanche (%)</th>
        <th>Avg Encrypt (ms)</th>
        <th>Throughput (MB/s)</th>
      </tr>
    </thead>
    <tbody>
      {% for row in last_audit.algorithms %}
      <tr>
        <td><code>{{ row.name }}</code></td>
        <td>
          <span class="badge {% if row.verdict == 'PASS' %}badge-pass{% elif row.verdict == 'WARN' %}badge-warn{% else %}badge-fail{% endif %}">{{ row.verdict }}</span>
        </td>
        <td>
          {% if row.findings %}
            <ul>
              {% for item in row.findings %}<li>{{ item }}</li>{% endfor %}
            </ul>
          {% else %}
            <span class="muted">None</span>
          {% endif %}
        </td>
        <td>{{ row.recommendation }}</td>
        <td>{{ row.standard_reference }}</td>
        <td>{{ row.difference_percent }}</td>
        <td>{{ row.avg_encrypt_ms }}</td>
        <td>{{ row.throughput_mb_s }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
{% else %}
  <p class="muted">No audit data yet. Run an encryption first.</p>
{% endif %}
"""


RESULT_BODY = """
<h1>{{ title }}</h1>
{% if warning %}
  <div class="flash-warn">{{ warning }}</div>
{% endif %}
<div class="flash-success">{{ success_message }}</div>
<p><strong>Operation:</strong> {{ operation }}</p>
<p><strong>Output Directory:</strong> <code>{{ output_dir }}</code></p>
{% if audit_summary %}
  <p><strong>Audit Summary:</strong></p>
  <table>
    <thead>
      <tr>
        <th>Algorithm</th>
        <th>Verdict</th>
        <th>Summary</th>
      </tr>
    </thead>
    <tbody>
      {% for row in audit_summary %}
      <tr>
        <td><code>{{ row.name }}</code></td>
        <td>
          <span class="badge {% if row.verdict == 'PASS' %}badge-pass{% elif row.verdict == 'WARN' %}badge-warn{% else %}badge-fail{% endif %}">{{ row.verdict }}</span>
        </td>
        <td>{{ row.summary }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
{% endif %}
{% if output_files %}
  <p><strong>Generated Output Files:</strong></p>
  <ul>
  {% for item in output_files %}<li><code>{{ item }}</code></li>{% endfor %}
  </ul>
{% endif %}
<div class="actions">
  <a href="{{ back_href }}"><button>Back</button></a>
</div>
{% if show_success_popup %}
<div class="modal-backdrop show" id="successModalBackdrop" role="dialog" aria-modal="true" aria-labelledby="successModalTitle">
  <div class="modal">
    <h3 id="successModalTitle">Encryption Successful</h3>
    <p>Your encryption run completed and output artifacts were generated locally.</p>
    <div class="actions">
      <a href="{{ url_for('app_home') }}"><button type="button">Continue</button></a>
    </div>
  </div>
</div>
{% endif %}
"""


def _render_page(body_template: str, **context: Any) -> str:
    body_html = render_template_string(body_template, **context)
    return render_template_string(BASE_TEMPLATE, body=body_html)


def _render_app_page(*, body_template: str, active_page: str, **context: Any) -> str:
    nav_html = render_template_string(
        APP_NAV,
        active_page=active_page,
        auth_enabled=context.get("auth_enabled", False),
        username=context.get("username"),
    )
    combined_template = "{{ nav|safe }}" + body_template
    return _render_page(combined_template, nav=nav_html, **context)


def _ui_algorithms() -> list[dict[str, Any]]:
    return [
        {"name": ALGO_AES_GCM, "label": "AES-256-GCM", "default_checked": True},
        {"name": ALGO_AES_192_GCM, "label": "AES-192-GCM", "default_checked": False},
        {"name": ALGO_AES_128_GCM, "label": "AES-128-GCM", "default_checked": False},
        {"name": ALGO_CHACHA, "label": "ChaCha20-Poly1305", "default_checked": False},
        {"name": ALGO_3DES, "label": "3DES-OFB", "default_checked": False},
        {"name": ALGO_DES_CBC, "label": "DES-CBC", "default_checked": False},
        {"name": ALGO_RC4, "label": "RC4", "default_checked": False},
    ]


def _ui_defaults() -> dict[str, int]:
    return {
        "pbkdf2": DEFAULT_PBKDF2_ITERATIONS,
        "bench_iter": DEFAULT_BENCHMARK_ITERATIONS,
        "bench_payload": DEFAULT_BENCHMARK_PAYLOAD_SIZE,
        "max_file": DEFAULT_MAX_FILE_SIZE,
    }


def _ui_decrypt_algorithms() -> list[dict[str, str]]:
    return [
        {"name": ALGO_AES_GCM, "label": "AES-256-GCM"},
        {"name": ALGO_AES_192_GCM, "label": "AES-192-GCM"},
        {"name": ALGO_AES_128_GCM, "label": "AES-128-GCM"},
        {"name": ALGO_CHACHA, "label": "ChaCha20-Poly1305"},
        {"name": ALGO_3DES, "label": "3DES-OFB"},
    ]


def _data_dir(app: Flask) -> Path:
    return Path(app.config["CRYPTOAUDIT_DATA_DIR"]).resolve()


def _db_path(app: Flask) -> Path:
    return _data_dir(app) / "users.db"


def _secret_path(app: Flask) -> Path:
    return _data_dir(app) / "secret.key"


def _temp_upload_dir(app: Flask) -> Path:
    return _data_dir(app) / "upload_tmp"


def _load_or_create_secret(path: Path) -> str:
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value

    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding="utf-8")
    return value


def _get_conn(app: Flask) -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path(app)))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(app: Flask) -> None:
    _data_dir(app).mkdir(parents=True, exist_ok=True)
    _temp_upload_dir(app).mkdir(parents=True, exist_ok=True)
    with _get_conn(app) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_utc TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )


def _user_count(app: Flask) -> int:
    with _get_conn(app) as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return int(row["c"])


def _create_user(app: Flask, username: str, password: str) -> None:
    hash_value = generate_password_hash(password)
    with _get_conn(app) as conn:
        conn.execute("INSERT INTO users(username, password_hash) VALUES(?, ?)", (username, hash_value))


def _authenticate_user(app: Flask, username: str, password: str) -> bool:
    with _get_conn(app) as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return False
    return bool(check_password_hash(row["password_hash"], password))


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _require_csrf() -> None:
    expected = session.get("csrf_token", "")
    provided = request.form.get("csrf_token", "")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        raise ValueError("Invalid CSRF token")


def _login_required(handler: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(handler)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not bool(current_app.config.get("AUTH_ENABLED", False)):
            return handler(*args, **kwargs)
        if not session.get("user"):
            return redirect(url_for("login"))
        return handler(*args, **kwargs)

    return wrapper


def _selected_algorithms() -> list[str]:
    selected_single = (request.form.get("algorithm", "") or "").strip()
    if selected_single:
        return [selected_single] if selected_single in ALGORITHM_SPECS else []

    # Backward-compatible fallback for stale form payloads using multi-select.
    selected = request.form.getlist("algorithms")
    return [alg for alg in selected if alg in ALGORITHM_SPECS]


def _coerce_optional_int(value: str, default: int) -> int:
    text = (value or "").strip()
    if not text:
        return default
    return int(text)


def _extract_last_audit_payload(report: dict[str, Any], fallback_run_id: str) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for entry in report.get("algorithms", []):
        audit = entry.get("audit", {})
        avalanche = entry.get("avalanche", {})
        benchmark = entry.get("benchmark", {})
        findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
        rows.append(
            {
                "name": str(entry.get("name", "")),
                "verdict": str(audit.get("verdict", "WARN")).upper(),
                "findings": [str(item) for item in findings],
                "recommendation": str(audit.get("recommendation", "")),
                "standard_reference": str(audit.get("standard_reference", "")),
                "difference_percent": avalanche.get("difference_percent"),
                "avg_encrypt_ms": benchmark.get("avg_encrypt_ms"),
                "throughput_mb_s": benchmark.get("throughput_mb_s"),
            }
        )

    return {
        "run_id": str(report.get("run_id", fallback_run_id)),
        "timestamp": str(report.get("timestamp_utc", "")),
        "algorithms": rows,
    }


def _to_audit_summary(last_audit: dict[str, Any]) -> list[dict[str, str]]:
    summary: list[dict[str, str]] = []
    for row in last_audit.get("algorithms", []):
        findings = row.get("findings") if isinstance(row.get("findings"), list) else []
        first_finding = str(findings[0]).strip() if findings else ""
        recommendation = str(row.get("recommendation", "")).strip()
        summary.append(
            {
                "name": str(row.get("name", "")),
                "verdict": str(row.get("verdict", "WARN")).upper(),
                "summary": first_finding or recommendation or "No additional notes.",
            }
        )
    return summary


def _config_from_upload(default: AppConfig) -> AppConfig:
    uploaded = request.files.get("config_file")
    if not uploaded or not uploaded.filename:
        return default

    payload = uploaded.stream.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError("Config file is too large")

    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid config JSON: {exc}") from exc

    config = AppConfig(
        algorithms=data.get("algorithms", default.algorithms),
        pbkdf2_iterations=data.get("pbkdf2_iterations", default.pbkdf2_iterations),
        benchmark_iterations=data.get("benchmark_iterations", default.benchmark_iterations),
        benchmark_payload_size=data.get("benchmark_payload_size", default.benchmark_payload_size),
        max_file_size_bytes=data.get("max_file_size_bytes", default.max_file_size_bytes),
        output_dir=data.get("output_dir", default.output_dir),
        mode_overrides=data.get("mode_overrides", {}),
        detect_reused_iv_in_config=data.get("detect_reused_iv_in_config", False),
    )
    validate_config(config)
    return config


def _save_upload_limited(app: Flask, field_name: str, max_size: int, suffix: str = "") -> Path:
    uploaded = request.files.get(field_name)
    if not uploaded or not uploaded.filename:
        raise ValueError("Required file upload is missing")

    _temp_upload_dir(app).mkdir(parents=True, exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, dir=str(_temp_upload_dir(app)), suffix=suffix)
    path = Path(temp_file.name)
    total = 0

    try:
        while True:
            chunk = uploaded.stream.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_size:
                raise ValueError(f"Uploaded file exceeds maximum size ({max_size} bytes)")
            temp_file.write(chunk)
    except Exception:
        temp_file.close()
        path.unlink(missing_ok=True)
        raise

    temp_file.flush()
    temp_file.close()
    return path


def create_app(test_config: Optional[dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        CRYPTOAUDIT_DATA_DIR=os.environ.get("CRYPTOAUDIT_WEB_DATA_DIR", ".cryptoaudit_web"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=104857600,
        AUTH_ENABLED=FEATURE_AUTH_ACCOUNTS,
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_or_create_secret(_secret_path(app))

    if app.config.get("AUTH_ENABLED"):
        _init_db(app)

    @app.context_processor
    def inject_csrf() -> dict[str, Any]:
        return {"csrf_token": _csrf_token()}

    @app.errorhandler(413)
    def request_entity_too_large(error: Any) -> Any:
        flash("Uploaded file exceeds the maximum allowed size of 100MB.", "error")
        return redirect(request.referrer or url_for("decrypt_page"))

    @app.get("/")
    def root() -> Any:
        return redirect(url_for("welcome"))

    @app.get("/welcome")
    def welcome() -> Any:
        return _render_page(WELCOME_BODY)

    @app.post("/start")
    def start() -> Any:
        try:
            _require_csrf()
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("welcome"))

        if app.config.get("AUTH_ENABLED") and _user_count(app) == 0:
            return redirect(url_for("setup"))
        if app.config.get("AUTH_ENABLED") and not session.get("user"):
            return redirect(url_for("login"))
        return redirect(url_for("app_home"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> Any:
        if not app.config.get("AUTH_ENABLED"):
            flash("Account setup is disabled in this build.", "warn")
            return redirect(url_for("welcome"))
        if _user_count(app) > 0:
            return redirect(url_for("login"))

        if request.method == "POST":
            try:
                _require_csrf()
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                confirm = request.form.get("confirm_password", "")

                if len(username) < 3:
                    raise ValueError("Username must be at least 3 characters")
                if len(password) < 12:
                    raise ValueError("Password must be at least 12 characters")
                if password != confirm:
                    raise ValueError("Passwords do not match")

                _create_user(app, username, password)
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except Exception as exc:
                flash(str(exc), "error")

        return _render_page(SETUP_BODY)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if not app.config.get("AUTH_ENABLED"):
            flash("Account login is disabled in this build.", "warn")
            return redirect(url_for("welcome"))
        if _user_count(app) == 0:
            return redirect(url_for("setup"))

        if request.method == "POST":
            try:
                _require_csrf()
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if not _authenticate_user(app, username, password):
                    raise ValueError("Invalid credentials")

                session.clear()
                session["user"] = username
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("app_home"))
            except Exception as exc:
                flash(str(exc), "error")

        return _render_page(LOGIN_BODY)

    @app.post("/logout")
    @_login_required
    def logout() -> Any:
        if not app.config.get("AUTH_ENABLED"):
            return redirect(url_for("welcome"))
        try:
            _require_csrf()
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("app_home"))

        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("login"))

    @app.get("/app")
    @_login_required
    def app_home() -> Any:
        return redirect(url_for("encrypt_page"))

    @app.get("/app/encrypt")
    @_login_required
    def encrypt_page() -> Any:
        return _render_app_page(
            body_template=ENCRYPT_BODY,
            active_page="encrypt",
            algorithms=_ui_algorithms(),
            defaults=_ui_defaults(),
            username=session.get("user"),
            auth_enabled=bool(app.config.get("AUTH_ENABLED")),
        )

    @app.get("/app/decrypt")
    @_login_required
    def decrypt_page() -> Any:
        return _render_app_page(
            body_template=DECRYPT_BODY,
            active_page="decrypt",
            decrypt_algorithms=_ui_decrypt_algorithms(),
            defaults=_ui_defaults(),
            username=session.get("user"),
            auth_enabled=bool(app.config.get("AUTH_ENABLED")),
        )

    @app.get("/app/audit")
    @_login_required
    def audit_page() -> Any:
        return _render_app_page(
            body_template=AUDIT_BODY,
            active_page="audit",
            last_audit=session.get("last_audit"),
            username=session.get("user"),
            auth_enabled=bool(app.config.get("AUTH_ENABLED")),
        )

    @app.post("/encrypt")
    @_login_required
    def encrypt() -> Any:
        password_buf: Optional[bytearray] = None
        temp_input: Optional[Path] = None

        try:
            _require_csrf()
            password = request.form.get("password", "")
            if not password:
                raise ValueError("Password is required")
            password_buf = bytearray(password.encode("utf-8"))

            config = _config_from_upload(AppConfig())
            selected_algorithms = _selected_algorithms()
            if selected_algorithms:
                config.algorithms = selected_algorithms

            if len(config.algorithms) != 1:
                raise ValueError("Select exactly one algorithm for each encryption run.")

            config.pbkdf2_iterations = _coerce_optional_int(request.form.get("pbkdf2_iterations", ""), config.pbkdf2_iterations)
            config.benchmark_iterations = _coerce_optional_int(request.form.get("benchmark_iterations", ""), config.benchmark_iterations)
            config.benchmark_payload_size = _coerce_optional_int(
                request.form.get("benchmark_payload_size", ""), config.benchmark_payload_size
            )
            config.max_file_size_bytes = _coerce_optional_int(request.form.get("max_file_size_bytes", ""), config.max_file_size_bytes)

            if ALGO_3DES in config.algorithms and request.form.get("confirm_legacy") != "yes":
                raise ValueError("3DES-OFB requires explicit confirmation before running")

            input_mode = request.form.get("input_mode", "text")
            input_file: Optional[str] = None
            input_text: Optional[str] = None

            if input_mode == "file":
                suffix = Path(request.files.get("input_file").filename or "").suffix[:16] if request.files.get("input_file") else ""
                temp_input = _save_upload_limited(app, "input_file", config.max_file_size_bytes, suffix=suffix)
                input_file = str(temp_input)
            else:
                input_text = request.form.get("input_text", "")
                if not input_text.strip():
                    raise ValueError("Raw text input cannot be empty in text mode")

            with tempfile.TemporaryDirectory(prefix="cryptoaudit_web_encrypt_") as run_tmp:
                config.output_dir = run_tmp
                validate_config(config)
                result = execute_pipeline(config=config, input_file=input_file, input_text=input_text, password=password_buf)

                report_json_path = Path(result.report_json_path)
                report_payload = json.loads(report_json_path.read_text(encoding="utf-8"))
                last_audit = _extract_last_audit_payload(report_payload, result.run_id)
                session["last_audit"] = last_audit

                if not result.encrypted_artifact_paths:
                    raise ValueError("No encrypted artifact was generated")

                artifact_path = Path(result.encrypted_artifact_paths[0])
                report_html_path = Path(result.report_html_path)
                artifact_bytes = artifact_path.read_bytes()
                report_html_bytes = report_html_path.read_bytes()
                artifact_name = artifact_path.name
                report_name = report_html_path.name

                artifact_path.unlink(missing_ok=True)
                report_html_path.unlink(missing_ok=True)
                report_json_path.unlink(missing_ok=True)

                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(artifact_name, artifact_bytes)
                    zf.writestr(report_name, report_html_bytes)
                zip_buffer.seek(0)

                return send_file(
                    zip_buffer,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name=f"cryptoaudit_{result.run_id}.zip",
                    max_age=0,
                )

        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("encrypt_page"))
        finally:
            if temp_input:
                temp_input.unlink(missing_ok=True)
            if password_buf is not None:
                wipe_bytearray(password_buf)

    @app.post("/decrypt")
    @_login_required
    def decrypt() -> Any:
        password_buf: Optional[bytearray] = None
        temp_artifact: Optional[Path] = None

        try:
            _require_csrf()
            password = request.form.get("password", "")
            if not password:
                raise ValueError("Password is required")
            password_buf = bytearray(password.encode("utf-8"))

            output_file_name = (request.form.get("output_file_name", "") or "").strip()
            if not output_file_name:
                flash(
                    "Output filename is required. Please enter the original filename with its extension (e.g. document.pdf)",
                    "error",
                )
                return redirect(url_for("decrypt_page"))
            decrypt_mode = (request.form.get("decrypt_mode", "artifact") or "artifact").strip().lower()

            with tempfile.TemporaryDirectory(prefix="cryptoaudit_web_decrypt_") as run_tmp:
                output_dir = run_tmp
                if decrypt_mode == "manual":
                    manual_algorithm = (request.form.get("manual_algorithm", "") or "").strip().lower()
                    manual_iterations = _coerce_optional_int(
                        request.form.get("manual_pbkdf2_iterations", ""),
                        DEFAULT_PBKDF2_ITERATIONS,
                    )
                    manual_salt_b64 = request.form.get("manual_salt_b64", "")
                    manual_nonce_b64 = request.form.get("manual_nonce_b64", "")
                    manual_ciphertext_b64 = request.form.get("manual_ciphertext_b64", "")

                    result = execute_manual_decrypt_pipeline(
                        algorithm=manual_algorithm,
                        pbkdf2_iterations=manual_iterations,
                        salt_b64=manual_salt_b64,
                        nonce_or_iv_b64=manual_nonce_b64,
                        ciphertext_b64=manual_ciphertext_b64,
                        password=password_buf,
                        output_dir=output_dir,
                        output_file_name=output_file_name,
                        original_filename=None,
                        allow_overwrite=False,
                    )
                else:
                    temp_artifact = _save_upload_limited(
                        app,
                        "artifact_file",
                        int(app.config.get("MAX_CONTENT_LENGTH", 104857600)),
                        suffix=".json",
                    )
                    result = execute_decrypt_pipeline(
                        artifact_file=str(temp_artifact),
                        password=password_buf,
                        output_dir=output_dir,
                        output_file_name=output_file_name,
                        original_filename=None,
                        allow_overwrite=False,
                    )

                decrypted_path = Path(result.decrypted_file_path)
                decrypted_bytes = decrypted_path.read_bytes()
                decrypted_path.unlink(missing_ok=True)

                response = send_file(
                    io.BytesIO(decrypted_bytes),
                    mimetype="application/octet-stream",
                    as_attachment=True,
                    download_name=output_file_name,
                    max_age=0,
                )

                if result.warning:
                    response.headers["X-CryptoAudit-Warning"] = (
                        "NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023. "
                        + result.warning
                    )

                return response

        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("decrypt_page"))
        finally:
            if temp_artifact:
                temp_artifact.unlink(missing_ok=True)
            if password_buf is not None:
                wipe_bytearray(password_buf)

    return app


def run_web_interface(open_browser: bool = True) -> int:
    app = create_app()
    url = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/"

    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    app.run(host=DEFAULT_HOST, port=DEFAULT_PORT, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_web_interface())





