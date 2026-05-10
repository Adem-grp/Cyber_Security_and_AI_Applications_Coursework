# CryptoAudit

CryptoAudit is a local-only cryptographic benchmarking and audit tool with CLI, desktop, and secure web interfaces.

## Security and Scope

- Runs fully local (loopback web UI only, no external API/network calls)
- Accepts file input or raw text input
- Handles any binary file type (including videos) as raw bytes
- Produces encrypted artifacts + JSON and HTML reports
- Never writes plaintext, passwords, or keys to disk
- Uses `PBKDF2-HMAC-SHA256` with random 16-byte salt

## Implemented Algorithms

- `aes-256-gcm` (recommended)
- `aes-192-gcm` (recommended)
- `aes-128-gcm` (recommended)
- `chacha20-poly1305` (recommended)
- `3des-ofb` (compatibility option; warning shown in UI before run)

## Install

```powershell
python -m pip install -r requirements.txt
```

## Project Structure

├── main.py                      # Entry point
├── requirements.txt             # Dependencies
├── sample_config.json           # Example config
├── cryptoaudit/                 # Final product
│   ├── backend/core.py          # Crypto engine
│   └── frontend/web.py          # Web interface
├── prototype/                   # Initial prototype
│   └── ui_tkinter.py            # Tkinter desktop app
├── tests/                       # Test suite
├── smoke_test.py                # Smoke tests
└── Documentation.md             # Project log

## Secure Local Web Interface (Recommended)

Run:

```powershell
python main.py
```

By default, `main.py` launches the web interface at `http://127.0.0.1:8765`.

Note: A secret key for session signing is automatically generated on first run and stored locally in `.cryptoaudit_web/secret.key`. No manual configuration is required.

First run:

1. Run: `python main.py`
2. Open `http://127.0.0.1:8765` in your browser
3. Use Encrypt, Decrypt, and Audit from the navigation bar

Security behavior in web mode:

- Session cookies are HTTPOnly + SameSite=Strict
- CSRF token protection on state-changing forms
- Passwords are submitted only via POST form body (never query string)
- Uploaded files are processed in local temporary storage and removed after processing
- No plaintext/password/key material is written to output reports

Notes:

- This app binds to localhost only (`127.0.0.1`) and is intended for local use.
- Quota/tokenization/payment hooks are intentionally not implemented yet.

## Desktop Interface (Optional)

- You can still run the Tkinter desktop UI directly:

```powershell
python prototype/ui_tkinter.py
```

The initial Tkinter prototype is in the prototype/ folder. See prototype/README_prototype.md for details.

## CLI Interface (Optional)

Use CLI commands below for automation/integration.

## Quick Run (raw text)

```powershell
$env:CRYPTOAUDIT_PASSWORD="StrongPass123!"
python main.py --text "hello from cryptoaudit" --password-env CRYPTOAUDIT_PASSWORD --output-dir outputs
```

## Quick Run (file input)

```powershell
$env:CRYPTOAUDIT_PASSWORD="StrongPass123!"
python main.py --file "C:\path\to\input.txt" --password-env CRYPTOAUDIT_PASSWORD --output-dir outputs
```

## Quick Decrypt (artifact)

```powershell
$env:CRYPTOAUDIT_PASSWORD="StrongPass123!"
python main.py --mode decrypt --artifact "outputs\20260326T000000Z_aes-256-gcm.enc.json" --password-env CRYPTOAUDIT_PASSWORD --output-dir outputs
```

## Config File

You can pass a JSON config with `--config`.

Example (`sample_config.json`):

```json
{
  "algorithms": ["aes-256-gcm", "chacha20-poly1305", "3des-ofb"],
  "pbkdf2_iterations": 600000,
  "benchmark_iterations": 10,
  "benchmark_payload_size": 1048576,
  "max_file_size_bytes": 104857600,
  "output_dir": "outputs",
  "mode_overrides": {
    "aes-256-gcm": "GCM"
  },
  "detect_reused_iv_in_config": false
}
```

Run with config:

```powershell
$env:CRYPTOAUDIT_PASSWORD="StrongPass123!"
python main.py --text "demo" --config sample_config.json --password-env CRYPTOAUDIT_PASSWORD
```

## Outputs

For each encryption run, after the pipeline completes you are directed to a result page showing:
- An inline audit summary with verdict (PASS/WARN/FAIL)
- A "Download Results (ZIP)" button

The ZIP archive contains:
- One encrypted artifact: *_algorithm.enc.json
- One HTML audit report: *_report.html

For decryption runs, after the pipeline completes you are directed to a result page showing:
- Output filename and any compatibility warnings
- A "Download Decrypted File" button
- A browser warning if you navigate away before downloading

For CLI runs, the output directory contains:
- One encrypted artifact per algorithm: *_algorithm.enc.json
- One machine-readable report: *_report.json
- One human-readable report: *_report.html

The Audit page retains the last 5 encryption run results across sessions, each independently downloadable.

## Smoke Test Harness

```powershell
python smoke_test.py
```

## Unit + Integration Tests

```powershell
python -m unittest discover -s tests -v
```
