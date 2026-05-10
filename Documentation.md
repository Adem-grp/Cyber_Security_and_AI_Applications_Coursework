# CryptoAudit Project Documentation (Step-by-Step)

Date updated: 2026-05-10
Repository/workspace: `C:\Users\USER\PycharmProjects\CyberSecurityAIApplications`

## Checklist

- [x] Capture the original project scope and constraints
- [x] Document implementation milestones in chronological order
- [x] Record security decisions and rationale
- [x] Record UI/UX evolution (CLI -> Tkinter -> Web)
- [x] Record crypto/audit/benchmark capabilities implemented
- [x] Record test evidence and current verification status
- [x] Include key prompts that drove major changes
- [x] List Scope boundaries and future work items

---

## 1) Original Goal and System Scope

CryptoAudit was designed as a **local-only cryptographic benchmarking + audit tool** for security-focused use cases.

### Target boundaries

- Runs locally only; no external network dependency for core crypto processing
- Accepts either:
  - file input (any binary type, including video), or
  - raw text input
- Uses config-driven behavior with secure defaults
- Outputs to local filesystem only:
  - encrypted artifact JSON files
  - machine-readable report JSON
  - human-readable report HTML
- No plaintext, passwords, or keys persisted in reports/artifacts

### Core cryptographic scope

- AES-GCM family:
  - `aes-256-gcm`
  - `aes-192-gcm`
  - `aes-128-gcm`
- `chacha20-poly1305`
- `3des-ofb` (compatibility/deprecated-warning path)

### Security baseline

- PBKDF2-HMAC-SHA256 key derivation with random 16-byte salt
- Fresh nonce/IV per encryption run
- Input validation + size caps
- Output directory safety checks
- Avoid dangerous execution patterns (`eval`, `exec`, shell injection patterns)

---

## 2) Chronological Implementation Milestones

## Milestone A - Hardened Core Pipeline in `main.py`

Implemented/confirmed the full pipeline lifecycle:

1. Input handling (`--file` or `--text`)
2. Validation of config and sizes
3. KDF generation per algorithm run
4. Encryption engine per selected algorithm
5. Audit layer with standards-aware verdicting
6. Benchmarking and timing metrics
7. HTML + JSON report generation
8. Output writing and path safety

### Important functions in `main.py`

- `validate_config` - enforces safe algorithm/value ranges
- `load_input` - validates readability and input size limits
- `derive_key` - PBKDF2-HMAC-SHA256
- `encrypt_payload` / `decrypt_payload` - algorithm-specific crypto handling
- `avalanche_test` - one-bit flip diffusion measurement
- `run_audit` - pass/warn/fail evaluation with standards references
- `benchmark_algorithm` - latency/throughput results
- `execute_pipeline` - full encrypt/audit/report orchestrator
- `execute_decrypt_pipeline` - artifact decryption/recovery path

---

## Milestone B - Desktop UI path in `ui_tkinter.py`

A local GUI was introduced to avoid mandatory CLI usage and improve presentation.

### UI capabilities added

- Encrypt/decrypt operation switching
- File input and raw text input
- Algorithm selection checkboxes
- Advanced settings section (with recommended defaults shown)
- Decryption artifact picker + output filename option
- Run execution on worker thread (UI responsiveness)
- Completion and error dialogs

### UX/safety behaviors added

- Password field masking
- Legacy/compatibility algorithm warning message before run
- Password buffer cleanup after run (best-effort overwrite)
- Clear success and warning messaging

---

## Milestone C - CLI/GUI entry behavior fix in `main.py`

Issue observed: running `python main.py` without args produced CLI argument errors in earlier flow expectations.

### Fix implemented

- `main.py` now launches interface mode when no CLI args are provided.
- Later improved to prefer web interface launcher, with Tkinter fallback:
  - First try `web_app.py`
  - fallback to `ui_tkinter.py`

---

## Milestone D - Algorithm set expansion + deprecation UX

Enhancements included:

- Added modern AES-GCM variants beyond AES-256 (`aes-192-gcm`, `aes-128-gcm`)
- Kept ChaCha20-Poly1305
- Kept 3DES-OFB as compatibility-only path
- Changed deprecation handling to user-confirmed warnings rather than static-only labels

---

## Milestone E - Advanced settings usability

To reduce user confusion while preserving power-user control:

- Recommended defaults clearly displayed
- Advanced controls separated from basic flow
- Guidance text indicates these fields are optional for most users

---

## Milestone F - Binary/video encryption support validation

The encryption pipeline already handled bytes, so support is format-agnostic.

### What was validated

- Integration testing performed with video-like random binary payload and file extension (`.mp4`)
- Encryption/decryption roundtrip verified byte-for-byte
- This confirms practical support for videos and other binary files

---

## Milestone G - Secure Local Web Interface (`web_app.py`)

A secure website-style interface was implemented while preserving core functionality.

### Implemented web features

- Local Flask app (`127.0.0.1:8765`)
- Main dashboard (`/app`) with:
  - text input
  - file upload + drag-and-drop
  - algorithm selection
  - optional advanced settings
- Encrypt endpoint (`/encrypt`) using existing core pipeline
- Decrypt endpoint (`/decrypt`) using existing decrypt pipeline

## 3) Files Added/Updated

### Added
- cryptoaudit/backend/core.py - cryptographic engine
- cryptoaudit/frontend/web.py - secure local web interface with result pages for encryption and decryption, audit history, and download handling
- prototype/ui_tkinter.py - initial Tkinter desktop prototype (early draft)
- prototype/README_prototype.md - setup and run instructions for the prototype
- tests/test_web_app.py - web behaviour tests
- Documentation.md - this project log

### Updated
- main.py - entry point, launches web interface with Tkinter fallback
- requirements.txt - all project dependencies
- README.md - run instructions and project structure
- .gitignore - excludes .cryptoaudit_web/, outputs/, __pycache__/

---

## 4) Testing and Verification Evidence

### Test command used

```powershell
python -u -m unittest discover -s tests -v
```

### Last verified result (from current session)

- Total tests: **32**
- Status: **OK**

### Coverage observed in test run

- Core config/input validation tests
- Crypto primitive wrapper tests
- Audit/report generation tests
- CLI integration tests
- Decrypt roundtrip and wrong-password handling
- UI warning logic tests
- New web encrypt warning tests

---

## 5) Important Prompt Log (Condensed)

Below are the key user prompts that drove scope changes and implementation decisions.

1. **System design specification provided**
   - Required local-only architecture, validation, KDF, multi-algorithm encryption, audit, benchmarking, report generation, and secure controls.

2. **"Comment near each function" request**
   - Led to explicit intention-revealing function docstrings/comments across modules.

3. **"Can we create an application interface"**
   - Triggered UI effort beyond pure CLI.

4. **"Find best option and implement interfaces securely"**
   - Drove security-first UI design decisions and stronger safeguards.

5. **"Run button and warnings should work"**
   - Added confirmation and clear success/error messaging.

6. **CLI error report: `--file` or `--text` required**
   - Prompted no-arg launch behavior to open interface instead of strict CLI requirement.

7. **"We are not doing CLI remember"**
   - Shifted default usage toward interface-first operation.

8. **"Add more algorithms" + better deprecation messaging**
   - Added AES-192/AES-128 and improved 3DES warning confirmation UX.

9. **"Are advanced params necessary?" / simplify for users**
   - Added recommended defaults and optional advanced section strategy.

10. **"Turn into a secure website with text/drag-drop/file + login"**
    - Resulted in `web_app.py`, local auth groundwork, and secure web interface implementation.

11. **"Include assignment constraints"**
    - Reinforced documentation quality, methodology traceability, and viva-readiness focus.

---

## 6) Security Posture Summary (Current Build)

### Strong points currently in place

- Local-only workflow for crypto processing and outputs
- Config and input range validation
- Random salt + random nonce/IV per run
- Standards-aware audit and deprecated algorithm warnings
- Password handling with in-memory buffers and wipe best-effort
- No plaintext/password/key exposure in reports
- Web session baseline with CSRF token protection
- Dedicated result pages for both encryption and decryption with browser navigation warnings to prevent accidental loss of download access

### Trade-offs acknowledged

- Web UI increases convenience but introduces additional local attack surface versus Tkinter
- Session secret key is auto-generated and stored locally; host endpoint is loopback-only by default

---

## 7) Scope Boundaries

- No remote cloud deployment hardening yet (this is local-first)
- No production WSGI server/reverse proxy setup in this coursework phase
- No key management service/HSM integration
- No payment/quota/token pipeline implementation yet

---

## 8) Future Work 

1. **Threat model appendix**
   - Include assets, adversaries, trust boundaries, abuse cases, and mitigations.
2. **Web hardening pass (if moving beyond local demo)**
   - Add rate limiting, lockout policy, structured audit logging, and secure deployment profile.
3. **Feature roadmap alignment**
   - Optional: add controlled API mode, usage quotas, and billing only after security review.
4. **Viva preparation**
   - Prepare a concise walkthrough of: requirements -> design decisions -> test evidence -> trade-offs.

---

## 9) Quick Run Guide

### Final Product (Web Interface — Recommended)
pip install -r requirements.txt
python main.py
Then open http://127.0.0.1:8765 in your browser.

### Initial Prototype (Tkinter Desktop)
pip install -r requirements.txt
python prototype/ui_tkinter.py

### CLI Mode (Optional)
Set password as environment variable:
$env:CRYPTOAUDIT_PASSWORD="YourPassword"

Encrypt text:
python main.py --text "your text" 
  --password-env CRYPTOAUDIT_PASSWORD 
  --output-dir outputs

Encrypt file:
python main.py --file "path/to/file.pdf"
  --password-env CRYPTOAUDIT_PASSWORD
  --output-dir outputs

Decrypt artifact:
python main.py --mode decrypt 
  --artifact "outputs/run_id_aes-256-gcm.enc.json"
  --password-env CRYPTOAUDIT_PASSWORD
  --output-dir outputs

### Run Tests
python -m unittest discover -s tests -v

---

## 10) Recent Milestones Added (Post-March Updates)

This section appends the latest work without removing earlier milestones.

### Milestone H - Web UX alignment for a genuine CryptoAudit workflow

- Encryption algorithm selector was changed from multi-checkboxes to a single-selection flow in `cryptoaudit/frontend/web.py`.
- Plain algorithm names are shown in the UI (removed inline `(recommended)` / `(deprecated)` suffixes from selection labels).
- Clarified behavior: one algorithm is applied per encryption run; multi-run comparison is done by separate runs.
- Legacy 3DES remains available behind explicit confirmation.
- Encryption heading changed from 'Encrypt + Audit' to 'Encrypt' to avoid confusion with the dedicated Audit page.

### Milestone I - Audit page changed from static text to real run data

- Added session-backed audit persistence in web flow (`session["last_audit"]`) after successful encryption in `cryptoaudit/frontend/web.py`.
- Stored minimal metadata only:
  - `run_id`, timestamp
  - per-algorithm verdict data, findings, recommendation, standards reference, avalanche %, average encryption ms, throughput MB/s
- Updated Audit tab rendering to show a structured table with colour-coded verdict badges:
  - PASS (green), WARN (amber), FAIL (red)
- Added empty-state message: `No audit data yet. Run an encryption first.`

### Milestone J - Standards-cited warning behavior improvements

- Updated 3DES modal warning text to cite standards directly (NIST SP 800-131A Rev.2 and FIPS 140-3 transition guidance) in `cryptoaudit/frontend/web.py`.
- Decrypt warning handling was updated to include standards-cited context in web responses.
- Avalanche warning text in `cryptoaudit/backend/core.py` (`run_audit`) was expanded to explicitly explain short-input statistical limitations.

### Milestone K - Web output handling hardened (result page + download-first)

- Web encryption route now redirects to a dedicated result page (/app/result/<run_id>) after each successful encryption run.
- Result page displays an inline audit summary table with algorithm name, colour-coded verdict badge, and key finding.
- A "Download Results (ZIP)" button on the result page serves an in-memory ZIP archive containing:
  - encrypted artifact JSON
  - HTML audit report
- ZIP is stored temporarily under tempfile.gettempdir()/cryptoaudit_downloads with a 24-hour retention window.
- /decrypt still returns recovered bytes as an in-memory binary download (application/octet-stream).
- Decrypt compatibility warnings are returned via X-CryptoAudit-Warning response header when present.
- Intermediate files are read into memory and deleted from disk before response completion.

### Milestone L - Test and smoke-run hygiene improvements

- Updated web tests in `tests/test_web_app.py` to validate current download-first behavior and warning header semantics.
- `smoke_test.py` output handling was updated to use `tempfile.TemporaryDirectory()` so ad-hoc smoke artifacts do not pollute project-root output folders.

### Milestone M - Audit history (up to 5 runs)

- Changed session-backed audit storage from single last_audit entry to audit_history list in cryptoaudit/frontend/web.py.
- Stores up to 5 most recent encryption run results, oldest removed when limit is exceeded.
- Audit page renders all history entries as collapsible sections, most recent first.
- Each section header shows run ID and timestamp.
- Each expanded entry shows full audit table plus a Download ZIP button for that specific run.
- History persists across server restarts via session cookie — intentional behaviour for a local single-user tool.
- Empty state message retained: "No audit data yet. Run an encryption first."

### Milestone N - UX polish and download safety

- Added beforeunload JavaScript warning on the result page: shown only if user attempts to navigate away before clicking Download Results.
- Warning message: "You have not downloaded your encrypted results yet. If you leave this page the download link may expire."
- Warning is suppressed once Download Results is clicked (downloaded flag set to true).
- Temp file retention extended from 1 hour to 24 hours to reduce likelihood of expiry during normal use.
- Raw text and file upload input sections on the encrypt page are now shown/hidden dynamically via JavaScript based on the selected radio button, reducing visual clutter.

### Milestone O - Decryption result page

- /decrypt POST route now redirects to a dedicated result page (/app/decrypt_result/<run_id>) instead of immediately returning the file as a download.
- Decrypt result page displays:
  - Run ID and timestamp
  - Output filename specified by the user
  - Compatibility warning banner if applicable (citing NIST SP 800-131A Rev.2 for 3DES)
  - Download Decrypted File button serving the recovered file via /app/download_decrypted/<run_id>
- Decrypted file is stored temporarily under tempfile.gettempdir()/cryptoaudit_downloads with 24-hour retention, consistent with encryption download retention.
- beforeunload JavaScript warning added, shown if user navigates away before clicking download.
- Applied to both CryptoAudit artifact mode and External/Manual Parameters mode.

### Recent verification evidence (targeted)

- Executed targeted web tests:

```powershell
python tests/test_web_app.py
```

- Executed a focused avalanche-message check:

```powershell
python -c "import main; cfg=main.AppConfig(); v=main.run_audit(main.ALGO_AES_GCM,cfg,20.0); print(v.findings[-1])"
```

- Note: a full `tests/test_main.py` run in this session encountered an existing long-running interface-launch path unrelated to these milestone updates.
