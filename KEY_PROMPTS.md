**Student:** Adem Garip | **Student ID:** 2549603 | **GitHub:** https://github.com/Adem-grp/Cyber_Security_and_AI_Applications_Coursework

# CryptoAudit — Key Agent Prompts

**Evidence of Agentic AI Co-Production Workflow**

The following prompts represent the most significant interactions with GitHub Copilot (GPT-5.3-Codex) and Claude (Anthropic) during the development of the CryptoAudit artefact. Each prompt is presented with its purpose and the full text submitted to the agent.

All architectural decisions, security constraints, and standards choices were made by the developer. The AI agents executed these decisions based on precise directions. A condensed summary of all agent interactions is provided in `Documentation.md`.

---

## Prompt 1 — System Design Specification

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Provided a complete system design specification before any implementation began. This was the foundational prompt that defined the full architectural scope, pipeline structure, and security controls of the CryptoAudit tool. All subsequent development was directed by this specification.

**Prompt text:**

Implement the following system design specification for CryptoAudit.

**System Boundaries**
- Runs entirely locally — no network calls, no data leaves the machine
- Operates on files or raw text input provided by the user
- Outputs to local filesystem only (HTML report, JSON)
- No database, no user accounts, no persistent state between runs

**Input Types**
- A file of any type (.txt, .pdf, .csv, etc.)
- Raw text string via CLI
- A config file (JSON) specifying which algorithms to run and parameters (key size, iteration count, payload size for benchmarking)

**Input Validation Rules**
- File must exist and be readable before anything runs
- File size cap (100MB maximum) to prevent memory abuse
- Config values validated against allowed ranges — no arbitrary key sizes accepted
- No execution of input content under any circumstance — guards against path traversal and shell injection

**Algorithms In Scope**
- AES-256 / GCM — Recommended / Primary encryption
- ChaCha20 / Poly1305 — Recommended / Alternative modern cipher
- 3DES / OFB — Deprecated / Comparison and audit demonstration

**Pipeline — Step by Step**

`[Input] → [Validation] → [Key Derivation] → [Encryption Engine] → [Audit Layer] → [Benchmarking] → [Report Generator] → [Output]`

- Step 1 — Input Handler: Accept file path or raw text. Validate input (type, size, readability). Load config if provided, else use secure defaults.
- Step 2 — Key Derivation: Password entered by user at runtime — never stored, never logged. PBKDF2-HMAC-SHA256 with random 16-byte salt. Configurable iteration count (default: 600,000 per current NIST guidance). Salt stored alongside ciphertext in output.
- Step 3 — Encryption Engine: Run input through each selected algorithm independently. Each run generates its own fresh IV/nonce — never reused. Authenticated encryption (GCM, Poly1305) verifies integrity on decryption. 3DES run is clearly flagged as deprecated in output.
- Step 4 — Audit Layer: Checks each algorithm against NIST SP 800-131A and FIPS 140-3. Checks mode safety — flags ECB mode, short keys, and reused IVs if detected in config. Avalanche effect test — flips one input bit, measures ciphertext difference. Outputs a verdict per algorithm: Pass / Warn / Fail.
- Step 5 — Benchmarking Module: Measures encryption time per algorithm in milliseconds. Calculates throughput in MB/s. Measures key derivation cost separately. Runs N iterations for statistical reliability (default: 10).
- Step 6 — Report Generator: Compiles all audit verdicts, benchmarks, and metadata. Produces HTML report (human readable) and JSON (machine readable). Report includes: algorithm used, verdict, standard referenced, timing, and recommendations. Timestamps report but does NOT include the original plaintext or key anywhere.
- Step 7 — Output Handler: Writes encrypted file to specified output directory. Writes report to same directory. Confirms success or surfaces clear error messages.

**Security Controls Within the Application**
- Password is taken via getpass — never echoed to terminal, never stored in memory longer than needed
- No logging of plaintext, keys, or passwords anywhere in the codebase
- Temporary variables holding sensitive data are explicitly overwritten after use
- All randomness sourced from os.urandom() — the Python random module is never used for cryptographic purposes
- No use of eval(), exec(), or subprocess with user input
- Output directory is validated — no path traversal possible
- Dependencies pinned in requirements.txt to avoid supply chain risk

**Explicitly Out of Scope**
- No decryption of arbitrary ciphertext from unknown sources
- No network functionality
- No key storage or key management system
- No graphical interface at this stage — keeps the attack surface minimal

---

## Prompt 2 — Web Interface Conversion

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Directed the conversion of the desktop Tkinter prototype into a secure locally hosted web application. The assignment brief was included as context to ensure the artefact remained within scope. This prompt marks the transition from the early draft to the intermediate draft of the artefact.

**Prompt text:**

Convert the existing application into a secure locally hosted web interface without losing any existing functionality. The interface should support raw text input, file selection, and drag-and-drop file upload. Implement this with security as the primary concern — all processing must remain local, passwords must never appear in query strings, and uploaded files must be handled in temporary storage and removed after processing.

The application is being developed for a security consultancy context as part of the following brief:

> The organisation is a leading consultancy in the security domain, specialising in AI co-production of artefacts for security-related services or applications. You may use AI co-production, agentic AI, or vibe computing to create a security-related digital artefact.

A billing and quota system has been considered for future development but must not be implemented at this stage. Focus on delivering a clean, secure, functional interface that is appropriate for professional use.

---

## Prompt 3 — Three Targeted Web Application Fixes

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Specified three precise, scoped fixes to the Flask web application. This prompt demonstrates the iterative refinement cycle and the practice of constraining the agent to a defined scope without touching working cryptographic logic.

**Prompt text:**

Fix three specific issues in the CryptoAudit Flask web application. Do not refactor or change anything outside the defined scope of these fixes.

**FIX 1 — Audit Tab: Display live session-backed results instead of static text.**

After each successful encryption run in the /encrypt POST route, serialise the audit verdicts from the RunArtifacts result into the Flask session as "last_audit". Store: run_id, timestamp, and for each algorithm: name, verdict (PASS/WARN/FAIL), findings list, recommendation, standard_reference, avalanche difference_percent, avg_encrypt_ms, and throughput_mb_s. Update the AUDIT_BODY template and audit_page route to read "last_audit" from the session and render a styled table with colour-coded verdict badges (green=PASS, amber=WARN, red=FAIL). If no session data exists, display: "No audit data yet. Run an encryption first."

**FIX 2 — Deprecation warnings must cite published standards by name.**

In the ENCRYPT_BODY legacy confirmation modal shown when 3DES-OFB is selected, replace the generic warning text with: "3DES-OFB is classified as a legacy compatibility cipher. NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023. FIPS 140-3 transition guidance recommends migration to AES-GCM or ChaCha20-Poly1305." In the /decrypt POST route, when result.warning is not None, prepend the warning with the same NIST SP 800-131A reference so it is standards-cited rather than generic.

**FIX 3 — Display an inline audit summary on the encryption result page.**

Extend the RESULT_BODY template to accept an optional audit_summary variable. When present for encryption runs, render a compact PASS/WARN/FAIL verdict table showing algorithm name, verdict badge, and the first finding or recommendation per row. In the /encrypt POST route, extract the audit verdicts from the generated JSON report and pass the summary to RESULT_BODY as audit_summary. For decryption runs, pass audit_summary=None so the section is not displayed.

**Constraints:**
- Do not change any cryptographic logic in core.py
- Do not change execute_pipeline or execute_decrypt_pipeline
- Do not add new dependencies
- Keep all session data minimal — no plaintext, keys, or passwords stored in session
- All changes must be backward compatible with existing CLI usage

---

## Prompt 4 — Download-First Web Output

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Addressed the architectural issue where the web application was writing encrypted outputs to the server filesystem instead of serving them directly to the browser. Outputs written to the server filesystem are inaccessible to the user and represent unnecessary data retention — this fix corrected both the usability and security posture of the web interface.

**Prompt text:**

Fix the web output handling in cryptoaudit/frontend/web.py. Do not touch core.py cryptographic logic or the CLI pipeline.

**Web output must be served as in-memory downloads, not written to the server filesystem.**

In the /encrypt POST route, after execute_pipeline completes: read the encrypted artifact JSON file and the HTML report into memory, delete both from disk immediately after reading, then return an in-memory ZIP archive as a Flask download response using io.BytesIO and Python's zipfile module. Name the archive: `cryptoaudit_{result.run_id}.zip`. In web mode, use tempfile.TemporaryDirectory() for all intermediate files and clean up after reading into memory. Stop writing to any persistent outputs directory in web mode entirely.

**Constraints:**
- Do not change any cryptographic logic in core.py
- Do not add new pip dependencies beyond what is already imported
- All sensitive data — keys, passwords, plaintext — must be wiped from memory before the response is returned
- CLI behaviour must remain completely unchanged

---

## Prompt 5 — Comprehensive Edge Case Handling

**Submitted to:** GitHub Copilot (GPT-5.3-Codex) — specification developed with Claude (Anthropic)

**Purpose:** Directed the agent to implement comprehensive edge case coverage across all audit scenarios, grounding each case in published cryptographic standards. This prompt demonstrates the technical depth of the standards alignment work and the iterative refinement applied to the audit layer.

**Prompt text:**

Add comprehensive edge case handling to the CryptoAudit audit layer in core.py. Do not change any encryption or decryption logic. Only modify run_audit and related audit verdict logic.

**EDGE CASE 1 — AES-GCM and ChaCha20-Poly1305 avalanche behaviour**

AES-256-GCM, AES-192-GCM, AES-128-GCM, and ChaCha20-Poly1305 all use CTR/stream XOR constructions. A single-bit plaintext change produces a localised ciphertext change by design — this is not a weakness. When avalanche_percent is below the expected range and the algorithm is one of these AEAD modes, set verdict to PASS and add finding: "Avalanche measured at {avalanche_percent}%. AEAD modes (GCM, ChaCha20-Poly1305) use CTR/stream XOR — single-bit input changes produce localised output changes by design. This is expected behaviour and does not indicate a weakness."

**EDGE CASE 2 — 3DES-OFB stream mode and authentication gap**

3DES-OFB is a stream-mode cipher (Output Feedback). Unlike AEAD modes, it has no authentication tag, so ciphertext tampering may not be detected on decryption. Always add findings: "3DES-OFB has no authentication tag. Ciphertext tampering may not be detected on decryption. NIST SP 800-131A Rev.2 disallows 3DES for new applications after 2023." and "Effective security is 112 bits due to meet-in-the-middle attacks on Triple DES, despite the 192-bit key size." Verdict must always be at minimum WARN for 3DES-OFB.

**EDGE CASE 3 — Near-empty input**

If the avalanche result shows total_bits under 16, add finding: "Input is too short for a reliable avalanche measurement. Avalanche result should be ignored for inputs under 2 bytes." Do not change verdict solely for this reason.

**EDGE CASE 4 — PBKDF2 iteration count thresholds**

Check config.pbkdf2_iterations: below 200,000 — verdict FAIL, cite NIST SP 800-132 minimum recommendation; between 200,000 and 599,999 — verdict at minimum WARN, cite NIST SP 800-132 recommended value of 600,000; 600,000 or above — no finding required.

**EDGE CASE 5 — Key length adequacy**

AES-128-GCM: add finding "AES-128-GCM provides 128-bit security. Acceptable per NIST SP 800-131A Rev.2 but AES-256-GCM is preferred for long-term data protection." Verdict stays PASS.

**EDGE CASE 6 — ChaCha20-Poly1305 FIPS validation context**

Add finding: "ChaCha20-Poly1305 is not included in FIPS 140-3 approved algorithm lists for all validation contexts. If operating in a FIPS-regulated environment, use AES-256-GCM instead. For general security use, ChaCha20-Poly1305 is a strong modern choice." Verdict stays PASS.

**Constraints:**
- Only modify run_audit and related audit verdict logic
- Do not change encrypt_payload, decrypt_payload, avalanche_test, or benchmark_algorithm
- Verdict precedence is always: FAIL > WARN > PASS — never downgrade a verdict already set to a higher severity

---

## Prompt 6 — AEAD Avalanche Verdict Correction

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Corrected a technically inaccurate audit verdict where AES-GCM and ChaCha20-Poly1305 were being flagged as WARN for low avalanche percentages. Low avalanche in these modes is expected and correct behaviour — the classical avalanche property applies to the raw block cipher permutation, not the full AEAD construction. This prompt demonstrates cryptographic understanding applied to improving the accuracy of the tool's audit output.

**Prompt text:**

In cryptoaudit/backend/core.py, in the run_audit function, correct the avalanche verdict logic. Currently the function sets verdict to WARN when avalanche_percent is below the expected range for all algorithms, including AES-GCM variants and ChaCha20-Poly1305. This is technically incorrect for AEAD modes.

Apply the following correction: when the algorithm is aes-256-gcm, aes-192-gcm, aes-128-gcm, or chacha20-poly1305 and avalanche_percent is below the expected range, set verdict to PASS and add finding: "Avalanche measured at {avalanche_percent}%. AEAD modes (GCM, ChaCha20-Poly1305) use CTR/stream XOR construction — single-bit input changes produce localised output changes by design. This is expected behaviour and does not indicate a weakness." When the algorithm is 3des-ofb and avalanche is below expected range, retain verdict as WARN — the algorithm itself warrants this classification regardless of the avalanche measurement.

Do not modify any logic outside the avalanche verdict assignment block in run_audit.

---

## Prompt 7 — Dedicated Result Pages with Download Buttons and Navigation Warning

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Replaced automatic file downloads with dedicated result pages for both encryption and decryption. Automatic downloads can be blocked by browser settings, which would leave the user with no output and no confirmation. The result pages provide an inline audit summary, a manual Download button, and a browser warning if the user navigates away before downloading — preventing accidental loss of access to the output.

**Prompt text:**

In cryptoaudit/frontend/web.py, replace the automatic download response in the /encrypt POST route with a dedicated result page flow.

After execute_pipeline completes, save the ZIP archive to a temporary location under tempfile.gettempdir()/cryptoaudit_downloads using the run_id as a unique identifier. Redirect to a new route /app/result/<run_id> that displays the inline audit summary table and a prominent Download Results (ZIP) button. Create a new route /app/download/<run_id> that reads the saved ZIP into memory, deletes it from disk, and returns it as a Flask send_file response. If the file is not found, flash an expiry error and redirect to the encrypt page.

Add a beforeunload JavaScript warning on the result page that fires only if the user navigates away before clicking the download button. Suppress the warning once the button is clicked. Extend temporary file retention to 24 hours and clean up files older than this threshold on application startup.

Apply the same result page pattern to the /decrypt POST route. After decryption completes, redirect to /app/decrypt_result/<run_id> showing the output filename, any compatibility warnings citing NIST SP 800-131A Rev.2 where applicable, and a Download Decrypted File button. Create /app/download_decrypted/<run_id> serving the recovered file. Apply the same beforeunload warning.

**Constraints:**
- Do not change any cryptographic logic
- Do not change the audit history display
- Apply to both CryptoAudit artifact mode and External/Manual Parameters mode

---

## Prompt 8 — Audit History Showing Up to Five Recent Runs

**Submitted to:** GitHub Copilot (GPT-5.3-Codex)

**Purpose:** Changed the session-backed audit storage from a single overwriting entry to a history of up to five recent runs. This made the audit page genuinely useful as a reference — users can review and compare results across multiple encryption runs, and each entry includes its own independent download link. History is intentionally persisted across server restarts, appropriate behaviour for a local single-user tool.

**Prompt text:**

In cryptoaudit/frontend/web.py, change the session-backed audit storage from storing only the most recent run to maintaining a history of up to five runs.

After each successful encryption, append the new audit result to session["audit_history"] as a list rather than overwriting session["last_audit"]. If the list exceeds five entries, remove the oldest. Update the /app/audit route and AUDIT_BODY template to render all entries in session["audit_history"] as collapsible sections ordered most recent first. Each section header must display the run ID and timestamp. Each expanded entry must show the full audit table and a Download ZIP button linking to /app/download/<run_id> for that specific run. Retain the existing empty state message when no history exists: "No audit data yet. Run an encryption first."

**Constraints:**
- Do not change any cryptographic logic
- Do not change the /encrypt pipeline
- History persistence across server restarts via session cookie is intentional — do not add any logic to clear it on startup
