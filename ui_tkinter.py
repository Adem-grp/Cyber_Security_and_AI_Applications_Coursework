from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from main import (
    ALGO_3DES,
    ALGO_AES_128_GCM,
    ALGO_AES_192_GCM,
    ALGO_AES_GCM,
    ALGORITHM_SPECS,
    ALGO_CHACHA,
    AppConfig,
    DEFAULT_BENCHMARK_ITERATIONS,
    DEFAULT_BENCHMARK_PAYLOAD_SIZE,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_PBKDF2_ITERATIONS,
    DecryptArtifacts,
    execute_pipeline,
    execute_decrypt_pipeline,
    load_config,
    wipe_bytearray,
)


def build_selection_warning(selected_algorithms: list[str]) -> Optional[str]:
    """Return a warning message when non-recommended algorithms are selected."""
    non_recommended = [alg for alg in selected_algorithms if ALGORITHM_SPECS.get(alg, {}).get("status") != "recommended"]
    if not non_recommended:
        return None

    display = ", ".join(non_recommended)
    return (
        f"You selected compatibility-focused algorithm(s): {display}.\n"
        "These are kept for interoperability/testing and are not recommended for new deployments.\n\n"
        "Do you want to continue this run?"
    )


class CryptoAuditUI:
    """Desktop interface that drives the same secure core pipeline as the CLI."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CryptoAudit - Secure Local Interface")
        self.root.geometry("860x700")

        self.input_mode = tk.StringVar(value="file")
        self.operation_mode = tk.StringVar(value="encrypt")
        self.file_path = tk.StringVar()
        self.artifact_path = tk.StringVar()
        self.decrypt_output_file = tk.StringVar()
        self.config_path = tk.StringVar()
        self.output_dir = tk.StringVar(value="outputs_ui")

        self.pbkdf2_iterations = tk.StringVar(value=str(DEFAULT_PBKDF2_ITERATIONS))
        self.benchmark_iterations = tk.StringVar(value=str(DEFAULT_BENCHMARK_ITERATIONS))
        self.benchmark_payload_size = tk.StringVar(value=str(DEFAULT_BENCHMARK_PAYLOAD_SIZE))
        self.max_file_size_bytes = tk.StringVar(value=str(DEFAULT_MAX_FILE_SIZE))

        self.algo_aes = tk.BooleanVar(value=True)
        self.algo_aes_192 = tk.BooleanVar(value=False)
        self.algo_aes_128 = tk.BooleanVar(value=False)
        self.algo_chacha = tk.BooleanVar(value=True)
        self.algo_3des = tk.BooleanVar(value=False)

        self.password = tk.StringVar()
        self.run_button: Optional[tk.Button] = None

        self._build_layout()

    def _build_layout(self) -> None:
        """Create and arrange all form controls for secure local operation."""
        container = tk.Frame(self.root, padx=12, pady=12)
        container.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)

        basic_tab = tk.Frame(notebook, padx=8, pady=8)
        advanced_tab = tk.Frame(notebook, padx=8, pady=8)
        notebook.add(basic_tab, text="Basic")
        notebook.add(advanced_tab, text="Advanced")

        tk.Label(basic_tab, text="Operation", font=("Arial", 11, "bold")).pack(anchor="w")
        op_frame = tk.Frame(basic_tab)
        op_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Radiobutton(
            op_frame,
            text="Encrypt",
            variable=self.operation_mode,
            value="encrypt",
            command=self._refresh_mode_ui,
        ).pack(side=tk.LEFT)
        tk.Radiobutton(
            op_frame,
            text="Decrypt",
            variable=self.operation_mode,
            value="decrypt",
            command=self._refresh_mode_ui,
        ).pack(side=tk.LEFT)

        self.encrypt_section = tk.Frame(basic_tab)
        self.decrypt_section = tk.Frame(basic_tab)
        self.encrypt_section.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.encrypt_section, text="Input Source", font=("Arial", 11, "bold")).pack(anchor="w")
        source_frame = tk.Frame(self.encrypt_section)
        source_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Radiobutton(source_frame, text="File", variable=self.input_mode, value="file").pack(side=tk.LEFT)
        tk.Radiobutton(source_frame, text="Raw Text", variable=self.input_mode, value="text").pack(side=tk.LEFT)

        file_frame = tk.Frame(self.encrypt_section)
        file_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(file_frame, text="File Path", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(file_frame, textvariable=self.file_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(file_frame, text="Browse", command=self._pick_input_file).pack(side=tk.LEFT, padx=(8, 0))

        tk.Label(self.encrypt_section, text="Raw Text (used only when 'Raw Text' is selected)", anchor="w").pack(fill=tk.X)
        self.text_input = tk.Text(self.encrypt_section, height=8)
        self.text_input.pack(fill=tk.BOTH, pady=(0, 10))

        tk.Label(self.encrypt_section, text="Algorithms", font=("Arial", 11, "bold")).pack(anchor="w")
        algo_frame = tk.Frame(self.encrypt_section)
        algo_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Checkbutton(algo_frame, text="AES-256-GCM", variable=self.algo_aes).pack(side=tk.LEFT)
        tk.Checkbutton(algo_frame, text="AES-192-GCM", variable=self.algo_aes_192).pack(side=tk.LEFT, padx=(10, 0))
        tk.Checkbutton(algo_frame, text="AES-128-GCM", variable=self.algo_aes_128).pack(side=tk.LEFT, padx=(10, 0))

        algo_frame_2 = tk.Frame(self.encrypt_section)
        algo_frame_2.pack(fill=tk.X, pady=(0, 10))
        tk.Checkbutton(algo_frame_2, text="ChaCha20-Poly1305", variable=self.algo_chacha).pack(side=tk.LEFT)
        tk.Checkbutton(algo_frame_2, text="3DES-OFB (Compatibility)", variable=self.algo_3des).pack(side=tk.LEFT, padx=(10, 0))

        tk.Label(self.decrypt_section, text="Artifact File", font=("Arial", 11, "bold")).pack(anchor="w")
        artifact_row = tk.Frame(self.decrypt_section)
        artifact_row.pack(fill=tk.X, pady=(0, 8))
        tk.Label(artifact_row, text="Artifact", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(artifact_row, textvariable=self.artifact_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(artifact_row, text="Browse", command=self._pick_artifact_file).pack(side=tk.LEFT, padx=(8, 0))

        decrypt_name_row = tk.Frame(self.decrypt_section)
        decrypt_name_row.pack(fill=tk.X, pady=(0, 8))
        tk.Label(decrypt_name_row, text="Output Filename", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(decrypt_name_row, textvariable=self.decrypt_output_file).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(
            self.decrypt_section,
            text="Decrypt mode accepts CryptoAudit artifact JSON and writes recovered bytes locally.",
            fg="#555555",
            justify="left",
            wraplength=780,
        ).pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            basic_tab,
            text="Advanced tuning is optional. Use the Advanced tab only if needed.",
            fg="#555555",
        ).pack(anchor="w", pady=(0, 8))

        pass_frame = tk.Frame(basic_tab)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(pass_frame, text="Password", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(pass_frame, textvariable=self.password, show="*").pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(
            basic_tab,
            text="Security notes: no plaintext/password/keys are written; outputs contain ciphertext and reports only.",
            fg="#333333",
            wraplength=800,
            justify="left",
        ).pack(fill=tk.X, pady=(4, 10))

        self.run_button = tk.Button(basic_tab, text="Run CryptoAudit", command=self._run_clicked, height=2)
        self.run_button.pack(fill=tk.X)
        self._refresh_mode_ui()

        defaults_frame = tk.Frame(advanced_tab, bd=1, relief=tk.GROOVE, padx=8, pady=8)
        defaults_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(defaults_frame, text="Recommended Defaults", font=("Arial", 11, "bold")).pack(anchor="w")
        tk.Label(
            defaults_frame,
            text=self._recommended_defaults_text(),
            justify="left",
            anchor="w",
            fg="#333333",
            wraplength=780,
        ).pack(fill=tk.X, pady=(4, 0))

        path_frame = tk.Frame(advanced_tab)
        path_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(path_frame, text="Config JSON", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(path_frame, textvariable=self.config_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(path_frame, text="Browse", command=self._pick_config_file).pack(side=tk.LEFT, padx=(8, 0))

        out_frame = tk.Frame(advanced_tab)
        out_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(out_frame, text="Output Directory", width=16, anchor="w").pack(side=tk.LEFT)
        tk.Entry(out_frame, textvariable=self.output_dir).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(out_frame, text="Browse", command=self._pick_output_dir).pack(side=tk.LEFT, padx=(8, 0))

        tk.Label(advanced_tab, text="Parameters", font=("Arial", 11, "bold")).pack(anchor="w")
        params = tk.Frame(advanced_tab)
        params.pack(fill=tk.X, pady=(0, 2))

        self._param_row(params, "PBKDF2 Iterations", self.pbkdf2_iterations)
        self._param_row(params, "Benchmark Iterations", self.benchmark_iterations)
        self._param_row(params, "Benchmark Payload Size", self.benchmark_payload_size)
        self._param_row(params, "Max File Size Bytes", self.max_file_size_bytes)

    @staticmethod
    def _recommended_defaults_text() -> str:
        """Return a plain-language summary of safe default advanced values."""
        benchmark_mb = DEFAULT_BENCHMARK_PAYLOAD_SIZE // (1024 * 1024)
        max_file_mb = DEFAULT_MAX_FILE_SIZE // (1024 * 1024)
        return (
            f"PBKDF2 Iterations: {DEFAULT_PBKDF2_ITERATIONS:,} (strong password hardening; higher is slower).\n"
            f"Benchmark Iterations: {DEFAULT_BENCHMARK_ITERATIONS} (stable timings without long runs).\n"
            f"Benchmark Payload Size: {benchmark_mb} MB (balanced speed test size).\n"
            f"Max File Size: {max_file_mb} MB (prevents oversized input abuse).\n"
            "Output Directory: outputs_ui (safe local default).\n"
            "Tip: leave these values unchanged unless you are benchmarking a specific environment."
        )

    @staticmethod
    def _param_row(parent: tk.Frame, label: str, var: tk.StringVar) -> None:
        """Render a single labeled numeric parameter entry row."""
        row = tk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        tk.Label(row, text=label, width=20, anchor="w").pack(side=tk.LEFT)
        tk.Entry(row, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _pick_input_file(self) -> None:
        """Open a file picker for selecting the input file path."""
        selected = filedialog.askopenfilename()
        if selected:
            self.file_path.set(selected)

    def _pick_artifact_file(self) -> None:
        """Open a file picker for selecting an encrypted artifact JSON file."""
        selected = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if selected:
            self.artifact_path.set(selected)

    def _pick_config_file(self) -> None:
        """Open a file picker for selecting an optional config JSON file."""
        selected = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")])
        if selected:
            self.config_path.set(selected)

    def _pick_output_dir(self) -> None:
        """Open a directory picker for selecting where outputs will be written."""
        selected = filedialog.askdirectory()
        if selected:
            self.output_dir.set(selected)

    def _refresh_mode_ui(self) -> None:
        """Toggle Encrypt/Decrypt sections based on the selected operation mode."""
        if self.operation_mode.get() == "encrypt":
            self.decrypt_section.pack_forget()
            if not self.encrypt_section.winfo_manager():
                self.encrypt_section.pack(fill=tk.BOTH, expand=True)
            return

        self.encrypt_section.pack_forget()
        if not self.decrypt_section.winfo_manager():
            self.decrypt_section.pack(fill=tk.BOTH, expand=True)


    def _selected_algorithms(self) -> list[str]:
        """Return the list of algorithms enabled by UI checkboxes."""
        selected: list[str] = []
        if self.algo_aes.get():
            selected.append(ALGO_AES_GCM)
        if self.algo_aes_192.get():
            selected.append(ALGO_AES_192_GCM)
        if self.algo_aes_128.get():
            selected.append(ALGO_AES_128_GCM)
        if self.algo_chacha.get():
            selected.append(ALGO_CHACHA)
        if self.algo_3des.get():
            selected.append(ALGO_3DES)
        return selected

    def _build_runtime_config(self) -> AppConfig:
        """Combine optional config file values with explicit UI overrides."""
        if self.config_path.get().strip():
            config = load_config(self.config_path.get().strip())
        else:
            config = AppConfig()

        config.algorithms = self._selected_algorithms()
        config.pbkdf2_iterations = int(self.pbkdf2_iterations.get().strip())
        config.benchmark_iterations = int(self.benchmark_iterations.get().strip())
        config.benchmark_payload_size = int(self.benchmark_payload_size.get().strip())
        config.max_file_size_bytes = int(self.max_file_size_bytes.get().strip())
        config.output_dir = self.output_dir.get().strip() or "outputs_ui"
        return config

    def _run_clicked(self) -> None:
        """Start pipeline execution on a worker thread to keep UI responsive."""
        if self.operation_mode.get() == "encrypt":
            selected_algorithms = self._selected_algorithms()
            warning_message = build_selection_warning(selected_algorithms)
            if warning_message:
                confirmed = messagebox.askyesno("Algorithm Selection Warning", warning_message, icon="warning")
                if not confirmed:
                    return

        if self.run_button is not None:
            self.run_button.config(state=tk.DISABLED, text="Running...")
        worker = threading.Thread(target=self._run_pipeline_safe, daemon=True)
        worker.start()

    def _run_pipeline_safe(self) -> None:
        """Validate inputs, execute the pipeline, and present results safely."""
        password_buf: Optional[bytearray] = None
        try:
            password_raw = self.password.get()
            if not password_raw:
                raise ValueError("Password is required")

            password_buf = bytearray(password_raw.encode("utf-8"))

            if self.operation_mode.get() == "encrypt":
                config = self._build_runtime_config()
                input_file: Optional[str] = None
                input_text: Optional[str] = None

                if self.input_mode.get() == "file":
                    input_file = self.file_path.get().strip()
                    if not input_file:
                        raise ValueError("Select an input file or switch to raw text mode")
                else:
                    input_text = self.text_input.get("1.0", tk.END).rstrip("\n")
                    if not input_text:
                        raise ValueError("Raw text input cannot be empty")

                if not config.algorithms:
                    raise ValueError("Select at least one algorithm")

                result = execute_pipeline(
                    config=config,
                    input_file=input_file,
                    input_text=input_text,
                    password=password_buf,
                )

                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "CryptoAudit Complete",
                        "Encryption finished successfully.\n\n"
                        f"Output Dir: {result.output_dir}\n"
                        f"JSON Report: {result.report_json_path}\n"
                        f"HTML Report: {result.report_html_path}",
                    ),
                )
            else:
                artifact_file = self.artifact_path.get().strip()
                if not artifact_file:
                    raise ValueError("Select an artifact file for decrypt mode")

                decrypt_name = self.decrypt_output_file.get().strip() or None
                result = execute_decrypt_pipeline(
                    artifact_file=artifact_file,
                    password=password_buf,
                    output_dir=self.output_dir.get().strip() or "outputs_ui",
                    output_file_name=decrypt_name,
                    allow_overwrite=False,
                )
                self.root.after(0, lambda: self._show_decrypt_success(result))

        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("CryptoAudit Error", str(exc)))
        finally:
            if password_buf is not None:
                wipe_bytearray(password_buf)
            self.root.after(0, self.password.set, "")
            self.root.after(0, self._reset_run_button)

    def _show_decrypt_success(self, result: DecryptArtifacts) -> None:
        """Show decrypt completion message and compatibility warning when relevant."""
        message = (
            "Decryption finished successfully.\n\n"
            f"Output Dir: {result.output_dir}\n"
            f"Recovered File: {result.decrypted_file_path}"
        )
        if result.warning:
            message = f"{message}\n\nWarning: {result.warning}"
        messagebox.showinfo("CryptoAudit Complete", message)

    def _reset_run_button(self) -> None:
        """Restore the run button state after background execution ends."""
        if self.run_button is not None:
            self.run_button.config(state=tk.NORMAL, text="Run CryptoAudit")


def main() -> int:
    """Launch the CryptoAudit desktop user interface."""
    root = tk.Tk()
    CryptoAuditUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


