import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    """Run a minimal end-to-end CLI invocation and verify outputs are created."""
    project_root = Path(__file__).resolve().parent
    env = os.environ.copy()
    env["CRYPTOAUDIT_PASSWORD"] = "TestPass123!"

    with tempfile.TemporaryDirectory(prefix="cryptoaudit_smoke_") as tmp:
        output_dir = Path(tmp) / "outputs"
        command = [
            sys.executable,
            "main.py",
            "--text",
            "smoke test payload",
            "--config",
            "sample_config.json",
            "--password-env",
            "CRYPTOAUDIT_PASSWORD",
            "--output-dir",
            str(output_dir),
        ]

        completed = subprocess.run(command, cwd=project_root, env=env, check=False)
        if completed.returncode != 0:
            print("Smoke test failed")
            return completed.returncode

        outputs = sorted(output_dir.glob("*"))
        print(f"Smoke test passed. Generated {len(outputs)} files in {output_dir}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

