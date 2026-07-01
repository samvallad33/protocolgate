from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from protocolgate.report import Violation


class OpaUnavailable(RuntimeError):
    """Raised when the opa binary is not available."""


def evaluate_with_opa(manifest: dict[str, Any], policy_dir: Path) -> list[Violation]:
    opa = shutil.which("opa")
    if not opa:
        raise OpaUnavailable("opa binary not found; install OPA or use --engine builtin")

    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as input_file:
        json.dump(manifest, input_file)
        input_file.flush()

        result = subprocess.run(
            [
                opa,
                "eval",
                "--format=json",
                "--data",
                str(policy_dir),
                "--input",
                input_file.name,
                "data.protocolgate.deny",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(details or "opa eval failed")

    payload = json.loads(result.stdout)
    values = payload.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
    return [
        Violation(
            rule_id=str(item.get("rule_id", "OPA")),
            severity=str(item.get("severity", "medium")),
            message=str(item.get("message", "")),
            path=str(item.get("path", "")),
            recommendation=str(item.get("recommendation", "")),
        )
        for item in values
    ]
