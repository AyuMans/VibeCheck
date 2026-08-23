import json
import os
import subprocess
import tempfile

from backend.models import Finding


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

SEMGREP_CONFIG = os.path.join(
    PROJECT_ROOT,
    "semgrep_rules",
    "python-security.yml"
)


def scan_code(code: str, language: str) -> list[Finding]:
    if language.lower() != "python":
        return []

    temp_file_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False
        ) as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name

        result = subprocess.run(
            [
                "semgrep",
                "--config",
                SEMGREP_CONFIG,
                "--json",
                temp_file_path
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        data = json.loads(result.stdout)

        findings = []

        for finding in data.get("results", []):
            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})
            start = finding.get("start", {})

            findings.append(
                Finding(
                    title=metadata.get(
                        "issue_type",
                        finding.get("check_id", "Semgrep Finding")
                    ),

                    category=metadata.get(
                        "category",
                        "security"
                    ),

                    severity=metadata.get(
                        "severity",
                        extra.get("severity", "MEDIUM")
                    ).upper(),

                    evidence=extra.get(
                        "message",
                        "Security issue detected by Semgrep."
                    ).strip(),

                    impact=metadata.get(
                        "impact",
                        (
                            f"Detected by rule "
                            f"{finding.get('check_id')} "
                            f"at line {start.get('line', 'unknown')}."
                        )
                    ),

                    remediation=metadata.get(
                        "remediation",
                        "Review the flagged code and apply the recommended security fix."
                    ),

                    source=["semgrep"]
                )
            )

        return findings

    except subprocess.TimeoutExpired:
        return []

    except json.JSONDecodeError:
        return []

    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)