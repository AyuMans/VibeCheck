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


ISSUE_TITLES = {
    "SHELL_COMMAND_EXECUTION": "Potential Shell Command Injection",
    "UNSAFE_DESERIALIZATION": "Unsafe Deserialization",
    "SQL_INJECTION": "Potential SQL Injection",
    "HARDCODED_SECRET": "Hardcoded Secret",
    "DYNAMIC_CODE_EXECUTION": "Dynamic Code Execution",
}


def get_code_evidence(
    code: str,
    start_line: int,
    end_line: int
) -> str:
    """
    Extract the exact code lines flagged by Semgrep.
    Semgrep line numbers start from 1.
    """

    lines = code.splitlines()

    start_index = max(start_line - 1, 0)
    end_index = min(end_line, len(lines))

    evidence_lines = lines[start_index:end_index]

    return "\n".join(evidence_lines).strip()


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
            end = finding.get("end", {})

            start_line = start.get("line", 1)
            end_line = end.get("line", start_line)

            issue_type = metadata.get(
                "issue_type",
                finding.get("check_id", "Semgrep Finding")
            )

            title = ISSUE_TITLES.get(
                issue_type,
                issue_type.replace("_", " ").title()
            )

            # Extract the ACTUAL flagged code from the submitted code.
            evidence = get_code_evidence(
                code,
                start_line,
                end_line
            )

            # Fallback only if line extraction somehow fails.
            if not evidence:
                evidence = extra.get(
                    "message",
                    "Security issue detected by Semgrep."
                ).strip()

            findings.append(
                Finding(
                    title=title,

                    category=metadata.get(
                        "category",
                        "security"
                    ),

                    severity=metadata.get(
                        "severity",
                        extra.get("severity", "MEDIUM")
                    ).upper(),

                    evidence=evidence,

                    impact=metadata.get(
                        "impact",
                        (
                            f"Detected by Semgrep rule "
                            f"{finding.get('check_id', 'unknown')} "
                            f"at line {start_line}."
                        )
                    ),

                    remediation=metadata.get(
                        "remediation",
                        (
                            "Review the flagged code and apply "
                            "the recommended security fix."
                        )
                    ),

                    source=["semgrep"]
                )
            )

        return findings

    except subprocess.TimeoutExpired:
        print("Semgrep scan timed out.")
        return []

    except json.JSONDecodeError:
        print("Failed to parse Semgrep JSON output.")
        return []

    except FileNotFoundError:
        print(
            "Semgrep executable was not found. "
            "Make sure Semgrep is installed and available in PATH."
        )
        return []

    except Exception as error:
        print(f"Error running Semgrep: {error}")
        return []

    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)