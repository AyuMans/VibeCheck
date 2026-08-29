import json
import os
import shutil
import subprocess
import sys
import tempfile

from backend.models import Finding


ISSUE_TITLES = {
    "SHELL_COMMAND_EXECUTION": "Potential Shell Command Injection",
    "UNSAFE_DESERIALIZATION": "Unsafe Deserialization",
    "SQL_INJECTION": "Potential SQL Injection",
    "HARDCODED_SECRET": "Hardcoded Secret",
    "DYNAMIC_CODE_EXECUTION": "Dynamic Code Execution",
}


def find_semgrep_executable() -> str | None:
    """
    Locate the Semgrep executable.

    First checks PATH, then checks locations associated
    with the currently running Python installation.
    """

    # 1. Check PATH
    semgrep = shutil.which("semgrep")

    if semgrep:
        return semgrep

    # 2. Check the current Python installation
    python_dir = os.path.dirname(sys.executable)

    possible_paths = [
        os.path.join(python_dir, "Scripts", "semgrep.exe"),
        os.path.join(python_dir, "Scripts", "semgrep"),
        os.path.join(python_dir, "bin", "semgrep"),
        os.path.join(python_dir, "semgrep.exe"),
        os.path.join(python_dir, "semgrep"),
    ]

    for path in possible_paths:
        if os.path.isfile(path):
            return path

    return None


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

    # Semgrep auto configuration determines applicable rules.
    # We still keep this check so unsupported/empty language values
    # don't trigger unnecessary scans.
    if not language.strip():
        return []

    semgrep_executable = find_semgrep_executable()

    if semgrep_executable is None:
        print(
            "Semgrep executable not found. "
            "Make sure Semgrep is installed."
        )
        return []

    temp_file_path = None

    try:
        # Create a temporary source file.
        #
        # The extension helps Semgrep identify the language.
        suffix = ".py" if language.lower() == "python" else ".txt"

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8"
        ) as temp_file:

            temp_file.write(code)
            temp_file_path = temp_file.name

        # Use Semgrep's automatic configuration.
        #
        # --config auto allows Semgrep to obtain applicable
        # community rules instead of relying on our own
        # python-security.yml file.
        result = subprocess.run(
            [
                semgrep_executable,
                "--config",
                "auto",
                "--json",
                temp_file_path
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120
        )

        # Semgrep may write useful diagnostic information to stderr.
        if result.stderr.strip():
            print("Semgrep:", result.stderr.strip())

        # Parse JSON output.
        data = json.loads(result.stdout)

        findings = []

        for finding in data.get("results", []):

            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})

            start = finding.get("start", {})
            end = finding.get("end", {})

            start_line = start.get("line", 1)
            end_line = end.get("line", start_line)

            check_id = finding.get(
                "check_id",
                "Semgrep Finding"
            )

            issue_type = metadata.get(
                "issue_type",
                check_id
            )

            title = ISSUE_TITLES.get(
                issue_type,
                issue_type.replace("_", " ").replace("-", " ").title()
            )

            # Extract the ACTUAL flagged code from the submitted code.
            evidence = get_code_evidence(
                code,
                start_line,
                end_line
            )

            # Fallback if line extraction fails.
            if not evidence:
                evidence = extra.get(
                    "message",
                    "Security issue detected by Semgrep."
                ).strip()

            severity = metadata.get(
                "severity",
                extra.get("severity", "MEDIUM")
            ).upper()

            category = metadata.get(
                "category",
                "security"
            )

            impact = metadata.get(
                "impact",
                (
                    f"Detected by Semgrep rule "
                    f"{check_id} at line {start_line}."
                )
            )

            remediation = metadata.get(
                "remediation",
                (
                    "Review the flagged code and apply "
                    "the recommended security fix."
                )
            )

            findings.append(
                Finding(
                    title=title,
                    category=category,
                    severity=severity,
                    evidence=evidence,
                    impact=impact,
                    remediation=remediation,
                    source=["semgrep"],
                    line_start=start_line,
                    line_end=end_line
                )
            )

        return findings

    except subprocess.TimeoutExpired:
        print("Semgrep scan timed out.")
        return []

    except json.JSONDecodeError:
        print("Failed to parse Semgrep JSON output.")

        if "result" in locals():
            print("Semgrep stdout:")
            print(result.stdout)

        return []

    except FileNotFoundError:
        print(
            "Semgrep executable could not be started. "
            "Make sure Semgrep is installed correctly."
        )
        return []

    except Exception as error:
        print(f"Error running Semgrep: {error}")
        return []

    finally:
        if (
            temp_file_path
            and os.path.exists(temp_file_path)
        ):
            try:
                os.remove(temp_file_path)
            except OSError:
                pass

