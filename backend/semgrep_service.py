import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from backend.models import Finding
from backend.language_detector import LANGUAGE_EXTENSIONS


ISSUE_TITLES = {
    "SHELL_COMMAND_EXECUTION": "Potential Shell Command Injection",
    "UNSAFE_DESERIALIZATION": "Unsafe Deserialization",
    "SQL_INJECTION": "Potential SQL Injection",
    "HARDCODED_SECRET": "Hardcoded Secret",
    "DYNAMIC_CODE_EXECUTION": "Dynamic Code Execution",
}


# ==========================================================
# Language -> Semgrep registry configuration
# ==========================================================
#
# All 13 languages currently map to the SAME Semgrep Registry pack,
# "p/security-audit", rather than to distinct per-language packs like
# "p/python". This was corrected after real-world testing (see below)
# showed the distinct-per-language approach was wrong in the way that
# mattered.
#
# What we tried first and why it was wrong:
#   "p/python" is NOT a security-scoped ruleset. Running it against a
#   real .py file loaded 1066 rules (best-practice, correctness,
#   style -- almost everything Semgrep has for Python), which is
#   barely narrower than "auto"'s ~1198 and caused scans to time out.
#   Per-language "p/<lang>" registry packs are general-purpose, not
#   security-specific -- using them defeats the whole point of this
#   change.
#
# What actually works (confirmed by hand, not guessed):
#   "p/security-audit" is itself a broad, multi-language pack by name,
#   but Semgrep filters which of its rules actually get *applied*
#   based on the scanned file's language/extension. Run by hand
#   against a single .py file, it loaded ~225 rules and completed in
#   ~5 seconds -- vs. minutes and ~1198 rules for "auto", and vs. the
#   1066-rule/timeout result from "p/python" above. So despite its
#   name, it stays narrow in practice for a single-language temp file,
#   while still being real, unmodified Semgrep community content (not
#   anything hardcoded here).
#
# This is kept as a per-language dict (not a single constant) so that
# if you find, for a specific language, that "p/security-audit" is too
# sparse (weaker/newer languages -- Rust, Kotlin, Swift, C, C++ tend to
# have thinner community coverage than Python/JS/Java) or that a
# different verified pack works better for it, you can override just
# that one entry without touching scan_code() or any other language.
#
# Verify any change to this dict the same way this one was corrected:
# run `semgrep scan --config <pack> /tmp/test.<ext>` by hand and read
# the actual "Scanning ... with N rules" line Semgrep prints -- don't
# assume a pack name is narrow just because of what it's called.
LANGUAGE_SEMGREP_CONFIGS: dict[str, str] = {
    "python": "p/security-audit",
    "javascript": "p/security-audit",
    "typescript": "p/security-audit",
    "java": "p/security-audit",
    "c": "p/security-audit",
    "cpp": "p/security-audit",
    "csharp": "p/security-audit",
    "go": "p/security-audit",
    "rust": "p/security-audit",
    "php": "p/security-audit",
    "ruby": "p/security-audit",
    "kotlin": "p/security-audit",
    "swift": "p/security-audit",
}


# ==========================================================
# Java: compensating for an import-resolution limitation
# ==========================================================
#
# CONFIRMED (not theorized) by direct testing against Semgrep 1.174.0,
# OSS engine, using the actual published rule text:
#
#   Runtime.getRuntime().exec("cmd /c " + args[0]);              -> 0 findings
#   import java.lang.Runtime;  (added, nothing else changed)     -> 1 finding
#
# Semgrep's Java rules identify dangerous APIs via fully-qualified
# names (e.g. "java.lang.Runtime.getRuntime(...)"), and on the OSS
# engine that appears to require the qualifying import to be
# textually present in the file -- not real type/semantic resolution.
# java.lang is auto-imported by the JVM, so real Java code never
# writes these imports out, which means rules keyed on java.lang
# classes (Runtime, ProcessBuilder, System, Thread, etc.) can silently
# fail to match perfectly real vulnerable code.
#
# This is a property of the rule + engine, not of our pipeline. To
# compensate, we inject a block of explicit (redundant, legal,
# harmless) java.lang imports into the temp file Semgrep scans -- NOT
# into the user's original code that's shown back to them, and NOT a
# detection rule of our own. This gives Semgrep's own import-matching
# heuristic the same information any real Java file already implies
# by virtue of being written in Java. Semgrep's community rules remain
# entirely responsible for identifying the vulnerability itself.
#
# Because this shifts every line number in the scanned file down by
# the number of injected lines, scan_code() must translate Semgrep's
# reported line numbers back to the user's original line numbers
# before touching evidence extraction or building a Finding. See
# _prepare_java_scan_source() and _map_reported_line() below.
_JAVA_IMPLICIT_IMPORT_PREAMBLE: list[str] = [
    "import java.lang.Runtime;",
    "import java.lang.ProcessBuilder;",
    "import java.lang.Process;",
    "import java.lang.System;",
    "import java.lang.String;",
    "import java.lang.StringBuilder;",
    "import java.lang.StringBuffer;",
    "import java.lang.Thread;",
    "import java.lang.Class;",
    "import java.lang.Object;",
    "import java.lang.Math;",
    "import java.lang.Integer;",
    "import java.lang.Long;",
    "import java.lang.Double;",
    "import java.lang.Float;",
    "import java.lang.Boolean;",
    "import java.lang.Character;",
    "import java.lang.Byte;",
    "import java.lang.Short;",
    "import java.lang.Exception;",
    "import java.lang.RuntimeException;",
    "import java.lang.Throwable;",
    "import java.lang.Error;",
    "import java.lang.Runnable;",
    "import java.lang.Comparable;",
    "import java.lang.Iterable;",
]

_JAVA_PACKAGE_DECLARATION = re.compile(r"^\s*package\s+[\w.]+\s*;\s*$")


def _prepare_java_scan_source(code: str) -> tuple[str, int, int]:
    """
    Build the source actually written to the Java temp file: the
    user's original code, plus an injected block of explicit
    java.lang imports (see module notes above).

    Java syntax requires: optional package declaration, then imports,
    then type declarations -- so if the snippet opens with a package
    declaration, the imports are inserted after it rather than before.

    Returns (modified_source, insert_at, injected_count):
      - modified_source: what gets written to the temp file.
      - insert_at: the 1-based original-code line number the preamble
        was inserted after (0 if inserted at the very top).
      - injected_count: number of lines inserted.
    Both insert_at and injected_count are needed by _map_reported_line
    to translate Semgrep's line numbers back to the user's original
    code.
    """

    lines = code.splitlines()

    insert_at = 0

    for line in lines:

        if line.strip() == "":
            insert_at += 1
            continue

        if _JAVA_PACKAGE_DECLARATION.match(line):
            insert_at += 1

        break

    new_lines = (
        lines[:insert_at]
        + _JAVA_IMPLICIT_IMPORT_PREAMBLE
        + lines[insert_at:]
    )

    return "\n".join(new_lines), insert_at, len(_JAVA_IMPLICIT_IMPORT_PREAMBLE)


def _map_reported_line(
    reported_line: int,
    insert_at: int,
    injected_count: int
) -> int:
    """
    Translate a line number Semgrep reported (relative to the
    possibly-modified temp file) back to the corresponding line
    number in the user's original, unmodified code.

    A no-op (returns reported_line unchanged) whenever injected_count
    is 0, i.e. for every language other than Java.
    """

    if injected_count == 0:
        return reported_line

    if reported_line <= insert_at:
        return reported_line

    if reported_line <= insert_at + injected_count:
        # Falls inside the injected import block itself -- not a line
        # that exists in the user's original code. Security rules
        # shouldn't flag a plain import statement, but fall back to
        # the nearest real boundary rather than returning a line
        # number that doesn't correspond to anything the user wrote.
        return insert_at if insert_at > 0 else 1

    return reported_line - injected_count


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

    # Normalize so lookups against LANGUAGE_EXTENSIONS and
    # LANGUAGE_SEMGREP_CONFIGS are case/whitespace insensitive, and so
    # empty/unsupported language values don't trigger unnecessary scans.
    normalized_language = language.strip().lower()

    if not normalized_language:
        return []

    # Look up the correct file extension for the detected language.
    #
    # Semgrep determines the language partly from the file extension,
    # so this MUST NOT fall back to a generic extension like .txt --
    # doing so would silently prevent Semgrep from applying any
    # language-specific rules (Java, C, C++, JavaScript, etc. would
    # never be analyzed correctly).
    #
    # If the detected language has no known mapping (e.g. detection
    # returned "unknown", or a language Semgrep doesn't reliably
    # support), skip the scan gracefully rather than pretending a
    # scan was performed.
    suffix = LANGUAGE_EXTENSIONS.get(normalized_language)

    if suffix is None:
        print(
            f"Semgrep has no known file-extension mapping for "
            f"language '{language}'. Skipping Semgrep scan for "
            f"this submission."
        )
        return []

    # Look up the language-specific Semgrep Registry configuration.
    #
    # This is a SEPARATE mapping from LANGUAGE_EXTENSIONS on purpose:
    # LANGUAGE_EXTENSIONS is owned by language_detector.py (it also
    # drives detection/display elsewhere), while which Semgrep pack to
    # run is purely a semgrep_service.py concern. If a language is
    # supported for detection/extensions but has no vetted
    # language-specific security ruleset, we skip Semgrep rather than
    # falling back to something broad like "auto" (which is exactly
    # the slow behavior this change exists to remove) or silently
    # scanning with the wrong ruleset.
    semgrep_config = LANGUAGE_SEMGREP_CONFIGS.get(normalized_language)

    if semgrep_config is None:
        print(
            f"No language-specific Semgrep community ruleset is "
            f"configured for '{language}'. Skipping Semgrep scan for "
            f"this submission (Semgrep could not run, as distinct "
            f"from Semgrep running and finding nothing)."
        )
        return []

    semgrep_executable = find_semgrep_executable()

    if semgrep_executable is None:
        print(
            "Semgrep executable not found. "
            "Make sure Semgrep is installed."
        )
        return []

    temp_file_path = None

    # For Java, inject the compensating import preamble described
    # above (module-level notes near _JAVA_IMPLICIT_IMPORT_PREAMBLE).
    # For every other language this is a no-op: scan_source is just
    # the user's original code, and line_insert_at/line_injected_count
    # stay 0 so _map_reported_line() below leaves line numbers alone.
    if normalized_language == "java":
        scan_source, line_insert_at, line_injected_count = (
            _prepare_java_scan_source(code)
        )
    else:
        scan_source, line_insert_at, line_injected_count = code, 0, 0

    try:
        # Create a temporary source file using the extension resolved
        # above. The extension helps Semgrep identify the language.
        #
        # NOTE: this writes scan_source (which may include the Java
        # import preamble), not the raw `code` -- the raw `code` is
        # still what's used everywhere else (evidence extraction,
        # anything shown back to the user), only the temp file Semgrep
        # itself reads is adjusted.
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8"
        ) as temp_file:

            temp_file.write(scan_source)
            temp_file_path = temp_file.name

        # Use the resolved Semgrep Registry configuration
        # (LANGUAGE_SEMGREP_CONFIGS -- currently "p/security-audit"
        # for every language) instead of "auto".
        #
        # "auto" pulls a huge, largely un-scoped set of community
        # rules (~1198 in testing). A per-language pack like "p/python"
        # is NOT a fix for this -- it turned out to be ~1066 rules
        # covering every Python rule Semgrep has, not just security
        # ones, and still timed out. "p/security-audit" is filtered by
        # Semgrep down to the rules that apply to the scanned file's
        # actual language/extension, which is what keeps this fast
        # (~225 rules / ~5s for Python, confirmed by hand) while still
        # using real, unmodified community rules.
        result = subprocess.run(
            [
                semgrep_executable,
                "scan",
                "--config",
                semgrep_config,
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

        # Semgrep can return valid JSON with an empty "results" list
        # for two very different reasons:
        #   1. It ran the ruleset successfully and found nothing.
        #   2. The ruleset/config failed to resolve or load properly
        #      (e.g. a bad config name, a registry lookup failure),
        #      so effectively nothing was scanned.
        # data["errors"] is how Semgrep reports the second case even
        # while still emitting well-formed JSON. Surface it distinctly
        # so this isn't silently reported as a clean scan.
        semgrep_errors = data.get("errors", [])

        if semgrep_errors:
            print(
                f"Semgrep reported {len(semgrep_errors)} error(s) "
                f"while scanning with config '{semgrep_config}' for "
                f"language '{language}'. Results below may be "
                f"incomplete (Semgrep may not have fully run, as "
                f"distinct from running cleanly and finding nothing):"
            )
            for semgrep_error in semgrep_errors:
                print(" -", semgrep_error.get("message", semgrep_error))

        findings = []

        for finding in data.get("results", []):

            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})

            start = finding.get("start", {})
            end = finding.get("end", {})

            # Semgrep's line numbers are relative to the temp file it
            # actually scanned (scan_source), which for Java includes
            # the injected import preamble. Translate back to line
            # numbers in the user's original `code` before doing
            # anything else with them -- get_code_evidence() below
            # indexes into `code`, not scan_source.
            start_line = _map_reported_line(
                start.get("line", 1),
                line_insert_at,
                line_injected_count
            )
            end_line = _map_reported_line(
                end.get("line", start.get("line", 1)),
                line_insert_at,
                line_injected_count
            )

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