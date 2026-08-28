from backend.models import Finding


SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def get_higher_severity(
    severity_one: str,
    severity_two: str
) -> str:
    one = SEVERITY_ORDER.get(severity_one.upper(), 0)
    two = SEVERITY_ORDER.get(severity_two.upper(), 0)

    if one >= two:
        return severity_one.upper()

    return severity_two.upper()


def normalize_text(text: str) -> str:
    """
    Normalize text so that small formatting differences do not
    prevent two findings from being correlated.
    """

    return " ".join(
        (text or "").lower().split()
    )


def get_finding_text(finding: Finding) -> str:
    """
    Combine relevant finding information into one normalized
    string for classification.
    """

    return normalize_text(
        " ".join([
            finding.title or "",
            finding.category or "",
            finding.evidence or "",
            finding.impact or "",
            finding.remediation or "",
        ])
    )


def get_issue_type(finding: Finding) -> str | None:
    """
    Identify the general issue type.

    This is intentionally based on the finding itself rather than
    requiring a specific Semgrep rule ID.
    """

    text = get_finding_text(finding)

    # -----------------------------------------
    # SHELL / COMMAND EXECUTION
    # -----------------------------------------

    shell_keywords = [
        "os.system",
        "subprocess",
        "shell=true",
        "shell command",
        "command execution",
        "command injection",
        "shell injection",
        "arbitrary command",
    ]

    if any(keyword in text for keyword in shell_keywords):
        return "SHELL_COMMAND_EXECUTION"

    # -----------------------------------------
    # UNSAFE DESERIALIZATION
    # -----------------------------------------

    deserialization_keywords = [
        "pickle.loads",
        "pickle.load",
        "avoid pickle",
        "unsafe deserialization",
        "unsafe pickle",
        "pickle deserialization",
        "deserializing untrusted",
        "insecure deserialization",
    ]

    if any(keyword in text for keyword in deserialization_keywords):
        return "UNSAFE_DESERIALIZATION"

    # -----------------------------------------
    # DYNAMIC CODE EXECUTION
    # -----------------------------------------

    dynamic_keywords = [
        "eval(",
        "exec(",
        "dynamic code execution",
        "dangerous eval",
        "dangerous exec",
    ]

    if any(keyword in text for keyword in dynamic_keywords):
        return "DYNAMIC_CODE_EXECUTION"

    # -----------------------------------------
    # SQL INJECTION
    # -----------------------------------------

    sql_keywords = [
        "sql injection",
        "formatted sql query",
        "sql query construction",
        "sql query",
        "parameterized query",
        "prepared statement",
        "raw query",
    ]

    if any(keyword in text for keyword in sql_keywords):
        return "SQL_INJECTION"

    # -----------------------------------------
    # HARDCODED SECRET
    # -----------------------------------------

    secret_keywords = [
        "hardcoded secret",
        "hardcoded password",
        "hardcoded credential",
        "hardcoded credentials",
        "hardcoded api key",
        "hardcoded token",
        "hardcoded_secret",
        "secret stored directly",
        "password stored directly",
        "credentials stored directly",
        "possible hardcoded password",
        "possible hardcoded password or secret",
    ]

    if any(keyword in text for keyword in secret_keywords):
        return "HARDCODED_SECRET"

    return None


def evidence_matches(
    ai_finding: Finding,
    semgrep_finding: Finding
) -> bool:
    """
    Determine whether the two findings refer to the same piece
    of code.

    Matching strategy:

    1. If both findings have line information, compare their
       line ranges.

    2. Otherwise compare normalized evidence.

    3. As a fallback, check whether one evidence snippet contains
       the other.

    This prevents unrelated findings of the same type from being
    incorrectly merged.
    """

    # -----------------------------------------
    # METHOD 1 — LINE RANGE MATCHING
    # -----------------------------------------

    ai_start = ai_finding.line_start
    ai_end = ai_finding.line_end

    sg_start = semgrep_finding.line_start
    sg_end = semgrep_finding.line_end

    if (
        ai_start is not None
        and ai_end is not None
        and sg_start is not None
        and sg_end is not None
    ):
        # Two ranges overlap.
        if ai_start <= sg_end and sg_start <= ai_end:
            return True

        # Both tools know the location, but they refer to
        # completely different lines.
        return False

    # -----------------------------------------
    # METHOD 2 — EXACT EVIDENCE MATCH
    # -----------------------------------------

    ai_evidence = normalize_text(
        ai_finding.evidence
    )

    sg_evidence = normalize_text(
        semgrep_finding.evidence
    )

    if not ai_evidence or not sg_evidence:
        return False

    if ai_evidence == sg_evidence:
        return True

    # -----------------------------------------
    # METHOD 3 — EVIDENCE CONTAINMENT
    # -----------------------------------------

    if (
        ai_evidence in sg_evidence
        or sg_evidence in ai_evidence
    ):
        return True

    return False


def findings_match(
    ai_finding: Finding,
    semgrep_finding: Finding
) -> bool:
    """
    Decide whether an AI finding and a Semgrep finding
    represent the same underlying issue.
    """

    ai_issue_type = get_issue_type(ai_finding)
    semgrep_issue_type = get_issue_type(semgrep_finding)

    # We cannot safely correlate unknown issue types.
    if (
        ai_issue_type is None
        or semgrep_issue_type is None
    ):
        return False

    # Different vulnerability types must never be merged.
    if ai_issue_type != semgrep_issue_type:
        return False

    # Same type is not enough.
    # They must also point to the same code.
    return evidence_matches(
        ai_finding,
        semgrep_finding
    )


def get_merged_title(
    ai_finding: Finding,
    semgrep_finding: Finding,
    issue_type: str
) -> str:
    """
    Use a consistent title when findings are merged.
    """

    titles = {
        "SHELL_COMMAND_EXECUTION":
            "Potential Shell Command Injection",

        "UNSAFE_DESERIALIZATION":
            "Unsafe Deserialization",

        "DYNAMIC_CODE_EXECUTION":
            "Dynamic Code Execution",

        "SQL_INJECTION":
            "Potential SQL Injection",

        "HARDCODED_SECRET":
            "Hardcoded Secret",
    }

    return titles.get(
        issue_type,
        semgrep_finding.title or ai_finding.title
    )


def merge_findings(
    ai_finding: Finding,
    semgrep_finding: Finding,
    issue_type: str
) -> Finding:
    """
    Merge two findings that refer to the same underlying issue.

    Semgrep provides deterministic location/evidence information,
    while AI provides richer explanations when available.
    """

    sources = list(
        dict.fromkeys(
            ai_finding.source +
            semgrep_finding.source
        )
    )

    # Prefer Semgrep's exact location when available.
    line_start = (
        semgrep_finding.line_start
        if semgrep_finding.line_start is not None
        else ai_finding.line_start
    )

    line_end = (
        semgrep_finding.line_end
        if semgrep_finding.line_end is not None
        else ai_finding.line_end
    )

    # Prefer Semgrep evidence because it comes from
    # deterministic source-code locations.
    evidence = (
        semgrep_finding.evidence
        if semgrep_finding.evidence
        else ai_finding.evidence
    )

    # Prefer AI's richer explanation when Semgrep only provides
    # generic fallback metadata.
    impact = (
        ai_finding.impact
        if ai_finding.impact
        else semgrep_finding.impact
    )

    remediation = (
        ai_finding.remediation
        if ai_finding.remediation
        else semgrep_finding.remediation
    )

    return Finding(
        title=get_merged_title(
            ai_finding,
            semgrep_finding,
            issue_type
        ),

        category=(
            ai_finding.category
            if ai_finding.category
            else semgrep_finding.category
        ),

        severity=get_higher_severity(
            ai_finding.severity,
            semgrep_finding.severity
        ),

        evidence=evidence,

        impact=impact,

        remediation=remediation,

        source=sources,

        line_start=line_start,

        line_end=line_end,
    )


def correlate_findings(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding]
) -> list[Finding]:
    """
    Correlate AI and Semgrep findings.

    Every finding from both systems is preserved unless there is
    strong evidence that the two findings describe the same issue.

    AI findings are processed first. Matching Semgrep findings are
    merged into them. Remaining Semgrep findings are then added.
    """

    correlated = []

    used_semgrep_indexes = set()

    # -----------------------------------------
    # PROCESS AI FINDINGS
    # -----------------------------------------

    for ai_finding in ai_findings:

        matched_semgrep_index = None

        for index, semgrep_finding in enumerate(
            semgrep_findings
        ):

            if index in used_semgrep_indexes:
                continue

            if findings_match(
                ai_finding,
                semgrep_finding
            ):
                matched_semgrep_index = index
                break

        # -----------------------------------------
        # MATCH FOUND
        # -----------------------------------------

        if matched_semgrep_index is not None:

            semgrep_finding = semgrep_findings[
                matched_semgrep_index
            ]

            issue_type = get_issue_type(
                ai_finding
            )

            merged_finding = merge_findings(
                ai_finding,
                semgrep_finding,
                issue_type
            )

            correlated.append(
                merged_finding
            )

            used_semgrep_indexes.add(
                matched_semgrep_index
            )

        # -----------------------------------------
        # NO MATCH
        # -----------------------------------------

        else:
            correlated.append(
                ai_finding
            )

    # -----------------------------------------
    # ADD UNMATCHED SEMGREP FINDINGS
    # -----------------------------------------

    for index, semgrep_finding in enumerate(
        semgrep_findings
    ):

        if index not in used_semgrep_indexes:
            correlated.append(
                semgrep_finding
            )

    return correlated