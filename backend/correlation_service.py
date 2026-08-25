from backend.models import Finding


SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
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


def get_finding_text(finding: Finding) -> str:
    """
    Combine all relevant finding information into one
    lowercase string for classification.
    """

    return " ".join([
        finding.title or "",
        finding.category or "",
        finding.evidence or "",
        finding.impact or "",
        finding.remediation or ""
    ]).lower()


def get_issue_type(finding: Finding) -> str | None:
    """
    Classify a finding into a known issue type.

    Returns None if the finding cannot be confidently classified.
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
        "arbitrary command"
    ]

    if any(keyword in text for keyword in shell_keywords):
        return "SHELL_COMMAND_EXECUTION"

    # -----------------------------------------
    # UNSAFE DESERIALIZATION
    # -----------------------------------------

    deserialization_keywords = [
        "pickle.loads",
        "pickle.load",
        "unsafe deserialization",
        "unsafe pickle",
        "pickle deserialization",
        "deserializing untrusted",
        "deserializing untrusted"
    ]

    if any(keyword in text for keyword in deserialization_keywords):
        return "UNSAFE_DESERIALIZATION"

    # -----------------------------------------
    # DYNAMIC CODE EXECUTION
    # -----------------------------------------

    eval_keywords = [
        "eval(",
        "dangerous eval",
        "dynamic code execution"
    ]

    if any(keyword in text for keyword in eval_keywords):
        return "DYNAMIC_CODE_EXECUTION"

    exec_keywords = [
        "exec(",
        "dangerous exec",
        "dynamic code execution"
    ]

    if any(keyword in text for keyword in exec_keywords):
        return "DYNAMIC_CODE_EXECUTION"

    # -----------------------------------------
    # SQL INJECTION
    # -----------------------------------------

    sql_keywords = [
        "sql injection",
        "sql query",
        "sql query construction",
        "parameterized quer",
        "prepared statement"
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
    "possible hardcoded password or secret"
]

    if any(keyword in text for keyword in secret_keywords):
        return "HARDCODED_SECRET"

    return None


def get_merged_title(
    ai_finding: Finding,
    semgrep_finding: Finding,
    issue_type: str
) -> str:
    """
    Use a consistent title when two findings are merged.
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
            "Hardcoded Secret"
    }

    return titles.get(issue_type, ai_finding.title)


def merge_findings(
    ai_finding: Finding,
    semgrep_finding: Finding,
    issue_type: str
) -> Finding:

    sources = list(
        dict.fromkeys(
            ai_finding.source +
            semgrep_finding.source
        )
    )

    return Finding(
        title=get_merged_title(
            ai_finding,
            semgrep_finding,
            issue_type
        ),

        category="security",

        severity=get_higher_severity(
            ai_finding.severity,
            semgrep_finding.severity
        ),

        # Prefer exact Semgrep evidence when available.
        evidence=(
            semgrep_finding.evidence
            if semgrep_finding.evidence
            else ai_finding.evidence
        ),

        # Semgrep rules provide deterministic security information.
        impact=(
            semgrep_finding.impact
            if semgrep_finding.impact
            else ai_finding.impact
        ),

        remediation=(
            semgrep_finding.remediation
            if semgrep_finding.remediation
            else ai_finding.remediation
        ),

        source=sources
    )

def correlate_findings(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding]
) -> list[Finding]:

    correlated = []

    used_semgrep_indexes = set()

    for ai_finding in ai_findings:

        ai_issue_type = get_issue_type(ai_finding)

        merged = False

        # Only attempt correlation if we can identify
        # the AI finding's issue type.
        if ai_issue_type is not None:

            for index, semgrep_finding in enumerate(
                semgrep_findings
            ):

                if index in used_semgrep_indexes:
                    continue

                semgrep_issue_type = get_issue_type(
                    semgrep_finding
                )

                # Merge only if both tools identify
                # the same underlying issue type.
                if ai_issue_type == semgrep_issue_type:

                    merged_finding = merge_findings(
                        ai_finding,
                        semgrep_finding,
                        ai_issue_type
                    )

                    correlated.append(merged_finding)

                    used_semgrep_indexes.add(index)

                    merged = True

                    break

        # No matching Semgrep finding.
        if not merged:
            correlated.append(ai_finding)

    # Add Semgrep findings that were not merged.
    for index, semgrep_finding in enumerate(semgrep_findings):

        if index not in used_semgrep_indexes:
            correlated.append(semgrep_finding)

    return correlated