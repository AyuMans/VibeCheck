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


def is_shell_execution_finding(finding: Finding) -> bool:
    text = " ".join([
        finding.title,
        finding.category,
        finding.evidence,
        finding.impact,
        finding.remediation
    ]).lower()

    keywords = [
        "os.system",
        "shell command",
        "command execution",
        "command injection",
        "shell injection",
        "arbitrary command"
    ]

    return any(keyword in text for keyword in keywords)


def correlate_findings(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding]
) -> list[Finding]:

    correlated = []
    used_semgrep_indexes = set()

    for ai_finding in ai_findings:
        merged = False

        for index, semgrep_finding in enumerate(semgrep_findings):

            if index in used_semgrep_indexes:
                continue

            same_shell_issue = (
                is_shell_execution_finding(ai_finding)
                and is_shell_execution_finding(semgrep_finding)
            )

            if same_shell_issue:

                merged_finding = Finding(
                    title="Potential Shell Command Injection",
                    category="security",
                    severity=get_higher_severity(
                        ai_finding.severity,
                        semgrep_finding.severity
                    ),
                    evidence=ai_finding.evidence,
                    impact=ai_finding.impact,
                    remediation=ai_finding.remediation,
                    source=list(
                        dict.fromkeys(
                            ai_finding.source +
                            semgrep_finding.source
                        )
                    )
                )

                correlated.append(merged_finding)

                used_semgrep_indexes.add(index)
                merged = True
                break

        if not merged:
            correlated.append(ai_finding)

    for index, semgrep_finding in enumerate(semgrep_findings):
        if index not in used_semgrep_indexes:
            correlated.append(semgrep_finding)

    return correlated