from backend.models import Finding
from backend.review_service import review_code
from backend.semgrep_service import scan_code
from backend.correlation_service import correlate_findings
from backend.policy_service import evaluate_policy


def generate_summary(
    findings: list[Finding],
    policy_result: dict
) -> str:
    """
    Generate the final summary from the correlated findings.

    The summary must describe the FINAL result, not just the AI review,
    because Semgrep may find issues that the AI missed.
    """

    if not findings:
        return "No meaningful security, bug, logic, or reliability issues were found."

    issue_count = len(findings)
    highest_severity = policy_result.get("highest_severity", "UNKNOWN")

    if issue_count == 1:
        finding = findings[0]

        return (
            f"The submitted code contains 1 issue that requires review: "
            f"{finding.title} ({finding.severity})."
        )

    finding_titles = ", ".join(
        finding.title for finding in findings
    )

    return (
        f"The submitted code contains {issue_count} issues that require "
        f"review. The highest severity is {highest_severity}. "
        f"Detected issues include: {finding_titles}."
    )


def analyze_code(code: str, language: str) -> dict:

    # 1. Get AI analysis
    ai_review = review_code(
        code=code,
        language=language
    )

    # 2. Convert AI findings into Finding objects
    ai_findings = [
        Finding(**finding)
        for finding in ai_review["findings"]
    ]

    # 3. Run Semgrep analysis
    semgrep_findings = scan_code(
        code=code,
        language=language
    )

    # 4. Correlate and merge duplicate findings
    final_findings = correlate_findings(
        ai_findings=ai_findings,
        semgrep_findings=semgrep_findings
    )

    # 5. Evaluate the FINAL findings against the policy
    policy_result = evaluate_policy(final_findings)

    # 6. Generate the FINAL summary from correlated findings
    summary = generate_summary(
        findings=final_findings,
        policy_result=policy_result
    )

    # 7. Return everything
    return {
        "summary": summary,
        "findings": [
            finding.model_dump()
            for finding in final_findings
        ],
        "policy": policy_result
    }