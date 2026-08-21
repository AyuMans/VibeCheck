from backend.models import Finding
from backend.review_service import review_code
from backend.semgrep_service import scan_code
from backend.correlation_service import correlate_findings
from backend.policy_service import evaluate_policy


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

    # 4. Correlate/merge duplicate findings
    final_findings = correlate_findings(
        ai_findings=ai_findings,
        semgrep_findings=semgrep_findings
    )

    # 5. Evaluate the final findings against our security policy
    policy_result = evaluate_policy(final_findings)

    # 6. Return everything
    return {
        "summary": ai_review["summary"],
        "findings": [
            finding.model_dump()
            for finding in final_findings
        ],
        "policy": policy_result
    }