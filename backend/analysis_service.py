from concurrent.futures import ThreadPoolExecutor

from backend.models import Finding
from backend.review_service import review_code
from backend.semgrep_service import scan_code
from backend.correlation_service import correlate_findings
from backend.policy_service import evaluate_policy


def analyze_code(code: str, language: str) -> dict:

    # Run AI review and Semgrep scan concurrently.
    #
    # Both operations are independent, so there is no reason
    # to wait for one to finish before starting the other.

    with ThreadPoolExecutor(max_workers=2) as executor:

        ai_future = executor.submit(
            review_code,
            code=code,
            language=language
        )

        semgrep_future = executor.submit(
            scan_code,
            code=code,
            language=language
        )

        # Wait for both operations to finish.
        ai_review = ai_future.result()
        semgrep_findings = semgrep_future.result()

    # Convert AI findings into Finding objects.
    ai_findings = [
        Finding(**finding)
        for finding in ai_review["findings"]
    ]

    # Correlate/merge duplicate findings from AI and Semgrep.
    final_findings = correlate_findings(
        ai_findings=ai_findings,
        semgrep_findings=semgrep_findings
    )

    # Evaluate the final findings against the security policy.
    policy_result = evaluate_policy(final_findings)

    # Return the complete analysis.
    return {
        "summary": ai_review["summary"],
        "findings": [
            finding.model_dump()
            for finding in final_findings
        ],
        "policy": policy_result
    }