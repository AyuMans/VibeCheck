import json
import os

from backend.models import Finding


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

POLICY_PATH = os.path.join(
    PROJECT_ROOT,
    "policies",
    "security_policy.json"
)


SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def load_policy() -> dict:
    with open(POLICY_PATH, "r") as policy_file:
        return json.load(policy_file)


def get_highest_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None

    highest = max(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(
            finding.severity.upper(),
            0
        )
    )

    return highest.severity.upper()


def evaluate_policy(findings: list[Finding]) -> dict:
    policy = load_policy()

    highest_severity = get_highest_severity(findings)

    if highest_severity is None:
        decision = policy["rules"]["no_findings"]
    else:
        decision = policy["rules"].get(
            highest_severity,
            "NEEDS_REVIEW"
        )

    return {
        "policy": policy["policy_name"],
        "decision": decision,
        "highest_severity": highest_severity
    }