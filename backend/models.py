from pydantic import BaseModel


class CodeReviewRequest(BaseModel):

    code: str

    language: str


class Finding(BaseModel):

    title: str

    category: str

    severity: str

    evidence: str

    impact: str

    remediation: str

    source: list[str]

    # Optional location information.
    # Semgrep can provide this deterministically.
    # AI may omit it when the exact location is unknown.
    line_start: int | None = None

    line_end: int | None = None


class AIReview(BaseModel):

    summary: str

    findings: list[Finding]


class PolicyResult(BaseModel):

    policy: str

    decision: str

    highest_severity: str | None


class CodeReviewResponse(BaseModel):

    language: str

    summary: str

    findings: list[Finding]

    policy: PolicyResult