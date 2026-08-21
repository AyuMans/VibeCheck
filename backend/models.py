from pydantic import BaseModel, Field


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


class AIReview(BaseModel):
    summary: str
    findings: list[Finding]


class CodeReviewResponse(AIReview):
    language: str