from backend.models import AIReview
from backend.ollama_client import ask_ollama


def review_code(code: str, language: str) -> dict:
    prompt = f"""
You are a security-focused software code reviewer.

Analyze the provided {language} code carefully.

Your job is to identify issues actually supported by the code.

Pay special attention to:
- User-controlled input
- Shell command execution
- Unsafe API usage
- Injection vulnerabilities
- File access problems
- Authentication or authorization problems
- Logic errors

For each finding:
- title: concise issue name
- category: security, bug, or code_quality
- severity: LOW, MEDIUM, HIGH, or CRITICAL
- evidence: exact relevant code
- impact: why the issue matters
- remediation: a concrete way to fix it
- "source": ["ai"]

Every finding must have `"source": "ai"`.

Analyze this code:

{code}
"""

    schema = AIReview.model_json_schema()

    answer = ask_ollama(
        prompt=prompt,
        format_schema=schema
    )

    return AIReview.model_validate_json(answer).model_dump()