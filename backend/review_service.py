from backend.models import AIReview
from backend.ollama_client import ask_ollama


def review_code(code: str, language: str) -> dict:
    prompt = f"""
You are a security-focused software code reviewer.

Analyze the provided {language} code carefully.

Identify only issues that are directly supported by the submitted code.

IMPORTANT SECURITY REASONING RULES:

- User-controlled input is NOT automatically a vulnerability.
- String formatting, including f-strings, does NOT execute shell commands.
- A shell injection finding requires an actual execution sink such as:
  os.system, subprocess with shell=True, shell command execution,
  or another mechanism that executes data as a command.
- Do not claim arbitrary command execution unless the submitted code
  actually contains a command execution mechanism.
- Do not invent functions, behavior, or code that is not present.
- Do not assume that a variable can execute itself merely because it
  contains user-controlled text.
- Every finding must be directly supported by exact code evidence.

Pay special attention to:
- User-controlled input reaching dangerous execution functions
- Shell command execution
- Unsafe API usage
- Injection vulnerabilities
- File access problems
- Authentication or authorization problems
- Logic errors

For each actual finding:
- title: concise issue name
- category: security, bug, or code_quality
- severity: LOW, MEDIUM, HIGH, or CRITICAL
- evidence: exact relevant code from the submitted code
- impact: why the actual issue matters
- remediation: a concrete way to fix it
- source: always return ["ai"]

IMPORTANT OUTPUT RULES:

1. Only create a finding when there is an actual problem in the
submitted code.

2. If the code has no meaningful security issue, bug, or code-quality
problem, return an empty findings list.

3. NEVER create a finding just to say the code is safe or has no
problems.

4. NEVER create findings such as:
- "No security risks"
- "No issues found"
- "Safe code"
- "No vulnerabilities"

5. The absence of a vulnerability is NOT a LOW severity finding.

6. If there are no actual problems, findings must be an empty list.

7. Never claim behavior that is not present in the submitted code.

Analyze this code:

{code}
"""

    schema = AIReview.model_json_schema()

    answer = ask_ollama(
        prompt=prompt,
        format_schema=schema
    )

    return AIReview.model_validate_json(answer).model_dump()