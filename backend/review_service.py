from backend.models import AIReview
from backend.ollama_client import ask_ollama


def review_code(code: str, language: str) -> dict:

    prompt = f"""
You are a software code reviewer performing a careful static review.

Analyze the provided {language} code for all relevant categories:

1. Security vulnerabilities
2. Bugs and possible runtime errors
3. Logic errors
4. Code quality and reliability problems

IMPORTANT:

A review is NOT limited to security vulnerabilities.

Check every relevant category independently, but do not assume that every
category contains a problem.

Identify only issues that are directly supported by the submitted code.

IMPORTANT REASONING RULES:

- User-controlled input is NOT automatically a vulnerability.

- User input should only be reported when its actual use in the submitted
  code creates a directly supported security, reliability, or correctness
  problem.

- String formatting, including f-strings, does NOT execute shell commands.

- A shell injection finding requires an actual command execution sink such as
  os.system, subprocess with shell=True, shell command execution,
  eval/exec when applicable, or another mechanism that actually executes
  supplied data as code or a command.

- Do not claim arbitrary command execution unless the submitted code contains
  an actual mechanism that could execute the relevant data.

- Do not invent functions, behavior, inputs, execution paths, APIs, or code
  that are not present in the submitted code.

- Do not create a finding about an operation or vulnerability that is absent
  from the submitted code.

- Every finding must be directly supported by exact code evidence.

- Verify the evidence before creating a finding.

- Do not report the same underlying problem multiple times.

- Prefer one precise finding over several redundant findings.

REVIEW CHECKLIST:

Silently inspect the submitted code for possible issues involving:

- Security vulnerabilities
- Division or modulo by a value that can become zero
- Infinite loops or loop-control variables that are never updated
- Variables actually used before being defined
- Missing error handling for operations that can obviously fail
- File operations with directly supported reliability problems
- Incorrect conditions or unreachable code when directly evident
- Unsafe deserialization actually present in the code
- SQL queries actually constructed unsafely
- User-controlled input actually reaching a command execution sink
- Hardcoded actual secrets or credentials
- Unsafe API usage
- Other directly supported bugs or logic errors

IMPORTANT:

The checklist is only for analysis.

Do NOT create one finding for every checklist item.

A checklist item produces a finding ONLY when the submitted code contains
direct evidence of that specific problem.

If a checklist category or operation is not present in the submitted code,
do not mention it at all.

Do not report a hypothetical problem merely because similar code could be
dangerous in another situation.

SPECIAL ACCURACY RULES:

- Only report "variable used before definition" when the variable is actually
  referenced before its assignment or definition in the submitted code.
  Verify the execution order before creating this finding.

- A hardcoded filename, database name, file path, host name, port number,
  or ordinary configuration value is NOT automatically a credential or secret.

- Only report hardcoded credentials or secrets when actual sensitive
  authentication material is present, such as passwords, API keys,
  access tokens, private keys, secret keys, or similar sensitive values.

- Do not report user input itself as a vulnerability when the real issue is
  already reported at the dangerous operation where that input is used.

- Do not create a finding whose own evidence says that no evidence exists.

- If the submitted code safely handles an error, do not report that error
  as unhandled.

- Do not report ordinary safe operations as shell execution, command
  injection, or arbitrary code execution.

- If you are uncertain whether an issue is directly supported by the code,
  do not report it.

FINDING REQUIREMENTS:

For each actual finding:

- title: concise issue name
- category: security, bug, or code_quality
- severity: LOW, MEDIUM, HIGH, or CRITICAL
- evidence: exact relevant code from the submitted code
- impact: explain the actual consequence supported by the code
- remediation: a concrete way to fix the actual issue
- source: always return ["ai"]

SEVERITY GUIDANCE:

- LOW: minor issue with limited impact.
- MEDIUM: meaningful bug, reliability issue, or security concern.
- HIGH: serious security vulnerability or major application failure risk.
- CRITICAL: severe vulnerability with potentially catastrophic impact.

IMPORTANT OUTPUT RULES:

1. Find all independent meaningful issues in the submitted code, not only
   the first issue you notice.

2. Only create a finding when there is an actual problem directly supported
   by the submitted code.

3. If the code has no meaningful security issue, bug, logic error, or
   code-quality problem, return an empty findings list.

4. NEVER create a finding just to say the code is safe or has no problems.

5. NEVER create findings such as:
   - "No security risks"
   - "No issues found"
   - "Safe code"
   - "No vulnerabilities"

6. The absence of a problem is NOT a LOW severity finding.

7. Never claim behavior that is not present in the submitted code.

8. Never report an absent feature or operation as a vulnerability.

9. Before creating each finding, verify:
   - Is the relevant operation actually present in the code?
   - Does the exact evidence support the title?
   - Is the claimed behavior actually possible from the submitted code?

   If any answer is no, do not create the finding.

Analyze this code:

{code}
"""

    schema = AIReview.model_json_schema()

    answer = ask_ollama(
        prompt=prompt,
        format_schema=schema
    )

    return AIReview.model_validate_json(answer).model_dump()