from backend.models import AIReview
from backend.ollama_client import ask_ollama


def review_code(code: str, language: str) -> dict:

    prompt = f"""
You are a careful static code reviewer.

Analyze the submitted {language} code.

Your job is to find ALL meaningful issues that are directly supported
by the submitted code.

Review these categories independently:

1. Security vulnerabilities
2. Bugs and runtime errors
3. Logic errors
4. Code quality and reliability problems


IMPORTANT REVIEW PROCESS

Perform the following checks INTERNALLY.

DO NOT output the result of a check when no problem is found.

The checklist below is ONLY for internal reasoning.
A checklist item is NOT automatically a finding.

Only add an item to the findings list when there is an actual,
specific problem directly supported by the submitted code.

If a check finds no problem, DO NOT mention that check anywhere in:
- findings
- evidence
- impact
- remediation


CHECK 1 — COMMAND EXECUTION

Look for:
- os.system(...)
- subprocess with shell=True
- eval(...)
- exec(...)

If dynamically constructed or potentially unsafe data reaches one of
these operations, report the actual issue.

Do not report ordinary string formatting as command execution.


CHECK 2 — UNSAFE DESERIALIZATION

Look specifically for:
- pickle.loads(...)
- pickle.load(...)

If either operation is present, report unsafe deserialization.

Do not skip this check merely because the source of the data is unclear.

State only what is directly supported by the code.


CHECK 3 — SQL INJECTION

Look for SQL queries built using:
- string concatenation
- f-strings
- string formatting with external or variable values

Only report SQL injection when the submitted code actually constructs
a query unsafely.


CHECK 4 — HARDCODED SECRETS

Look for actual sensitive values such as:
- passwords
- API keys
- tokens
- secret keys
- private keys

Do NOT treat ordinary values such as:
- filenames
- database filenames
- hostnames
- ports
- ordinary configuration values

as secrets.


CHECK 5 — DIVISION AND MODULO

Check whether a denominator or modulo operand can become zero.

If the submitted code accepts a value and uses it as a divisor without
validation, report the possible runtime error.


CHECK 6 — LOOPS AND LOGIC

Check for:
- infinite loops
- loop control variables that are never updated
- clearly incorrect conditions
- unreachable code

Only report an issue when the problem actually exists in the code.


CHECK 7 — VARIABLES AND RUNTIME ERRORS

Check for:
- variables actually used before definition
- invalid operations
- directly evident runtime errors

Verify execution order before reporting.


CHECK 8 — FILE AND RESOURCE OPERATIONS

Check for directly supported problems involving:

- file operations
- database connections
- network connections
- missing resource cleanup
- obviously unhandled failures

Only report missing resource cleanup when ALL of the following are true:

1. The submitted code clearly creates or opens a resource.
2. The complete submitted code does not close or release that resource.
3. The resource is not managed by a context manager such as `with`.
4. The issue is meaningful in the context of the submitted code.

Do NOT report missing cleanup merely because a short code snippet contains
an `open()` or connection call.

Do not require exception handling around every operation.
Only report a meaningful reliability problem when directly supported by
the submitted code.

CHECK 9 — OTHER UNSAFE API USAGE

Check for other APIs that directly create a security or reliability risk.


STRICT FINDING FILTER

Before adding EACH finding, verify ALL of the following:

1. An actual problem EXISTS in the submitted code.
2. The problem is directly supported by the submitted code.
3. You can provide actual code evidence for the problem.
4. The evidence demonstrates the presence of the problem.

Only create the finding if ALL four conditions are true.

The following are NOT valid findings and must NEVER be returned:

- "No infinite loop is present"
- "No unreachable code is present"
- "No variables are used before definition"
- "No invalid operations are present"
- "No file operations are present"
- "No missing resource cleanup is present"
- "No security risks"
- "No issues found"
- "Safe code"
- "No vulnerabilities"

Never create a finding describing the ABSENCE of a problem.

If a check finds nothing, simply omit it.

A finding must describe a problem that EXISTS.


IMPORTANT ACCURACY RULES

- Inspect all nine checks before finalizing.
- Find all independent issues, not just the first issue.
- Do not invent code, variables, execution paths, or behavior.
- Every finding must be supported by the submitted code.
- Evidence must contain the exact relevant code whenever possible.
- Do not report the same underlying problem twice.
- Do not report normal user input as a vulnerability by itself.
- Do not report an operation that is absent from the submitted code.
- Do not create a finding merely to say that code is safe.
- Do not create generic findings such as "User Input Handling".
- Do not create generic findings such as "Missing Error Handling"
  unless you can identify a specific failing operation and a specific
  consequence.
- If no meaningful issues are found after completing all checks,
  return an empty findings list.


FINDING FORMAT

For every actual finding provide:

- title: concise issue name
- category: security, bug, or code_quality
- severity: LOW, MEDIUM, HIGH, or CRITICAL
- evidence: exact relevant code from the submitted code
- impact: the actual consequence of the problem
- remediation: a concrete fix
- source: always ["ai"]


SEVERITY GUIDANCE

LOW:
Minor issue with limited impact.

MEDIUM:
Meaningful bug, runtime error, or reliability problem.

HIGH:
Serious security vulnerability or major application failure risk.

CRITICAL:
Severe vulnerability with potentially catastrophic consequences.


FINAL OUTPUT RULES

1. The findings list must contain ONLY actual problems.

2. Every finding must describe a problem that EXISTS in the submitted code.

3. Never create a finding just to document that a review check was performed.

4. Never create a finding describing the absence of a problem.

5. If a review category contains no problems, omit that category completely.

6. An empty findings list is valid only when no meaningful problems
   were found after completing all checks.

7. Do not use negative evidence such as:
   "No issue is present"
   "No loop exists"
   "No vulnerability was found"
   "Does not contain"
   "Not present"

8. Each finding must contain positive evidence: actual code that
   demonstrates the problem.

9. Do not add placeholder, checklist, informational, or confirmation
   findings.

10. Do not stop after finding one issue.
    Complete all nine checks before returning the result.


Submitted code:

{code}
"""

    schema = AIReview.model_json_schema()

    answer = ask_ollama(
        prompt=prompt,
        format_schema=schema
    )

    return AIReview.model_validate_json(answer).model_dump()