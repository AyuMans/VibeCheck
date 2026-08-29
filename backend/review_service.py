from backend.models import AIReview
from backend.ollama_client import ask_ollama


# ==========================================================
# Evidence validation helpers
# ==========================================================

def _normalize_text(text: str | None) -> str:
    """
    Normalize whitespace so small formatting differences
    do not prevent evidence comparison.
    """

    if not text:
        return ""

    return " ".join(text.split())


def _evidence_exists_in_code(
    code: str,
    evidence: str,
) -> bool:
    """
    Verify that AI-generated evidence actually exists
    somewhere in the submitted source code.
    """

    if not code or not evidence:
        return False

    normalized_code = _normalize_text(code)
    normalized_evidence = _normalize_text(evidence)

    if not normalized_evidence:
        return False

    return normalized_evidence in normalized_code


def _find_evidence_lines(
    code: str,
    evidence: str,
) -> tuple[int | None, int | None]:
    """
    Determine the 1-based source-code line range
    corresponding to the AI evidence.
    """

    if not code or not evidence:
        return None, None

    code_lines = code.splitlines()

    evidence_lines = [
        line.strip()
        for line in evidence.splitlines()
        if line.strip()
    ]

    if not evidence_lines:
        return None, None

    # ------------------------------------------------------
    # 1. Exact contiguous line matching
    # ------------------------------------------------------

    for start_index in range(len(code_lines)):

        if (
            start_index + len(evidence_lines)
            > len(code_lines)
        ):
            break

        matched = True

        for offset, evidence_line in enumerate(
            evidence_lines
        ):

            code_line = code_lines[
                start_index + offset
            ].strip()

            if code_line != evidence_line:

                matched = False
                break

        if matched:

            return (
                start_index + 1,
                start_index + len(evidence_lines),
            )

    # ------------------------------------------------------
    # 2. Normalized contiguous line matching
    # ------------------------------------------------------

    normalized_evidence_lines = [
        _normalize_text(line)
        for line in evidence_lines
    ]

    for start_index in range(len(code_lines)):

        if (
            start_index
            + len(normalized_evidence_lines)
            > len(code_lines)
        ):
            break

        matched = True

        for offset, evidence_line in enumerate(
            normalized_evidence_lines
        ):

            code_line = _normalize_text(
                code_lines[
                    start_index + offset
                ]
            )

            if code_line != evidence_line:

                matched = False
                break

        if matched:

            return (
                start_index + 1,
                start_index + len(evidence_lines),
            )

    # ------------------------------------------------------
    # 3. Single-line expression matching
    # ------------------------------------------------------

    normalized_evidence = _normalize_text(
        evidence
    )

    for index, code_line in enumerate(
        code_lines
    ):

        normalized_code_line = _normalize_text(
            code_line
        )

        if (
            normalized_evidence
            and normalized_evidence
            in normalized_code_line
        ):

            return (
                index + 1,
                index + 1,
            )

    return None, None


def _validate_ai_findings(
    code: str,
    review: AIReview,
) -> AIReview:
    """
    Validate AI findings before they enter the
    correlation pipeline.

    A finding is retained only when:

    1. Evidence exists in the submitted source.
    2. The evidence can be located.
    """

    valid_findings = []

    for finding in review.findings:

        evidence = (
            finding.evidence or ""
        ).strip()

        # --------------------------------------------------
        # Evidence is mandatory.
        # --------------------------------------------------

        if not evidence:
            continue

        # --------------------------------------------------
        # Evidence must exist in source code.
        # --------------------------------------------------

        if not _evidence_exists_in_code(
            code,
            evidence,
        ):
            continue

        # --------------------------------------------------
        # Determine actual source location.
        # --------------------------------------------------

        line_start, line_end = (
            _find_evidence_lines(
                code,
                evidence,
            )
        )

        # --------------------------------------------------
        # Normalize AI source.
        # --------------------------------------------------

        finding.source = ["ai"]

        # --------------------------------------------------
        # Never trust model-provided line numbers.
        # --------------------------------------------------

        finding.line_start = line_start
        finding.line_end = line_end

        valid_findings.append(
            finding
        )

    return AIReview(
        summary=review.summary,
        findings=valid_findings,
    )


# ==========================================================
# AI Code Review
# ==========================================================

def review_code(
    code: str,
    language: str,
) -> dict:

    prompt = f"""
You are a STRICT static code security analyzer.

Analyze ONLY the submitted {language} source code.

Your output will be consumed by another security-analysis system.
Therefore, FALSE POSITIVES are worse than missing minor issues.

Your most important rule is:

ONLY REPORT A FINDING WHEN THE SUBMITTED CODE ITSELF PROVIDES
CONCRETE EVIDENCE THAT THE PROBLEM EXISTS.

Do NOT report theoretical possibilities.

Do NOT report something merely because it is sometimes considered
bad practice.

Do NOT invent execution paths.

Do NOT assume code that is not shown.

Do NOT assume that a variable contains malicious input unless the
submitted code provides evidence that it can.

Do NOT report the absence of a problem.

Do NOT create informational findings.

============================================================
EVIDENCE-FIRST ANALYSIS
============================================================

Before creating ANY finding, silently perform these steps:

1. Identify the exact suspicious operation.
2. Locate that operation in the submitted source.
3. Determine whether the operation actually creates a security,
   bug, logic, or reliability problem.
4. Determine the realistic consequence.
5. Copy the smallest useful piece of actual source code as evidence.
6. Reject the finding if any of these steps cannot be established.

Every finding MUST contain positive evidence from the submitted code.

For example, this is valid:

    result = eval(user_input)

because the submitted code actually contains eval() operating on
user-controlled input.

This is NOT valid:

    for item in items:

simply because loops can theoretically become infinite.

============================================================
SECURITY ANALYSIS
============================================================

CHECK 1 — COMMAND / CODE EXECUTION

Look for:

- os.system(...)
- os.popen(...)
- subprocess(..., shell=True)
- subprocess.run(..., shell=True)
- subprocess.Popen(..., shell=True)
- eval(...)
- exec(...)

Report the issue when the submitted code actually demonstrates
unsafe command or code execution.

For os.system(), os.popen(), shell=True, eval(), and exec(),
consider the operation itself dangerous when it is used with
variable or externally supplied data.

Do NOT report ordinary function calls or string formatting.

============================================================
CHECK 2 — UNSAFE DESERIALIZATION
============================================================

Look for:

- pickle.loads(...)
- pickle.load(...)
- yaml.load(...) with unsafe/default loading
- other clearly unsafe deserialization APIs

If the dangerous API is actually present, report it.

Do not invent a malicious payload.

============================================================
CHECK 3 — SQL INJECTION
============================================================

Look for SQL queries constructed using:

- string concatenation
- f-strings
- % formatting
- .format()

Example:

query = "SELECT * FROM users WHERE username = '" + username + "'"

This is a valid finding.

Parameterized queries such as:

conn.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)

are NOT SQL injection.

Do not report a database connection itself as SQL injection.

============================================================
CHECK 4 — HARDCODED SECRETS
============================================================

Report actual sensitive credentials such as:

- API keys
- passwords
- authentication tokens
- private keys
- access tokens
- secret keys

Example:

API_KEY = "sk-actual-secret-value"

may be a finding.

Do NOT report:

DATABASE = "users.db"

Do NOT report:

HOST = "localhost"

Do NOT report:

PORT = 5432

Do NOT report ordinary filenames, database names,
configuration values, or placeholder values as secrets.

============================================================
CHECK 5 — PATH TRAVERSAL
============================================================

Look for user-controlled or externally controlled paths used in
file operations.

Example:

filename = input("Filename: ")
file_path = base / filename
file_path.read_text()

This may be a path traversal vulnerability because the input is
used directly to construct a filesystem path.

Report it only when the submitted code provides enough evidence
that the path is not restricted to the intended directory.

============================================================
CHECK 6 — FILE PERMISSION PROBLEMS
============================================================

Look for dangerous permission changes such as:

os.chmod(filename, 0o777)

Report overly permissive permissions when the submitted code
actually applies them.

Do not report ordinary file access as a permission vulnerability.

============================================================
CHECK 7 — DIVISION / MODULO ERRORS
============================================================

Report division-by-zero or modulo-by-zero only when the submitted
code actually allows the denominator to become zero.

Example:

number = int(input("Number: "))
result = 100 / number

This is a meaningful potential runtime error because number can
be zero.

But:

result = number / 5

is NOT a division-by-zero finding.

IMPORTANT:

Do not infer unrelated conditions.

For example:

number / 0

means division by zero regardless of whether number is 5, 10,
100, or any other value.

The numerator does not control whether division by zero occurs.

============================================================
CHECK 8 — LOOPS AND LOGIC
============================================================

Look for ACTUAL:

- infinite loops
- incorrect loop conditions
- loop variables that fail to change when they must
- unreachable code
- contradictory conditions
- obviously incorrect logic

Do NOT report:

for row in result:

as an infinite loop.

Do NOT report an unused loop variable as a security or bug finding
unless its unused state demonstrably causes incorrect behavior.

Do NOT report a loop merely because its termination cannot be proven
from a short snippet.

============================================================
CHECK 9 — VARIABLES AND RUNTIME ERRORS
============================================================

Look for actual:

- use-before-definition
- undefined variables
- impossible operations
- invalid type operations that are evident from the code
- directly evident runtime exceptions

Example:

print(username)

when username has never been defined is a valid finding.

But:

username = input("Username: ")
print(username)

is NOT a use-before-definition issue.

============================================================
CHECK 10 — RESOURCE MANAGEMENT
============================================================

Look for meaningful resource-management problems involving:

- files
- database connections
- network connections
- locks
- other manually managed resources

Only report missing cleanup when:

1. The resource is clearly created/opened.
2. The submitted code is sufficiently complete to judge cleanup.
3. No context manager or explicit cleanup exists.
4. The missing cleanup could meaningfully affect reliability.

For short snippets, prefer NOT reporting missing cleanup when the
surrounding lifecycle is unknown.

Do not assume every open() requires a finding.

============================================================
CHECK 11 — OTHER SECURITY / RELIABILITY APIs
============================================================

Look for clearly unsafe API usage that is directly supported by
the submitted code.

Do not generate generic "best practice" findings.

============================================================
FALSE POSITIVE PROTECTION
============================================================

NEVER return findings such as:

- Infinite Loop for a normal for loop
- Unreachable Code when the code is reachable
- Unused Variable unless it actually causes a problem
- Missing Error Handling merely because try/except is absent
- Missing Resource Cleanup for an incomplete snippet
- Hardcoded Secret for a filename
- Hardcoded Secret for a database filename
- Security Risk for normal input()
- SQL Injection for parameterized queries
- Command Injection for ordinary string operations
- Path Traversal without actual path construction
- Runtime Error without a concrete failing operation

A finding must describe a problem that EXISTS.

============================================================
SEVERITY RULES
============================================================

Use severity carefully.

CRITICAL:

Only use CRITICAL for vulnerabilities where successful exploitation
could directly result in severe consequences such as arbitrary code
execution or equivalent complete compromise.

Examples may include:

- eval(user_input)
- exec(user_input)
- unsafe pickle deserialization of untrusted data

HIGH:

Use HIGH for serious security vulnerabilities such as:

- command injection
- SQL injection
- serious authentication/security failures
- dangerous hardcoded credentials when clearly sensitive

MEDIUM:

Use MEDIUM for meaningful but more limited issues such as:

- path traversal
- dangerous file permissions
- significant runtime failures

LOW:

Use LOW only for genuinely minor issues.

Do NOT inflate severity merely because an API is considered unsafe.

============================================================
DUPLICATE PREVENTION
============================================================

Do not report the same underlying problem multiple times.

For example:

query = "SELECT ... " + username
result = conn.execute(query)

should normally produce ONE SQL injection finding.

Use the evidence that best demonstrates the vulnerability.

============================================================
SUMMARY
============================================================

The summary should briefly describe the overall review.

Do not list categories that have no findings.

Do not say "no vulnerabilities found" inside a finding.

============================================================
OUTPUT REQUIREMENTS
============================================================

Return ONLY findings for problems that actually exist.

Every finding MUST contain:

- title
- category
- severity
- evidence
- impact
- remediation
- source
- line_start
- line_end

The evidence MUST be copied from the submitted code.

The evidence MUST NOT contain invented code.

The evidence should normally be one or a few relevant lines.

Use:

source: ["ai"]

Line numbers are 1-based.

If you cannot confidently determine the line number,
use null.

============================================================
FINAL INTERNAL VALIDATION
============================================================

Before returning each finding, silently ask:

1. Does this problem actually exist?
2. Is the suspicious operation actually present?
3. Is my evidence copied from the submitted code?
4. Does the evidence demonstrate the problem?
5. Am I assuming code that was not provided?
6. Am I reporting a theoretical possibility instead of an actual issue?
7. Is the severity justified?
8. Is this a duplicate of another finding?
9. Would a deterministic SAST analyzer reasonably consider this
   a real issue?

If any answer is NO, DO NOT RETURN THE FINDING.

If no meaningful issues exist:

findings = []

Never create a finding simply because a checklist item was checked.

============================================================
SUBMITTED CODE
============================================================

{code}
"""

    # ------------------------------------------------------
    # Ask local AI for structured output.
    # ------------------------------------------------------

    schema = AIReview.model_json_schema()

    answer = ask_ollama(
        prompt=prompt,
        format_schema=schema,
    )

    # ------------------------------------------------------
    # Validate model response against Pydantic schema.
    # ------------------------------------------------------

    review = AIReview.model_validate_json(
        answer
    )

    # ------------------------------------------------------
    # Independently validate evidence and line numbers.
    # ------------------------------------------------------

    review = _validate_ai_findings(
        code=code,
        review=review,
    )

    return review.model_dump()