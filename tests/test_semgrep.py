from backend.semgrep_service import scan_code


code = """import os

filename = input("Enter filename: ")
os.system("cat " + filename)
"""

findings = scan_code(
    code=code,
    language="python"
)

for finding in findings:
    print(finding.model_dump())