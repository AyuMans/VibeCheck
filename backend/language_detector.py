"""
Lightweight, dependency-free heuristic source-code language detector.

The user pastes/types code directly into the editor rather than opening a
file from disk, so detection is based on code characteristics (keywords,
imports, declarations, distinctive syntax, shebangs) rather than file
extensions.

This module is also the SINGLE SOURCE OF TRUTH for the language ->
file-extension mapping used when writing temporary files for Semgrep, and
for the language -> display-name mapping used by the GUI. Any new
language should only need to be added here (LANGUAGE_EXTENSIONS,
LANGUAGE_DISPLAY_NAMES, and a detection rule set in _RULES).
"""

import re


# ==========================================================
# Canonical language identifiers
# ==========================================================
#
# Only languages that Semgrep can reliably analyze via `--config auto`
# are included. Detection intentionally returns "unknown" rather than
# guessing when confidence is low.

UNKNOWN_LANGUAGE = "unknown"

LANGUAGE_EXTENSIONS: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "go": ".go",
    "rust": ".rs",
    "php": ".php",
    "ruby": ".rb",
    "kotlin": ".kt",
    "swift": ".swift",
}

LANGUAGE_DISPLAY_NAMES: dict[str, str] = {
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
    "c": "C",
    "cpp": "C++",
    "csharp": "C#",
    "go": "Go",
    "rust": "Rust",
    "php": "PHP",
    "ruby": "Ruby",
    "kotlin": "Kotlin",
    "swift": "Swift",
    UNKNOWN_LANGUAGE: "Unknown",
}


# ==========================================================
# Shebang detection
# ==========================================================
#
# When present, a shebang is a very strong, unambiguous signal and is
# checked before any heuristic scoring.

_SHEBANG_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^#!.*\bpython[0-9.]*\b"), "python"),
    (re.compile(r"^#!.*\bnode\b"), "javascript"),
    (re.compile(r"^#!.*\bruby\b"), "ruby"),
    (re.compile(r"^#!.*\bphp\b"), "php"),
]


def _detect_from_shebang(code: str) -> str | None:

    stripped = code.lstrip()

    if not stripped.startswith("#!"):
        return None

    first_line = stripped.splitlines()[0]

    for pattern, language in _SHEBANG_RULES:

        if pattern.search(first_line):
            return language

    return None


# ==========================================================
# Heuristic scoring rules
# ==========================================================
#
# Each language maps to a list of (pattern, weight) rules. A rule
# contributes its weight to that language's score when it matches
# ANYWHERE in the snippet (matched once, not per-occurrence, so a
# single repeated token cannot dominate the score).
#
# Weights are chosen so that near-unambiguous signals (e.g. "<?php",
# "fn main(", "#include <iostream>") dominate, while generic/weak
# signals (e.g. a trailing semicolon) contribute only a little.

_RULES: dict[str, list[tuple[re.Pattern, int]]] = {

    "python": [
        (re.compile(r"^\s*def\s+\w+\s*\(.*\)\s*:", re.MULTILINE), 4),
        (re.compile(r"^\s*class\s+\w+.*:\s*$", re.MULTILINE), 3),
        (re.compile(r"^\s*from\s+[\w.]+\s+import\s+", re.MULTILINE), 4),
        (re.compile(r"^\s*import\s+\w+(\.\w+)*\s*$", re.MULTILINE), 1),
        (re.compile(r"\bself\b"), 2),
        (re.compile(r"^\s*elif\b.*:\s*$", re.MULTILINE), 3),
        (re.compile(r"\bprint\s*\("), 1),
        (re.compile(r"^\s*#(?!include|import|define)\S?", re.MULTILINE), 1),
        (
            re.compile(
                r"\bos\.(system|popen|execvp?|remove|unlink|"
                r"path\.\w+)\s*\("
            ),
            3,
        ),
        (re.compile(r"\bsubprocess\.\w+\s*\("), 3),
        (re.compile(r"\bsys\.(argv|exit)\b"), 2),
    ],

    "javascript": [
        (re.compile(r"\b(const|let|var)\s+\w+\s*="), 2),
        (re.compile(r"\bfunction\s*\w*\s*\("), 2),
        (re.compile(r"=>\s*{?"), 2),
        (re.compile(r"\bconsole\.log\s*\("), 3),
        (re.compile(r"\brequire\s*\(\s*['\"]"), 3),
        (re.compile(r"\bimport\s+.*\s+from\s+['\"]"), 2),
        (re.compile(r"\bexport\s+(default\s+)?(function|class|const)\b"), 2),
        (re.compile(r"===|!=="), 1),
    ],

    "typescript": [
        (re.compile(r":\s*(string|number|boolean|any|void|unknown)\b"), 6),
        (re.compile(r"\binterface\s+\w+\s*{"), 4),
        (re.compile(r"\btype\s+\w+\s*=\s*"), 3),
        (re.compile(r"\bimplements\s+\w+"), 2),
        (re.compile(r"\bpublic\s+\w+|\bprivate\s+\w+|\breadonly\s+\w+"), 2),
        (
            re.compile(
                r"\bexport\s+(default\s+)?"
                r"(function|class|const|interface|type)\b"
            ),
            2,
        ),
        (re.compile(r"\bconsole\.log\s*\("), 1),
    ],

    "java": [
        (re.compile(r"\bpublic\s+class\s+\w+"), 5),
        (re.compile(r"\bpublic\s+static\s+void\s+main\s*\(\s*String"), 5),
        (re.compile(r"\bSystem\.out\.println\s*\("), 4),
        (re.compile(r"^\s*package\s+[\w.]+;", re.MULTILINE), 3),
        (re.compile(r"^\s*import\s+java\.", re.MULTILINE), 4),
        (re.compile(r"@Override\b"), 2),
    ],

    "csharp": [
        (re.compile(r"\bnamespace\s+[\w.]+"), 4),
        (re.compile(r"^\s*using\s+System(\.\w+)*\s*;", re.MULTILINE), 4),
        (re.compile(r"\bConsole\.WriteLine\s*\("), 4),
        (re.compile(r"\bstatic\s+void\s+Main\s*\("), 4),
        (re.compile(r"\bpublic\s+class\s+\w+"), 1),
        (re.compile(r"^\s*\[\w+(\(.*\))?\]\s*$", re.MULTILINE), 1),
    ],

    "c": [
        (re.compile(r"^\s*#include\s*<[\w./]+\.h>", re.MULTILINE), 3),
        (re.compile(r"\bprintf\s*\("), 3),
        (re.compile(r"\bmalloc\s*\(|\bfree\s*\("), 3),
        (re.compile(r"\bint\s+main\s*\(\s*(void|int\s+argc)?"), 3),
        (re.compile(r"\bstruct\s+\w+\s*{"), 2),
        (re.compile(r"->\w+"), 1),
    ],

    "cpp": [
        (re.compile(r"^\s*#include\s*<iostream>", re.MULTILINE), 5),
        (re.compile(r"\bstd::\w+"), 4),
        (re.compile(r"\busing\s+namespace\s+std\s*;"), 4),
        (re.compile(r"\bcout\s*<<|\bcin\s*>>"), 4),
        (re.compile(r"\btemplate\s*<"), 3),
        (re.compile(r"\bnullptr\b"), 2),
        (re.compile(r"\bclass\s+\w+\s*(:\s*public\s+\w+)?\s*{"), 1),
    ],

    "go": [
        (re.compile(r"^\s*package\s+main\s*$", re.MULTILINE), 5),
        (re.compile(r"\bfunc\s+\w+\s*\("), 4),
        (re.compile(r"^\s*import\s*\(", re.MULTILINE), 3),
        (re.compile(r"\bfmt\.Println\s*\(|\bfmt\.Printf\s*\("), 4),
        (re.compile(r"\w+\s*:=\s*"), 2),
        (re.compile(r"\bgo\s+func\s*\("), 2),
    ],

    "rust": [
        (re.compile(r"\bfn\s+main\s*\(\s*\)\s*{"), 5),
        (re.compile(r"\bfn\s+\w+\s*\("), 3),
        (re.compile(r"\blet\s+mut\s+\w+"), 3),
        (re.compile(r"\bprintln!\s*\("), 4),
        (re.compile(r"::<"), 2),
        (re.compile(r"^\s*use\s+\w+(::\w+)*\s*;", re.MULTILINE), 2),
    ],

    "php": [
        (re.compile(r"<\?php"), 6),
        (re.compile(r"\$\w+\s*="), 3),
        (re.compile(r"\becho\s+"), 2),
        (re.compile(r"\bfunction\s+\w+\s*\([^)]*\$"), 2),
        (re.compile(r"->\w+\s*\("), 1),
    ],

        "ruby": [
        # Ruby-specific input
        (re.compile(r"\bgets(?:\.chomp)?\b"), 5),

        # Ruby shell/system execution
        (re.compile(r"\bsystem\s*\("), 4),

        # Ruby backtick command execution
        (re.compile(r"`[^`]+`"), 4),

        # Ruby method definitions
        (re.compile(r"^\s*def\s+\w+(?:[!?=])?", re.MULTILINE), 4),

        # Ruby block/method termination
        (re.compile(r"^\s*end\s*$", re.MULTILINE), 3),

        # Ruby output
        (re.compile(r"\bputs\s+"), 3),
        (re.compile(r"\bprint\s+"), 2),

        # Ruby imports
        (re.compile(r"^\s*require\s+['\"]", re.MULTILINE), 3),
        (re.compile(r"^\s*require_relative\s+['\"]", re.MULTILINE), 4),

        # Ruby symbols / hash syntax
        (re.compile(r":\w+\s*=>"), 2),
        (re.compile(r"\b\w+\s*:\s*[^,\n}]+"), 1),

        # Ruby-specific object/class syntax
        (re.compile(r"\battr_(?:accessor|reader|writer)\b"), 4),
        (re.compile(r"\bclass\s+\w+\s*(?:<\s*\w+)?"), 3),
        (re.compile(r"\bmodule\s+\w+"), 3),

        # Ruby blocks
        (re.compile(r"\bdo\s*\|[^|]*\|"), 3),

        # Ruby interpolation
        (re.compile(r"#\{[^}]+\}"), 2),

        # Ruby instance/class variables
        (re.compile(r"@@\w+"), 2),
        (re.compile(r"@\w+"), 1),
    ],

    "kotlin": [
        (re.compile(r"\bfun\s+main\s*\("), 5),
        (re.compile(r"\bfun\s+\w+\s*\("), 3),
        (re.compile(r"\bval\s+\w+\s*[:=]"), 3),
        (re.compile(r"\bvar\s+\w+\s*[:=]"), 2),
        (re.compile(r"^\s*package\s+[\w.]+\s*$", re.MULTILINE), 2),
        (re.compile(r"\bdata\s+class\s+\w+"), 3),
    ],

    "swift": [
        (re.compile(r"\bimport\s+(Foundation|UIKit|SwiftUI)\b"), 5),
        (re.compile(r"\bfunc\s+\w+\s*\("), 2),
        (re.compile(r"\bvar\s+\w+\s*:\s*\w+"), 2),
        (re.compile(r"\blet\s+\w+\s*[:=]"), 2),
        (re.compile(r"\bguard\s+let\b"), 3),
        (re.compile(r"@objc\b|@IBOutlet\b|@IBAction\b"), 3),
    ],
}


# A language must clear this absolute score to be considered at all,
# and must beat the runner-up by at least this margin. Both guards
# exist so that short or ambiguous snippets fall back to "unknown"
# rather than being confidently misclassified.
_MIN_CONFIDENCE_SCORE = 4
_MIN_MARGIN = 2


def _score_language(code: str, language: str) -> int:

    score = 0

    for pattern, weight in _RULES[language]:

        if pattern.search(code):
            score += weight

    return score


def detect_language(code: str) -> str:
    """
    Heuristically detect the programming language of a snippet of
    pasted/typed source code.

    Returns a canonical identifier from LANGUAGE_EXTENSIONS (e.g.
    "python", "javascript", "rust", ...), or UNKNOWN_LANGUAGE
    ("unknown") when confidence is too low to be safe.
    """

    if not code or not code.strip():
        return UNKNOWN_LANGUAGE

    shebang_language = _detect_from_shebang(code)

    if shebang_language:
        return shebang_language

    scores = {
        language: _score_language(code, language)
        for language in _RULES
    }

    ranked = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    best_language, best_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    if best_score < _MIN_CONFIDENCE_SCORE:
        return UNKNOWN_LANGUAGE

    if (best_score - second_score) < _MIN_MARGIN:
        return UNKNOWN_LANGUAGE

    return best_language