"""
Correlation engine
==================

Purpose
-------
AI and Semgrep analyze the same source code from different perspectives.

This module performs three operations:

    1. AI-to-AI deduplication
    2. Semgrep-to-Semgrep deduplication
    3. AI-to-Semgrep correlation

The engine intentionally does NOT maintain a vulnerability taxonomy or
a growing list of rule IDs.

Instead, correlation uses generic signals:

    - source location
    - evidence similarity
    - code identifier overlap
    - title/category similarity
    - impact/remediation similarity

This allows new Semgrep rules and new AI issue names to work without
requiring changes to this file.
"""

import difflib
import keyword
import re

from backend.models import Finding


# ==========================================================
# Configuration
# ==========================================================

# ----------------------------------------------------------
# AI <-> Semgrep correlation
# ----------------------------------------------------------

LOCATION_WEIGHT = 0.25
EVIDENCE_WEIGHT = 0.30
IDENTIFIER_WEIGHT = 0.20
TEXT_WEIGHT = 0.20
IMPACT_WEIGHT = 0.05

MERGE_THRESHOLD = 0.50

MIN_EVIDENCE_SUPPORT = 0.12
MIN_IDENTIFIER_SUPPORT = 0.20
MIN_TEXT_SUPPORT = 0.28
MIN_IMPACT_SUPPORT = 0.30


# ----------------------------------------------------------
# AI <-> AI deduplication
# ----------------------------------------------------------

AI_DEDUP_LOCATION_WEIGHT = 0.15
AI_DEDUP_EVIDENCE_WEIGHT = 0.55
AI_DEDUP_IDENTIFIER_WEIGHT = 0.10
AI_DEDUP_TEXT_WEIGHT = 0.15
AI_DEDUP_IMPACT_WEIGHT = 0.05

AI_DEDUP_THRESHOLD = 0.62

AI_DEDUP_MIN_EVIDENCE = 0.45
AI_DEDUP_MIN_TEXT = 0.35


# ----------------------------------------------------------
# Semgrep <-> Semgrep deduplication
# ----------------------------------------------------------

SEMGREP_DEDUP_LOCATION_WEIGHT = 0.45
SEMGREP_DEDUP_EVIDENCE_WEIGHT = 0.40
SEMGREP_DEDUP_IDENTIFIER_WEIGHT = 0.10
SEMGREP_DEDUP_TEXT_WEIGHT = 0.05

SEMGREP_DEDUP_THRESHOLD = 0.55

SEMGREP_DEDUP_MIN_EVIDENCE = 0.30
SEMGREP_DEDUP_MIN_IDENTIFIER = 0.25
SEMGREP_DEDUP_MIN_TEXT = 0.40


# Lines this far apart are considered nearby.
LINE_TOLERANCE = 3


SEVERITY_ORDER = {
    "WARNING": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "ERROR": 3,
    "CRITICAL": 4,
}


GENERIC_STOPWORDS = {
    "the",
    "this",
    "that",
    "is",
    "are",
    "was",
    "were",
    "a",
    "an",
    "of",
    "to",
    "and",
    "or",
    "in",
    "on",
    "with",
    "for",
    "from",
    "by",
    "as",
    "at",
    "be",
    "it",
    "its",
}


# Generic words that are common in source code and therefore
# provide little useful correlation information.
CODE_IDENTIFIER_STOPWORDS = {
    "true",
    "false",
    "none",
    "self",
}


GENERIC_FALLBACK_PREFIXES = (
    "detected by semgrep rule",
    "review the flagged code",
)


# ==========================================================
# Severity
# ==========================================================

def get_higher_severity(
    severity_one: str,
    severity_two: str,
) -> str:

    one = SEVERITY_ORDER.get(
        (severity_one or "").upper(),
        0,
    )

    two = SEVERITY_ORDER.get(
        (severity_two or "").upper(),
        0,
    )

    if one >= two:
        return (severity_one or "MEDIUM").upper()

    return (severity_two or "MEDIUM").upper()


# ==========================================================
# Generic text helpers
# ==========================================================

def normalize_text(
    text: str | None,
) -> str:
    """
    Normalize text for generic comparisons.
    """

    text = (text or "").lower()

    text = re.sub(
        r"[^a-z0-9_]+",
        " ",
        text,
    )

    text = re.sub(
        r"\s+",
        " ",
        text,
    ).strip()

    return text


def tokenize(
    normalized_text: str,
) -> set[str]:

    return {
        token
        for token in normalized_text.split()
        if (
            len(token) > 2
            and token not in GENERIC_STOPWORDS
        )
    }


def fuzzy_similarity(
    text_one: str,
    text_two: str,
) -> float:

    if not text_one or not text_two:
        return 0.0

    ratio = difflib.SequenceMatcher(
        None,
        text_one,
        text_two,
    ).ratio()

    tokens_one = tokenize(
        text_one
    )

    tokens_two = tokenize(
        text_two
    )

    if tokens_one and tokens_two:

        jaccard = (
            len(tokens_one & tokens_two)
            / len(tokens_one | tokens_two)
        )

    else:

        jaccard = 0.0

    return (
        0.60 * ratio
        + 0.40 * jaccard
    )


# NEW: a second, code-oriented similarity measure.
#
# fuzzy_similarity() above is tuned for prose (titles, categories,
# impact/remediation) where difflib's character-sequence ratio is a
# meaningful signal. For short CODE snippets it is not: two unrelated
# one-liners like `os.system("cat " + filename)` and
# `os.chmod(filename, 0o777)` share the "os." prefix and parenthesis
# syntax, which inflates their character-sequence ratio even though
# they perform unrelated operations. Token overlap (which identifier/
# keyword words actually appear in both) is the more meaningful
# signal for code, so evidence comparison weights it much more
# heavily and lets raw character similarity only break ties.
def code_text_similarity(
    text_one: str,
    text_two: str,
) -> float:

    if not text_one or not text_two:
        return 0.0

    ratio = difflib.SequenceMatcher(
        None,
        text_one,
        text_two,
    ).ratio()

    tokens_one = tokenize(
        text_one
    )

    tokens_two = tokenize(
        text_two
    )

    if tokens_one and tokens_two:

        jaccard = (
            len(tokens_one & tokens_two)
            / len(tokens_one | tokens_two)
        )

    else:

        jaccard = 0.0

    return (
        0.25 * ratio
        + 0.75 * jaccard
    )


# ==========================================================
# Generic fallback detection
# ==========================================================

def is_generic_fallback_text(
    text: str | None,
) -> bool:

    normalized = (
        text or ""
    ).strip().lower()

    return any(
        normalized.startswith(prefix)
        for prefix in GENERIC_FALLBACK_PREFIXES
    )


def pick_more_informative_text(
    text_one: str | None,
    text_two: str | None,
) -> str:

    text_one = text_one or ""
    text_two = text_two or ""

    one_generic = (
        is_generic_fallback_text(
            text_one
        )
    )

    two_generic = (
        is_generic_fallback_text(
            text_two
        )
    )

    if (
        one_generic
        and not two_generic
        and text_two
    ):
        return text_two

    if (
        two_generic
        and not one_generic
        and text_one
    ):
        return text_one

    if (
        len(text_two) > len(text_one)
        and len(text_two) > 30
    ):
        return text_two

    return text_one or text_two


# ==========================================================
# Source location
# ==========================================================

def get_line_range(
    finding: Finding,
) -> tuple[int, int] | None:

    if finding.line_start is None:
        return None

    start = finding.line_start

    end = (
        finding.line_end
        if finding.line_end is not None
        else start
    )

    return start, end


def get_line_gap(
    finding_one: Finding,
    finding_two: Finding,
) -> int | None:

    range_one = get_line_range(
        finding_one
    )

    range_two = get_line_range(
        finding_two
    )

    if (
        range_one is None
        or range_two is None
    ):
        return None

    start_one, end_one = range_one
    start_two, end_two = range_two

    # Overlap.
    if (
        start_one <= end_two
        and start_two <= end_one
    ):
        return 0

    if end_one < start_two:
        return start_two - end_one

    return start_one - end_two


def location_score(
    finding_one: Finding,
    finding_two: Finding,
) -> float | None:

    gap = get_line_gap(
        finding_one,
        finding_two,
    )

    if gap is None:
        return None

    if gap == 0:
        return 1.0

    if gap > LINE_TOLERANCE:
        return 0.0

    return max(
        0.0,
        1.0
        - (
            0.5
            * gap
            / LINE_TOLERANCE
        ),
    )


# ==========================================================
# Evidence similarity
# ==========================================================

def evidence_similarity(
    finding_one: Finding,
    finding_two: Finding,
) -> float:

    evidence_one = normalize_text(
        finding_one.evidence
    )

    evidence_two = normalize_text(
        finding_two.evidence
    )

    if (
        not evidence_one
        or not evidence_two
    ):
        return 0.0

    # Identical evidence is the strongest possible signal.
    if evidence_one == evidence_two:
        return 1.0

    # One tool may return a full statement while the other
    # returns the important sub-expression.
    if (
        evidence_one in evidence_two
        or evidence_two in evidence_one
    ):
        return 0.95

    # NEW: use the code-oriented similarity measure (token overlap
    # weighted heavily) rather than the prose-oriented one, since raw
    # character-sequence ratio is easily fooled by shared code syntax
    # (e.g. two unrelated "os.xxx(...)" calls).
    return code_text_similarity(
        evidence_one,
        evidence_two,
    )


# ==========================================================
# Code identifier overlap
# ==========================================================

def extract_identifiers(
    text: str | None,
) -> set[str]:
    """
    Extract source-code-style identifiers.

    This is generic language/string analysis. It has no
    vulnerability-specific knowledge.
    """

    if not text:
        return set()

    identifiers = set(
        re.findall(
            r"\b[A-Za-z_][A-Za-z0-9_]*\b",
            text,
        )
    )

    result = set()

    for identifier in identifiers:

        normalized = identifier.lower()

        if len(normalized) <= 2:
            continue

        if normalized in CODE_IDENTIFIER_STOPWORDS:
            continue

        if keyword.iskeyword(normalized):
            continue

        result.add(
            normalized
        )

    return result


def identifier_similarity(
    finding_one: Finding,
    finding_two: Finding,
) -> float:
    """
    Compare identifiers contained in the evidence.

    Unlike normal Jaccard similarity, this uses the smaller
    identifier set as the denominator.

    Example:

        query = ...
        conn.execute(query)

    Both snippets contain `query`, which is useful evidence
    that the statements may participate in the same operation.
    """

    ids_one = extract_identifiers(
        finding_one.evidence
    )

    ids_two = extract_identifiers(
        finding_two.evidence
    )

    if not ids_one or not ids_two:
        return 0.0

    intersection = (
        ids_one & ids_two
    )

    if not intersection:
        return 0.0

    base_score = (
        len(intersection)
        / min(
            len(ids_one),
            len(ids_two),
        )
    )

    # NEW: proximity is treated as an ADDITIVE bonus, not a floor
    # that overrides the base score. A hard floor (e.g. "any shared
    # identifier on adjacent lines scores >= 0.75") would make a
    # single coincidentally-shared common variable look just as
    # strong as a large, meaningful overlap - which is exactly the
    # kind of false-merge risk this signal needs to avoid. An
    # additive, capped bonus still rewards data-flow-adjacent code
    # (query = ...\n cursor.execute(query)) without inflating weak
    # overlaps into strong ones.
    gap = get_line_gap(
        finding_one,
        finding_two,
    )

    if gap is not None and gap <= 1:
        proximity_bonus = 0.20
    elif gap is not None and gap <= LINE_TOLERANCE:
        proximity_bonus = 0.10
    else:
        proximity_bonus = 0.0

    return min(1.0, base_score + proximity_bonus)


# ==========================================================
# Title/category similarity
# ==========================================================

def text_similarity(
    finding_one: Finding,
    finding_two: Finding,
) -> float:

    text_one = normalize_text(
        f"{finding_one.title} "
        f"{finding_one.category}"
    )

    text_two = normalize_text(
        f"{finding_two.title} "
        f"{finding_two.category}"
    )

    return fuzzy_similarity(
        text_one,
        text_two,
    )


# ==========================================================
# Impact/remediation similarity
# ==========================================================

def impact_similarity(
    finding_one: Finding,
    finding_two: Finding,
) -> float:

    impact_one = (
        finding_one.impact or ""
    )

    impact_two = (
        finding_two.impact or ""
    )

    remediation_one = (
        finding_one.remediation or ""
    )

    remediation_two = (
        finding_two.remediation or ""
    )

    if is_generic_fallback_text(
        impact_one
    ):
        impact_one = ""

    if is_generic_fallback_text(
        impact_two
    ):
        impact_two = ""

    if is_generic_fallback_text(
        remediation_one
    ):
        remediation_one = ""

    if is_generic_fallback_text(
        remediation_two
    ):
        remediation_two = ""

    text_one = normalize_text(
        f"{impact_one} {remediation_one}"
    )

    text_two = normalize_text(
        f"{impact_two} {remediation_two}"
    )

    if (
        not text_one
        or not text_two
    ):
        return 0.0

    return fuzzy_similarity(
        text_one,
        text_two,
    )


# ==========================================================
# Generic title selection
# ==========================================================

def choose_title(
    title_one: str,
    title_two: str,
) -> str:
    """
    Pick a reasonable title without knowing vulnerability types.

    Similar titles collapse to one title.

    Dissimilar titles remain combined when merging findings from
    the same tool.
    """

    title_one = title_one or ""
    title_two = title_two or ""

    if not title_one:
        return title_two

    if not title_two:
        return title_one

    normalized_one = normalize_text(
        title_one
    )

    normalized_two = normalize_text(
        title_two
    )

    if normalized_one == normalized_two:
        return title_one

    if normalized_one in normalized_two:
        return title_two

    if normalized_two in normalized_one:
        return title_one

    similarity = fuzzy_similarity(
        normalized_one,
        normalized_two,
    )

    if similarity >= 0.55:

        # Prefer the shorter readable title when two
        # strings appear to describe essentially the
        # same concept.
        if len(title_one) <= len(title_two):
            return title_one

        return title_two

    return (
        f"{title_one} / {title_two}"
    )


# ==========================================================
# Merge same-tool findings
# ==========================================================

def merge_same_tool_findings(
    finding_one: Finding,
    finding_two: Finding,
) -> Finding:

    sources = list(
        dict.fromkeys(
            finding_one.source
            + finding_two.source
        )
    )

    range_one = get_line_range(
        finding_one
    )

    range_two = get_line_range(
        finding_two
    )

    if range_one and range_two:

        line_start = min(
            range_one[0],
            range_two[0],
        )

        line_end = max(
            range_one[1],
            range_two[1],
        )

    else:

        line_start = (
            finding_one.line_start
            if finding_one.line_start is not None
            else finding_two.line_start
        )

        line_end = (
            finding_one.line_end
            if finding_one.line_end is not None
            else finding_two.line_end
        )

    # For duplicate findings, shorter evidence tends to
    # be more focused and easier to display.
    evidence_one = (
        finding_one.evidence or ""
    )

    evidence_two = (
        finding_two.evidence or ""
    )

    if evidence_one and evidence_two:

        if len(evidence_one) <= len(evidence_two):
            evidence = evidence_one
        else:
            evidence = evidence_two

    else:

        evidence = (
            evidence_one
            or evidence_two
        )

    return Finding(
        title=choose_title(
            finding_one.title,
            finding_two.title,
        ),
        category=(
            finding_one.category
            or finding_two.category
            or "security"
        ),
        severity=get_higher_severity(
            finding_one.severity,
            finding_two.severity,
        ),
        evidence=evidence,
        impact=pick_more_informative_text(
            finding_one.impact,
            finding_two.impact,
        ),
        remediation=pick_more_informative_text(
            finding_one.remediation,
            finding_two.remediation,
        ),
        source=sources,
        line_start=line_start,
        line_end=line_end,
    )


# ==========================================================
# Stage 1: AI deduplication
# ==========================================================

def _ai_pair_score(
    finding_one: Finding,
    finding_two: Finding,
) -> tuple[
    float,
    float,
    float,
    float,
]:

    loc = location_score(
        finding_one,
        finding_two,
    )

    evidence = evidence_similarity(
        finding_one,
        finding_two,
    )

    identifiers = identifier_similarity(
        finding_one,
        finding_two,
    )

    text = text_similarity(
        finding_one,
        finding_two,
    )

    impact = impact_similarity(
        finding_one,
        finding_two,
    )

    if loc is None:

        remaining = (
            AI_DEDUP_EVIDENCE_WEIGHT
            + AI_DEDUP_IDENTIFIER_WEIGHT
            + AI_DEDUP_TEXT_WEIGHT
            + AI_DEDUP_IMPACT_WEIGHT
        )

        combined = (
            evidence
            * (
                AI_DEDUP_EVIDENCE_WEIGHT
                / remaining
            )
            + identifiers
            * (
                AI_DEDUP_IDENTIFIER_WEIGHT
                / remaining
            )
            + text
            * (
                AI_DEDUP_TEXT_WEIGHT
                / remaining
            )
            + impact
            * (
                AI_DEDUP_IMPACT_WEIGHT
                / remaining
            )
        )

    else:

        combined = (
            loc
            * AI_DEDUP_LOCATION_WEIGHT
            + evidence
            * AI_DEDUP_EVIDENCE_WEIGHT
            + identifiers
            * AI_DEDUP_IDENTIFIER_WEIGHT
            + text
            * AI_DEDUP_TEXT_WEIGHT
            + impact
            * AI_DEDUP_IMPACT_WEIGHT
        )

    return (
        combined,
        evidence,
        text,
        identifiers,
    )


def _deduplicate_ai_findings(
    findings: list[Finding],
) -> list[Finding]:

    working = list(
        findings
    )

    while len(working) > 1:

        best_score = -1.0
        best_pair = None

        for i in range(
            len(working)
        ):

            for j in range(
                i + 1,
                len(working),
            ):

                (
                    combined,
                    evidence,
                    text,
                    identifiers,
                ) = _ai_pair_score(
                    working[i],
                    working[j],
                )

                if (
                    combined
                    < AI_DEDUP_THRESHOLD
                ):
                    continue

                # AI findings should only be collapsed when
                # the evidence itself is strongly related.
                # Similar titles alone are not enough.
                has_support = (
                    evidence
                    >= AI_DEDUP_MIN_EVIDENCE
                    or (
                        evidence >= 0.30
                        and text
                        >= AI_DEDUP_MIN_TEXT
                        and identifiers >= 0.20
                    )
                )

                if not has_support:
                    continue

                if combined > best_score:

                    best_score = (
                        combined
                    )

                    best_pair = (
                        i,
                        j,
                    )

        if best_pair is None:
            break

        i, j = best_pair

        merged = (
            merge_same_tool_findings(
                working[i],
                working[j],
            )
        )

        working = [
            finding
            for index, finding
            in enumerate(working)
            if index not in (i, j)
        ]

        working.append(
            merged
        )

    return working


# ==========================================================
# Stage 2: Semgrep deduplication
# ==========================================================

def _semgrep_pair_score(
    finding_one: Finding,
    finding_two: Finding,
) -> tuple[
    float,
    float,
    float,
    float,
]:

    loc = location_score(
        finding_one,
        finding_two,
    )

    evidence = evidence_similarity(
        finding_one,
        finding_two,
    )

    identifiers = identifier_similarity(
        finding_one,
        finding_two,
    )

    text = text_similarity(
        finding_one,
        finding_two,
    )

    if loc is None:

        remaining = (
            SEMGREP_DEDUP_EVIDENCE_WEIGHT
            + SEMGREP_DEDUP_IDENTIFIER_WEIGHT
            + SEMGREP_DEDUP_TEXT_WEIGHT
        )

        combined = (
            evidence
            * (
                SEMGREP_DEDUP_EVIDENCE_WEIGHT
                / remaining
            )
            + identifiers
            * (
                SEMGREP_DEDUP_IDENTIFIER_WEIGHT
                / remaining
            )
            + text
            * (
                SEMGREP_DEDUP_TEXT_WEIGHT
                / remaining
            )
        )

    else:

        combined = (
            loc
            * SEMGREP_DEDUP_LOCATION_WEIGHT
            + evidence
            * SEMGREP_DEDUP_EVIDENCE_WEIGHT
            + identifiers
            * SEMGREP_DEDUP_IDENTIFIER_WEIGHT
            + text
            * SEMGREP_DEDUP_TEXT_WEIGHT
        )

    return (
        combined,
        evidence,
        text,
        identifiers,
    )


def _deduplicate_semgrep_findings(
    findings: list[Finding],
) -> list[Finding]:

    working = list(
        findings
    )

    while len(working) > 1:

        best_score = -1.0
        best_pair = None

        for i in range(
            len(working)
        ):

            for j in range(
                i + 1,
                len(working),
            ):

                (
                    combined,
                    evidence,
                    text,
                    identifiers,
                ) = _semgrep_pair_score(
                    working[i],
                    working[j],
                )

                if (
                    combined
                    < SEMGREP_DEDUP_THRESHOLD
                ):
                    continue

                has_support = (
                    evidence
                    >= SEMGREP_DEDUP_MIN_EVIDENCE
                    or identifiers
                    >= SEMGREP_DEDUP_MIN_IDENTIFIER
                    or text
                    >= SEMGREP_DEDUP_MIN_TEXT
                )

                if not has_support:
                    continue

                if combined > best_score:

                    best_score = combined

                    best_pair = (
                        i,
                        j,
                    )

        if best_pair is None:
            break

        i, j = best_pair

        merged = (
            merge_same_tool_findings(
                working[i],
                working[j],
            )
        )

        working = [
            finding
            for index, finding
            in enumerate(working)
            if index not in (i, j)
        ]

        working.append(
            merged
        )

    return working


# ==========================================================
# Stage 3: AI <-> Semgrep correlation
# ==========================================================

def correlation_score(
    ai_finding: Finding,
    semgrep_finding: Finding,
) -> tuple[
    float,
    float,
    float,
    float,
    float,
]:

    loc = location_score(
        ai_finding,
        semgrep_finding,
    )

    evidence = evidence_similarity(
        ai_finding,
        semgrep_finding,
    )

    identifiers = identifier_similarity(
        ai_finding,
        semgrep_finding,
    )

    text = text_similarity(
        ai_finding,
        semgrep_finding,
    )

    impact = impact_similarity(
        ai_finding,
        semgrep_finding,
    )

    # Same evidence is almost certainly the same finding.
    if evidence >= 0.95:

        return (
            1.0,
            evidence,
            identifiers,
            text,
            impact,
        )

    if loc is None:

        remaining = (
            EVIDENCE_WEIGHT
            + IDENTIFIER_WEIGHT
            + TEXT_WEIGHT
            + IMPACT_WEIGHT
        )

        combined = (
            evidence
            * (
                EVIDENCE_WEIGHT
                / remaining
            )
            + identifiers
            * (
                IDENTIFIER_WEIGHT
                / remaining
            )
            + text
            * (
                TEXT_WEIGHT
                / remaining
            )
            + impact
            * (
                IMPACT_WEIGHT
                / remaining
            )
        )

    else:

        combined = (
            loc
            * LOCATION_WEIGHT
            + evidence
            * EVIDENCE_WEIGHT
            + identifiers
            * IDENTIFIER_WEIGHT
            + text
            * TEXT_WEIGHT
            + impact
            * IMPACT_WEIGHT
        )

    return (
        combined,
        evidence,
        identifiers,
        text,
        impact,
    )


def merge_findings(
    ai_finding: Finding,
    semgrep_finding: Finding,
) -> Finding:

    sources = list(
        dict.fromkeys(
            ai_finding.source
            + semgrep_finding.source
        )
    )

    # Prefer Semgrep location because it is obtained
    # deterministically from parsed source code.
    line_start = (
        semgrep_finding.line_start
        if semgrep_finding.line_start
        is not None
        else ai_finding.line_start
    )

    line_end = (
        semgrep_finding.line_end
        if semgrep_finding.line_end
        is not None
        else ai_finding.line_end
    )

    # Prefer Semgrep evidence when both tools point
    # directly at the same operation.
    evidence_similarity_score = (
        evidence_similarity(
            ai_finding,
            semgrep_finding,
        )
    )

    if evidence_similarity_score >= 0.75:

        evidence = (
            semgrep_finding.evidence
            or ai_finding.evidence
        )

    else:

        # When AI identifies the vulnerability at its
        # construction point and Semgrep identifies its
        # execution/use point, AI evidence is often more
        # explanatory for the user.
        evidence = (
            ai_finding.evidence
            or semgrep_finding.evidence
        )

    # AI generally gives a much cleaner user-facing title
    # than Semgrep's rule identifier.
    title = (
        ai_finding.title
        or semgrep_finding.title
    )

    category = (
        ai_finding.category
        or semgrep_finding.category
        or "security"
    )

    severity = get_higher_severity(
        ai_finding.severity,
        semgrep_finding.severity,
    )

    impact = pick_more_informative_text(
        ai_finding.impact,
        semgrep_finding.impact,
    )

    remediation = (
        pick_more_informative_text(
            ai_finding.remediation,
            semgrep_finding.remediation,
        )
    )

    return Finding(
        title=title,
        category=category,
        severity=severity,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        source=sources,
        line_start=line_start,
        line_end=line_end,
    )


def _correlate_ai_with_semgrep(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding],
) -> list[Finding]:

    candidate_pairs = []

    for ai_index, ai_finding in enumerate(
        ai_findings
    ):

        for (
            semgrep_index,
            semgrep_finding,
        ) in enumerate(
            semgrep_findings
        ):

            (
                combined,
                evidence,
                identifiers,
                text,
                impact,
            ) = correlation_score(
                ai_finding,
                semgrep_finding,
            )

            if combined < MERGE_THRESHOLD:
                continue

            # --------------------------------------------------
            # Location by itself can NEVER merge two findings.
            # --------------------------------------------------

            has_real_support = (
                evidence
                >= MIN_EVIDENCE_SUPPORT
                or identifiers
                >= MIN_IDENTIFIER_SUPPORT
                or text
                >= MIN_TEXT_SUPPORT
                or impact
                >= MIN_IMPACT_SUPPORT
            )

            if not has_real_support:
                continue

            # --------------------------------------------------
            # Extra protection against accidental merges.
            #
            # If evidence is weak, require at least two
            # supporting non-location signals.
            # --------------------------------------------------

            if evidence < 0.20:

                supporting_signals = sum([
                    identifiers
                    >= MIN_IDENTIFIER_SUPPORT,

                    text
                    >= MIN_TEXT_SUPPORT,

                    impact
                    >= MIN_IMPACT_SUPPORT,
                ])

                if supporting_signals < 2:
                    continue

            candidate_pairs.append(
                (
                    combined,
                    ai_index,
                    semgrep_index,
                )
            )

    # Highest-confidence pairs first.
    candidate_pairs.sort(
        key=lambda pair: pair[0],
        reverse=True,
    )

    matched_ai = {}

    used_semgrep_indexes = set()

    for (
        _score,
        ai_index,
        semgrep_index,
    ) in candidate_pairs:

        if ai_index in matched_ai:
            continue

        if (
            semgrep_index
            in used_semgrep_indexes
        ):
            continue

        matched_ai[
            ai_index
        ] = semgrep_index

        used_semgrep_indexes.add(
            semgrep_index
        )

    correlated = []

    # ------------------------------------------------------
    # AI findings
    # ------------------------------------------------------

    for (
        ai_index,
        ai_finding,
    ) in enumerate(
        ai_findings
    ):

        if ai_index in matched_ai:

            semgrep_finding = (
                semgrep_findings[
                    matched_ai[
                        ai_index
                    ]
                ]
            )

            correlated.append(
                merge_findings(
                    ai_finding,
                    semgrep_finding,
                )
            )

        else:

            correlated.append(
                ai_finding
            )

    # ------------------------------------------------------
    # Unmatched Semgrep findings
    # ------------------------------------------------------

    for (
        semgrep_index,
        semgrep_finding,
    ) in enumerate(
        semgrep_findings
    ):

        if (
            semgrep_index
            not in used_semgrep_indexes
        ):

            correlated.append(
                semgrep_finding
            )

    return correlated


# ==========================================================
# Public entry point
# ==========================================================

def correlate_findings(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding],
) -> list[Finding]:
    """
    Three-stage correlation pipeline.

    Stage 1:
        Remove duplicate AI findings.

    Stage 2:
        Remove duplicate Semgrep findings.

    Stage 3:
        Correlate AI findings with Semgrep findings.

    Findings that cannot be confidently correlated remain
    independent rather than being incorrectly merged.
    """

    deduplicated_ai = (
        _deduplicate_ai_findings(
            ai_findings
        )
    )

    deduplicated_semgrep = (
        _deduplicate_semgrep_findings(
            semgrep_findings
        )
    )

    return _correlate_ai_with_semgrep(
        ai_findings=deduplicated_ai,
        semgrep_findings=deduplicated_semgrep,
    )