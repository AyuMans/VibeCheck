"""
Correlation engine
===================

Purpose
-------
AI review and Semgrep look at the same code from two very different angles,
and Semgrep itself can fire more than one rule on the same underlying issue.
Findings need to be merged when they describe the *same* issue and kept
separate when they don't - without a hand-written table of vulnerability
names ("if 'sql' in text...").

Two stages
----------
STAGE 1 - Semgrep-to-Semgrep deduplication.
    Semgrep can raise multiple rules against the same statement (e.g. a
    generic "formatted SQL query" rule and a "sqlalchemy raw execute" rule
    both firing on `cursor.execute(query)`). Before AI findings are ever
    considered, Semgrep's own findings are collapsed so duplicates don't
    inflate the final report or confuse Stage 2.

STAGE 2 - AI-to-Semgrep correlation.
    Each AI finding is scored against every (deduplicated) Semgrep finding
    using several independent, generic signals, and the globally strongest
    set of pairings is chosen.

Signals used throughout (nothing here knows what "SQL injection" means):

  1. Location overlap     - do the reported line ranges overlap/nearly overlap?
  2. Evidence similarity   - substring containment + fuzzy text/token overlap
                             of the flagged code itself (this is where
                             "evidence token overlap" and "code identifier
                             overlap" both live: normalized evidence is
                             tokenized into identifier-like words and
                             compared as sets, blended with a sequence-ratio
                             comparison of the raw text).
  3. Title/category text similarity - generic fuzzy string comparison.
  4. Impact/remediation similarity  - a light-weight supporting signal used
                             when it's available; useful as a tie-breaker,
                             never load-bearing on its own.

Every score is combined into one weighted "correlation score" per pair.
Pairs are matched greedily from highest score to lowest (an approximation
of the optimal global assignment - simple to reason about, and correct in
practice for the small numbers of findings a single file produces). A
match is only made if the combined score clears a threshold AND has
genuine support from evidence/text/impact (never location alone) - this is
what stops "division by zero" on line 20 from merging with an unrelated
"security issue" also on line 20.

This module contains NO list of vulnerability names, rule IDs, or security
keywords anywhere. The only domain knowledge is a generic severity ordering
(a formatting concern, not a taxonomy) and a couple of phrases that
identify Semgrep's OWN generic fallback text (from semgrep_service.py),
used purely to recognize "this text is a boilerplate placeholder, not real
information" - not to identify vulnerability types.
"""

import difflib
import re

from backend.models import Finding


# ==========================================================
# Tunable configuration
#
# These are the only "knobs" of the correlation engine.
# Nothing below this block needs to change when Semgrep adds
# a new rule or category - that's the whole point.
# ==========================================================

# --- Stage 2: AI <-> Semgrep correlation weights -----------
LOCATION_WEIGHT = 0.40
EVIDENCE_WEIGHT = 0.35
TEXT_WEIGHT = 0.15
IMPACT_WEIGHT = 0.10

MERGE_THRESHOLD = 0.40
MIN_EVIDENCE_SUPPORT = 0.12
MIN_TEXT_SUPPORT = 0.25
MIN_IMPACT_SUPPORT = 0.35

# --- Stage 1: Semgrep <-> Semgrep dedup weights -------------
# Two rules firing on the *same tool's* output for the same code should
# look much more alike than an AI description does, so this stage uses
# a stricter bar than Stage 2.
DEDUP_LOCATION_WEIGHT = 0.50
DEDUP_EVIDENCE_WEIGHT = 0.40
DEDUP_TEXT_WEIGHT = 0.10

DEDUP_THRESHOLD = 0.55
DEDUP_MIN_EVIDENCE_SUPPORT = 0.30
DEDUP_MIN_TEXT_SUPPORT = 0.40

# Line numbers within this many lines of each other (but not strictly
# overlapping) still count as a partial location match.
LINE_TOLERANCE = 3

# Generic severity ordering - a comparison/formatting concern, not a
# vulnerability taxonomy.
SEVERITY_ORDER = {
    "WARNING": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "ERROR": 3,
    "CRITICAL": 4,
}

# A small, generic (non security-specific) stopword list, used only to
# keep token-overlap comparisons from being dominated by very common
# English words.
GENERIC_STOPWORDS = {
    "the", "this", "that", "is", "are", "was", "were", "a", "an",
    "of", "to", "and", "or", "in", "on", "with", "for", "from",
    "by", "as", "at", "be", "it", "its",
}

# Recognizes semgrep_service.py's own generic fallback text so it isn't
# mistaken for real, tool-specific information when merging. This is
# about the SOURCE of the text (a boilerplate template vs. real
# analysis), not about vulnerability types.
GENERIC_FALLBACK_PREFIXES = (
    "detected by semgrep rule",
    "review the flagged code",
)


# ==========================================================
# Severity helper
# ==========================================================

def get_higher_severity(severity_one: str, severity_two: str) -> str:

    one = SEVERITY_ORDER.get(severity_one.upper(), 0)
    two = SEVERITY_ORDER.get(severity_two.upper(), 0)

    return severity_one.upper() if one >= two else severity_two.upper()


# ==========================================================
# Generic text normalization / tokenization
#
# These helpers know nothing about security. They are exactly
# the same helpers you'd use to compare any two pieces of text.
# ==========================================================

def normalize_text(text: str) -> str:
    """
    Lowercase, collapse punctuation to spaces, collapse whitespace.
    Used for evidence code snippets, title/category text, and
    impact/remediation text alike, so one normalizer is enough.
    """

    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9_]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text


def tokenize(normalized_text: str) -> set[str]:
    """
    Turn normalized text into a set of meaningful tokens - this is
    where "evidence token overlap" / "code identifier overlap" actually
    happens: normalized code like "cursor.execute(query)" tokenizes to
    {"cursor", "execute", "query"}, so it can be compared as a set
    against any other snippet's tokens, regardless of vocabulary.
    """

    return {
        token
        for token in normalized_text.split()
        if len(token) > 2 and token not in GENERIC_STOPWORDS
    }


def fuzzy_similarity(text_one: str, text_two: str) -> float:
    """
    General-purpose string similarity blending:
      - difflib's sequence ratio (near-identical strings, reordered
        fragments, partial overlaps)
      - token Jaccard overlap (same words/identifiers, different
        order or wrapping)

    Neither component knows anything about vulnerability types.
    """

    if not text_one or not text_two:
        return 0.0

    ratio = difflib.SequenceMatcher(None, text_one, text_two).ratio()

    tokens_one = tokenize(text_one)
    tokens_two = tokenize(text_two)

    if tokens_one and tokens_two:
        jaccard = len(tokens_one & tokens_two) / len(tokens_one | tokens_two)
    else:
        jaccard = 0.0

    return (0.6 * ratio) + (0.4 * jaccard)


def is_generic_fallback_text(text: str) -> bool:
    """
    True if `text` is one of semgrep_service.py's own templated
    placeholders rather than real, specific information.
    """

    normalized = (text or "").strip().lower()

    return any(
        normalized.startswith(prefix)
        for prefix in GENERIC_FALLBACK_PREFIXES
    )


def pick_more_informative_text(text_one: str, text_two: str) -> str:
    """
    Generic heuristic for choosing between two candidate strings for
    the same field (impact, remediation, title): prefer whichever is
    NOT a known boilerplate placeholder, then prefer the longer one.
    This is about recognizing "template text" vs. "real content" -
    not about vulnerability semantics.
    """

    text_one = text_one or ""
    text_two = text_two or ""

    one_is_generic = is_generic_fallback_text(text_one)
    two_is_generic = is_generic_fallback_text(text_two)

    if one_is_generic and not two_is_generic and text_two:
        return text_two

    if two_is_generic and not one_is_generic and text_one:
        return text_one

    if len(text_two) > len(text_one) and len(text_two) > 30:
        return text_two

    return text_one or text_two


# ==========================================================
# Location signal
# ==========================================================

def get_line_range(finding: Finding) -> tuple[int, int] | None:

    if finding.line_start is None:
        return None

    start = finding.line_start
    end = finding.line_end if finding.line_end is not None else start

    return (start, end)


def location_score(finding_one: Finding, finding_two: Finding) -> float | None:
    """
    Returns:
      1.0      - line ranges overlap
      0.0..1.0 - close but not overlapping (decays within LINE_TOLERANCE)
      0.0      - too far apart
      None     - location data isn't available on at least one side;
                 callers should redistribute this signal's weight
                 rather than penalize the pair for missing data.
    """

    range_one = get_line_range(finding_one)
    range_two = get_line_range(finding_two)

    if range_one is None or range_two is None:
        return None

    start_one, end_one = range_one
    start_two, end_two = range_two

    if start_one <= end_two and start_two <= end_one:
        return 1.0

    gap = min(abs(start_one - end_two), abs(start_two - end_one))

    if gap <= LINE_TOLERANCE:
        # Gentle decay: adjacent lines are still a strong signal
        # (e.g. a variable built on one line, used on the next).
        return max(0.0, 1.0 - (0.5 * gap / LINE_TOLERANCE))

    return 0.0


# ==========================================================
# Evidence signal
# ==========================================================

def evidence_similarity(finding_one: Finding, finding_two: Finding) -> float:
    """
    Compares the actual flagged code text. Handles the common case
    where one tool reports a full statement and the other reports a
    sub-expression of that same statement, via substring containment,
    then falls back to generic fuzzy/token similarity.
    """

    evidence_one = normalize_text(finding_one.evidence)
    evidence_two = normalize_text(finding_two.evidence)

    if not evidence_one or not evidence_two:
        return 0.0

    if evidence_one in evidence_two or evidence_two in evidence_one:
        return 1.0

    return fuzzy_similarity(evidence_one, evidence_two)


# ==========================================================
# Title/category signal
# ==========================================================

def text_similarity(finding_one: Finding, finding_two: Finding) -> float:
    """
    Compares title + category text using generic fuzzy matching only -
    no hardcoded vocabulary. This is what lets "SQL Injection" (AI)
    line up with "Formatted Sql Query" (Semgrep) without a table saying
    those two strings mean the same thing.
    """

    text_one = normalize_text(f"{finding_one.title} {finding_one.category}")
    text_two = normalize_text(f"{finding_two.title} {finding_two.category}")

    return fuzzy_similarity(text_one, text_two)


# ==========================================================
# Impact/remediation signal (supporting only)
# ==========================================================

def impact_similarity(finding_one: Finding, finding_two: Finding) -> float:
    """
    Compares impact + remediation text. Deliberately excludes known
    generic Semgrep boilerplate before comparing, so two findings don't
    look "similar" just because they both used the same fallback
    template - that would be a false, uninformative signal.
    """

    impact_one = finding_one.impact or ""
    impact_two = finding_two.impact or ""
    remediation_one = finding_one.remediation or ""
    remediation_two = finding_two.remediation or ""

    if is_generic_fallback_text(impact_one):
        impact_one = ""
    if is_generic_fallback_text(impact_two):
        impact_two = ""
    if is_generic_fallback_text(remediation_one):
        remediation_one = ""
    if is_generic_fallback_text(remediation_two):
        remediation_two = ""

    text_one = normalize_text(f"{impact_one} {remediation_one}")
    text_two = normalize_text(f"{impact_two} {remediation_two}")

    if not text_one or not text_two:
        return 0.0

    return fuzzy_similarity(text_one, text_two)


# ==========================================================
# Stage 1: Semgrep <-> Semgrep deduplication
# ==========================================================

def _semgrep_pair_score(
    finding_one: Finding,
    finding_two: Finding,
) -> tuple[float, float, float]:
    """
    Returns (combined_score, evidence_score, text_score) for two
    Semgrep findings, using the stricter Stage-1 weighting.
    """

    loc = location_score(finding_one, finding_two)
    evidence = evidence_similarity(finding_one, finding_two)
    text = text_similarity(finding_one, finding_two)

    if loc is None:
        remaining = DEDUP_EVIDENCE_WEIGHT + DEDUP_TEXT_WEIGHT

        combined = (
            (evidence * (DEDUP_EVIDENCE_WEIGHT / remaining))
            + (text * (DEDUP_TEXT_WEIGHT / remaining))
        )
    else:
        combined = (
            (loc * DEDUP_LOCATION_WEIGHT)
            + (evidence * DEDUP_EVIDENCE_WEIGHT)
            + (text * DEDUP_TEXT_WEIGHT)
        )

    return combined, evidence, text


def _combine_titles(title_one: str, title_two: str) -> str:
    """
    Generic strategy for keeping useful information from both rule
    names when two Semgrep findings turn out to be duplicates:
      - if one title is essentially contained in / the same as the
        other (by generic string similarity), keep the more
        descriptive (longer) one
      - otherwise the two rules genuinely say different things about
        the same code, so keep both rather than silently dropping one
    """

    if not title_two:
        return title_one
    if not title_one:
        return title_two

    norm_one = normalize_text(title_one)
    norm_two = normalize_text(title_two)

    if norm_one == norm_two or norm_two in norm_one:
        return title_one
    if norm_one in norm_two:
        return title_two

    if fuzzy_similarity(norm_one, norm_two) >= 0.5:
        return title_one if len(title_one) >= len(title_two) else title_two

    return f"{title_one} / {title_two}"


def _merge_semgrep_duplicates(finding_one: Finding, finding_two: Finding) -> Finding:
    """
    Merges two Semgrep findings believed to describe the same
    underlying issue. Symmetric: neither finding is assumed to be
    "primary" just because of list order.
    """

    sources = list(dict.fromkeys(finding_one.source + finding_two.source))

    range_one = get_line_range(finding_one)
    range_two = get_line_range(finding_two)

    if range_one and range_two:
        # Union of both ranges: if two rules flagged slightly
        # different sub-ranges of the same statement, cover all of it.
        line_start = min(range_one[0], range_two[0])
        line_end = max(range_one[1], range_two[1])
    else:
        line_start = finding_one.line_start or finding_two.line_start
        line_end = finding_one.line_end or finding_two.line_end

    evidence = pick_more_informative_text(finding_one.evidence, finding_two.evidence)
    title = _combine_titles(finding_one.title, finding_two.title)
    category = finding_one.category or finding_two.category or "security"
    severity = get_higher_severity(finding_one.severity, finding_two.severity)
    impact = pick_more_informative_text(finding_one.impact, finding_two.impact)
    remediation = pick_more_informative_text(
        finding_one.remediation, finding_two.remediation
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


def _deduplicate_semgrep_findings(findings: list[Finding]) -> list[Finding]:
    """
    Collapses Semgrep findings that likely describe the same
    underlying issue (e.g. two different rules both firing on the
    same `cursor.execute(query)` call).

    Runs as simple agglomerative merging: repeatedly find the highest-
    scoring remaining pair; if it clears DEDUP_THRESHOLD with genuine
    evidence/text support, merge it into one finding and try again.
    Stops when no remaining pair qualifies. This naturally handles
    chains of 3+ duplicate rules on the same statement while still
    requiring every individual merge decision to clear the bar.
    """

    working = list(findings)

    while len(working) > 1:

        best_score = -1.0
        best_pair = None

        for i in range(len(working)):
            for j in range(i + 1, len(working)):

                combined, evidence, text = _semgrep_pair_score(
                    working[i], working[j]
                )

                if combined < DEDUP_THRESHOLD:
                    continue

                has_real_support = (
                    evidence >= DEDUP_MIN_EVIDENCE_SUPPORT
                    or text >= DEDUP_MIN_TEXT_SUPPORT
                )

                if not has_real_support:
                    continue

                if combined > best_score:
                    best_score = combined
                    best_pair = (i, j)

        if best_pair is None:
            break

        i, j = best_pair
        merged = _merge_semgrep_duplicates(working[i], working[j])

        working = [
            finding
            for index, finding in enumerate(working)
            if index not in (i, j)
        ]
        working.append(merged)

    return working


# ==========================================================
# Stage 2: AI <-> Semgrep correlation
# ==========================================================

def correlation_score(
    ai_finding: Finding,
    semgrep_finding: Finding,
) -> tuple[float, float, float, float]:
    """
    Returns (combined_score, evidence_score, text_score, impact_score).
    The individual scores are returned so the caller can apply the
    "minimum real support" safety check without recomputing them.
    """

    loc = location_score(ai_finding, semgrep_finding)
    evidence = evidence_similarity(ai_finding, semgrep_finding)
    text = text_similarity(ai_finding, semgrep_finding)
    impact = impact_similarity(ai_finding, semgrep_finding)

    if loc is None:
        # No usable location data on at least one side - redistribute
        # that weight across the remaining signals instead of
        # penalizing the pair for missing information.
        remaining = EVIDENCE_WEIGHT + TEXT_WEIGHT + IMPACT_WEIGHT

        combined = (
            (evidence * (EVIDENCE_WEIGHT / remaining))
            + (text * (TEXT_WEIGHT / remaining))
            + (impact * (IMPACT_WEIGHT / remaining))
        )
    else:
        combined = (
            (loc * LOCATION_WEIGHT)
            + (evidence * EVIDENCE_WEIGHT)
            + (text * TEXT_WEIGHT)
            + (impact * IMPACT_WEIGHT)
        )

    return combined, evidence, text, impact


def merge_findings(ai_finding: Finding, semgrep_finding: Finding) -> Finding:
    """
    Merges one AI finding with one (already deduplicated) Semgrep
    finding believed to describe the same issue.
    """

    sources = list(dict.fromkeys(ai_finding.source + semgrep_finding.source))

    # Semgrep's location is deterministic (derived from parsing), so
    # prefer it; fall back to the AI's if Semgrep didn't have one.
    line_start = (
        semgrep_finding.line_start
        if semgrep_finding.line_start is not None
        else ai_finding.line_start
    )
    line_end = (
        semgrep_finding.line_end
        if semgrep_finding.line_end is not None
        else ai_finding.line_end
    )

    # Same reasoning for evidence text.
    evidence = semgrep_finding.evidence or ai_finding.evidence

    # The AI generally writes a more contextual, human-readable title;
    # Semgrep's is derived mechanically from its rule ID.
    title = ai_finding.title or semgrep_finding.title

    category = ai_finding.category or semgrep_finding.category or "security"
    severity = get_higher_severity(ai_finding.severity, semgrep_finding.severity)

    # Never let Semgrep's generic boilerplate override a real AI
    # explanation, and vice versa if the AI ever omits one.
    impact = pick_more_informative_text(ai_finding.impact, semgrep_finding.impact)
    remediation = pick_more_informative_text(
        ai_finding.remediation, semgrep_finding.remediation
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
    """
    Stage 2: matches AI findings against (already deduplicated)
    Semgrep findings using a global best-match strategy, then merges
    matched pairs. Unmatched findings on either side are preserved.
    """

    candidate_pairs = []

    for ai_index, ai_finding in enumerate(ai_findings):
        for semgrep_index, semgrep_finding in enumerate(semgrep_findings):

            combined, evidence, text, impact = correlation_score(
                ai_finding, semgrep_finding
            )

            if combined < MERGE_THRESHOLD:
                continue

            has_real_support = (
                evidence >= MIN_EVIDENCE_SUPPORT
                or text >= MIN_TEXT_SUPPORT
                or impact >= MIN_IMPACT_SUPPORT
            )

            if not has_real_support:
                continue

            candidate_pairs.append((combined, ai_index, semgrep_index))

    # Best matches first - a greedy approximation of the globally
    # optimal assignment. Simple to reason about, and correct in
    # practice for the small number of findings a single file produces.
    candidate_pairs.sort(key=lambda pair: pair[0], reverse=True)

    matched_ai: dict[int, int] = {}
    used_semgrep_indexes: set[int] = set()

    for _score, ai_index, semgrep_index in candidate_pairs:

        if ai_index in matched_ai or semgrep_index in used_semgrep_indexes:
            continue

        matched_ai[ai_index] = semgrep_index
        used_semgrep_indexes.add(semgrep_index)

    correlated = []

    for ai_index, ai_finding in enumerate(ai_findings):

        if ai_index in matched_ai:
            semgrep_finding = semgrep_findings[matched_ai[ai_index]]
            correlated.append(merge_findings(ai_finding, semgrep_finding))
        else:
            correlated.append(ai_finding)

    for semgrep_index, semgrep_finding in enumerate(semgrep_findings):
        if semgrep_index not in used_semgrep_indexes:
            correlated.append(semgrep_finding)

    return correlated


# ==========================================================
# Public entry point
# ==========================================================

def correlate_findings(
    ai_findings: list[Finding],
    semgrep_findings: list[Finding],
) -> list[Finding]:
    """
    Two-stage correlation:

      1. Deduplicate Semgrep's own findings (multiple rules firing on
         the same underlying issue collapse into one).
      2. Correlate AI findings against the deduplicated Semgrep
         findings using generic location/evidence/text/impact signals
         and a global best-match strategy.

    Nothing here is specific to any vulnerability type, so it requires
    no changes when Semgrep adds new rules. Anything left unmatched on
    either side is preserved untouched in the output.
    """

    deduplicated_semgrep_findings = _deduplicate_semgrep_findings(semgrep_findings)

    return _correlate_ai_with_semgrep(ai_findings, deduplicated_semgrep_findings)