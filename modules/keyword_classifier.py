"""Zero-cost keyword-based article classifier.

Replaces the AI engine for classification, using regex patterns to determine
if an article is cybersecurity-related and categorise it. No API calls; runs
entirely locally.

The large regex data tables (`_RULES`, `_NOISE_PATTERNS`, `_CYBER_KEYWORDS`,
`_CONTEXT_PRIORITY`, `_COMPOUND_OVERRIDES`) live in `modules.keyword_data` so
this file stays focused on classification logic.
"""

import re
import logging
import hashlib

from modules.ai_cache import get_cached_result, cache_result
from modules.config import MAX_CONTENT_CHARS
from modules.keyword_data import (
    _RULES,
    _NOISE_PATTERNS,
    _CYBER_KEYWORDS,
    _CONTEXT_PRIORITY,
    _COMPOUND_OVERRIDES,
)

logger = logging.getLogger(__name__)


def _resolve_compound_events(matches, matched_cats, title):
    """Override scoring when two categories co-occur and title disambiguates."""
    for rule in _COMPOUND_OVERRIDES:
        cat_a, cat_b = rule["if_both"]
        if cat_a in matched_cats and cat_b in matched_cats:
            if rule["title_re"].search(title):
                winner = rule["winner"]
                # Give the winner a massive score boost to ensure it wins
                return [
                    (cat, conf, score + 50) if cat == winner else (cat, conf, score)
                    for cat, conf, score in matches
                ]
    return matches


def classify_article(title, content=None, source_language="en"):
    """Classify an article using keyword patterns with multi-match scoring.

    All matching rules are collected. The winner is chosen by:
    1. Context-priority bonus (actor/campaign > technique)
    2. Base confidence from the rule

    Returns same dict structure as ai_engine.analyze_article for compatibility.
    """
    cache_key = _compute_hash(title + (content or ""))

    cached = get_cached_result(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    text = title + " " + (content or "")

    # Collect ALL matching rules (not just the first)
    # Title-match bonus: +10 if the rule matches the title directly (not just body)
    matches = []
    for rule in _RULES:
        if rule["re"].search(text):
            priority_bonus = _CONTEXT_PRIORITY.get(rule["category"], 0)
            title_bonus = 10 if rule["re"].search(title) else 0
            score = rule["confidence"] + priority_bonus + title_bonus
            matches.append((rule["category"], rule["confidence"], score))

    # Compound-event resolver: when two categories co-occur, the "outcome"
    # category wins over the "method" if the outcome appears in the title.
    matched_cats = {m[0] for m in matches}
    if matches:
        matches = _resolve_compound_events(matches, matched_cats, title)

    if matches:
        # Pick the highest-scoring match
        best = max(matches, key=lambda m: m[2])
        category = best[0]
        confidence = best[1]
        rule_matched = True
    else:
        category = "General Cyber Threat"
        confidence = 60
        rule_matched = False

    # Check if cybersecurity-related (broad keywords OR specific rule match)
    is_cyber = rule_matched or bool(_CYBER_KEYWORDS.search(text))

    if not is_cyber:
        result = {
            "is_cyber_attack": False,
            "category": "General Cyber Threat",
            "confidence": 0,
            "translated_title": title,
            "summary": "",
        }
        cache_result(cache_key, result)
        return result

    # Filter out noise — passes cyber check but is not threat intel
    for noise_re in _NOISE_PATTERNS:
        if noise_re.search(text):
            logger.debug("Noise filtered: %s", title[:80])
            result = {
                "is_cyber_attack": False,
                "category": "Noise",
                "confidence": 0,
                "translated_title": title,
                "summary": "",
            }
            cache_result(cache_key, result)
            return result

    # Use RSS summary as the article summary (free, no AI needed)
    summary = ""
    if content:
        # Take first 3 sentences from content as summary
        sentences = re.split(r'(?<=[.!?])\s+', content.strip())
        summary = " ".join(sentences[:3])
        if len(summary) > 500:
            summary = summary[:497] + "..."

    result = {
        "is_cyber_attack": True,
        "category": category,
        "confidence": confidence,
        "translated_title": title,
        "summary": summary,
    }

    cache_result(cache_key, result)
    return result


def _rules_version():
    """Hash of all rule/noise/compound patterns for cache invalidation."""
    parts = [r["re"].pattern + r["category"] for r in _RULES]
    parts.extend(p.pattern for p in _NOISE_PATTERNS)
    for c in _COMPOUND_OVERRIDES:
        parts.append(c["title_re"].pattern + c["winner"])
    return hashlib.sha256("".join(parts).encode()).hexdigest()[:12]


_RULES_VERSION = _rules_version()


def _compute_hash(text):
    return hashlib.sha256(
        (_RULES_VERSION + text[:MAX_CONTENT_CHARS]).encode()
    ).hexdigest()
