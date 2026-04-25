#!/usr/bin/env python3
"""One-shot: run the CVE narrative enricher over the full persisted corpus.

The normal pipeline only runs ``enrich_articles_with_cve_narratives`` on the
current tick's newly-deduplicated batch (typically 2-7 articles). CVE records
that were ingested before the narrative module shipped — or on ticks where
the narrator budget was exhausted — never get revisited, so the backlog of
qualifying CVEs (CVSS>=8.0 or EPSS>=80th percentile) accumulates without a
narrative.

This script iterates ``daily_latest.json``, runs the same narrator over every
qualifying article, writes in place via merge-by-hash, and mirrors the
updates into SQLite so both stores stay in sync. Safe to re-run — narrator
output is cached by CVE ID, so repeat invocations are free.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.config import OUTPUT_DIR
from modules.cve_narrative import generate_cve_narrative, should_narrate
from modules.llm_client import reset_circuit

logging.basicConfig(level=logging.INFO, format="%(asctime)s [backfill_cve] %(message)s")
logger = logging.getLogger(__name__)

DAILY_PATH = OUTPUT_DIR / "daily_latest.json"

# Pacing tuned for Groq free tier. The real bottleneck isn't RPM — it's
# tokens-per-minute (~6K TPM per model on free tier). Narrative prompts are
# ~500-800 tokens each, so naive bursting saturates TPM within seconds and
# trips the circuit breaker. The pipeline's own regional/briefing calls
# (each 6K+ tokens) can consume the entire TPM window on a single tick, so
# we keep the backfill slow-and-steady and small-batched by default.
SLEEP_BETWEEN_CALLS = 8.0
BACKOFF_ON_RATE_LIMIT = 90.0
MAX_RATE_LIMIT_BACKOFFS = 3


def _load() -> list[dict]:
    with open(DAILY_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save_with_merge(narratives_by_hash: dict[str, str]) -> int:
    """Re-read daily_latest, apply per-hash narratives, write back.

    Merge-by-hash preserves any pipeline writes that happened mid-backfill.
    Returns the number of articles actually mutated on disk.
    """
    fresh = _load()
    touched = 0
    for a in fresh:
        h = a.get("hash")
        if not h or h not in narratives_by_hash:
            continue
        if (a.get("cve_narrative") or "").strip():
            continue
        a["cve_narrative"] = narratives_by_hash[h]
        touched += 1
    with open(DAILY_PATH, "w", encoding="utf-8") as f:
        json.dump(fresh, f, ensure_ascii=False)
    return touched


def _sync_to_db(narratives_by_hash: dict[str, str]) -> int:
    """Mirror the new narratives into SQLite so the DB-backed API sees them."""
    try:
        from modules.db import load_articles_from_db, upsert_articles
    except ImportError as exc:
        logger.warning("db module unavailable, skipping DB sync: %s", exc)
        return 0
    existing = load_articles_from_db()
    to_update: list[dict] = []
    for a in existing:
        h = a.get("hash")
        if not h or h not in narratives_by_hash:
            continue
        if (a.get("cve_narrative") or "").strip():
            continue
        a["cve_narrative"] = narratives_by_hash[h]
        to_update.append(a)
    if not to_update:
        return 0
    return upsert_articles(to_update)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-calls", type=int, default=5,
        help="Cap on narratives to generate this run (default 5). "
             "Tuned low because Groq free-tier TPM is the binding constraint.",
    )
    parser.add_argument(
        "--sleep", type=float, default=SLEEP_BETWEEN_CALLS,
        help=f"Seconds between calls (default {SLEEP_BETWEEN_CALLS}).",
    )
    args = parser.parse_args()

    if not DAILY_PATH.exists():
        logger.error("daily_latest.json not found at %s", DAILY_PATH)
        return 1

    articles = _load()
    pending = [
        a for a in articles
        if a.get("hash")
        and should_narrate(a)
        and not (a.get("cve_narrative") or "").strip()
    ]
    logger.info("starting: %d/%d articles qualify for narrative backfill",
                len(pending), len(articles))
    if not pending:
        logger.info("nothing to do")
        return 0
    if args.max_calls and len(pending) > args.max_calls:
        logger.info("capping this run at %d narratives (%d remain for later runs)",
                    args.max_calls, len(pending) - args.max_calls)
        pending = pending[:args.max_calls]

    narratives_by_hash: dict[str, str] = {}
    failures = 0
    backoffs_used = 0
    idx = 0
    remaining = list(pending)
    while remaining:
        article = remaining.pop(0)
        idx += 1
        cve_id = article.get("cve_id", "?")
        # Process-local breaker can be tripped by a burst 429. Reset before
        # each call so one transient rate-limit doesn't short-circuit the
        # entire backlog the way it did pre-patch.
        reset_circuit()
        narrative = generate_cve_narrative(article)
        if narrative:
            narratives_by_hash[article["hash"]] = narrative
            logger.info("[%d/%d] %s: ok", idx, len(pending), cve_id)
            time.sleep(args.sleep)
            continue
        # No narrative — either circuit tripped on 429s, LLM returned empty,
        # or some other transient failure. Back off once and requeue the
        # article so we don't lose it.
        if backoffs_used < MAX_RATE_LIMIT_BACKOFFS:
            backoffs_used += 1
            logger.warning(
                "[%d/%d] %s: narrator returned nothing — backing off %.0fs (%d/%d)",
                idx, len(pending), cve_id, BACKOFF_ON_RATE_LIMIT,
                backoffs_used, MAX_RATE_LIMIT_BACKOFFS,
            )
            remaining.insert(0, article)
            idx -= 1
            time.sleep(BACKOFF_ON_RATE_LIMIT)
            continue
        failures += 1
        logger.warning("[%d/%d] %s: narrator returned nothing — giving up",
                       idx, len(pending), cve_id)

    logger.info("collected %d narratives (%d failures); merging to disk",
                len(narratives_by_hash), failures)
    touched_json = _save_with_merge(narratives_by_hash)
    touched_db = _sync_to_db(narratives_by_hash)
    logger.info("done: %d JSON rows updated, %d DB rows updated",
                touched_json, touched_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
