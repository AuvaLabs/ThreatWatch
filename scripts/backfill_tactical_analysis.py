#!/usr/bin/env python3
"""One-shot: run the deep TTP extractor over the full persisted corpus.

The normal pipeline only runs ``enrich_articles_with_ttps`` on the current
tick's newly-deduplicated batch. Articles ingested before the TTP extractor
shipped — or on ticks where the budget cap fired — never get revisited, so
qualifying articles (is_cyber_attack + body >= 500 chars) accumulate without
``tactical_analysis``.

This script iterates ``daily_latest.json``, runs the same extractor over
every qualifying article, writes in place via merge-by-hash, and mirrors
the updates into SQLite. Safe to re-run — extractor output is cached by
article hash, so repeat invocations are free.

Retry shape:
    Each article gets up to ``--retries`` independent attempts, separated
    by ``--retry-wait`` seconds. Between articles we always sleep
    ``--sleep`` seconds. Unlike the early version, there's no global
    backoff budget — a streak of TPM-induced failures can't poison the
    rest of the run.
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
from modules.llm_client import reset_circuit
from modules.ttp_extractor import _eligible, _extract_ttps

logging.basicConfig(level=logging.INFO, format="%(asctime)s [backfill_ttp] %(message)s")
logger = logging.getLogger(__name__)

DAILY_PATH = OUTPUT_DIR / "daily_latest.json"


def _load() -> list[dict]:
    with open(DAILY_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save_with_merge(by_hash: dict[str, dict]) -> int:
    fresh = _load()
    touched = 0
    for a in fresh:
        h = a.get("hash")
        if not h or h not in by_hash:
            continue
        if a.get("tactical_analysis"):
            continue
        a["tactical_analysis"] = by_hash[h]
        touched += 1
    with open(DAILY_PATH, "w", encoding="utf-8") as f:
        json.dump(fresh, f, ensure_ascii=False)
    return touched


def _sync_to_db(by_hash: dict[str, dict]) -> int:
    try:
        from modules.db import load_articles_from_db, upsert_articles
    except ImportError as exc:
        logger.warning("db module unavailable, skipping DB sync: %s", exc)
        return 0
    existing = load_articles_from_db()
    to_update: list[dict] = []
    for a in existing:
        h = a.get("hash")
        if not h or h not in by_hash:
            continue
        if a.get("tactical_analysis"):
            continue
        a["tactical_analysis"] = by_hash[h]
        to_update.append(a)
    if not to_update:
        return 0
    return upsert_articles(to_update)


def _try_extract(article: dict, idx: int, total: int, retries: int, retry_wait: float) -> dict | None:
    """Attempt extraction up to `retries` times with `retry_wait`s between attempts."""
    title = (article.get("title") or "")[:60]
    for attempt in range(1, retries + 1):
        reset_circuit()
        result = _extract_ttps(article)
        if result:
            if attempt > 1:
                logger.info("[%d/%d] ok (attempt %d): %s", idx, total, attempt, title)
            else:
                logger.info("[%d/%d] ok: %s", idx, total, title)
            return result
        if attempt < retries:
            logger.warning(
                "[%d/%d] attempt %d/%d failed, retry in %.0fs: %s",
                idx, total, attempt, retries, retry_wait, title,
            )
            time.sleep(retry_wait)
    logger.warning("[%d/%d] gave up after %d attempts: %s", idx, total, retries, title)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-calls", type=int, default=10,
        help="Cap on articles to attempt this run (default 10).",
    )
    parser.add_argument(
        "--sleep", type=float, default=8.0,
        help="Seconds between articles, regardless of success/fail (default 8).",
    )
    parser.add_argument(
        "--retries", type=int, default=3,
        help="Attempts per article before giving up (default 3).",
    )
    parser.add_argument(
        "--retry-wait", type=float, default=60.0,
        help="Seconds between retry attempts on the same article (default 60).",
    )
    args = parser.parse_args()

    if not DAILY_PATH.exists():
        logger.error("daily_latest.json not found at %s", DAILY_PATH)
        return 1

    articles = _load()
    pending = [
        a for a in articles
        if a.get("hash") and _eligible(a) and not a.get("tactical_analysis")
    ]
    logger.info("starting: %d/%d articles qualify for TTP backfill",
                len(pending), len(articles))
    if not pending:
        logger.info("nothing to do")
        return 0
    if args.max_calls and len(pending) > args.max_calls:
        logger.info("capping this run at %d articles (%d remain for later runs)",
                    args.max_calls, len(pending) - args.max_calls)
        pending = pending[:args.max_calls]

    by_hash: dict[str, dict] = {}
    failures = 0
    for idx, article in enumerate(pending, 1):
        result = _try_extract(article, idx, len(pending), args.retries, args.retry_wait)
        if result:
            by_hash[article["hash"]] = result
        else:
            failures += 1
        # Always pace between articles, regardless of outcome.
        if idx < len(pending):
            time.sleep(args.sleep)

    logger.info("collected %d extractions (%d failures); merging to disk",
                len(by_hash), failures)
    touched_json = _save_with_merge(by_hash)
    touched_db = _sync_to_db(by_hash)
    logger.info("done: %d JSON rows updated, %d DB rows updated",
                touched_json, touched_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
