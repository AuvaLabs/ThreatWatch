"""Tests for modules/ttp_extractor.py — deep TTP extraction LLM caller."""

import json
from unittest.mock import patch

import pytest

import modules.ttp_extractor as tx


def _article(hash_val="h1", body_len=1000, is_cyber=True, title="Ransomware hits Acme Corp"):
    body = "Paragraph of body text. " * (body_len // 24 + 1)
    return {
        "hash": hash_val,
        "title": title,
        "summary": "Short summary here.",
        "full_content": body,
        "is_cyber_attack": is_cyber,
        "cve_ids": [],
    }


class TestEligible:
    def test_short_body_rejected(self):
        a = _article(body_len=100)
        assert tx._eligible(a) is False

    def test_non_incident_rejected(self):
        a = _article(is_cyber=False)
        assert tx._eligible(a) is False

    def test_qualifying_article_accepted(self):
        assert tx._eligible(_article()) is True


class TestParseResponse:
    def test_valid_response_returned(self):
        raw = json.dumps({
            "summary": "Ransomware deployment via phishing link.",
            "ttps": ["Phishing email with malicious link"],
            "persistence": ["Scheduled task creation"],
            "confidence": "high",
        })
        parsed = tx._parse_response(raw)
        assert parsed["summary"].startswith("Ransomware")
        assert parsed["ttps"] == ["Phishing email with malicious link"]
        assert parsed["confidence"] == "high"

    def test_invalid_json_returns_none(self):
        assert tx._parse_response("not json") is None

    def test_list_items_truncated_and_capped(self):
        raw = json.dumps({
            "ttps": ["t" * 300] + [f"ttp {i}" for i in range(10)],
        })
        parsed = tx._parse_response(raw)
        assert len(parsed["ttps"]) == 6
        assert len(parsed["ttps"][0]) <= 160

    def test_bad_confidence_dropped(self):
        raw = json.dumps({"summary": "x", "confidence": "super high"})
        parsed = tx._parse_response(raw)
        assert "confidence" not in parsed

    def test_empty_response_returns_none(self):
        assert tx._parse_response("") is None


class TestEnrich:
    def test_calls_llm_with_correct_caller(self):
        articles = [_article()]
        llm_out = json.dumps({"summary": "test"})
        with patch.object(tx, "get_cached_result", return_value=None), \
             patch.object(tx, "call_llm", return_value=llm_out, create=True) as _, \
             patch("modules.llm_client.call_llm", return_value=llm_out) as llm, \
             patch.object(tx, "cache_result"):
            tx.enrich_articles_with_ttps(articles)
        call_kwargs = llm.call_args.kwargs
        assert call_kwargs["caller"] == "ttp_extract"
        assert articles[0]["tactical_analysis"]["summary"] == "test"

    def test_budget_cap_respected(self):
        articles = [_article(hash_val=f"h{i}") for i in range(5)]
        llm_out = json.dumps({"summary": "ok"})
        with patch.object(tx, "get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value=llm_out) as llm, \
             patch.object(tx, "cache_result"):
            tx.enrich_articles_with_ttps(articles, max_calls=2)
        assert llm.call_count == 2

    def test_cache_hit_reuses_without_llm(self):
        articles = [_article()]
        cached = {"summary": "from cache"}
        with patch.object(tx, "get_cached_result", return_value=cached), \
             patch("modules.llm_client.call_llm") as llm:
            tx.enrich_articles_with_ttps(articles)
        llm.assert_not_called()
        assert articles[0]["tactical_analysis"]["summary"] == "from cache"

    def test_ineligible_articles_skipped(self):
        articles = [_article(body_len=100), _article(is_cyber=False)]
        with patch("modules.llm_client.call_llm") as llm:
            tx.enrich_articles_with_ttps(articles)
        llm.assert_not_called()
