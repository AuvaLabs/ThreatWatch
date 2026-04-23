"""Tests for modules/cve_narrative.py — LLM exploitation narratives for CVEs."""

from unittest.mock import patch

import pytest

import modules.cve_narrative as cn


def _cve(
    cve_id="CVE-2026-00001",
    cvss=9.8,
    severity="CRITICAL",
    vector="AV:N/AC:L/PR:N/UI:N",
    epss_pctl=0.9,
    desc="A buffer overflow in WidgetCo allows remote code execution.",
):
    return {
        "cve_id": cve_id,
        "cvss_score": cvss,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cwe_ids": ["CWE-787"],
        "affected_products": ["WidgetCo AppServer"],
        "summary": desc,
        "epss_percentile": epss_pctl,
    }


class TestShouldNarrate:
    def test_high_cvss_qualifies(self):
        assert cn.should_narrate(_cve(cvss=8.5, epss_pctl=0.1)) is True

    def test_high_epss_qualifies(self):
        assert cn.should_narrate(_cve(cvss=6.0, epss_pctl=0.9)) is True

    def test_both_low_does_not_qualify(self):
        assert cn.should_narrate(_cve(cvss=6.0, epss_pctl=0.5)) is False

    def test_missing_cve_id_rejected(self):
        article = _cve(cvss=9.0)
        del article["cve_id"]
        assert cn.should_narrate(article) is False


class TestGenerateCveNarrative:
    def test_returns_narrative_on_success(self):
        article = _cve()
        with patch.object(cn, "get_cached_result", return_value=None), \
             patch.object(cn, "call_llm", return_value="Attacker gains RCE. Affects ...  Patch urgently.") as llm, \
             patch.object(cn, "cache_result") as cache:
            result = cn.generate_cve_narrative(article)
        assert result.startswith("Attacker gains RCE")
        call_kwargs = llm.call_args.kwargs
        assert call_kwargs["caller"] == "cve_narrative"
        cache.assert_called_once()

    def test_cache_hit_skips_llm(self):
        with patch.object(cn, "get_cached_result", return_value="CACHED narrative."), \
             patch.object(cn, "call_llm") as llm:
            result = cn.generate_cve_narrative(_cve())
        assert result == "CACHED narrative."
        llm.assert_not_called()

    def test_llm_failure_returns_none(self):
        with patch.object(cn, "get_cached_result", return_value=None), \
             patch.object(cn, "call_llm", side_effect=RuntimeError("boom")):
            assert cn.generate_cve_narrative(_cve()) is None

    def test_empty_response_returns_none(self):
        with patch.object(cn, "get_cached_result", return_value=None), \
             patch.object(cn, "call_llm", return_value="   "), \
             patch.object(cn, "cache_result") as cache:
            assert cn.generate_cve_narrative(_cve()) is None
        cache.assert_not_called()


class TestEnrichArticles:
    def test_budget_cap_limits_llm_calls(self):
        articles = [_cve(cve_id=f"CVE-2026-{i:05d}") for i in range(5)]
        with patch.object(cn, "get_cached_result", return_value=None), \
             patch.object(cn, "call_llm", return_value="narrative here") as llm, \
             patch.object(cn, "cache_result"):
            cn.enrich_articles_with_cve_narratives(articles, max_calls=2)
        assert llm.call_count == 2
        assert sum(1 for a in articles if a.get("cve_narrative")) == 2

    def test_cached_articles_not_counted_against_budget(self):
        articles = [_cve(cve_id=f"CVE-2026-{i:05d}") for i in range(3)]
        # Cache key for the first two CVEs returns a hit; third is a miss.
        cached_keys = {cn._cache_key("CVE-2026-00000"), cn._cache_key("CVE-2026-00001")}

        def side_effect(key):
            return "cached text" if key in cached_keys else None

        with patch.object(cn, "get_cached_result", side_effect=side_effect), \
             patch.object(cn, "call_llm", return_value="fresh narrative") as llm, \
             patch.object(cn, "cache_result"):
            cn.enrich_articles_with_cve_narratives(articles, max_calls=1)
        assert llm.call_count == 1
        # All three should have a narrative — two from cache, one from LLM
        assert sum(1 for a in articles if a.get("cve_narrative")) == 3

    def test_skips_articles_below_thresholds(self):
        articles = [_cve(cvss=5.0, epss_pctl=0.1)]
        with patch.object(cn, "call_llm") as llm:
            cn.enrich_articles_with_cve_narratives(articles)
        llm.assert_not_called()
        assert "cve_narrative" not in articles[0]
