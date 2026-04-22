"""Tests for modules/groq_usage.py — Groq/OpenAI-compatible usage tracker.

The existing cost_tracker was wired into Anthropic SDK responses only,
which meant Groq traffic — the bulk of pipeline LLM activity — went
entirely unmeasured. This tracker reads OpenAI-style ``usage.*_tokens``
from the response JSON and aggregates per-key and per-caller.
"""
import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

import modules.groq_usage as gu


@pytest.fixture(autouse=True)
def _isolated_usage_file(tmp_path, monkeypatch):
    """Redirect USAGE_FILE to a tmp path so tests never touch real state."""
    monkeypatch.setattr(gu, "USAGE_FILE", tmp_path / "groq_usage.json")
    yield


class TestMaskKey:
    def test_returns_prefix_with_ellipsis(self):
        assert gu._mask_key("gsk_ABCDEFGHIJKLMN") == "gsk_ABCD…"

    def test_handles_none(self):
        assert gu._mask_key(None) == "unknown"

    def test_handles_empty(self):
        assert gu._mask_key("") == "unknown"


class TestRecordUsage:
    def _resp(self, prompt=100, completion=50):
        return {
            "id": "chatcmpl-xyz",
            "usage": {
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "total_tokens": prompt + completion,
            },
            "choices": [{"message": {"content": "ok"}}],
        }

    def test_records_first_call(self):
        added = gu.record_usage("gsk_abc12345", self._resp(100, 50), caller="briefing")
        assert added == {"calls": 1, "prompt_tokens": 100, "completion_tokens": 50}
        today = gu.get_today_usage()
        assert today["total_calls"] == 1
        assert today["total_prompt_tokens"] == 100
        assert today["total_completion_tokens"] == 50
        assert today["keys"]["gsk_abc1…"]["calls"] == 1
        assert today["by_caller"]["briefing"]["calls"] == 1

    def test_accumulates_across_calls(self):
        gu.record_usage("gsk_abc12345", self._resp(100, 50), caller="briefing")
        gu.record_usage("gsk_abc12345", self._resp(200, 80), caller="briefing")
        today = gu.get_today_usage()
        assert today["total_calls"] == 2
        assert today["total_prompt_tokens"] == 300
        assert today["total_completion_tokens"] == 130
        assert today["by_caller"]["briefing"]["tokens"] == 430

    def test_separates_per_key(self):
        gu.record_usage("gsk_keyA0000", self._resp(100, 20))
        gu.record_usage("gsk_keyB0000", self._resp(300, 40))
        today = gu.get_today_usage()
        assert today["keys"]["gsk_keyA…"]["prompt_tokens"] == 100
        assert today["keys"]["gsk_keyB…"]["prompt_tokens"] == 300

    def test_separates_per_caller(self):
        gu.record_usage("gsk_k", self._resp(100, 20), caller="classify")
        gu.record_usage("gsk_k", self._resp(500, 100), caller="briefing")
        today = gu.get_today_usage()
        assert today["by_caller"]["classify"]["calls"] == 1
        assert today["by_caller"]["briefing"]["calls"] == 1
        assert today["by_caller"]["classify"]["tokens"] == 120
        assert today["by_caller"]["briefing"]["tokens"] == 600

    def test_no_caller_still_records_totals(self):
        """caller is optional — totals + per-key still recorded."""
        gu.record_usage("gsk_k", self._resp(100, 20))
        today = gu.get_today_usage()
        assert today["total_calls"] == 1
        assert today["by_caller"] == {}

    def test_missing_usage_skipped(self):
        assert gu.record_usage("gsk_k", {"choices": []}) is None
        assert gu.get_today_usage()["total_calls"] == 0

    def test_none_response_skipped(self):
        assert gu.record_usage("gsk_k", None) is None
        assert gu.get_today_usage()["total_calls"] == 0

    def test_zero_tokens_skipped(self):
        """Edge case: provider returns a usage object with zero tokens.
        Don't count the call — it was probably an error or empty reply."""
        resp = {"usage": {"prompt_tokens": 0, "completion_tokens": 0}}
        assert gu.record_usage("gsk_k", resp) is None

    def test_unknown_key_recorded(self):
        gu.record_usage(None, self._resp(10, 5))
        today = gu.get_today_usage()
        assert "unknown" in today["keys"]


class TestRetention:
    def test_keeps_last_90_days(self, monkeypatch):
        monkeypatch.setattr(gu, "_MAX_DAYS_RETAINED", 3)
        # Seed 5 days by patching _today_key each round.
        for i, day in enumerate(["2026-01-01", "2026-01-02", "2026-01-03", "2026-01-04", "2026-01-05"]):
            with patch.object(gu, "_today_key", return_value=day):
                gu.record_usage("gsk_k", {"usage": {"prompt_tokens": 10, "completion_tokens": 5}})
        data = gu._load()
        days = sorted(data["daily"].keys())
        assert len(days) == 3
        assert days == ["2026-01-03", "2026-01-04", "2026-01-05"]


class TestGetUsageSummary:
    def test_empty_state_returns_empty_shape(self):
        summary = gu.get_usage_summary()
        assert summary["today"]["total_calls"] == 0
        assert summary["last_7d"] == []
        assert "generated_at" in summary

    def test_summary_includes_today_and_history(self):
        gu.record_usage("gsk_k", {"usage": {"prompt_tokens": 100, "completion_tokens": 50}})
        summary = gu.get_usage_summary()
        assert summary["today"]["total_calls"] == 1
        # last_7d must include today's entry.
        assert any(d["total_calls"] == 1 for d in summary["last_7d"])


class TestResilience:
    def test_corrupt_file_returns_empty(self, tmp_path, monkeypatch):
        path = tmp_path / "broken.json"
        path.write_text("not json {{{")
        monkeypatch.setattr(gu, "USAGE_FILE", path)
        assert gu._load() == {"daily": {}}

    def test_write_failure_swallowed(self, tmp_path, monkeypatch):
        """Persist failures must not propagate — tracking is observability,
        not correctness."""
        monkeypatch.setattr(gu, "USAGE_FILE", tmp_path / "locked.json")
        with patch("pathlib.Path.write_text", side_effect=OSError("readonly")):
            # Should not raise.
            gu.record_usage("gsk_k", {"usage": {"prompt_tokens": 1, "completion_tokens": 1}})
