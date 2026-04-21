import json
import pytest
from unittest.mock import patch, MagicMock

from modules.ai_engine import _extract_json, analyze_article, SAFE_DEFAULT


class TestExtractJson:
    def test_valid_json(self):
        result = _extract_json('{"is_cyber_attack": true, "category": "Malware"}')
        assert result["is_cyber_attack"] is True

    def test_json_with_surrounding_text(self):
        text = 'Here is the result: {"is_cyber_attack": false, "category": "None"} end'
        result = _extract_json(text)
        assert result is not None
        assert result["is_cyber_attack"] is False

    def test_invalid_json(self):
        assert _extract_json("not json at all") is None

    def test_empty_string(self):
        assert _extract_json("") is None


class TestAnalyzeArticle:
    @patch("modules.ai_engine.track_usage")
    @patch("modules.ai_engine.check_daily_budget", return_value=True)
    @patch("modules.ai_engine._get_client")
    def test_successful_analysis(self, mock_get_client, mock_budget, mock_track):
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = json.dumps({
            "is_cyber_attack": True,
            "category": "Ransomware",
            "confidence": 95,
            "translated_title": "Test Title",
            "summary": "A ransomware attack occurred.",
        })
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title", "Some content")
        assert result["is_cyber_attack"] is True
        assert result["category"] == "Ransomware"
        assert result["confidence"] == 95

    @patch("modules.ai_engine._get_client")
    def test_malformed_json_returns_safe_default(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "I cannot parse this as JSON properly {broken"
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title")
        assert result["is_cyber_attack"] is False
        assert result["translated_title"] == "Test Title"

    @patch("modules.ai_engine._get_client")
    def test_api_error_returns_safe_default(self, mock_get_client):
        import anthropic
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APIError(
            message="rate limited",
            request=MagicMock(),
            body=None,
        )
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title")
        assert result["is_cyber_attack"] is False
        assert result["translated_title"] == "Test Title"

    @patch("modules.ai_engine.get_cached_result")
    def test_cache_hit_skips_api(self, mock_cache):
        cached = {
            "is_cyber_attack": True,
            "category": "DDoS",
            "confidence": 88,
            "translated_title": "Cached Title",
            "summary": "Cached summary.",
        }
        mock_cache.return_value = cached

        result = analyze_article("Some Title", "Some content")
        assert result == cached

    @patch("modules.ai_engine.check_daily_budget", return_value=False)
    @patch("modules.ai_engine.get_cached_result", return_value=None)
    def test_budget_exceeded_returns_skipped(self, mock_cache, mock_budget):
        result = analyze_article("Budget test")
        assert result["_budget_skipped"] is True
        assert result["is_cyber_attack"] is False

    @patch("modules.ai_engine.track_usage")
    @patch("modules.ai_engine.check_daily_budget", return_value=True)
    @patch("modules.ai_engine._get_client")
    @patch("modules.ai_engine.get_cached_result", return_value=None)
    def test_fills_missing_fields(self, mock_cache, mock_get_client, mock_budget, mock_track):
        """Response missing some fields gets defaults filled in."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = json.dumps({
            "is_cyber_attack": True,
            "category": "Malware",
            # Missing: confidence, translated_title, summary
        })
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Fill test")
        assert result["confidence"] == 0  # Filled from SAFE_DEFAULT
        assert result["translated_title"] == "Fill test"  # Filled from title arg

    @patch("modules.ai_engine.track_usage")
    @patch("modules.ai_engine.check_daily_budget", return_value=True)
    @patch("modules.ai_engine._get_client")
    @patch("modules.ai_engine.get_cached_result", return_value=None)
    def test_with_content(self, mock_cache, mock_get_client, mock_budget, mock_track):
        """Article content is included in the prompt."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = json.dumps({
            "is_cyber_attack": True, "category": "Ransomware",
            "confidence": 85, "translated_title": "Test", "summary": "S",
        })
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Test", "Full article content here")
        assert result["is_cyber_attack"] is True
        # Check content was passed to API
        call_args = mock_client.messages.create.call_args
        user_msg = call_args.kwargs["messages"][0]["content"]
        assert "Full article content" in user_msg

    @patch("modules.ai_engine._get_client")
    @patch("modules.ai_engine.get_cached_result", return_value=None)
    def test_unexpected_exception_returns_failed(self, mock_cache, mock_get_client):
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("unexpected")
        mock_get_client.return_value = mock_client

        result = analyze_article("Exception test")
        assert result["ai_analysis_failed"] is True


class TestGetFailureStats:
    def test_returns_dict(self):
        from modules.ai_engine import get_failure_stats
        stats = get_failure_stats()
        assert "failures" in stats
        assert "budget_skips" in stats


class TestComputeContentHash:
    def test_returns_hex_string(self):
        from modules.ai_engine import compute_content_hash
        h = compute_content_hash("test content")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        from modules.ai_engine import compute_content_hash
        assert compute_content_hash("same") == compute_content_hash("same")
