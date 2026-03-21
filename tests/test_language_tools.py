"""Tests for modules/language_tools.py — language detection via lingua."""
import logging
import sys
import types
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers — build lingua mock objects with configurable behaviour
# ---------------------------------------------------------------------------

def _make_iso_code(name: str):
    code = MagicMock()
    code.name = name
    return code


def _make_result(iso_name: str):
    """Return a lingua detection result object whose iso_code_639_1.name is *iso_name*."""
    result = MagicMock()
    result.iso_code_639_1 = _make_iso_code(iso_name)
    return result


def _make_detector(return_value):
    """Return a mock _detector with detect_language_of returning *return_value*."""
    detector = MagicMock()
    detector.detect_language_of.return_value = return_value
    return detector


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDetectLanguageHappyPath:
    """detect_language returns the correct ISO 639-1 code in lower-case."""

    def test_english_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("EN"))):
            assert language_tools.detect_language("Hello world") == "en"

    def test_german_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("DE"))):
            assert language_tools.detect_language("Guten Morgen") == "de"

    def test_french_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("FR"))):
            assert language_tools.detect_language("Bonjour le monde") == "fr"

    def test_spanish_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("ES"))):
            assert language_tools.detect_language("Hola mundo") == "es"

    def test_chinese_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("ZH"))):
            assert language_tools.detect_language("你好世界") == "zh"

    def test_result_is_always_lowercase(self):
        """Whatever case the iso_code_639_1.name returns, detect_language should be lower."""
        from modules import language_tools

        for raw in ("EN", "En", "en"):
            with patch.object(language_tools, "_detector", _make_detector(_make_result(raw))):
                assert language_tools.detect_language("test") == raw.lower()

    def test_calls_detector_with_provided_text(self):
        """detect_language passes the text string verbatim to the detector."""
        from modules import language_tools

        detector = _make_detector(_make_result("EN"))
        with patch.object(language_tools, "_detector", detector):
            language_tools.detect_language("some specific text")
        detector.detect_language_of.assert_called_once_with("some specific text")

    def test_empty_string_passed_to_detector(self):
        """Empty string is a valid input — result depends on what the detector returns."""
        from modules import language_tools

        detector = _make_detector(_make_result("EN"))
        with patch.object(language_tools, "_detector", detector):
            result = language_tools.detect_language("")
        assert result == "en"
        detector.detect_language_of.assert_called_once_with("")


class TestDetectLanguageFallbackOnNone:
    """When the detector cannot identify the language it returns None → fallback to 'en'."""

    def test_none_result_returns_en(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            assert language_tools.detect_language("???") == "en"

    def test_none_result_does_not_raise(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            result = language_tools.detect_language("gibberish text 1234")
        assert result == "en"

    def test_none_result_does_not_log_warning(self, caplog):
        """A None result is expected (low-confidence detection) — no warning should be logged."""
        from modules import language_tools

        with caplog.at_level(logging.WARNING, logger="root"):
            with patch.object(language_tools, "_detector", _make_detector(None)):
                language_tools.detect_language("???")
        assert caplog.records == []


class TestDetectLanguageFallbackOnException:
    """When the detector raises an exception, detect_language logs a warning and returns 'en'."""

    def test_generic_exception_returns_en(self):
        from modules import language_tools

        detector = MagicMock()
        detector.detect_language_of.side_effect = RuntimeError("detector exploded")
        with patch.object(language_tools, "_detector", detector):
            assert language_tools.detect_language("text") == "en"

    def test_exception_emits_warning(self, caplog):
        from modules import language_tools

        detector = MagicMock()
        detector.detect_language_of.side_effect = ValueError("bad value")
        with caplog.at_level(logging.WARNING, logger="root"):
            with patch.object(language_tools, "_detector", detector):
                language_tools.detect_language("text")
        assert any(rec.levelno == logging.WARNING for rec in caplog.records)

    def test_warning_message_contains_exception_text(self, caplog):
        from modules import language_tools

        detector = MagicMock()
        detector.detect_language_of.side_effect = RuntimeError("unique_error_marker")
        with caplog.at_level(logging.WARNING, logger="root"):
            with patch.object(language_tools, "_detector", detector):
                language_tools.detect_language("text")
        combined = " ".join(rec.message for rec in caplog.records)
        assert "unique_error_marker" in combined

    def test_attribute_error_returns_en(self):
        """If attribute access on the result raises, the exception is caught."""
        from modules import language_tools

        class _BrokenResult:
            """Truthy result whose iso_code_639_1 property raises AttributeError."""
            @property
            def iso_code_639_1(self):
                raise AttributeError("no attr")

            def __bool__(self):
                return True

        detector = MagicMock()
        detector.detect_language_of.return_value = _BrokenResult()

        with patch.object(language_tools, "_detector", detector):
            assert language_tools.detect_language("some text") == "en"

    def test_exception_does_not_propagate(self):
        """detect_language must never raise, regardless of the detector's behaviour."""
        from modules import language_tools

        for exc in (RuntimeError("r"), ValueError("v"), OSError("o"), Exception("e")):
            detector = MagicMock()
            detector.detect_language_of.side_effect = exc
            with patch.object(language_tools, "_detector", detector):
                result = language_tools.detect_language("text")
            assert result == "en", f"Expected 'en' fallback for {type(exc).__name__}"


class TestDetectLanguageReturnType:
    """detect_language always returns a plain str."""

    def test_return_type_is_str_on_success(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("EN"))):
            assert isinstance(language_tools.detect_language("hello"), str)

    def test_return_type_is_str_on_none(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            assert isinstance(language_tools.detect_language("hello"), str)

    def test_return_type_is_str_on_exception(self):
        from modules import language_tools

        detector = MagicMock()
        detector.detect_language_of.side_effect = RuntimeError("boom")
        with patch.object(language_tools, "_detector", detector):
            assert isinstance(language_tools.detect_language("hello"), str)


class TestDetectLanguageEdgeCases:
    """Boundary and unusual inputs."""

    def test_very_long_text(self):
        from modules import language_tools

        long_text = "a" * 100_000
        with patch.object(language_tools, "_detector", _make_detector(_make_result("EN"))):
            assert language_tools.detect_language(long_text) == "en"

    def test_unicode_symbols(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("AR"))):
            assert language_tools.detect_language("مرحبا") == "ar"

    def test_newline_only_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            assert language_tools.detect_language("\n\n\n") == "en"

    def test_whitespace_only_text(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            assert language_tools.detect_language("   ") == "en"

    def test_numeric_string(self):
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(None)):
            assert language_tools.detect_language("123456") == "en"

    def test_two_letter_code_preserved(self):
        """Codes that are already two letters are returned as-is after lowercasing."""
        from modules import language_tools

        with patch.object(language_tools, "_detector", _make_detector(_make_result("JA"))):
            result = language_tools.detect_language("日本語のテキスト")
        assert result == "ja"
