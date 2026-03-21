"""Tests for modules/logger_utils.py"""
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from modules.logger_utils import setup_logger, log_article_summary


class TestSetupLogger:
    def test_returns_path_object(self, tmp_path):
        with patch("modules.logger_utils.Path") as mock_path_cls:
            # Build a real tmp directory as the log_dir target
            log_dir = tmp_path / "data" / "logs"
            mock_log_dir = MagicMock()
            mock_log_dir.__truediv__ = lambda self, name: log_dir / name
            mock_path_cls.return_value = mock_log_dir
            mock_log_dir.mkdir.return_value = None

            # We want setup_logger to write into tmp_path — patch Path("data/logs")
            # Use real Path but rooted in tmp_path
            real_log_dir = tmp_path / "data" / "logs"
            real_log_dir.mkdir(parents=True, exist_ok=True)

            with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
                result = setup_logger()

            assert result is not None

    def test_creates_log_directory(self, tmp_path):
        target_dir = tmp_path / "data" / "logs"
        assert not target_dir.exists()

        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            setup_logger()

        assert target_dir.exists()

    def test_creates_log_file(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_file = setup_logger()

        assert log_file.exists()

    def test_log_file_name_contains_timestamp(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_file = setup_logger()

        assert "run_" in log_file.name
        assert log_file.suffix == ".log"

    def test_basicconfig_called(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p), \
             patch("modules.logger_utils.logging.basicConfig") as mock_basic_config, \
             patch("modules.logger_utils.logging.info"):
            setup_logger()

        mock_basic_config.assert_called_once()
        call_kwargs = mock_basic_config.call_args[1]
        assert call_kwargs.get("level") == logging.INFO

    def test_handlers_include_file_and_stream(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p), \
             patch("modules.logger_utils.logging.basicConfig") as mock_basic_config, \
             patch("modules.logger_utils.logging.info"):
            setup_logger()

        handlers = mock_basic_config.call_args[1]["handlers"]
        handler_types = [type(h).__name__ for h in handlers]
        assert "FileHandler" in handler_types
        assert "StreamHandler" in handler_types

    def test_logs_initialized_message(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p), \
             patch("modules.logger_utils.logging.basicConfig"), \
             patch("modules.logger_utils.logging.info") as mock_info:
            setup_logger()

        mock_info.assert_called_once()
        assert "Logger initialized" in mock_info.call_args[0][0]


class TestLogArticleSummary:
    def test_writes_entry_to_jsonl(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_article_summary("https://example.com/article", "Test summary text")

        summaries_dir = tmp_path / "data" / "logs" / "summaries"
        jsonl_files = list(summaries_dir.glob("summary_*.jsonl"))
        assert len(jsonl_files) == 1

        with open(jsonl_files[0], "r") as f:
            entry = json.loads(f.readline())

        assert entry["url"] == "https://example.com/article"
        assert entry["summary"] == "Test summary text"
        assert "timestamp" in entry

    def test_appends_multiple_entries(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_article_summary("https://example.com/1", "First summary")
            log_article_summary("https://example.com/2", "Second summary")

        summaries_dir = tmp_path / "data" / "logs" / "summaries"
        jsonl_files = list(summaries_dir.glob("summary_*.jsonl"))
        assert len(jsonl_files) == 1

        with open(jsonl_files[0], "r") as f:
            lines = f.readlines()

        assert len(lines) == 2

    def test_timestamp_is_utc_iso_format(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_article_summary("https://example.com/article", "Summary")

        summaries_dir = tmp_path / "data" / "logs" / "summaries"
        jsonl_files = list(summaries_dir.glob("summary_*.jsonl"))
        with open(jsonl_files[0], "r") as f:
            entry = json.loads(f.readline())

        # Should parse as ISO 8601
        ts = entry["timestamp"]
        assert "T" in ts

    def test_creates_summaries_directory(self, tmp_path):
        target_dir = tmp_path / "data" / "logs" / "summaries"
        assert not target_dir.exists()

        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_article_summary("https://example.com/", "Summary")

        assert target_dir.exists()

    def test_handles_exception_gracefully(self, caplog):
        with patch("modules.logger_utils.Path") as mock_path_cls:
            mock_dir = MagicMock()
            mock_dir.mkdir.side_effect = PermissionError("cannot create dir")
            mock_path_cls.return_value = mock_dir

            with caplog.at_level(logging.ERROR, logger="root"):
                # Should not raise
                log_article_summary("https://example.com/", "Summary")

        assert any("Failed to log summary" in r.message for r in caplog.records)

    def test_logs_success_message(self, tmp_path, caplog):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            with caplog.at_level(logging.INFO, logger="root"):
                log_article_summary("https://example.com/test", "Summary text")

        assert any("Summary logged for" in r.message for r in caplog.records)

    def test_entry_json_valid(self, tmp_path):
        with patch("modules.logger_utils.Path", side_effect=lambda p: tmp_path / p):
            log_article_summary("https://example.com/article", "Summary with 'quotes' & <html>")

        summaries_dir = tmp_path / "data" / "logs" / "summaries"
        jsonl_files = list(summaries_dir.glob("summary_*.jsonl"))
        with open(jsonl_files[0], "r") as f:
            # Should parse without error
            entry = json.loads(f.readline())
        assert entry["summary"] == "Summary with 'quotes' & <html>"
