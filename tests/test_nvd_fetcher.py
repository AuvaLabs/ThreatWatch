import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from modules.nvd_fetcher import fetch_nvd_cves, _cvss_score, _severity_label


class TestCvssScore:
    def test_extracts_v31_score(self):
        vuln = {
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}
                }]
            }
        }
        score, vector = _cvss_score(vuln)
        assert score == 9.8
        assert "CVSS:3.1" in vector

    def test_falls_back_to_v30(self):
        vuln = {
            "metrics": {
                "cvssMetricV30": [{
                    "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/AV:N"}
                }]
            }
        }
        score, _ = _cvss_score(vuln)
        assert score == 7.5

    def test_falls_back_to_v2(self):
        vuln = {
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {"baseScore": 10.0, "vectorString": "AV:N/AC:L"}
                }]
            }
        }
        score, _ = _cvss_score(vuln)
        assert score == 10.0

    def test_returns_zero_for_empty_metrics(self):
        score, vector = _cvss_score({"metrics": {}})
        assert score == 0.0
        assert vector == ""


class TestSeverityLabel:
    def test_critical(self):
        assert _severity_label(9.5) == "CRITICAL"

    def test_high(self):
        assert _severity_label(7.5) == "HIGH"

    def test_medium(self):
        assert _severity_label(5.0) == "MEDIUM"

    def test_low(self):
        assert _severity_label(2.0) == "LOW"


class TestFetchNvdCves:
    @patch("modules.nvd_fetcher._should_fetch", return_value=True)
    @patch("modules.nvd_fetcher._save_state")
    @patch("modules.nvd_fetcher._get_session")
    def test_fetches_and_parses_cves(self, mock_session, mock_save, mock_should):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-04-01T12:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Remote code execution in FooBar"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L"}
                        }]
                    },
                    "configurations": [],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }]
        }
        mock_session.return_value.get.return_value = mock_resp

        articles = fetch_nvd_cves()
        assert len(articles) == 1
        assert articles[0]["cve_id"] == "CVE-2026-12345"
        assert articles[0]["cvss_score"] == 9.8
        assert articles[0]["cvss_severity"] == "CRITICAL"
        assert articles[0]["source"] == "nvd:cve"
        assert "CWE-79" in articles[0]["cwe_ids"]

    @patch("modules.nvd_fetcher._should_fetch", return_value=False)
    def test_respects_rate_limit(self, mock_should):
        articles = fetch_nvd_cves()
        assert articles == []

    @patch("modules.nvd_fetcher._should_fetch", return_value=True)
    @patch("modules.nvd_fetcher._get_session")
    def test_handles_api_error_gracefully(self, mock_session, mock_should):
        mock_session.return_value.get.side_effect = Exception("Connection refused")
        articles = fetch_nvd_cves()
        assert articles == []
