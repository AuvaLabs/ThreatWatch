"""Pre-install lightweight mocks for heavy optional dependencies so test
collection succeeds in environments where those packages are not installed.

Only installed if the real package is absent — real packages take precedence.
"""

import sys
import types
from unittest.mock import MagicMock


def _make_anthropic_mock():
    """Minimal anthropic mock with the exception hierarchy tests depend on."""
    mod = types.ModuleType("anthropic")

    class APIError(Exception):
        def __init__(self, message="", *, request=None, body=None):
            super().__init__(message)
            self.request = request
            self.body = body

    class APIConnectionError(APIError):
        pass

    class APITimeoutError(APIError):
        pass

    class InternalServerError(APIError):
        pass

    mod.APIError = APIError
    mod.APIConnectionError = APIConnectionError
    mod.APITimeoutError = APITimeoutError
    mod.InternalServerError = InternalServerError
    mod.Anthropic = MagicMock
    return mod


def _make_feedparser_mock():
    """Minimal feedparser mock — parse() returns empty .entries by default."""
    mod = types.ModuleType("feedparser")

    def parse(content_or_url, **kwargs):
        result = MagicMock()
        result.entries = []
        return result

    mod.parse = parse
    return mod


def _make_trafilatura_mock():
    """Minimal trafilatura mock — fetch_url returns None, extract returns None."""
    mod = types.ModuleType("trafilatura")

    def fetch_url(url, **kwargs):
        return None

    def extract(content, **kwargs):
        return None

    mod.fetch_url = fetch_url
    mod.extract = extract
    return mod


def _make_lingua_mock():
    """Minimal lingua mock — always detects English."""
    mod = types.ModuleType("lingua")

    class _IsoCode639_1:
        name = "EN"

    class _Language:
        iso_code_639_1 = _IsoCode639_1()

    class _Detector:
        def detect_language_of(self, text):
            return _Language()

    class _Builder:
        def build(self):
            return _Detector()

        def with_preloaded_language_models(self):
            return self

    class LanguageDetectorBuilder:
        @classmethod
        def from_all_languages(cls):
            return _Builder()

    mod.LanguageDetectorBuilder = LanguageDetectorBuilder
    return mod


def _make_bs4_mock():
    """Minimal bs4 mock."""
    mod = types.ModuleType("bs4")

    class BeautifulSoup:
        def __init__(self, markup="", parser="html.parser", **kwargs):
            self._markup = markup

        def find(self, *args, **kwargs):
            return None

        def find_all(self, *args, **kwargs):
            return []

        def __call__(self, *args, **kwargs):
            return []

        def decompose(self):
            pass

    mod.BeautifulSoup = BeautifulSoup
    return mod


def _make_feedgen_mock():
    """Minimal feedgen mock matching the real feedgen.feed API surface."""
    mod = types.ModuleType("feedgen")
    feed_mod = types.ModuleType("feedgen.feed")

    class FeedEntry:
        def __init__(self):
            self._title = None
            self._link = None
            self._guid = None
            self._guid_permalink = False
            self._description = None
            self._category = None
            self._pub_date = None

        def title(self, val=None, *a, **kw):
            if val is not None:
                self._title = val
            return self._title

        def link(self, *a, **kw):
            href = kw.get("href") or (a[0] if a else None)
            if href is not None:
                self._link = href
            return self._link

        def guid(self, val=None, permalink=False, **kw):
            if val is not None:
                self._guid = val
                self._guid_permalink = permalink
            return self._guid

        def description(self, val=None, *a, **kw):
            if val is not None:
                self._description = val
            return self._description

        def category(self, *a, term=None, **kw):
            if term is not None:
                self._category = term
            return self._category

        def pubDate(self, val=None, *a, **kw):
            if val is not None:
                self._pub_date = val
            return self._pub_date

    class FeedGenerator:
        def __init__(self):
            self._entries = []

        def id(self, *a, **kw): pass
        def title(self, *a, **kw): pass
        def link(self, *a, **kw): pass
        def language(self, *a, **kw): pass
        def description(self, *a, **kw): pass

        def add_entry(self):
            entry = FeedEntry()
            self._entries.append(entry)
            return entry

        def rss_file(self, path, **kw):
            # Write a minimal valid RSS file so XML-parsing tests work
            items_xml = ""
            for e in self._entries:
                guid_tag = f"<guid isPermaLink=\"{'true' if e._guid_permalink else 'false'}\">{e._guid or ''}</guid>"
                cat_tag = f"<category>{e._category}</category>" if e._category else ""
                items_xml += (
                    f"<item>"
                    f"<title>{e._title or 'No Title'}</title>"
                    f"<link>{e._link or '#'}</link>"
                    f"{guid_tag}"
                    f"<description>{e._description or ''}</description>"
                    f"{cat_tag}"
                    f"</item>"
                )
            xml = (
                "<?xml version='1.0' encoding='UTF-8'?>"
                "<rss version=\"2.0\"><channel>"
                "<title>ThreatWatch</title>"
                f"{items_xml}"
                "</channel></rss>"
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml)

    feed_mod.FeedGenerator = FeedGenerator
    mod.feed = feed_mod
    sys.modules["feedgen.feed"] = feed_mod
    return mod


if "anthropic" not in sys.modules:
    sys.modules["anthropic"] = _make_anthropic_mock()

_optional_mocks = [
    ("feedparser", _make_feedparser_mock),
    ("trafilatura", _make_trafilatura_mock),
    ("lingua", _make_lingua_mock),
    ("bs4", _make_bs4_mock),
    ("feedgen", _make_feedgen_mock),
]
for _mod_name, _mock_factory in _optional_mocks:
    try:
        __import__(_mod_name)
    except ImportError:
        sys.modules[_mod_name] = _mock_factory()
        if _mod_name == "feedgen":
            sys.modules["feedgen.feed"] = sys.modules["feedgen"].feed
