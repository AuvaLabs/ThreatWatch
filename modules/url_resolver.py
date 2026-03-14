# ==== Module Imports ====
import base64
import logging
import re
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

_CACHE: dict[str, str] = {}
_CACHE_MAX = 1000


def is_clearnet_url(url: str) -> bool:
    """Return True only if url is a regular clearnet http/https address.

    Rejects:
    - .onion domains (Tor hidden services)
    - .i2p domains (I2P network)
    - non-http/https schemes
    - empty or non-string values
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if host.endswith(".onion") or host == "onion":
            return False
        if host.endswith(".i2p") or host == "i2p":
            return False
        return bool(host)
    except Exception:
        return False


# ==== Google News URL Decoding ====
_GNEWS_URL_RE = re.compile(
    rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

def decode_google_news_url(url: str) -> str | None:
    """Decode a Google News RSS article link to the actual article URL.

    Google News RSS feeds wrap article links as base64-encoded protobuf:
      https://news.google.com/rss/articles/<encoded>?hl=...
    The encoded part contains the real URL embedded in protobuf bytes.
    Decoding is done locally — no HTTP request, no CAPTCHA risk.
    Returns the decoded URL, or None if the URL is not a Google News link
    or decoding fails.
    """
    if 'news.google.com' not in url or '/articles/' not in url:
        return None
    try:
        encoded = url.split('/articles/')[-1].split('?')[0]
        pad = (4 - len(encoded) % 4) % 4
        decoded = base64.urlsafe_b64decode(encoded + '=' * pad)
        match = _GNEWS_URL_RE.search(decoded)
        if match:
            return match.group(0).decode('utf-8')
    except Exception:
        pass
    return None


# ==== Embedded URL Extraction ====
def extract_embedded_url(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return query.get('url', [None])[0]

# ==== Redirect Resolution via HEAD ====
def follow_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        if response.status_code in [301, 302] and 'Location' in response.headers:
            return response.headers['Location']
        final = response.url
        # Never return a Tor or I2P address even if a redirect leads there
        return final if is_clearnet_url(final) else None
    except requests.RequestException as e:
        logging.warning(f"Redirect failed for {url}: {e}")
        return None

# ==== Canonical URL Extraction from HTML ====
def extract_canonical_from_html(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=8)
        soup = BeautifulSoup(resp.text, 'html.parser')
        canonical = soup.find('link', rel='canonical')
        if canonical and canonical.get('href'):
            return canonical['href']
    except Exception as e:
        logging.warning(f"Failed to extract canonical URL from {url}: {e}")
    return url

# ==== Final URL Resolver ====
def resolve_original_url(url):
    if url in _CACHE:
        return _CACHE[url]

    # Google News article links must be decoded locally — following them via HTTP
    # triggers Google's bot-detection CAPTCHA page.
    gnews_decoded = decode_google_news_url(url)
    if gnews_decoded:
        result = gnews_decoded
    else:
        embedded = extract_embedded_url(url)
        if embedded:
            result = embedded
        else:
            redirected = follow_redirects(url)
            if redirected and redirected != url:
                result = redirected
            else:
                result = extract_canonical_from_html(url) or url

    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[url] = result
    return result
