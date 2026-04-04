"""Deploy latest threat data to GitHub Pages (docs/ folder).

Copies threatwatch.html → docs/index.html with embedded SSR data
so the site works as a fully static page on GitHub Pages.
"""

import json
import logging
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"
HTML_SRC = BASE_DIR / "threatwatch.html"
FAVICON_SRC = BASE_DIR / "favicon.svg"
DATA_FILE = BASE_DIR / "data" / "output" / "daily_latest.json"
STATS_FILE = BASE_DIR / "data" / "output" / "run_stats.json"
BRIEFING_FILE = BASE_DIR / "data" / "output" / "briefing.json"
TOP_STORIES_FILE = BASE_DIR / "data" / "output" / "top_stories.json"
CLUSTERS_FILE = BASE_DIR / "data" / "output" / "clusters.json"
PROFILES_FILE = BASE_DIR / "data" / "output" / "actor_profiles.json"
SSR_PLACEHOLDER = "<!-- __SSR_DATA__ -->"


def load_json(path):
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def build_ssr_html():
    """Build static HTML with embedded article + AI data."""
    html = HTML_SRC.read_text()

    articles = load_json(DATA_FILE) or []
    stats = load_json(STATS_FILE)
    briefing = load_json(BRIEFING_FILE)
    top_stories = load_json(TOP_STORIES_FILE)
    clusters = load_json(CLUSTERS_FILE)
    actor_profiles = load_json(PROFILES_FILE)

    # Strip full_content to reduce page size
    articles = [
        {k: v for k, v in a.items() if k != "full_content"}
        for a in articles
        if isinstance(a, dict)
    ]

    ssr_payload = {"articles": articles}
    if stats:
        ssr_payload["stats"] = stats
    if briefing:
        ssr_payload["briefing"] = briefing
    if top_stories:
        ssr_payload["top_stories"] = top_stories
    if clusters:
        ssr_payload["clusters"] = clusters
    if actor_profiles:
        ssr_payload["actor_profiles"] = actor_profiles

    raw_json = json.dumps(ssr_payload, separators=(",", ":"))
    safe_json = raw_json.replace("</", "<\\/")
    ssr_script = f'<script id="ssr-data" type="application/json">{safe_json}</script>'

    html = html.replace(SSR_PLACEHOLDER, ssr_script)

    # For GitHub Pages, the API fetch will fail (no server), so disable
    # the periodic refresh to avoid console errors. SSR data is sufficient.
    html = html.replace(
        "setInterval(refreshData, REFRESH_INTERVAL);",
        "// setInterval(refreshData, REFRESH_INTERVAL); // Disabled for static site",
    )

    # Fix absolute favicon path for GitHub Pages (site lives at /ThreatWatch/, not /)
    html = html.replace(
        'href="/favicon.svg"',
        'href="favicon.svg"',
    )

    return html


def deploy():
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    DOCS_DIR.mkdir(exist_ok=True)

    # Build and write static HTML
    html = build_ssr_html()
    index_path = DOCS_DIR / "index.html"
    index_path.write_text(html)
    logging.info(f"Built {index_path} ({len(html):,} bytes)")

    # Copy favicon
    if FAVICON_SRC.exists():
        shutil.copy2(FAVICON_SRC, DOCS_DIR / "favicon.svg")

    # Also provide articles.json as a static data file
    articles = load_json(DATA_FILE) or []
    data_path = DOCS_DIR / "articles.json"
    data_path.write_text(json.dumps(articles, separators=(",", ":")))
    logging.info(f"Wrote {data_path} ({len(articles)} articles)")

    # Write RSS feed if available
    rss_src = BASE_DIR / "data" / "output" / "rss_cyberattacks.xml"
    if rss_src.exists():
        shutil.copy2(rss_src, DOCS_DIR / "feed.xml")
        logging.info("Copied RSS feed to docs/feed.xml")

    logging.info("Static site built — git commit handled by CI workflow.")


if __name__ == "__main__":
    deploy()
