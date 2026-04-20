# Changelog

All notable changes to ThreatWatch are documented here.

## [Unreleased]

### Added (2026-04-20 CTI batch)
- Campaign persistence (`modules/campaign_tracker.py`): stable UUIDs keyed by `(entity_type, entity_name)` that survive across pipeline reclusters. Persists to `data/output/campaigns.json`. Tracks `first_observed` (ever-earliest), `last_observed`, `total_observed_articles`, `status` (active, dormant, archived by 14d and 90d thresholds), capped at 500 hashes per campaign. Atomic tmp+rename writes.
- Victim-sector taxonomy (`modules/victim_tagger.py`): 14-sector regex taxonomy (Healthcare, Finance, Government, Education, Energy, Technology, Telecom, Retail, Manufacturing, Transportation, Media, Legal, Critical Infrastructure, Hospitality). Writes `victim_sectors` list onto each article.
- IOC extraction (`modules/ioc_extractor.py`): IPv4, IPv6, domains, URLs, SHA256, SHA1, MD5, emails with defang handling (`[.]`, `hxxp://`, `[at]`), TLD allowlist, placeholder-IP blocklist. Writes `iocs` dict on each article.
- CVE write-back (`modules/incident_correlator.annotate_articles_with_cves`): extracts CVE IDs to `cve_ids` on every article so the dashboard can facet by CVE.
- New API endpoints: `GET /api/cve/<ID>`, `GET /api/campaigns[?status=...]`, `GET /api/campaign/<uuid>`.
- `modules/date_utils.py`: single source of truth for feed/article date parsing. Consolidates four divergent parsers across `feed_fetcher`, `output_writer`, `darkweb_monitor`, `incident_correlator`.
- `modules/safe_http.py`: process-wide SSRF guard that monkey-patches urllib3 `create_connection` to re-validate hostnames at connect time, closing the DNS-rebind TOCTOU in `is_safe_url`.
- Frontend pills on each article card: CVE pill (clickable, filters feed), IOC pill (type-grouped tooltip), sector pill (clickable, filters feed), story pill (prefers campaign `first_observed` so long-running campaigns keep their true age across 7-day corpus rotations).
- Nightly Docker volume backup (`scripts/backup_volume.sh`), rotates to 7 archives in `~/backups/threatwatch/`. Cron at 03:15 UTC.
- `scripts/cleanup.py` applies `ARCHIVE_RETENTION_DAYS` (default 30) to `hourly/` and `daily/` subdirs; previously retained 365 days of archive snapshots.

### Security (2026-04-20 CTI batch)
- Fix `javascript:` URI XSS via feed `<link>`: new `safeHref()` allowlist (`http:`, `https:`, `mailto:`) wrapping every feed-supplied href insertion.
- Rate limiter reads `X-Real-IP` only when the TCP peer is a trusted proxy (new `TRUSTED_PROXIES` env var, default `127.0.0.1,::1`). Previously every nginx-proxied request bucketed into `127.0.0.1`, giving all public users one shared 120/min window.
- Thread-safety fixes on shared in-process state: `serve_threatwatch._cache`, `url_resolver._CACHE` (including FIFO eviction), `feed_health.record_fetch` (8 concurrent fetch threads), `hybrid_classifier._escalation_count` (two threads could both exceed the budget cap).
- `/api/health` returns real `status` (`ok`, `degraded`, `stale`, `unknown`) with `reasons[]`, driven by last-run freshness (2.5x `PIPELINE_INTERVAL` + 60s), LLM budget, analysis-failure rate, dead-feed count.
- Pipeline container healthcheck tests `stats.json` mtime under 25 minutes. Previously the file just needed to exist so a stuck pipeline stayed "healthy" forever.

### Fixed (2026-04-20 CTI batch)
- `output_writer._parse_pub_date` no longer falls back to `datetime.now()` on parse failure. The cutoff filter previously kept corrupt-date articles inside the window indefinitely. RSS pubDate keeps the `now()` fallback because `feedgen` requires a valid RFC 822 date.
- `darkweb_monitor._parse_date` format-slice bug (`fmt[:len(date_str)]` inverted intent) replaced with shared `date_utils.parse_datetime`. The ThreatFox ` UTC` suffix convention is normalised explicitly.
- `deduplicate_articles` no longer mutates caller article dicts. Each article is shallow-copied at loop entry; `_add_related` rebuilds `related_articles` as a new list.
- Incident correlator persists all clusters (not just top 15) and emits `first_seen` + `article_hashes` per cluster so the frontend can annotate every related article.

### Changed (2026-04-20 CTI batch)
- `_MAX_SUMMARIES_PER_RUN` raised from 30 to 150 (env-overridable `MAX_SUMMARIES_PER_RUN`). Previous cap covered about 2 percent of the ~1600-article daily backlog.
- SSR payload strips `article_hashes` from per-cluster objects after article-level annotation runs, saving 50 to 500 hashes per cluster from the wire.
- `depends_on: service_started` (not `service_healthy`) for the server so the dashboard stays up while the pipeline is mid-fetch.

### Security
- Add bearer token auth for POST `/api/watchlist` (`WATCHLIST_TOKEN` env var)
- Add HSTS (Strict-Transport-Security) header
- Fix CSP to allow Google Fonts (font-src, style-src-elem)
- Add 64KB payload size limit on POST `/api/watchlist`
- Sanitize error responses — no internal paths or exceptions leaked to clients
- Fix XSS variable shadowing bug in `app/dashboard.py` — `html` module was overwritten by string concatenation
- Restrict CORS on sensitive endpoints (`/api/health`, `/api/watchlist`) — no wildcard
- Add `CORS_ORIGIN` env var for cross-origin access to restricted endpoints
- Add rate limiter IP eviction to prevent unbounded memory growth
- Add thread-safe atomic writes for watchlist persistence (tmp+rename pattern)

### Changed
- Strip `full_content` from SSR payload to reduce initial page size
- Raise CI coverage threshold from 65% to 75%
- `/api/articles` now always returns envelope `{articles, total, offset, limit, has_more}` (breaking: previously returned raw array when no limit specified)

### Added
- STIX 2.1: confidence field mapped from article confidence score
- STIX 2.1: relationship objects linking indicators to identity
- STIX 2.1: report `object_refs` now includes indicator IDs
- RSS: `<guid>` element per item for reliable deduplication
- RSS: `<category>` element per item from article category
- RSS: proper `atom:link rel="self"` pointing to feed URL
- API response examples in README
- Missing API endpoints documented (health, stix, watchlist)
- `.env.example` updated with all current env vars
- `SECURITY.md` updated with security controls list
- 157 new tests (541 total, up from 345) — coverage at 82%

## 2026-03-19 — UI Redesign + Multi-Theme System

### Added
- Full UI redesign with professional modern look
- 5 switchable themes: Nightwatch (dark), Parchment (light), Solarized, Arctic, Phosphor (CRT)
- Theme dropdown picker with localStorage persistence
- IBM Plex Mono + Space Grotesk typography
- Phosphor CRT scanline overlay effect

## 2026-03-18 — NewsAPI + Briefing Hardening

### Added
- NewsAPI integration with rate limiting (free tier: 100 req/day)
- Three-layer region accuracy fix (content inference, ISO-2 codes, multi-region collapse)
- Non-Commercial License

### Fixed
- Briefing accuracy (max_tokens, cache key, schema validation)
- Crash bug in briefing generator

## 2026-03-15 — Features Expansion

### Added
- Brand Watch tab — monitor custom brand keywords
- Tech Watch tab — 244 vendors across 18 categories
- APT Tracker with actor intelligence grid
- IOC Tracker with ThreatFox integration
- STIX 2.1 export endpoint
- Webhook alerts (Slack and generic)
- Watchlist monitor module
- Feed search in left panel
- IOC export functionality
- NEW/APT CRITICAL badges

## 2026-03-14 — Architecture + CI/CD

### Added
- `/api/health` endpoint
- `scripts/run_pipeline.py` scheduler
- Docker Compose two-service deployment
- GitHub Actions CI (lint, test, coverage, pip-audit, Docker build)
- 243 initial tests

### Security
- SSRF protection on URL fetching
- Security headers (CSP, X-Frame-Options, nosniff)
- XSS escaping on SSR data injection
- Docker non-root user
- Rate limiting (120 req/min per IP)
