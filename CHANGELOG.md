# Changelog

All notable changes to ThreatWatch are documented here.

## [Unreleased]

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
