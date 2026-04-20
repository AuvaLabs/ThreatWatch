"""Region-collapse helpers shared across the pipeline.

Previously lived as private `_collapse_regions` / `_MAX_MERGED_REGIONS` inside
`modules.deduplicator` and was imported via underscore-prefixed names by
`output_writer`. Any refactor of the deduplicator internals therefore broke an
unrelated module. This file makes the contract public so the two consumers
(deduplicator and output_writer) depend on a stable shared primitive.
"""
from __future__ import annotations

# Collapse to "Global" when more than this many distinct regions merge on a
# single article — avoids long run-on strings like "US,UK,France,Germany,...".
MAX_MERGED_REGIONS = 2


def collapse_regions(regions: set[str]) -> str:
    """Return a region string, collapsing to 'Global' if too many regions merged."""
    regions = set(regions)
    regions.discard("Global")
    if not regions:
        return "Global"
    if len(regions) > MAX_MERGED_REGIONS:
        return "Global"
    return ",".join(sorted(regions))
