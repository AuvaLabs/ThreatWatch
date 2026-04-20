"""Victim-sector taxonomy — tags articles with the SECTOR of the victim.

`feed_region` tells you where the news was *reported*; this module tells you
who was *hit*. Articles covering a breach at a hospital get "Healthcare";
an energy-grid attack gets "Energy" and "Critical Infrastructure". The
dashboard uses these to power sector drilldowns and sector-breakdown charts
that were previously impossible.

Sectors follow a pragmatic CTI taxonomy (CISA's 16 critical-infrastructure
sectors, compressed down to 13 that actually appear frequently in feeds).

Matching is intentionally conservative:
- Short ambiguous tokens ("energy", "tech") are anchored to strong co-occurring
  context (`tech GIANT`, `ENERGY grid`) where they would otherwise fire on
  every press release.
- Each pattern matches on the *title+summary* of an article, not just the
  title. Titles are often too terse to carry the sector signal.
- An article can belong to multiple sectors — a ransomware attack on a
  hospital's billing system is both Healthcare AND Finance. Returning the
  full set gives analysts a proper facet.

This module is zero-cost and deterministic. It does NOT call any LLM — the
regex patterns here can be audited, tuned, and extended without retraining.
"""
from __future__ import annotations

import re
from typing import Iterable

# ── sector patterns ───────────────────────────────────────────────────────────
# Each entry: (sector name, compiled regex). The regex is matched against the
# lowercased "title + ' ' + summary" with re.IGNORECASE so the patterns below
# can stay case-readable.
#
# When adding patterns: prefer multi-word anchors and specific proper nouns
# over bare single words. Single-word triggers must be unambiguous in context.

def _pat(*alts: str) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(alts) + r")\b", re.IGNORECASE)


_SECTOR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Healthcare", _pat(
        r"hospital", r"hospitals", r"clinic", r"clinics",
        r"healthcare", r"health[- ]care", r"health system",
        r"medical center", r"medical centre", r"medical records",
        r"patient (?:data|records|information)",
        r"NHS", r"HHS", r"HIPAA", r"medicaid", r"medicare",
        r"pharmacy", r"pharmacies", r"pharmaceutical",
        r"biotech", r"biopharma", r"drug maker",
        r"EMR", r"EHR", r"electronic health records?",
        r"medical device",
    )),
    ("Finance", _pat(
        r"bank", r"banks", r"banking",
        r"credit union", r"credit card",
        r"financial services", r"financial institution",
        r"stock exchange", r"NYSE", r"NASDAQ",
        r"broker(?:age)?", r"hedge fund",
        r"cryptocurrency", r"crypto exchange", r"crypto wallet",
        r"fintech", r"insurance (?:firm|company|provider|carrier)",
        r"payment processor", r"POS breach", r"POS malware",
        r"Wall Street", r"SEC filing", r"FINRA",
    )),
    ("Government", _pat(
        r"federal (?:agency|government|contractor)",
        r"state (?:agency|government|department)",
        r"municipal", r"city government", r"local government",
        r"ministry of", r"government agency",
        r"FBI", r"CIA", r"NSA", r"DoD", r"DoJ", r"DHS", r"CISA",
        r"Pentagon", r"White House",
        r"GCHQ", r"NCSC", r"BSI", r"ANSSI",
        r"military", r"army", r"navy", r"air force",
        r"parliament", r"congress", r"senate",
        r"tax (?:authority|agency)", r"IRS", r"HMRC",
        r"customs (?:service|agency)",
        r"diplomatic", r"embassy",
    )),
    ("Education", _pat(
        r"university", r"universities", r"college",
        r"school district", r"K-12",
        r"higher education", r"academic institution",
        r"student (?:data|records)",
        r"research institute", r"research lab",
        r"campus (?:network|system)",
    )),
    ("Energy", _pat(
        r"oil (?:company|firm|major|giant)",
        r"gas (?:company|utility|provider)",
        r"electric (?:utility|grid|company)",
        r"power grid", r"power (?:plant|station|utility|company)",
        r"energy (?:company|firm|sector|provider|utility|giant)",
        r"nuclear (?:plant|facility|power)",
        r"pipeline operator", r"pipeline company",
        r"refinery", r"petrochemical",
        r"LNG (?:terminal|plant)", r"coal (?:plant|miner)",
        r"renewable (?:energy|power)",
    )),
    ("Technology", _pat(
        r"tech (?:giant|firm|company|vendor)",
        r"software (?:company|vendor|firm|giant|maker)",
        r"SaaS (?:provider|platform|vendor)",
        r"cloud (?:provider|service|platform)",
        r"chip ?maker", r"semiconductor",
        r"IT services (?:firm|provider)",
        r"Microsoft", r"Google", r"Apple", r"Amazon Web Services", r"AWS",
        r"Oracle", r"SAP", r"Salesforce", r"Adobe", r"Atlassian",
        r"Cisco", r"VMware", r"Citrix", r"Fortinet", r"SonicWall",
    )),
    ("Telecom", _pat(
        r"telecom", r"telco", r"telecoms",
        r"ISP", r"internet service provider",
        r"wireless carrier", r"mobile (?:operator|carrier|network)",
        r"5G network",
        r"broadband (?:provider|company)",
        r"AT&T", r"Verizon", r"T[- ]Mobile",
        r"Vodafone", r"Telef[oó]nica", r"Orange (?:Telecom|S\.A\.)",
        r"Deutsche Telekom", r"BT Group",
        r"Nokia", r"Ericsson",
    )),
    ("Retail", _pat(
        r"retailer", r"retail (?:chain|giant|company)",
        r"e-commerce (?:platform|site|firm|company)",
        r"online store",
        r"supermarket", r"grocery chain",
        r"POS system", r"point-of-sale",
        r"Walmart", r"Target (?:Corp|stores|Corporation)",
        r"Home Depot", r"Macy", r"Kohl", r"IKEA",
    )),
    ("Manufacturing", _pat(
        r"manufacturer", r"manufacturing (?:firm|company|plant)",
        r"factory", r"factories",
        r"industrial (?:firm|company)",
        r"auto ?maker", r"automotive",
        r"aerospace (?:manufacturer|company|firm)",
        r"steel (?:maker|mill|plant)",
        r"chemical (?:maker|plant|company)",
        r"supply chain (?:attack|compromise|breach)",
    )),
    ("Transportation", _pat(
        r"airline", r"airlines", r"airport",
        r"railway", r"rail operator",
        r"shipping (?:company|firm|giant)",
        r"logistics (?:firm|provider|company)",
        r"trucking (?:company|firm)",
        r"port authority", r"maritime (?:firm|company)",
        r"Maersk", r"FedEx", r"UPS",
        r"DHL", r"Boeing", r"Airbus",
    )),
    ("Media", _pat(
        r"news (?:outlet|agency|publisher|organi[sz]ation)",
        r"newspaper", r"magazine",
        r"broadcaster", r"broadcast (?:network|company)",
        r"streaming (?:service|platform|provider)",
        r"gaming (?:company|firm|studio)", r"game studio",
        r"publisher",
        r"television network", r"radio station",
    )),
    ("Legal", _pat(
        r"law firm", r"legal services (?:firm|provider)",
        r"consulting firm",
        r"accounting firm", r"big four", r"PwC", r"Deloitte", r"KPMG",
    )),
    ("Critical Infrastructure", _pat(
        r"critical infrastructure",
        r"power (?:plant|station|grid)",
        r"water (?:utility|treatment|authority)",
        r"SCADA", r"\bICS\b", r"operational technology", r"\bOT\b",
        r"industrial control",
        r"nuclear (?:plant|facility)",
        r"chemical plant",
        r"dam operator",
        r"16 critical",
    )),
    ("Hospitality", _pat(
        r"hotel chain", r"casino (?:operator|company)",
        r"restaurant chain",
        r"hospitality (?:firm|company|industry)",
        r"Marriott", r"Hilton", r"MGM Resorts", r"Caesars",
    )),
]


# ── public API ────────────────────────────────────────────────────────────────
def tag_sectors(title: str | None, summary: str | None) -> list[str]:
    """Return the set of sector names matched in an article's text.

    Order is deterministic (follows `_SECTOR_PATTERNS` declaration order). An
    empty list means "no sector inferred" — downstream UI should treat that
    as "uncategorised" rather than guessing.
    """
    text = " ".join(filter(None, [title, summary]))
    if not text:
        return []
    return [name for name, rx in _SECTOR_PATTERNS if rx.search(text)]


def annotate_articles_with_sectors(articles: Iterable[dict]) -> int:
    """Write `victim_sectors` onto each article in place.

    Matches over title + summary + full_content where available. Returns the
    count of articles that picked up at least one sector.
    """
    hits = 0
    for a in articles:
        sectors = tag_sectors(
            a.get("title"),
            " ".join(filter(None, [a.get("summary"), a.get("full_content")])),
        )
        if sectors:
            a["victim_sectors"] = sectors
            hits += 1
        elif "victim_sectors" in a:
            del a["victim_sectors"]
    return hits
