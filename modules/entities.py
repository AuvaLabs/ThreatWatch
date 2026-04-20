"""Shared entity patterns (threat actors, CVEs) used by multiple modules.

These lived inside `modules.incident_correlator` with a leading underscore and
were imported via `_ACTOR_PATTERNS` by `actor_profiler`. Private-underscore
cross-module imports make it impossible to refactor the correlator internals
without breaking unrelated modules, so the patterns are lifted here as a
stable public contract.
"""
from __future__ import annotations

import re

# CVE ID extraction — strong clustering signal and the input to annotate_articles_with_cves.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# Threat actor patterns: each entry is (compiled_regex, canonical_name, actor_type, origin).
# `actor_type` is a coarse taxonomy (Nation-State, Ransomware, Cybercrime); `origin` is
# a country or "Criminal" / "Unknown" for non-nation-state groups.
#
# The regex side of each tuple intentionally tolerates spacing variants (for example
# "Volt\s*Typhoon" matches both "VoltTyphoon" and "Volt Typhoon"). When adding new
# entries, prefer multi-word / proper-noun anchors; bare single words cause false
# positives in news articles.
ACTOR_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    # Nation-State: Russia
    (re.compile(r"\bAPT28\b|Fancy\s*Bear|Forest\s*Blizzard", re.I), "APT28", "Nation-State", "Russia"),
    (re.compile(r"\bAPT29\b|Cozy\s*Bear|Midnight\s*Blizzard|Nobelium", re.I), "APT29", "Nation-State", "Russia"),
    (re.compile(r"Sandworm|Seashell\s*Blizzard", re.I), "Sandworm", "Nation-State", "Russia"),
    (re.compile(r"Gamaredon|Shuckworm", re.I), "Gamaredon", "Nation-State", "Russia"),
    (re.compile(r"\bTurla\b|Venomous\s*Bear", re.I), "Turla", "Nation-State", "Russia"),
    # Nation-State: China
    (re.compile(r"\bAPT41\b|Winnti|Double\s*Dragon", re.I), "APT41", "Nation-State", "China"),
    (re.compile(r"Volt\s*Typhoon", re.I), "Volt Typhoon", "Nation-State", "China"),
    (re.compile(r"Salt\s*Typhoon", re.I), "Salt Typhoon", "Nation-State", "China"),
    (re.compile(r"Mustang\s*Panda", re.I), "Mustang Panda", "Nation-State", "China"),
    (re.compile(r"Silk\s*Typhoon|Hafnium", re.I), "Silk Typhoon", "Nation-State", "China"),
    # Nation-State: North Korea
    (re.compile(r"Lazarus|Hidden\s*Cobra", re.I), "Lazarus Group", "Nation-State", "North Korea"),
    (re.compile(r"Kimsuky|Emerald\s*Sleet", re.I), "Kimsuky", "Nation-State", "North Korea"),
    (re.compile(r"BlueNoroff|Sapphire\s*Sleet", re.I), "BlueNoroff", "Nation-State", "North Korea"),
    # Nation-State: Iran
    (re.compile(r"MuddyWater|Mango\s*Sandstorm", re.I), "MuddyWater", "Nation-State", "Iran"),
    (re.compile(r"Charming\s*Kitten|APT35|Mint\s*Sandstorm", re.I), "Charming Kitten", "Nation-State", "Iran"),
    (re.compile(r"CyberAv3ngers", re.I), "CyberAv3ngers", "Nation-State", "Iran"),
    (re.compile(r"\bHandala\b", re.I), "Handala", "Nation-State", "Iran"),
    # Ransomware
    (re.compile(r"LockBit", re.I), "LockBit", "Ransomware", "Criminal"),
    (re.compile(r"BlackCat|ALPHV", re.I), "BlackCat/ALPHV", "Ransomware", "Criminal"),
    (re.compile(r"\bCl0p\b|Clop", re.I), "Cl0p", "Ransomware", "Criminal"),
    (re.compile(r"\bAkira\b", re.I), "Akira", "Ransomware", "Criminal"),
    (re.compile(r"Black\s*Basta", re.I), "Black Basta", "Ransomware", "Criminal"),
    (re.compile(r"RansomHub", re.I), "RansomHub", "Ransomware", "Criminal"),
    (re.compile(r"\bQilin\b", re.I), "Qilin", "Ransomware", "Criminal"),
    (re.compile(r"Scattered\s*Spider|UNC3944", re.I), "Scattered Spider", "Cybercrime", "Unknown"),
    (re.compile(r"ShinyHunters", re.I), "ShinyHunters", "Cybercrime", "Unknown"),
]
