"""MITRE ATT&CK technique tagger.

Maps articles to ATT&CK techniques using keyword-based pattern matching.
Zero cost — runs entirely locally with compiled regex patterns.

Each article gets a list of matched ATT&CK technique IDs with names,
grouped by tactic. This transforms news articles into structured
threat intelligence with TTP context.
"""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ATT&CK technique patterns: (technique_id, technique_name, tactic, regex_pattern)
# Covers the most commonly referenced techniques in threat reporting.
_TECHNIQUE_PATTERNS = [
    # Initial Access
    ("T1566", "Phishing", "Initial Access",
     re.compile(r"phishing|spearphish|email\s+lure|credential\s+harvest|fake\s+login|smishing|vishing", re.I)),
    ("T1566.001", "Spearphishing Attachment", "Initial Access",
     re.compile(r"spearphish.*attach|malicious\s+(attachment|document|pdf|docx|xlsx)", re.I)),
    ("T1566.002", "Spearphishing Link", "Initial Access",
     re.compile(r"spearphish.*link|phishing\s+link|malicious\s+url|lookalike\s+domain", re.I)),
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     re.compile(r"exploit.*public.facing|web\s+shell|rce\s+in\s+.{0,30}(server|appliance|gateway)", re.I)),
    ("T1133", "External Remote Services", "Initial Access",
     re.compile(r"vpn\s+(exploit|compromise|vulnerability)|rdp\s+(brute|exposed|attack)", re.I)),
    ("T1195", "Supply Chain Compromise", "Initial Access",
     re.compile(r"supply[\s-]chain\s+(attack|compromise)|dependency\s+confusion|trojanized\s+update", re.I)),
    ("T1078", "Valid Accounts", "Initial Access",
     re.compile(r"stolen\s+credentials|credential\s+stuffing|compromised\s+accounts?|valid\s+accounts", re.I)),

    # Execution
    ("T1059", "Command and Scripting Interpreter", "Execution",
     re.compile(r"powershell\s+(attack|malicious|payload)|malicious\s+(script|macro|vba|python)", re.I)),
    ("T1204", "User Execution", "Execution",
     re.compile(r"social\s+engineering\s+attack|trick.*(open|click|execute)|lure.*execute", re.I)),

    # Persistence
    ("T1547", "Boot or Logon Autostart Execution", "Persistence",
     re.compile(r"registry\s+persistence|autostart|startup\s+folder\s+malware|boot\s+persistence", re.I)),
    ("T1053", "Scheduled Task/Job", "Persistence",
     re.compile(r"scheduled\s+task\s+persistence|cron\s+job\s+malware|at\s+job\s+persistence", re.I)),

    # Privilege Escalation
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
     re.compile(r"privilege\s+escalation|local\s+privilege|kernel\s+exploit|root\s+exploit|elevation\s+of\s+privilege", re.I)),

    # Defense Evasion
    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
     re.compile(r"obfuscated|packed\s+malware|encrypted\s+payload|code\s+obfuscation|packing\s+technique", re.I)),
    ("T1562", "Impair Defenses", "Defense Evasion",
     re.compile(r"disable.*antivirus|bypass.*edr|edr\s+evasion|tamper.*security|impair\s+defenses", re.I)),
    ("T1070", "Indicator Removal", "Defense Evasion",
     re.compile(r"clear\s+event\s+logs|delete.*evidence|anti.forensic|indicator\s+removal", re.I)),

    # Credential Access
    ("T1003", "OS Credential Dumping", "Credential Access",
     re.compile(r"credential\s+dump|mimikatz|lsass\s+dump|ntds\.dit|password\s+hash\s+dump", re.I)),
    ("T1110", "Brute Force", "Credential Access",
     re.compile(r"brute\s+force\s+attack|password\s+spray|credential\s+stuffing", re.I)),
    ("T1539", "Steal Web Session Cookie", "Credential Access",
     re.compile(r"session\s+(hijack|steal|token\s+theft)|cookie\s+theft|steal.*session", re.I)),

    # Lateral Movement
    ("T1021", "Remote Services", "Lateral Movement",
     re.compile(r"lateral\s+movement|rdp\s+lateral|psexec|smb\s+lateral|wmi\s+lateral", re.I)),

    # Collection
    ("T1005", "Data from Local System", "Collection",
     re.compile(r"data\s+exfiltration|steal.*data|harvest.*(file|data|document)", re.I)),
    ("T1119", "Automated Collection", "Collection",
     re.compile(r"automated\s+collection|mass\s+data\s+collection|bulk\s+harvest", re.I)),

    # Command and Control
    ("T1071", "Application Layer Protocol", "Command and Control",
     re.compile(r"\bc2\b.*server|command\s+and\s+control|cobalt\s*strike|beacon|c2\s+(channel|traffic|infrastructure)", re.I)),
    ("T1573", "Encrypted Channel", "Command and Control",
     re.compile(r"encrypted\s+c2|https\s+c2|dns\s+tunnel|covert\s+channel", re.I)),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     re.compile(r"download.*payload|stage[dr]?\s+payload|tool\s+transfer|drop.*second.stage", re.I)),

    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     re.compile(r"exfiltrat.*c2|data\s+exfiltration|stolen\s+data.*upload|exfiltrate.*server", re.I)),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration",
     re.compile(r"exfiltrat.*(cloud|telegram|discord|pastebin|google\s+drive)", re.I)),

    # Impact
    ("T1486", "Data Encrypted for Impact", "Impact",
     re.compile(r"ransomware|encrypted\s+files|ransom\s+demand|file\s+encryption\s+attack", re.I)),
    ("T1489", "Service Stop", "Impact",
     re.compile(r"wiper\s+malware|destructive\s+malware|kill\s+switch|service\s+disruption\s+attack", re.I)),
    ("T1498", "Network Denial of Service", "Impact",
     re.compile(r"\bddos\b|denial\s+of\s+service|volumetric\s+attack|flood\s+attack", re.I)),
    ("T1531", "Account Access Removal", "Impact",
     re.compile(r"account\s+lockout\s+attack|mass\s+password\s+reset|access\s+removal", re.I)),

    # Resource Development
    ("T1588", "Obtain Capabilities", "Resource Development",
     re.compile(r"exploit\s+kit|malware.as.a.service|raas|stealer.as.a.service", re.I)),
    ("T1583", "Acquire Infrastructure", "Resource Development",
     re.compile(r"bulletproof\s+hosting|malicious\s+infrastructure|c2\s+infrastructure\s+setup", re.I)),
]


def tag_article_with_attack(article: dict) -> dict:
    """Tag a single article with matching ATT&CK techniques.

    Scans title, summary, and full_content for technique patterns.
    Returns article with added 'attack_techniques' and 'attack_tactics' fields.
    """
    text = " ".join(filter(None, [
        article.get("title", ""),
        article.get("summary", ""),
        article.get("translated_title", ""),
        (article.get("full_content", "") or "")[:2000],
    ]))

    if not text:
        return article

    matched = []
    seen_ids = set()

    for tech_id, tech_name, tactic, pattern in _TECHNIQUE_PATTERNS:
        if tech_id not in seen_ids and pattern.search(text):
            matched.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tactic,
            })
            seen_ids.add(tech_id)
            # Also add parent technique if this is a sub-technique
            parent_id = tech_id.split(".")[0]
            if parent_id != tech_id and parent_id not in seen_ids:
                parent = next(
                    (t for t in _TECHNIQUE_PATTERNS if t[0] == parent_id),
                    None,
                )
                if parent:
                    matched.append({
                        "technique_id": parent[0],
                        "technique_name": parent[1],
                        "tactic": parent[2],
                    })
                    seen_ids.add(parent[0])

    if not matched:
        return article

    # Group by tactic for structured output
    tactics = sorted(set(m["tactic"] for m in matched))

    return {
        **article,
        "attack_techniques": matched,
        "attack_tactics": tactics,
    }


def tag_articles_with_attack(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch version — tag all articles with ATT&CK techniques."""
    tagged = [tag_article_with_attack(a) for a in articles]
    tagged_count = sum(1 for a in tagged if a.get("attack_techniques"))
    logger.info(
        f"ATT&CK: tagged {tagged_count}/{len(articles)} articles with "
        f"MITRE ATT&CK techniques"
    )
    return tagged
