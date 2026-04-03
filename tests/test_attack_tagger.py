import pytest

from modules.attack_tagger import tag_article_with_attack, tag_articles_with_attack


class TestTagArticleWithAttack:
    def test_tags_phishing_article(self):
        article = {"title": "Spearphishing campaign targets government agencies"}
        result = tag_article_with_attack(article)
        assert "attack_techniques" in result
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1566" in ids
        assert "Initial Access" in result["attack_tactics"]

    def test_tags_ransomware_article(self):
        article = {"title": "LockBit ransomware encrypts hospital files"}
        result = tag_article_with_attack(article)
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1486" in ids  # Data Encrypted for Impact
        assert "Impact" in result["attack_tactics"]

    def test_tags_ddos_article(self):
        article = {"title": "Massive DDoS attack takes down banking services"}
        result = tag_article_with_attack(article)
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1498" in ids

    def test_tags_multiple_techniques(self):
        article = {
            "title": "APT group uses spearphishing to deliver Cobalt Strike beacon",
            "summary": "Lateral movement via RDP observed after initial compromise",
        }
        result = tag_article_with_attack(article)
        assert len(result["attack_techniques"]) >= 2
        assert len(result["attack_tactics"]) >= 2

    def test_no_tags_for_generic_article(self):
        article = {"title": "Cybersecurity market grows 15% in 2026"}
        result = tag_article_with_attack(article)
        assert "attack_techniques" not in result

    def test_includes_parent_technique(self):
        article = {"title": "Spearphishing attachment with malicious PDF payload"}
        result = tag_article_with_attack(article)
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1566.001" in ids
        assert "T1566" in ids  # parent should be included

    def test_tags_supply_chain(self):
        article = {"title": "Supply chain compromise via trojanized software update"}
        result = tag_article_with_attack(article)
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1195" in ids

    def test_tags_credential_dumping(self):
        article = {"title": "Attackers use mimikatz to dump credentials from LSASS"}
        result = tag_article_with_attack(article)
        ids = [t["technique_id"] for t in result["attack_techniques"]]
        assert "T1003" in ids


class TestBatchTagging:
    def test_batch_tags_articles(self):
        articles = [
            {"title": "Phishing campaign targets users"},
            {"title": "DDoS hits major CDN"},
            {"title": "New market report released"},
        ]
        result = tag_articles_with_attack(articles)
        assert len(result) == 3
        tagged = [a for a in result if a.get("attack_techniques")]
        assert len(tagged) == 2
