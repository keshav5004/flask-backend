"""
Similarity-based phishing and typosquatting detection service.

Analyzes URLs that are not found in the exact-match blacklist and
generates a risk score based on multiple heuristic signals:
  - Fuzzy string similarity to known malicious domains
  - Suspicious keyword presence (login, secure, verify, bank, etc.)
  - Suspicious TLD usage (.xyz, .tk, .ml, etc.)
  - IP address usage instead of domain
  - Excessive subdomain depth
  - Homoglyph / lookalike character substitutions
  - Hyphen abuse patterns
"""

import re
import difflib
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Optional


# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------
RISK_LEVELS = {
    "safe":       (0,  20),
    "low":        (21, 40),
    "medium":     (41, 60),
    "high":       (61, 80),
    "malicious":  (81, 100),
}

# Suspicious keywords frequently abused in phishing domains
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "amazon", "apple", "google", "microsoft",
    "facebook", "instagram", "netflix", "ebay", "wallet", "crypto", "support",
    "helpdesk", "password", "credential", "auth", "access", "validate",
    "recover", "unlock", "suspend", "limited", "alert", "urgent", "free",
    "winner", "prize", "reward", "bonus", "offer", "click", "download",
    "billing", "invoice", "receipt", "payment", "refund", "charge", "overdue",
    "statement", "portal", "service", "activation", "registration", "validation",
    "verification", "two-factor", "2fa", "mfa", "document", "doc-share",
    "file-access", "pdf-view", "shipping", "tracking", "delivery", "fedex",
    "ups", "usps", "dhl", "post", "mail", "inbox", "webmail", "cpanel",
    "outlook", "office365", "sharepoint", "onedrive", "chase", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "barclays", "metamask", "coinbase",
    "trustwallet", "binance", "ledger", "trezor", "phantom", "renew",
    "subscription", "expiration", "alert-verify", "urgent-action", "free-gift",
    "giftcard", "cashback", "reimbursement", "compensation", "webshield",
    "security", "protection", "safety", "official-site", "real-signin",
    "original-login"
]

# TLDs commonly abused in phishing/spam campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".club",
    ".online", ".site", ".website", ".tech", ".link", ".info", ".bid",
    ".win", ".loan", ".date", ".faith", ".review", ".trade", ".webcam",
    ".stream", ".gdn", ".men", ".work", ".party", ".download",
    ".pro", ".buzz", ".icu", ".rest", ".quest", ".cfd", ".sbs",
    ".click", ".lol", ".zip", ".mov", ".life", ".fit", ".surf",
    ".cc", ".cn", ".vip", ".bond", ".cam", ".shop", ".store", ".fun",
    ".live", ".space", ".science", ".cricket", ".kim", ".xin", ".tokyo",
    ".pub"
}

# Homoglyph map: lookalike Unicode/ASCII substitutions
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "rn": "m", "vv": "w", "l": "i", "i": "l", "cl": "d"
}

# Legitimate popular domains — used to detect brand impersonation
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "github.com", "youtube.com", "reddit.com", "wikipedia.org", "ebay.com",
    "yahoo.com", "bing.com", "adobe.com", "dropbox.com", "spotify.com",
    "tiktok.com", "whatsapp.com", "telegram.org", "discord.com", "twitch.tv",
]


class SimilarityChecker:
    """
    Performs multi-signal similarity analysis on a URL to determine
    how likely it is to be a phishing / lookalike site.
    """

    def __init__(self, blacklist: set):
        """
        Args:
            blacklist: Set of normalized malicious domains (from CSVBlacklistChecker).
        """
        self.blacklist = blacklist
        # Combine known-bad domains with popular targets for similarity comparison
        self._comparison_pool = list(blacklist) + POPULAR_DOMAINS
        
        # Precompute signatures for fast similarity searching
        import re
        self._comparison_cores = []
        for cand in self._comparison_pool:
            core = re.sub(r"\.(com|org|net|io|co)$", "", cand)
            L2 = len(core)
            S2 = set(core)
            cand_dups = L2 - len(S2)
            self._comparison_cores.append((cand, core, L2, S2, cand_dups))
            
        # Sort POPULAR_DOMAINS first so we prune search space quickly
        self._comparison_cores.sort(key=lambda x: x[0] in POPULAR_DOMAINS, reverse=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, url: str) -> Dict:
        """
        Full analysis pipeline for a single URL.

        Returns a dict with:
            risk_score      int  0-100
            risk_level      str  safe | low | medium | high | malicious
            similarity_score float  0.0-1.0 (highest match against comparison pool)
            matched_domain  str  the closest matching domain
            signals         list of human-readable detection notes
            detection_method str
        """
        domain = self._normalize(url)
        if not domain:
            return self._build_result(0, [], "", 0.0, "invalid")

        # Whitelist Check: If domain is a registered popular brand, it is Safe.
        if domain in POPULAR_DOMAINS:
            return self._build_result(0, ["This is a verified and trusted website."], domain, 1.0, "whitelist_bypass")

        signals = []
        score = 0

        # Signal 1: Fuzzy similarity to known malicious / popular domains
        similarity, matched = self._best_similarity(domain)
        if similarity >= 0.85:
            score += 45
            signals.append(f"This website looks very similar ({similarity:.0%} match) to a known dangerous site: {matched}")
        elif similarity >= 0.70:
            score += 30
            signals.append(f"This website closely resembles ({similarity:.0%} match) a known dangerous site: {matched}")
        elif similarity >= 0.55:
            score += 15
            signals.append(f"This website somewhat resembles ({similarity:.0%} match) a known site: {matched}")

        # Signal 2: Suspicious keyword in domain
        kw_hits = self._suspicious_keywords(domain)
        if kw_hits:
            kw_score = min(25, len(kw_hits) * 12)
            score += kw_score
            signals.append(f"Contains risky words often used by fake websites: {', '.join(kw_hits)}")

        # Signal 3: Suspicious TLD
        if self._has_suspicious_tld(domain):
            score += 15
            signals.append(f"Uses a web address ending that is commonly used by scam websites")

        # Signal 4: IP address used instead of domain
        if self._is_ip_address(domain):
            score += 20
            signals.append("Uses a number-based address instead of a normal website name — a common trick used by fake sites")

        # Signal 5: Excessive subdomain depth
        depth_penalty = self._subdomain_depth_penalty(domain)
        if depth_penalty > 0:
            score += depth_penalty
            signals.append("Website address is unusually long and complex — often a sign of a fake site")

        # Signal 6: Hyphen abuse
        if self._hyphen_abuse(domain):
            score += 10
            signals.append("Website name contains too many dashes — a common trick to mimic real websites")

        # Signal 7: Homoglyph substitution
        if self._has_homoglyphs(domain):
            score += 20
            signals.append("Website name uses look-alike characters to impersonate a real website")

        # Signal 8: Brand name in subdomain (not in SLD)
        brand_hit = self._brand_in_subdomain(domain)
        if brand_hit:
            score += 20
            signals.append(f"Tries to look like '{brand_hit}' but is not the official website")

        # Signal 9: Gibberish / high-entropy domain name
        if self._is_gibberish(domain):
            score += 20
            signals.append("Website name looks randomly generated — a strong indicator of a fake site")

        # Multi-signal bonus: when 3+ weak signals combine, elevate the score
        signal_count = len(signals)
        if signal_count >= 4:
            score += 15
        elif signal_count >= 3:
            score += 10

        # Cap at 100
        score = min(100, score)

        if not signals:
            signals.append("No warning signs found — this website appears safe")

        return self._build_result(score, signals, matched, similarity, "similarity_analysis")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
            domain = domain.split(":")[0].lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return url.lower()

    def _best_similarity(self, domain: str) -> Tuple[float, str]:
        """Return (best_ratio, matched_domain) from the comparison pool."""
        best_ratio = 0.0
        best_match = ""
        # Also compare the "core" domain (strip popular TLDs for cleaner comparison)
        core = re.sub(r"\.(com|org|net|io|co)$", "", domain)
        L1 = len(core)
        S1 = set(core)
        L1_dups = L1 - len(S1)
        
        matcher = difflib.SequenceMatcher(None, core, "")
        
        for candidate, cand_core, L2, S2, cand_dups in self._comparison_cores:
            # The current pruning threshold is the max of our base threshold (0.55) and the best ratio found so far
            threshold = best_ratio if best_ratio > 0.55 else 0.55
            
            # Dynamic length range check:
            # 2.0 * min(L1, L2) / (L1 + L2) >= threshold
            min_len = (threshold / (2.0 - threshold)) * L1
            max_len = ((2.0 - threshold) / threshold) * L1
            if not (min_len <= L2 <= max_len):
                continue
                
            # Dynamic character overlap bounds check
            common_bound = len(S1 & S2) + (L1_dups if L1_dups < cand_dups else cand_dups)
            if common_bound < 0.5 * threshold * (L1 + L2):
                continue
                
            matcher.set_seq2(cand_core)
            if matcher.quick_ratio() < threshold:
                continue
                
            ratio = matcher.ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = candidate
                
        return round(best_ratio, 4), best_match

    @staticmethod
    def _suspicious_keywords(domain: str) -> List[str]:
        hits = []
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain:
                hits.append(kw)
        return hits

    @staticmethod
    def _has_suspicious_tld(domain: str) -> bool:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        return False

    @staticmethod
    def _is_ip_address(domain: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    @staticmethod
    def _subdomain_depth_penalty(domain: str) -> int:
        parts = domain.split(".")
        depth = len(parts)
        if depth >= 5:
            return 15
        if depth >= 4:
            return 8
        return 0

    @staticmethod
    def _hyphen_abuse(domain: str) -> bool:
        # 2 or more hyphens in the domain label is suspicious
        sld = domain.split(".")[0]
        return sld.count("-") >= 2

    @staticmethod
    def _has_homoglyphs(domain: str) -> bool:
        for fake, real in HOMOGLYPHS.items():
            if fake in domain:
                # Check if replacing the glyph produces a known word
                candidate = domain.replace(fake, real)
                if candidate != domain:
                    return True
        return False

    @staticmethod
    def _is_gibberish(domain: str) -> bool:
        """
        Detect randomly generated / gibberish domain names.
        Checks for high consonant-to-vowel ratio and digit mixing.
        """
        sld = domain.split(".")[0].replace("-", "")
        if len(sld) < 4:
            return False

        vowels = set("aeiou")
        digits = sum(1 for c in sld if c.isdigit())
        letters = sum(1 for c in sld if c.isalpha())
        vowel_count = sum(1 for c in sld.lower() if c in vowels)

        # Domain has mixed digits and letters (e.g., dstrb013, platfrme013)
        has_mixed = digits >= 2 and letters >= 3

        # Very low vowel ratio suggests consonant-heavy gibberish
        vowel_ratio = vowel_count / max(letters, 1)
        is_consonant_heavy = vowel_ratio < 0.2 and letters >= 5

        # Long consonant sequences (3+ consonants in a row)
        consonant_runs = len(re.findall(r'[b-df-hj-np-tv-z]{4,}', sld.lower()))

        return has_mixed or is_consonant_heavy or consonant_runs >= 1

    @staticmethod
    def _brand_in_subdomain(domain: str) -> Optional[str]:
        parts = domain.split(".")
        if len(parts) < 3:
            return None
        # The subdomains are everything before the last two parts (SLD + TLD)
        subdomains = ".".join(parts[:-2])
        for brand_domain in POPULAR_DOMAINS:
            brand = brand_domain.split(".")[0]  # e.g., "paypal", "google"
            if brand in subdomains:
                return brand
        return None

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(score: int, signals: List[str], matched: str,
                      similarity: float, method: str) -> Dict:
        level = "safe"
        for lvl, (lo, hi) in RISK_LEVELS.items():
            if lo <= score <= hi:
                level = lvl
                break
        return {
            "risk_score": score,
            "risk_level": level,
            "similarity_score": round(similarity, 4),
            "matched_domain": matched,
            "signals": signals,
            "detection_method": method,
        }


def get_risk_label(risk_level: str) -> str:
    """Human-readable label for a risk level string."""
    return {
        "safe": "Safe",
        "low": "Low Risk",
        "medium": "Medium Risk",
        "high": "High Risk",
        "malicious": "Malicious",
    }.get(risk_level, "Unknown")


def get_risk_color(risk_level: str) -> str:
    """Bootstrap / CSS color class for a given risk level."""
    return {
        "safe": "#00ff88",
        "low": "#88ff00",
        "medium": "#ffaa00",
        "high": "#ff6600",
        "malicious": "#ff3366",
    }.get(risk_level, "#aaaaaa")
