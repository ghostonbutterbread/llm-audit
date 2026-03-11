"""Bug bounty platform integration for threat modeling."""
import re
import requests
from typing import Dict, Any, Optional


class BountyPlatform:
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    UNKNOWN = "unknown"


class BountyFinder:
    PLATFORM_PATTERNS = {
        BountyPlatform.HACKERONE: r"hackerone\.com/",
        BountyPlatform.BUGCROWD: r"bugcrowd\.com/",
    }

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "LLM-Audit/1.0"})

    def detect_platform(self, url: str) -> str:
        for p, pat in self.PLATFORM_PATTERNS.items():
            if re.search(pat, url, re.I):
                return p
        return BountyPlatform.UNKNOWN

    def extract_handle(self, url: str, platform: str) -> Optional[str]:
        if platform == BountyPlatform.HACKERONE:
            m = re.search(r"hackerone\.com/(?:programs/)?([a-zA-Z0-9_-]+)", url)
            if m:
                return m.group(1)
        elif platform == BountyPlatform.BUGCROWD:
            m = re.search(r"bugcrowd\.com/(?:vendors|programs)/([a-zA-Z0-9_-]+)", url)
            if m:
                return m.group(1)
        return None

    def fetch_program(self, url: str) -> Dict[str, Any]:
        platform = self.detect_platform(url)
        if platform == BountyPlatform.UNKNOWN:
            return {"error": "Unknown platform", "platform": "unknown"}
        handle = self.extract_handle(url, platform)
        if not handle:
            return {"error": "Could not extract handle", "platform": platform}
        if platform == BountyPlatform.HACKERONE:
            return self._fetch_hackerone(handle)
        elif platform == BountyPlatform.BUGCROWD:
            return self._fetch_bugcrowd(handle)
        return {"error": "Unsupported", "platform": platform}

    def _fetch_hackerone(self, slug: str) -> Dict[str, Any]:
        try:
            r = self.session.get(f"https://hackerone.com/programs/{slug}", timeout=15)
            if r.status_code == 200:
                return self._parse_h1(r.text, slug)
        except:
            pass
        return {"error": "Not found", "platform": "hackerone"}

    def _parse_h1(self, html: str, slug: str) -> Dict[str, Any]:
        bugs = []
        kws = {"SQL Injection": "sql", "XSS": "xss", "IDOR": "idor", "RCE": "rce", 
               "SSRF": "ssrf", "Info Disclosure": "information"}
        hl = html.lower()
        for b, k in kws.items():
            if k in hl:
                bugs.append(b)
        return {"platform": "hackerone", "program": slug, 
                "bug_classes": bugs or ["XSS", "SQLi", "IDOR"],
                "scope": [], "severity_breakdown": {}}

    def _fetch_bugcrowd(self, slug: str) -> Dict[str, Any]:
        for path in ["vendors", "programs"]:
            try:
                r = self.session.get(f"https://bugcrowd.com/{path}/{slug}", timeout=15)
                if r.status_code == 200:
                    return self._parse_bc(r.text, slug)
            except:
                pass
        return {"error": "Not found", "platform": "bugcrowd"}

    def _parse_bc(self, html: str, slug: str) -> Dict[str, Any]:
        bugs = []
        kws = {"SQL Injection": "sql", "XSS": "xss", "IDOR": "idor", "RCE": "rce"}
        hl = html.lower()
        for b, k in kws.items():
            if k in hl:
                bugs.append(b)
        return {"platform": "bugcrowd", "program": slug,
                "bug_classes": bugs or ["XSS", "SQLi", "IDOR"],
                "scope": [], "severity_breakdown": {}}


def find_bounty(url: str) -> Dict[str, Any]:
    """Convenience function to find bounty program info."""
    finder = BountyFinder()
    return finder.fetch_program(url)