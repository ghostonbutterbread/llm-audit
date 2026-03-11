"""Generate threat models from CVE patterns using LLM."""

import json
from typing import List, Dict, Any, Optional
from .config import Config
from .llm_client import LLMClient


class ThreatModelGenerator:
    """Generate threat model from CVE patterns."""

    SYSTEM_PROMPT = """You are a security expert specializing in vulnerability research and threat modeling.
Given a list of past security advisories (CVEs/GHSAs) for a software project, your task is to:

1. Analyze the vulnerability patterns
2. Identify the root causes and attack vectors
3. Generate a threat model with specific bug classes to hunt for
4. Prioritize based on severity and likelihood

Output a JSON structure with:
- "threat_model": List of bug classes with descriptions
- "patterns": Common vulnerability patterns found
- "priority": Recommended priority order for testing
- "recommendations": Testing strategy recommendations"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize threat model generator."""
        self.llm_client = llm_client or LLMClient(Config())

    def analyze_cves(self, advisories: List[Dict[str, Any]], bounty_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze CVE list and bug bounty data to generate threat model."""
        if not advisories and not bounty_data:
            return self._default_threat_model()

        # Build CVE summary for LLM
        cve_summary = self._build_cve_summary(advisories)
        
        # Add bounty data to the summary
        bounty_summary = ""
        if bounty_data and "error" not in bounty_data:
            bounty_summary = self._build_bounty_summary(bounty_data)

        prompt = f"""Analyze these security advisories and bug bounty program details to generate a threat model:

=== CVEs/Advisories ===
{cve_summary}

=== Bug Bounty Program ===
{bounty_summary}

For each vulnerability type found, provide:
1. Bug class name (e.g., "SQL Injection", "XSS", "IDOR")
2. Root cause description
3. Attack vector
4. Severity (Critical/High/Medium/Low)
5. Code patterns to search for

Generate a structured threat model in JSON format."""

        response = self.llm_client.complete(prompt, system=self.SYSTEM_PROMPT)

        try:
            # Try to parse JSON from response
            model = self._parse_json_response(response)
            if model:
                return model
        except Exception:
            pass

        # Fallback to structured analysis
        return self._generate_fallback_model(advisories)

    def _build_cve_summary(self, advisories: List[Dict[str, Any]]) -> str:
        """Build summary text from advisories."""
        lines = []
        for adv in advisories[:20]:  # Limit to 20
            ghsa = adv.get("ghsa_id", adv.get("ghsaId", "N/A"))
            summary = adv.get("summary", adv.get("description", ""))
            severity = adv.get("severity", "UNKNOWN")
            package = adv.get("package", "")

            lines.append(f"- {ghsa} [{severity}] {package}: {summary[:200]}")

        return "\n".join(lines) if lines else "No specific advisories found."

    def _build_bounty_summary(self, bounty_data: Dict[str, Any]) -> str:
        """Build summary text from bug bounty data."""
        if not bounty_data or "error" in bounty_data:
            return "No bug bounty data available."
        
        lines = []
        lines.append(f"Platform: {bounty_data.get('platform', 'unknown')}")
        lines.append(f"Program: {bounty_data.get('program', 'unknown')}")
        
        bug_classes = bounty_data.get("bug_classes", [])
        if bug_classes:
            lines.append(f"Accepted bug types: {', '.join(bug_classes)}")
        
        scope = bounty_data.get("scope", [])
        if scope:
            lines.append(f"In-scope assets: {len(scope)} items")
        
        severity = bounty_data.get("severity_breakdown", {})
        if severity:
            lines.append(f"Severity info: {severity}")
        
        return "\n".join(lines)

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Try to parse JSON from LLM response."""
        # Look for JSON block
        import re

        # Try markdown code block
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if json_match:
            return json.loads(json_match.group(1))

        # Try raw JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())

        return None

    def _default_threat_model(self, bounty_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return default threat model when no CVEs found."""
        # Start with default bugs
        threat_model = [
            {
                "bug_class": "Authentication Bypass",
                "description": "Circumvention of authentication mechanisms",
                "severity": "Critical",
                "patterns": ["session bypass", "weak auth check", "missing @auth"]
            },
            {
                "bug_class": "IDOR",
                "description": "Insecure Direct Object Reference - unauthorized access to resources",
                "severity": "High",
                "patterns": ["user_id param", "object id", "resource access"]
            },
            {
                "bug_class": "SQL Injection",
                "description": "SQL injection via unsanitized input",
                "severity": "Critical",
                "patterns": ["raw SQL", "string concat", "execute() with user input"]
            },
            {
                "bug_class": "XSS",
                "description": "Cross-site scripting vulnerabilities",
                "severity": "High",
                "patterns": ["innerHTML", "dangerouslySetInnerHTML", "document.write"]
            },
            {
                "bug_class": "SSRF",
                "description": "Server-Side Request Forgery",
                "severity": "High",
                "patterns": ["fetch URL", "requests.get", "urllib open"]
            },
            {
                "bug_class": "Command Injection",
                "description": "Command injection via user input",
                "severity": "Critical",
                "patterns": ["exec()", "system()", "popen()", "shell=True"]
            },
            {
                "bug_class": "Path Traversal",
                "description": "Directory traversal via unsanitized paths",
                "severity": "High",
                "patterns": ["open file", "path join", "../../"]
            },
            {
                "bug_class": "Data Leakage",
                "description": "Exposure of sensitive data",
                "severity": "High",
                "patterns": ["api key", "token", "password", "secret", "PII"]
            }
        ]
        
        # Add bug classes from bounty program if available
        if bounty_data and "error" not in bounty_data:
            bug_classes = bounty_data.get("bug_classes", [])
            if bug_classes:
                # Add bounty-specific bugs to the front with high priority
                for bug in bug_classes:
                    threat_model.insert(0, {
                        "bug_class": bug,
                        "description": f"Found in bug bounty program: {bounty_data.get('program', 'unknown')}",
                        "severity": "High",
                        "patterns": [f"search for {bug.lower()}"],
                        "source": "bounty"
                    })
        
        return {
            "threat_model": threat_model,
            "patterns": [
                "Input validation missing",
                "Authorization checks missing",
                "Insecure deserialization",
                "Security misconfiguration"
            ],
            "priority": [
                "IDOR",
                "Authentication Bypass",
                "Data Leakage",
                "SQL Injection",
                "XSS",
                "Command Injection",
                "SSRF",
                "Path Traversal"
            ],
            "recommendations": "No historical CVEs found. Use comprehensive testing covering common vulnerability classes. Prioritize IDOR, authentication issues, and data leaks based on bug bounty focus areas."
        }

    def _generate_fallback_model(self, advisories: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate model from advisory patterns without LLM."""
        bug_classes = {}

        for adv in advisories:
            desc = adv.get("summary", "").lower()
            severity = adv.get("severity", "medium").upper()

            # Classify based on keywords
            keywords = {
                "SQL Injection": ["sql", "injection", "database", "query"],
                "XSS": ["xss", "cross-site", "scripting", "html injection"],
                "RCE": ["rce", "remote code", "exec", "command injection"],
                "IDOR": ["idor", "authorization", "access control", "permission"],
                "SSRF": ["ssrf", "request forgery", "fetch", "url"],
                "Path Traversal": ["path traversal", "directory", "traversal", "lfi"],
                "Info Leak": ["information disclosure", "leak", "sensitive", "exposure"],
            }

            for bug_class, kws in keywords.items():
                if any(kw in desc for kw in kws):
                    if bug_class not in bug_classes:
                        bug_classes[bug_class] = {
                            "bug_class": bug_class,
                            "severity": severity,
                            "count": 0,
                            "samples": []
                        }
                    bug_classes[bug_class]["count"] += 1
                    bug_classes[bug_class]["samples"].append(adv.get("ghsa_id", ""))

        # Add default high-priority bugs from config
        priority_bugs = Config.get_priority_bugs()
        for pb in priority_bugs:
            pb_name = pb.upper() if pb.lower() in ["idor", "xss", "ssrf"] else pb
            if pb_name not in bug_classes:
                bug_classes[pb_name] = {
                    "bug_class": pb_name,
                    "severity": "HIGH",
                    "count": 0,
                    "samples": [],
                    "priority": True
                }

        return {
            "threat_model": list(bug_classes.values()),
            "patterns": [f"Found {len(advisories)} historical vulnerabilities"],
            "priority": list(bug_classes.keys()),
            "recommendations": f"Based on {len(advisories)} historical advisories. Focus on {', '.join(bug_classes.keys())}."
        }

    def format_threat_model(self, model: Dict[str, Any]) -> str:
        """Format threat model as readable text."""
        lines = ["=" * 60, "THREAT MODEL", "=" * 60, ""]

        lines.append("VULNERABILITY CLASSES TO HUNT:")
        lines.append("-" * 40)

        for item in model.get("threat_model", []):
            sev = item.get("severity", "UNKNOWN")
            bug = item.get("bug_class", "Unknown")
            desc = item.get("description", "")[:60]
            count = item.get("count", "")

            count_str = f" ({count} found)" if count else ""
            lines.append(f"[{sev}] {bug}{count_str}")
            lines.append(f"    {desc}")
            lines.append("")

        lines.append("RECOMMENDED TESTING ORDER:")
        lines.append("-" * 40)
        for i, bug in enumerate(model.get("priority", [])[:5], 1):
            lines.append(f"  {i}. {bug}")

        lines.append("")
        lines.append("RECOMMENDATIONS:")
        lines.append("-" * 40)
        lines.append(model.get("recommendations", ""))

        return "\n".join(lines)


def generate_threat_model(advisories: List[Dict[str, Any]], llm_client: Optional[LLMClient] = None, bounty_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convenience function to generate threat model.
    
    Args:
        advisories: List of CVE/GHSA advisory dictionaries
        llm_client: LLM client for AI-powered analysis
        bounty_data: Bug bounty program data from bounty_finder
    """
    generator = ThreatModelGenerator(llm_client)
    return generator.analyze_cves(advisories, bounty_data)