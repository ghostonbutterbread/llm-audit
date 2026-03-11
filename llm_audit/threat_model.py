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

    # Desktop application prompt (different bug classes)
    DESKTOP_SYSTEM_PROMPT = """You are a security expert specializing in desktop application vulnerability research.
Given a list of past security advisories (CVEs/GHSAs) for a desktop application, your task is to:

1. Analyze vulnerability patterns specific to desktop apps
2. Identify root causes: memory safety, cryptography, input validation, access controls
3. Generate a threat model with bug classes relevant to desktop software
4. Prioritize based on severity and exploitability

Desktop app vulnerability categories:
- Cryptographic Failures (weak crypto, hardcoded keys)
- Broken Access Controls (privilege escalation, insufficient authorization)
- Insecure Design (security by design flaws)
- Buffer Overflows (memory safety issues)
- SQL Injection (local database access)
- Improper Input Validation (input sanitization)
- Race Conditions (TOCTOU, concurrency issues)
- Insecure Storage (credential storage, local data protection)
- Deserialization Issues (unsafe deserialization)

Output a JSON structure with:
- "threat_model": List of bug classes with descriptions
- "patterns": Common vulnerability patterns found
- "priority": Recommended priority order for testing
- "recommendations": Testing strategy for desktop apps"""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize threat model generator."""
        self.llm_client = llm_client or LLMClient(Config())

    def analyze_cves(self, advisories: List[Dict[str, Any]], bounty_data: Optional[Dict[str, Any]] = None, target_type: str = "web") -> Dict[str, Any]:
        """Analyze CVE list and bug bounty data to generate threat model."""
        if not advisories and not bounty_data:
            return self._default_threat_model(target_type=target_type, bounty_data=bounty_data)

        # Build CVE summary for LLM
        cve_summary = self._build_cve_summary(advisories)
        
        # Add bounty data to the summary
        bounty_summary = ""
        if bounty_data and "error" not in bounty_data:
            bounty_summary = self._build_bounty_summary(bounty_data)

        # Choose system prompt based on target type
        if target_type == "desktop":
            system_prompt = self.DESKTOP_SYSTEM_PROMPT
        else:
            system_prompt = self.SYSTEM_PROMPT

        prompt = f"""Analyze these security advisories and bug bounty program details to generate a threat model:

=== CVEs/Advisories ===
{cve_summary}

=== Bug Bounty Program ===
{bounty_summary}

=== Target Type ===
{target_type.upper()}

For each vulnerability type found, provide:
1. Bug class name (e.g., "SQL Injection", "XSS", "IDOR", "Buffer Overflow")
2. Root cause description
3. Attack vector
4. Severity (Critical/High/Medium/Low)
5. Code patterns to search for

Generate a structured threat model in JSON format."""

        response = self.llm_client.complete(prompt, system=system_prompt)

        try:
            # Try to parse JSON from response
            model = self._parse_json_response(response)
            if model:
                return model
        except Exception:
            pass

        # Fallback to structured analysis
        return self._generate_fallback_model(advisories, bounty_data, target_type)

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

    def _default_threat_model(self, target_type: str = "web", bounty_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return default threat model when no CVEs found."""
        # Use target-type-specific bug classes
        bug_classes = Config.get_bug_classes_by_target_type(target_type)
        
        # Build threat model from bug classes
        threat_model = []
        
        # Critical bugs
        for bug in bug_classes.get("critical", []):
            threat_model.append({
                "bug_class": bug,
                "description": self._get_bug_description(bug, target_type),
                "severity": "Critical",
                "patterns": self._get_bug_patterns(bug),
                "source": "default"
            })
        
        # High bugs
        for bug in bug_classes.get("high", []):
            threat_model.append({
                "bug_class": bug,
                "description": self._get_bug_description(bug, target_type),
                "severity": "High",
                "patterns": self._get_bug_patterns(bug),
                "source": "default"
            })
        
        # Medium bugs
        for bug in bug_classes.get("medium", []):
            threat_model.append({
                "bug_class": bug,
                "description": self._get_bug_description(bug, target_type),
                "severity": "Medium",
                "patterns": self._get_bug_patterns(bug),
                "source": "default"
            })
        
        # Add bug classes from bounty program if available
        if bounty_data and "error" not in bounty_data:
            bug_classes_list = bounty_data.get("bug_classes", [])
            if bug_classes_list:
                for bug in bug_classes_list:
                    threat_model.insert(0, {
                        "bug_class": bug,
                        "description": f"Found in bug bounty program: {bounty_data.get('program', 'unknown')}",
                        "severity": "High",
                        "patterns": [f"search for {bug.lower()}"],
                        "source": "bounty"
                    })
        
        # Build priority list
        priority = [item["bug_class"] for item in threat_model[:8]]
        
        # Get recommendations based on target type
        if target_type == "desktop":
            recommendations = "No historical CVEs found. Desktop app testing: prioritize cryptographic failures, buffer overflows, and insecure storage. Check for hardcoded credentials, improper input validation, and race conditions."
        else:
            recommendations = "No historical CVEs found. Use comprehensive testing covering common web vulnerability classes. Prioritize IDOR, authentication issues, and data leaks based on bug bounty focus areas."
        
        return {
            "threat_model": threat_model,
            "patterns": [
                "Input validation missing",
                "Authorization checks missing",
                "Insecure deserialization",
                "Security misconfiguration"
            ],
            "priority": priority,
            "recommendations": recommendations
        }

    def _get_bug_description(self, bug: str, target_type: str) -> str:
        """Get description for a bug class."""
        descriptions = {
            # Desktop-specific
            "Buffer Overflow": "Memory safety issues allowing arbitrary code execution",
            "Deserialization Issues": "Unsafe deserialization leading to code execution",
            "Improper Input Validation": "Insufficient validation of user input",
            "Cryptographic Failures": "Weak cryptography or improper key management",
            "Broken Access Controls": "Privilege escalation or insufficient authorization",
            "Insecure Design": "Security design flaws in application architecture",
            "Insecure Storage": "Insecure storage of credentials or sensitive data",
            "Race Conditions": "TOCTOU and concurrency issues",
            # Web-specific
            "SQL Injection": "SQL injection via unsanitized input",
            "Remote Code Execution (RCE)": "Arbitrary code execution via user input",
            "Authentication Bypass": "Circumvention of authentication mechanisms",
            "IDOR (Insecure Direct Object Reference)": "Unauthorized access to resources",
            "Path Traversal": "Directory traversal via unsanitized paths",
            "Cross-Site Scripting (XSS)": "Cross-site scripting vulnerabilities",
            "XML External Entity (XXE)": "XML external entity injection",
            "Server-Side Request Forgery (SSRF)": "Server-side request forgery",
            "Command Injection": "Command injection via user input",
            "Information Disclosure": "Exposure of sensitive data",
        }
        return descriptions.get(bug, f"{bug} vulnerability")

    def _get_bug_patterns(self, bug: str) -> List[str]:
        """Get code patterns to search for a bug class."""
        patterns = {
            "SQL Injection": ["raw SQL", "string concat", "execute() with user input"],
            "XSS": ["innerHTML", "dangerouslySetInnerHTML", "document.write"],
            "IDOR": ["user_id param", "object id", "resource access"],
            "Buffer Overflow": ["strcpy", "sprintf", "gets", "unsafe pointer"],
            "Cryptographic Failures": ["MD5", "SHA1", "hardcoded key", "ECB mode"],
            "Command Injection": ["exec()", "system()", "popen()", "shell=True"],
            "Insecure Storage": ["sharedpreferences", "userdefaults", "plaintext password"],
            "Race Conditions": ["race condition", "concurrent", "mutex", "lock"],
        }
        return patterns.get(bug, [f"search for {bug.lower()}"])

    def _generate_fallback_model(self, advisories: List[Dict[str, Any]], bounty_data: Optional[Dict[str, Any]] = None, target_type: str = "web") -> Dict[str, Any]:
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
                # Desktop-specific
                "Buffer Overflow": ["buffer", "overflow", "heap", "stack"],
                "Cryptographic Failures": ["crypto", "encryption", "key", "certificate"],
                "Race Conditions": ["race", "toctou", "concurrent", "concurrency"],
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

        # Add default high-priority bugs from config based on target type
        priority_bugs = Config.get_bug_classes_by_target_type(target_type).get("high", [])
        for pb in priority_bugs[:5]:
            pb_name = pb.upper() if pb.lower() in ["idor", "xss", "ssrf"] else pb
            if pb_name not in bug_classes:
                bug_classes[pb_name] = {
                    "bug_class": pb_name,
                    "severity": "HIGH",
                    "count": 0,
                    "samples": [],
                    "priority": True
                }

        # Add bounty program bug classes if available
        if bounty_data and "error" not in bounty_data:
            bug_classes_from_bounty = bounty_data.get("bug_classes", [])
            if bug_classes_from_bounty:
                for bug in bug_classes_from_bounty:
                    if bug.upper() not in [b.get("bug_class", "").upper() for b in bug_classes.values()]:
                        bug_classes[bug] = {
                            "bug_class": bug,
                            "severity": "HIGH",
                            "count": 0,
                            "samples": [],
                            "source": "bounty"
                        }

        return {
            "threat_model": list(bug_classes.values()),
            "patterns": [f"Found {len(advisories)} historical vulnerabilities"],
            "priority": list(bug_classes.keys()),
            "recommendations": f"Based on {len(advisories)} historical advisories for {target_type} app. Focus on {', '.join(bug_classes.keys())}."
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


def generate_threat_model(advisories: List[Dict[str, Any]], llm_client: Optional[LLMClient] = None, bounty_data: Optional[Dict[str, Any]] = None, target_type: str = "web") -> Dict[str, Any]:
    """Convenience function to generate threat model.
    
    Args:
        advisories: List of CVE/GHSA advisory dictionaries
        llm_client: LLM client for AI-powered analysis
        bounty_data: Bug bounty program data from bounty_finder
        target_type: Target type - "web" or "desktop"
    """
    generator = ThreatModelGenerator(llm_client)
    return generator.analyze_cves(advisories, bounty_data, target_type)