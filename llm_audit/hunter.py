"""LLM-powered vulnerability hunter."""

import json
import re
from typing import List, Dict, Any, Optional
from .llm_client import LLMClient
from .slicer import CodeSlicer
from .config import Config


class VulnerabilityHunter:
    """Hunt for vulnerabilities using LLM analysis of code slices."""

    HUNTING_PROMPT = """You are an expert security vulnerability researcher.

Your task is to analyze code for specific vulnerability types based on a threat model.

THREAT MODEL BUG CLASS: {bug_class}

CODE SLICE:
```{language}
{code}
```

Instructions:
1. Analyze the code carefully for {bug_class} vulnerabilities
2. Look for common patterns and anti-patterns
3. Consider the attack surface and input flows
4. Assess each finding for exploitability

For each vulnerability found, provide:
- **Location**: File, function, and line reference
- **Issue**: Clear description of the vulnerability
- **Severity**: Critical/High/Medium/Low with justification
- **Impact**: Potential security impact
- **PoC**: Simple proof of concept (if applicable)

Respond in this JSON format:
```json
{{
  "bug_class": "{bug_class}",
  "findings": [
    {{
      "location": "path/to/file:function() or line ~42",
      "issue": "description of the vulnerability",
      "severity": "High",
      "impact": "security impact",
      "poc": "proof of concept code or steps"
    }}
  ],
  "summary": "brief summary of findings"
}}
```

If no vulnerabilities are found, respond with:
```json
{{"bug_class": "{bug_class}", "findings": [], "summary": "No {bug_class} vulnerabilities found in this code slice."}}
```"""

    # Desktop-specific hunting prompt
    DESKTOP_HUNTING_PROMPT = """You are an expert security vulnerability researcher specializing in desktop applications.

Your task is to analyze desktop application code for specific vulnerability types.

THREAT MODEL BUG CLASS: {bug_class}

APPLICATION TYPE: Desktop Application (Python/Electron/Java/Rust/C++)
CODE SLICE:
```{language}
{code}
```

Desktop-specific considerations:
- Memory safety issues (buffer overflows, use-after-free)
- Cryptographic failures (hardcoded keys, weak crypto)
- Insecure storage (credentials in config files, plaintext passwords)
- Input validation (file paths, command-line args, network input)
- Race conditions (file access, concurrent operations)
- Privilege escalation (missing permission checks)
- Deserialization issues (pickle, YAML, JSON)

Instructions:
1. Analyze the code carefully for {bug_class} vulnerabilities
2. Look for common patterns and anti-patterns in desktop apps
3. Consider the attack surface: files, network, IPC, CLI args
4. Assess each finding for exploitability and impact

For each vulnerability found, provide:
- **Location**: File, function, and line reference
- **Issue**: Clear description of the vulnerability
- **Severity**: Critical/High/Medium/Low with justification
- **Impact**: Potential security impact
- **PoC**: Simple proof of concept (if applicable)

Respond in this JSON format:
```json
{{
  "bug_class": "{bug_class}",
  "findings": [
    {{
      "location": "path/to/file:function() or line ~42",
      "issue": "description of the vulnerability",
      "severity": "High",
      "impact": "security impact",
      "poc": "proof of concept code or steps"
    }}
  ],
  "summary": "brief summary of findings"
}}
```

If no vulnerabilities are found, respond with:
```json
{{"bug_class": "{bug_class}", "findings": [], "summary": "No {bug_class} vulnerabilities found in this code slice."}}"""

    def __init__(self, llm_client: Optional[LLMClient] = None, config: Optional[Config] = None):
        """Initialize vulnerability hunter."""
        self.llm_client = llm_client or LLMClient(config)
        self.config = config or Config()
        self.slicer = CodeSlicer(config)
        self.findings = []

    def hunt(self, target: str, threat_model: Dict[str, Any], max_slices: int = 20, verbose: bool = False, target_type: str = "web") -> List[Dict[str, Any]]:
        """Hunt for vulnerabilities in target based on threat model."""
        self.target_type = target_type  # Store for use in _analyze_slice
        
        # Get code slices
        print(f"[*] Slicing codebase: {target}")
        slices = self.slicer.slice_target(target)
        slice_summary = self.slicer.get_slice_summary(slices)
        print(f"[*] {slice_summary}")

        if not slices:
            print("[!] No code slices found")
            return []

        # Get bug classes from threat model
        bug_classes = self._extract_bug_classes(threat_model)
        print(f"[*] Hunting for {len(bug_classes)} vulnerability classes")

        # Analyze each bug class across slices
        all_findings = []

        for bug_class in bug_classes:
            print(f"\n[*] Hunting: {bug_class}")

            # Limit slices to analyze
            slices_to_analyze = slices[:max_slices]

            for i, slice_data in enumerate(slices_to_analyze):
                if verbose:
                    print(f"    Analyzing slice {i+1}/{len(slices_to_analyze)}: {slice_data.get('path', 'unknown')}")

                try:
                    findings = self._analyze_slice(slice_data, bug_class)
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    if verbose:
                        print(f"    [!] Error: {e}")
                    continue

        self.findings = all_findings
        return all_findings

    def _extract_bug_classes(self, threat_model: Dict[str, Any]) -> List[str]:
        """Extract bug classes from threat model."""
        bug_classes = []

        # From threat_model list
        for item in threat_model.get("threat_model", []):
            bug_class = item.get("bug_class", "")
            if bug_class:
                bug_classes.append(bug_class)

        # From priority list
        for bug in threat_model.get("priority", []):
            if bug not in bug_classes:
                bug_classes.append(bug)

        # Fallback to priority bugs
        if not bug_classes:
            bug_classes = self.config.get_priority_bugs()

        return bug_classes

    def _analyze_slice(self, slice_data: Dict[str, Any], bug_class: str) -> List[Dict[str, Any]]:
        """Analyze a single code slice for a bug class."""
        content = slice_data.get("content", "")
        if not content or len(content.strip()) < 50:
            return []

        # Detect language
        language = self._detect_language(slice_data.get("path", ""))

        # Choose prompt based on target type
        if hasattr(self, 'target_type') and self.target_type == "desktop":
            base_prompt = self.DESKTOP_HUNTING_PROMPT
        else:
            base_prompt = self.HUNTING_PROMPT

        # Build prompt
        prompt = base_prompt.format(
            bug_class=bug_class,
            code=content[:15000],  # Limit context
            language=language
        )

        try:
            response = self.llm_client.complete(prompt)
            findings = self._parse_findings(response, bug_class, slice_data)

            if findings:
                print(f"    [!] Found {len(findings)} potential {bug_class} issue(s)")

            return findings

        except Exception as e:
            print(f"    [!] LLM error: {e}")
            return []

    def _detect_language(self, path: str) -> str:
        """Detect programming language from file path."""
        ext = path.split('.')[-1].lower() if '.' in path else ""
        lang_map = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'jsx': 'javascript',
            'tsx': 'typescript',
            'java': 'java',
            'go': 'go',
            'rs': 'rust',
            'rb': 'ruby',
            'php': 'php',
            'cs': 'csharp',
            'cpp': 'cpp',
            'c': 'c',
            'h': 'c',
            'swift': 'swift',
            'kt': 'kotlin',
            'scala': 'scala',
            'vue': 'vue',
            'svelte': 'svelte',
            'html': 'html',
            'css': 'css',
        }
        return lang_map.get(ext, 'code')

    def _parse_findings(self, response: str, bug_class: str, slice_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse LLM response to extract findings."""
        findings = []

        # Try to extract JSON
        try:
            # Look for JSON block
            json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
            if json_match:
                data = json.loads(json_match.group(1))
            else:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    data = json.loads(json_match.group())
                else:
                    return []

            # Extract findings
            found_list = data.get("findings", [])
            for f in found_list:
                findings.append({
                    "bug_class": bug_class,
                    "location": f.get("location", "unknown"),
                    "issue": f.get("issue", ""),
                    "severity": f.get("severity", "Medium"),
                    "impact": f.get("impact", ""),
                    "poc": f.get("poc", ""),
                    "source": slice_data.get("source", ""),
                    "file": slice_data.get("path", "")
                })

        except (json.JSONDecodeError, AttributeError) as e:
            # Try simpler parsing
            if "no" not in response.lower() and "not found" not in response.lower():
                # Might have findings, try to extract
                pass

        return findings

    def get_findings_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity."""
        grouped = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}

        for finding in self.findings:
            sev = finding.get("severity", "Medium").title()
            if sev in grouped:
                grouped[sev].append(finding)
            else:
                grouped["Info"].append(finding)

        return grouped


def hunt_vulnerabilities(
    target: str,
    threat_model: Dict[str, Any],
    llm_client: Optional[LLMClient] = None,
    config: Optional[Config] = None,
    target_type: str = "web"
) -> List[Dict[str, Any]]:
    """Convenience function to hunt for vulnerabilities.
    
    Args:
        target: Target repo or path
        threat_model: Threat model from generate_threat_model
        llm_client: LLM client instance
        config: Config instance
        target_type: Target type - "web" or "desktop"
    """
    hunter = VulnerabilityHunter(llm_client, config)
    return hunter.hunt(target, threat_model, target_type=target_type)