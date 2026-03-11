"""Aggregator for combining findings from parallel agents."""

import json
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    bug_class: str
    location: str
    issue: str
    severity: str
    impact: str
    poc: str
    source: str = ""
    file: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "bug_class": self.bug_class,
            "location": self.location,
            "issue": self.issue,
            "severity": self.severity,
            "impact": self.impact,
            "poc": self.poc,
            "source": self.source,
            "file": self.file
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create from dictionary."""
        return cls(
            bug_class=data.get("bug_class", ""),
            location=data.get("location", ""),
            issue=data.get("issue", ""),
            severity=data.get("severity", "Medium"),
            impact=data.get("impact", ""),
            poc=data.get("poc", ""),
            source=data.get("source", ""),
            file=data.get("file", "")
        )


class FindingAggregator:
    """Aggregates and deduplicates findings from multiple agents."""
    
    def __init__(self):
        """Initialize aggregator."""
        self.findings: List[Finding] = []
        self._seen_hashes: set = set()
    
    def add_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Add findings from a single agent.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Number of unique findings added
        """
        added = 0
        
        for finding_data in findings:
            finding = Finding.from_dict(finding_data)
            
            # Generate hash for deduplication
            hash_input = self._generate_hash(finding)
            
            if hash_input not in self._seen_hashes:
                self._seen_hashes.add(hash_input)
                self.findings.append(finding)
                added += 1
        
        return added
    
    def add_raw_findings(self, raw_data: Dict[str, Any]) -> int:
        """Add findings from raw agent response.
        
        Args:
            raw_data: Raw response from agent (may contain findings list)
            
        Returns:
            Number of findings added
        """
        if isinstance(raw_data, dict):
            findings_list = raw_data.get("findings", [])
            if isinstance(findings_list, list):
                return self.add_findings(findings_list)
        
        return 0
    
    def _generate_hash(self, finding: Finding) -> str:
        """Generate a hash for deduplication.
        
        Uses location + bug_class + issue as the basis for deduplication.
        """
        # Normalize the data for hashing
        location = finding.location.lower().strip()
        bug_class = finding.bug_class.lower().strip()
        issue = finding.issue.lower().strip()[:100]  # Truncate issue for hashing
        
        hash_input = f"{location}|{bug_class}|{issue}"
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all aggregated findings as dictionaries.
        
        Returns:
            List of finding dictionaries
        """
        return [f.to_dict() for f in self.findings]
    
    def get_findings_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity.
        
        Returns:
            Dictionary mapping severity to list of findings
        """
        grouped = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Info": []
        }
        
        for finding in self.findings:
            sev = finding.severity.title()
            if sev in grouped:
                grouped[sev].append(finding.to_dict())
            else:
                grouped["Info"].append(finding.to_dict())
        
        return grouped
    
    def get_findings_by_bug_class(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by bug class.
        
        Returns:
            Dictionary mapping bug class to list of findings
        """
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        
        for finding in self.findings:
            bug_class = finding.bug_class
            if bug_class not in grouped:
                grouped[bug_class] = []
            grouped[bug_class].append(finding.to_dict())
        
        return grouped
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all findings.
        
        Returns:
            Summary dictionary
        """
        by_severity = self.get_findings_by_severity()
        by_class = self.get_findings_by_bug_class()
        
        return {
            "total_findings": len(self.findings),
            "by_severity": {
                sev: len(findings) 
                for sev, findings in by_severity.items()
            },
            "by_bug_class": {
                bug_class: len(findings)
                for bug_class, findings in by_class.items()
            },
            "unique_locations": len(set(f.location for f in self.findings))
        }
    
    def merge_aggregators(self, other: "FindingAggregator") -> int:
        """Merge findings from another aggregator.
        
        Args:
            other: Another FindingAggregator instance
            
        Returns:
            Number of unique findings merged
        """
        return self.add_findings(other.get_all_findings())
    
    def filter_by_severity(self, min_severity: str) -> List[Dict[str, Any]]:
        """Filter findings by minimum severity.
        
        Args:
            min_severity: Minimum severity (Critical, High, Medium, Low)
            
        Returns:
            Filtered findings
        """
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        min_level = severity_order.get(min_severity.lower(), 0)
        
        filtered = []
        for finding in self.findings:
            level = severity_order.get(finding.severity.lower(), 0)
            if level >= min_level:
                filtered.append(finding.to_dict())
        
        return filtered
    
    def clear(self) -> None:
        """Clear all findings."""
        self.findings.clear()
        self._seen_hashes.clear()


def aggregate_findings(all_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convenience function to aggregate findings from multiple agents.
    
    Args:
        all_results: List of result dictionaries from agents
        
    Returns:
        List of unique, aggregated findings
    """
    aggregator = FindingAggregator()
    
    for result in all_results:
        if isinstance(result, dict):
            # Try to extract findings
            findings = result.get("findings", [])
            if findings:
                aggregator.add_findings(findings)
            else:
                # Try to parse as raw response
                aggregator.add_raw_findings(result)
    
    return aggregator.get_all_findings()


def create_report(findings: List[Dict[str, Any]], format: str = "markdown") -> str:
    """Create a formatted report from findings.
    
    Args:
        findings: List of finding dictionaries
        format: Output format (markdown or json)
        
    Returns:
        Formatted report string
    """
    if format == "json":
        return json.dumps(findings, indent=2)
    
    # Markdown format
    lines = ["# Vulnerability Findings Report", ""]
    
    # Group by severity
    by_severity: Dict[str, List] = {}
    for f in findings:
        sev = f.get("severity", "Medium").title()
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)
    
    # Output by severity (critical first)
    for sev in ["Critical", "High", "Medium", "Low"]:
        if sev in by_severity:
            lines.append(f"## {sev} Severity ({len(by_severity[sev])})")
            lines.append("")
            
            for f in by_severity[sev]:
                lines.append(f"### {f.get('bug_class', 'Unknown')}")
                lines.append(f"**Location:** {f.get('location', 'Unknown')}")
                lines.append(f"**Issue:** {f.get('issue', 'No description')}")
                lines.append(f"**Impact:** {f.get('impact', 'Unknown')}")
                
                if f.get('poc'):
                    lines.append(f"**PoC:** {f.get('poc')}")
                
                lines.append("")
    
    return "\n".join(lines)
