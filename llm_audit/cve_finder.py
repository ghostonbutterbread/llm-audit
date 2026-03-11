"""CVE/Advisory finder using GitHub API."""

import json
import subprocess
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


class CVEFinder:
    """Find CVEs and security advisories for GitHub repos."""

    def __init__(self, gh_token: Optional[str] = None):
        """Initialize CVE finder."""
        self.gh_token = gh_token
        self.base_url = "https://api.github.com"

    def _run_gh(self, args: List[str]) -> Dict[str, Any]:
        """Run gh CLI command."""
        cmd = ["gh"]
        if self.gh_token:
            cmd.extend(["--header", f"Authorization: Bearer {self.gh_token}"])
        cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip()}

            # Try to parse JSON
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw": result.stdout}

        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            return {"error": str(e)}

    def is_github_repo(self, target: str) -> bool:
        """Check if target is a GitHub repository."""
        # Pattern: owner/repo
        if re.match(r'^[\w-]+/[\w-]+$', target):
            return True
        # Pattern: https://github.com/owner/repo
        if 'github.com' in target and '/' in target:
            return True
        return False

    def parse_repo(self, target: str) -> tuple:
        """Parse GitHub repo from various formats."""
        # Direct owner/repo
        if re.match(r'^[\w-]+/[\w-]+$', target):
            return target.split('/')

        # URL format
        match = re.search(r'github\.com[/:]([\w-]+)/([\w-]+?)(?:\.git)?$', target)
        if match:
            return match.group(1), match.group(2)

        # Local path
        if Path(target).exists():
            git_dir = Path(target) / ".git"
            if git_dir.exists():
                # Try to get remote from git config
                try:
                    result = subprocess.run(
                        ["git", "-C", str(target), "remote", "get-url", "origin"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        return self.parse_repo(result.stdout.strip())
                except Exception:
                    pass

        return None, None

    def find_advisories(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Find security advisories for a repository via GraphQL."""
        # Try GraphQL first (most reliable)
        advisories = self._find_via_graphql(owner, repo)
        if advisories:
            return advisories

        # Fallback: try REST API
        return self._find_via_rest(owner, repo)

    def _find_via_graphql(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Find advisories via GraphQL API."""
        query = """
        query($owner: String!, $repo: String!) {
          repository(owner: $owner, name: $repo) {
            vulnerabilityAlerts(first: 50, state: OPEN) {
              nodes {
                securityVulnerability {
                  package {
                    name
                    ecosystem
                  }
                  severity
                  advisory {
                    ghsaId
                    summary
                    description
                    publishedAt
                    vulnerabilities(first: 10) {
                      nodes {
                        package {
                          name
                          ecosystem
                        }
                        vulnerableVersionRange
                        firstPatchedVersion {
                          identifier
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

        # Try direct API call
        try:
            result = subprocess.run(
                ["gh", "api", "graphql",
                 "-f", f"query={query}",
                 "-f", f"owner={owner}",
                 "-f", f"repo={repo}",
                 "--jq", ".data.repository.vulnerabilityAlerts.nodes"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return self._parse_advisories(data)
        except Exception:
            pass

        return self._find_cve_references(owner, repo)

    def _parse_advisories(self, data: Any) -> List[Dict[str, Any]]:
        """Parse advisory data into structured format."""
        advisories = []
        if not data or not isinstance(data, list):
            return advisories

        for item in data:
            if not item:
                continue
            vuln = item.get("securityVulnerability", {})
            advisory = vuln.get("advisory", {})

            advisories.append({
                "ghsa_id": advisory.get("ghsaId", ""),
                "summary": advisory.get("summary", ""),
                "description": advisory.get("description", ""),
                "severity": vuln.get("severity", "UNKNOWN"),
                "package": vuln.get("package", {}).get("name", ""),
                "ecosystem": vuln.get("package", {}).get("ecosystem", ""),
                "published_at": advisory.get("publishedAt", ""),
            })

        return advisories

    def _find_cve_references(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Find CVEs via commit/PR references."""
        # Search for CVE mentions in commits
        result = self._run_gh([
            "search", "commits",
            "--repo", f"{owner}/{repo}",
            "CVE",
            "-L", "20"
        ])

        if isinstance(result, dict) and "raw" in result:
            return [{"type": "cve_reference", "source": "commits", "data": result["raw"]}]

        return []

    def _find_via_rest(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Find advisories via REST API (dependabot alerts)."""
        result = self._run_gh([
            "api", f"repos/{owner}/{repo}/dependabot/alerts",
            "-X", "GET", "-L", "50"
        ])

        if isinstance(result, list):
            advisories = []
            for alert in result:
                adv = alert.get("security_advisory", {})
                advisories.append({
                    "ghsa_id": adv.get("ghsa_id", ""),
                    "summary": adv.get("summary", ""),
                    "description": adv.get("description", ""),
                    "severity": adv.get("severity", "UNKNOWN"),
                    "package": alert.get("dependency", {}).get("package", {}).get("name", ""),
                    "ecosystem": alert.get("dependency", {}).get("package", {}).get("ecosystem", ""),
                    "published_at": adv.get("published_at", ""),
                })
            return advisories

        return []

    def get_cve_summary(self, advisories: List[Dict[str, Any]]) -> str:
        """Generate a summary of found CVEs."""
        if not advisories:
            return "No security advisories found."

        summary = f"Found {len(advisories)} security advisory(s):\n\n"

        severity_counts = {}
        for adv in advisories:
            sev = adv.get("severity", "UNKNOWN").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary += "By severity: " + ", ".join(
            f"{k}: {v}" for k, v in sorted(severity_counts.items())
        ) + "\n\n"

        # Show sample CVEs
        for adv in advisories[:5]:
            ghsa = adv.get("ghsa_id", "N/A")
            summary_text = adv.get("summary", "")[:100]
            summary += f"- {ghsa}: {summary_text}...\n"

        return summary


def find_cves(target: str, gh_token: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to find CVEs for a target."""
    finder = CVEFinder(gh_token)

    if not finder.is_github_repo(target):
        # Try local path
        owner, repo = finder.parse_repo(target)
        if not owner:
            return {"error": "Could not determine GitHub repository", "advisories": []}
        target = f"{owner}/{repo}"
    else:
        owner, repo = finder.parse_repo(target)

    if not owner or not repo:
        return {"error": "Invalid repository", "advisories": []}

    advisories = finder.find_advisories(owner, repo)

    return {
        "target": target,
        "owner": owner,
        "repo": repo,
        "advisories": advisories,
        "count": len(advisories),
        "summary": finder.get_cve_summary(advisories)
    }