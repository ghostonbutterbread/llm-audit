"""LLM-powered vulnerability hunter with parallel agent support."""

import json
import re
import threading
import subprocess
import os
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .llm_client import LLMClient
from .slicer import CodeSlicer
from .config import Config
from .job_queue import JobQueue, Job, JobStatus, create_job_queue
from .aggregator import FindingAggregator


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
{{"bug_class": "{bug_class}", "findings": [], "summary": "No {bug_class} vulnerabilities found in this code slice."}}"""

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

    def hunt_parallel(self, target: str, threat_model: Dict[str, Any], max_slices: int = 20, max_agents: int = 3, verbose: bool = False, target_type: str = "web", cli_tool: str = "codex") -> List[Dict[str, Any]]:
        """Hunt for vulnerabilities using parallel agents.
        
        Args:
            target: Target repo or path
            threat_model: Threat model from generate_threat_model
            max_slices: Maximum code slices to analyze
            max_agents: Maximum number of parallel agents (default: 3, max: 10)
            verbose: Verbose output
            target_type: Target type - "web" or "desktop"
            cli_tool: CLI tool to use for agents (codex, claude, aider)
            
        Returns:
            List of all findings
        """
        max_agents = min(max(max_agents, 1), 10)  # Clamp to 1-10
        
        self.target_type = target_type
        
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
        print(f"[*] Hunting for {len(bug_classes)} vulnerability classes with {max_agents} parallel agents")

        # Limit slices
        slices_to_analyze = slices[:max_slices]
        total_jobs = len(bug_classes) * len(slices_to_analyze)
        print(f"[*] Total jobs: {total_jobs} ({len(bug_classes)} bug classes × {len(slices_to_analyze)} slices)")

        # Create job queue
        job_queue = create_job_queue(bug_classes, slices_to_analyze, max_slices)
        
        # Create aggregator
        aggregator = FindingAggregator()
        
        # Track active jobs for progress
        active_jobs = []
        completed_count = 0
        
        # Run parallel agents
        print(f"[*] Starting {max_agents} parallel agents...")
        
        with ThreadPoolExecutor(max_workers=max_agents) as executor:
            # Submit initial batch of jobs
            futures = []
            for _ in range(max_agents):
                job = job_queue.get_job(block=False)
                if job:
                    future = executor.submit(self._run_agent_job, job, cli_tool, verbose)
                    futures.append((future, job))
                    active_jobs.append(job)
            
            # Process completed jobs and submit new ones
            while futures or not job_queue.is_empty():
                # Wait for at least one job to complete
                done_futures = []
                for future, job in futures[:]:
                    if future.done():
                        done_futures.append((future, job))
                        futures.remove((future, job))
                        active_jobs.remove(job)
                
                # Process completed jobs
                for future, job in done_futures:
                    completed_count += 1
                    try:
                        result = future.result()
                        if result and result.get("findings"):
                            added = aggregator.add_findings(result["findings"])
                            if added > 0:
                                print(f"    [Agent] Job {job.job_id} ({job.bug_class}): Found {added} finding(s)")
                            else:
                                if verbose:
                                    print(f"    [Agent] Job {job.job_id} ({job.bug_class}): No findings")
                        else:
                            if verbose:
                                print(f"    [Agent] Job {job.job_id} ({job.bug_class}): Completed (no findings)")
                    except Exception as e:
                        if verbose:
                            print(f"    [Agent] Job {job.job_id} ({job.bug_class}): Error - {e}")
                    
                    # Progress update
                    print(f"\r    Progress: {completed_count}/{total_jobs} jobs completed", end="")
                
                # Submit new jobs if available
                while len(active_jobs) < max_agents and not job_queue.is_empty():
                    job = job_queue.get_job(block=False)
                    if job:
                        future = executor.submit(self._run_agent_job, job, cli_tool, verbose)
                        futures.append((future, job))
                        active_jobs.append(job)
                    else:
                        break
                
                # Small delay to avoid busy waiting
                if not done_futures and futures:
                    import time
                    time.sleep(0.1)
        
        print(f"\n[+] Completed {completed_count} jobs")
        
        # Get all findings
        self.findings = aggregator.get_all_findings()
        
        # Print summary
        summary = aggregator.get_summary()
        print(f"\n[+] Found {summary['total_findings']} unique issues")
        
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = summary["by_severity"].get(sev, 0)
            if count:
                print(f"    [{sev}]: {count}")
        
        return self.findings

    def _run_agent_job(self, job: Job, cli_tool: str, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Run a single agent job.
        
        Args:
            job: Job to run
            cli_tool: CLI tool to use
            verbose: Verbose output
            
        Returns:
            Result dictionary or None
        """
        try:
            # Build prompt for this specific bug class
            prompt = self._build_hunting_prompt(job.bug_class, job.slice_data)
            
            # Run via CLI tool
            result = self._run_cli_agent(prompt, cli_tool)
            
            # Parse findings
            if result:
                findings = self._parse_findings_from_text(result, job.bug_class, job.slice_data)
                return {
                    "job_id": job.job_id,
                    "bug_class": job.bug_class,
                    "findings": findings,
                    "raw_response": result
                }
            
            return None
            
        except Exception as e:
            if verbose:
                print(f"    [!] Agent error: {e}")
            return None

    def _run_cli_agent(self, prompt: str, cli_tool: str) -> Optional[str]:
        """Run CLI agent with prompt.
        
        Args:
            prompt: Prompt to send
            cli_tool: CLI tool (codex, claude, aider)
            
        Returns:
            Agent response or None
        """
        try:
            if cli_tool == "codex":
                return self._run_codex(prompt)
            elif cli_tool == "claude":
                return self._run_claude(prompt)
            elif cli_tool == "aider":
                return self._run_aider(prompt)
            else:
                print(f"[!] Unknown CLI tool: {cli_tool}")
                return None
        except Exception as e:
            print(f"[!] CLI agent error: {e}")
            return None

    def _run_codex(self, prompt: str) -> Optional[str]:
        """Run codex CLI agent."""
        try:
            cmd = [
                "codex", "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "-o", "/tmp/codex_output.txt",
                "--",
                prompt
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=os.getcwd()
            )
            
            # Read output
            try:
                with open("/tmp/codex_output.txt", "r") as f:
                    output = f.read()
            except FileNotFoundError:
                output = result.stdout
            
            # Parse response
            lines = output.strip().split('\n')
            if lines:
                for line in reversed(lines):
                    line = line.strip()
                    if line and not line.startswith('tokens used'):
                        return line
            return output.strip()
            
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            print(f"[!] Codex error: {e}")
            return None

    def _run_claude(self, prompt: str) -> Optional[str]:
        """Run claude CLI agent."""
        try:
            cmd = ["claude", "-p", "--dangerously-skip-permissions", prompt]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=os.getcwd()
            )
            
            if result.returncode != 0:
                return None
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            print(f"[!] Claude error: {e}")
            return None

    def _run_aider(self, prompt: str) -> Optional[str]:
        """Run aider CLI agent."""
        try:
            cmd = [
                "aider",
                "--no-auto-commits",
                "--pretty",
                "--message", prompt
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=os.getcwd()
            )
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            print(f"[!] Aider error: {e}")
            return None

    def _build_hunting_prompt(self, bug_class: str, slice_data: Dict[str, Any]) -> str:
        """Build hunting prompt for a specific bug class and slice.
        
        Args:
            bug_class: The vulnerability class to hunt
            slice_data: Code slice data
            
        Returns:
            Formatted prompt
        """
        content = slice_data.get("content", "")[:15000]
        language = self._detect_language(slice_data.get("path", ""))
        
        # Choose prompt based on target type
        if hasattr(self, 'target_type') and self.target_type == "desktop":
            base_prompt = self.DESKTOP_HUNTING_PROMPT
        else:
            base_prompt = self.HUNTING_PROMPT
        
        return base_prompt.format(
            bug_class=bug_class,
            code=content,
            language=language
        )

    def _parse_findings_from_text(self, response: str, bug_class: str, slice_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse findings from agent text response.
        
        Args:
            response: Agent's text response
            bug_class: The bug class that was searched
            slice_data: The code slice that was analyzed
            
        Returns:
            List of findings
        """
        findings = []
        
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
                
        except (json.JSONDecodeError, AttributeError):
            pass
        
        return findings

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
    target_type: str = "web",
    max_slices: int = 20,
    max_agents: int = 3,
    use_parallel: bool = False
) -> List[Dict[str, Any]]:
    """Convenience function to hunt for vulnerabilities.
    
    Args:
        target: Target repo or path
        threat_model: Threat model from generate_threat_model
        llm_client: LLM client instance
        config: Config instance
        target_type: Target type - "web" or "desktop"
        max_slices: Maximum code slices to analyze
        max_agents: Maximum parallel agents (only used if use_parallel=True)
        use_parallel: Whether to use parallel agents
        
    Returns:
        List of vulnerability findings
    """
    hunter = VulnerabilityHunter(llm_client, config)
    
    if use_parallel:
        return hunter.hunt_parallel(
            target, threat_model, 
            max_slices=max_slices,
            max_agents=max_agents,
            target_type=target_type
        )
    else:
        return hunter.hunt(
            target, threat_model, 
            max_slices=max_slices,
            target_type=target_type
        )
