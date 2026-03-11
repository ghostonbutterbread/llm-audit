"""LLM-Audit CLI - Main entry point."""

import sys
import argparse
import os
from pathlib import Path
from typing import Optional

from .config import Config
from .cve_finder import find_cves
from .bounty_finder import find_bounty
from .threat_model import generate_threat_model, ThreatModelGenerator
from .slicer import CodeSlicer
from .hunter import VulnerabilityHunter
from .reporter import generate_report
from .llm_client import LLMClient


def setup_args() -> argparse.ArgumentParser:
    """Setup command line arguments."""
    parser = argparse.ArgumentParser(
        prog="llm-audit",
        description="LLM-powered vulnerability research tool",
        epilog="""
Examples:
  llm-audit --target owner/repo
  llm-audit --target /path/to/code --format json
  llm-audit --target owner/repo --model gpt-4o
  llm-audit --target /path/to/code --no-cache
  llm-audit --target owner/repo --provider cli --model codex
  llm-audit --target owner/repo --provider cli --model claude
  llm-audit -t spotify-desktop --target-type desktop
  llm-audit -t /path/to/app --target-type auto  # auto-detect
  llm-audit -t owner/repo --agents 5  # use 5 parallel agents
  llm-audit -t owner/repo --agents 3 --cli-tool claude
        """
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target GitHub repo (owner/repo), local path, or desktop application"
    )

    parser.add_argument(
        "--target-type", "-T",
        choices=["web", "desktop", "auto"],
        default="auto",
        help="Target type: web application (default), desktop app, or auto-detect"
    )

    parser.add_argument(
        "--output", "-o",
        help="Output directory for reports (default: reports/)"
    )

    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Report format (default: markdown)"
    )

    parser.add_argument(
        "--model", "-m",
        help="LLM model to use (overrides config). For --provider cli, use: codex, claude, or aider"
    )

    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "openrouter", "cli"],
        default="cli",
        help="LLM provider (default: cli)"
    )

    parser.add_argument(
        "--max-slices",
        type=int,
        default=20,
        help="Maximum code slices to analyze (default: 20)"
    )

    parser.add_argument(
        "--skip-cve",
        action="store_true",
        help="Skip CVE/advisory lookup"
    )

    parser.add_argument(
        "--bounty", "-b",
        help="Bug bounty program URL (e.g., hackerone.com/programs/abc, bugcrowd.com/vendors/xyz)"
    )

    parser.add_argument(
        "--skip-hunt",
        action="store_true",
        help="Skip vulnerability hunting (just get CVE/threat model)"
    )

    parser.add_argument(
        "--config",
        help="Path to config file"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    parser.add_argument(
        "--api-key",
        help="API key (or set via OPENROUTER_API_KEY, OPENAI_API_KEY, etc.)"
    )

    parser.add_argument(
        "--agents", "-a",
        type=int,
        default=3,
        help="Number of parallel agents for vulnerability hunting (default: 3, max: 10)"
    )

    parser.add_argument(
        "--cli-tool",
        choices=["codex", "claude", "aider"],
        default="codex",
        help="CLI tool to use for parallel agents (default: codex)"
    )

    return parser


def check_dependencies():
    """Check required dependencies."""
    # Check for gh CLI
    import shutil
    if not shutil.which("gh"):
        print("[!] GitHub CLI (gh) is required but not installed.")
        print("    Install: https://cli.github.com/")
        return False

    return True


def run_audit(args):
    """Run the vulnerability audit."""
    print("=" * 60)
    print("LLM-Audit - Vulnerability Research Tool")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    
    # Determine target type
    if args.target_type == "auto":
        target_type = Config.detect_target_type(args.target)
        print(f"[*] Auto-detected target type: {target_type}")
    else:
        target_type = args.target_type
    
    print(f"[*] Target type: {target_type}")
    print()

    # Initialize config
    config = Config(args.config)

    # Override with CLI args
    if args.output:
        config.config["output"] = {"dir": args.output}
    if args.model:
        config.config["llm"] = config.config.get("llm", {})
        config.config["llm"]["model"] = args.model
    if args.provider:
        config.config["llm"] = config.config.get("llm", {})
        config.config["llm"]["provider"] = args.provider

    # Set API key if provided (skip for CLI provider)
    if args.api_key and args.provider != "cli":
        provider = args.provider or "openrouter"
        env_map = {
            "openrouter": "OPENROUTER_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY"
        }
        os.environ[env_map.get(provider, "OPENROUTER_API_KEY")] = args.api_key

    # For CLI provider, verify CLI tool is available
    if args.provider == "cli":
        from .llm_client import LLMClient
        available = LLMClient._detect_cli_tools()
        if not available:
            print("[!] No CLI tools (codex, claude, aider) found on system.")
            print("    Install one of: codex, claude, aider")
            return 1
        print(f"[*] Using CLI provider with available tools: {', '.join(available)}")

    # Step 1: Find CVEs
    cve_data = {"count": 0, "advisories": [], "summary": "Skipped", "target": args.target}

    if not args.skip_cve:
        print("[*] Step 1: Finding CVEs/advisories...")
        try:
            gh_token = config.get_gh_token()
            cve_data = find_cves(args.target, gh_token)

            if "error" in cve_data:
                print(f"    [!] {cve_data['error']}")
            else:
                print(f"    [+] Found {cve_data.get('count', 0)} advisories")
        except Exception as e:
            print(f"    [!] CVE lookup failed: {e}")
    else:
        print("[*] Step 1: Skipping CVE lookup (--skip-cve)")

    # Step 1b: Find bounty program info (if provided)
    bounty_data = None
    if args.bounty:
        print("[*] Step 1b: Fetching bug bounty program info...")
        try:
            bounty_data = find_bounty(args.bounty)
            if "error" in bounty_data:
                print(f"    [!] {bounty_data['error']}")
            else:
                bugs = bounty_data.get("bug_classes", [])
                print(f"    [+] Found {len(bugs)} bug types: {', '.join(bugs[:5])}")
        except Exception as e:
            print(f"    [!] Bounty lookup failed: {e}")
    else:
        print("[*] Step 1b: No bounty program specified (use --bounty)")

    print()

    # Step 2: Generate threat model
    print("[*] Step 2: Generating threat model...")
    try:
        llm_client = LLMClient(config)
        threat_model = generate_threat_model(
            cve_data.get("advisories", []), 
            llm_client,
            bounty_data=bounty_data,
            target_type=target_type
        )

        print("    [+] Threat model generated")
        print(f"    [+] Hunting for {len(threat_model.get('threat_model', []))} vulnerability classes")

        if args.verbose:
            print("\n" + ThreatModelGenerator().format_threat_model(threat_model))

    except Exception as e:
        print(f"    [!] Threat model generation failed: {e}")
        threat_model = {"threat_model": [], "priority": [], "recommendations": ""}

    print()

    # Step 3: Hunt vulnerabilities
    findings = []

    if not args.skip_hunt:
        print("[*] Step 3: Hunting vulnerabilities...")
        
        # Determine if we should use parallel mode
        use_parallel = args.agents > 1
        max_agents = min(max(args.agents, 1), 10)  # Clamp to 1-10
        
        if use_parallel:
            print(f"[*] Using parallel mode with {max_agents} agents")
            print(f"[*] CLI tool: {args.cli_tool}")
        
        try:
            hunter = VulnerabilityHunter(llm_client, config)
            
            if use_parallel:
                # Use parallel agent hunting
                findings = hunter.hunt_parallel(
                    args.target, 
                    threat_model, 
                    max_slices=args.max_slices,
                    max_agents=max_agents,
                    verbose=args.verbose, 
                    target_type=target_type,
                    cli_tool=args.cli_tool
                )
            else:
                # Use sequential hunting
                findings = hunter.hunt(
                    args.target, 
                    threat_model, 
                    args.max_slices, 
                    args.verbose, 
                    target_type
                )

            print(f"\n[+] Found {len(findings)} potential issues")

            # Show summary by severity
            grouped = hunter.get_findings_by_severity()
            for sev in ["Critical", "High", "Medium", "Low"]:
                count = len(grouped.get(sev, []))
                if count:
                    print(f"    [{sev}]: {count}")

        except Exception as e:
            print(f"    [!] Vulnerability hunting failed: {e}")
            import traceback
            if args.verbose:
                traceback.print_exc()
    else:
        print("[*] Step 3: Skipping vulnerability hunt (--skip-hunt)")

    print()

    # Step 4: Generate report
    print("[*] Step 4: Generating report...")
    try:
        report_path = generate_report(
            args.target,
            cve_data,
            threat_model,
            findings,
            config,
            args.format
        )
        print(f"    [+] Report saved to: {report_path}")
    except Exception as e:
        print(f"    [!] Report generation failed: {e}")

    print()
    print("=" * 60)
    print("Audit complete!")
    print("=" * 60)

    return 0


def main():
    """Main entry point."""
    # Check dependencies
    if not check_dependencies():
        return 1

    parser = setup_args()
    args = parser.parse_args()

    return run_audit(args)


if __name__ == "__main__":
    sys.exit(main())