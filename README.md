# LLM-Audit

<p align="center">
  <img src="https://img.shields.io/badge/LLM-Powered%20Vulnerability%20Research-brightgreen" alt="LLM-Powered">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Python-3.9+-yellow" alt="Python">
</p>

LLM-Audit is an LLM-powered vulnerability research tool that systematically identifies security vulnerabilities in codebases using a targeted methodology. It combines automated CVE discovery, intelligent threat modeling, and focused vulnerability hunting to help security researchers and bug bounty hunters find real vulnerabilities efficiently.

## Methodology

Based on the approach outlined in Devansh's article, LLM-Audit follows a four-step targeted methodology:

```
1. Find CVEs   →   2. Threat Model   →   3. Slice Code   →   4. Hunt
```

1. **Find CVEs** - Query the GitHub Advisory Database for past vulnerability disclosures affecting the target project
2. **Generate Threat Model** - Analyze CVE patterns using LLM to identify specific bug classes to hunt for
3. **Slice Codebase** - Break the codebase into manageable chunks to avoid LLM context rot
4. **Targeted Hunt** - Have the LLM analyze each slice for specific vulnerabilities based on the threat model

---

## Features

### CVE Lookup
- **GitHub Advisory Database Integration** - Automatically fetch CVEs and security advisories for target repositories
- Historical vulnerability analysis to understand past issues

### Bug Bounty Integration
- **HackerOne Support** - Fetch program details, scope, and bounty information
- **Bugcrowd Support** - Integrate with Bugcrowd programs for context-aware testing
- Automatic platform detection from URLs
- Scope extraction for focused testing

### Intelligent Code Slicing
- Smart codebase segmentation to avoid LLM context limits
- Security-priority directory ordering (auth, security, api, database, middleware, etc.)
- Support for 15+ programming languages (Python, JavaScript, TypeScript, Go, Rust, Ruby, Java, C#, PHP, Swift, Kotlin, Scala, C/C++, Vue, Svelte, React)
- Configurable max tokens per slice
- Filters out non-code files and large binaries

### Target Type Support
- **Web Applications** - Full support for web vulnerability classes (XSS, SQLi, IDOR, etc.)
- **Desktop Applications** - Analyze desktop app codebases for security flaws

### CLI Provider Support
- **Codex** - OpenAI Codex CLI integration
- **Claude** - Anthropic Claude CLI integration  
- **Aider** - AI pair programming tool integration

### Multi-LLM Support
- **OpenAI** - GPT-4o, GPT-4 Turbo, and other OpenAI models
- **Anthropic** - Claude Sonnet, Claude Haiku, and other Anthropic models
- **OpenRouter** - Access to 100+ LLMs through unified API

---

## Installation

### Prerequisites

- Python 3.9+
- GitHub CLI (gh) installed and authenticated
- At least one LLM API key (OpenRouter, OpenAI, or Anthropic)

### Quick Start

```bash
cd ~/projects/llm-audit
pip install -e .
llm-audit --help
```

### Environment Setup

Set your API key based on your preferred provider:

```bash
# OpenRouter (recommended - access to 100+ models)
export OPENROUTER_API_KEY="your-key-here"

# OpenAI
export OPENAI_API_KEY="your-key-here"

# Anthropic
export ANTHROPIC_API_KEY="your-key-here"
```

---

## Usage Examples

### Basic Auditing

```bash
# Audit a GitHub repository
llm-audit --target owner/repo

# Audit local code
llm-audit --target /path/to/project

# Use specific model
llm-audit --target owner/repo --model gpt-4o

# Output as JSON
llm-audit --target owner/repo --format json

# Increase analysis depth (more code slices)
llm-audit --target owner/repo --max-slices 30

# Verbose output for debugging
llm-audit --target owner/repo --verbose
```

### Skip Steps

```bash
# Skip CVE lookup (faster for repeated scans)
llm-audit --target owner/repo --skip-cve

# Skip vulnerability hunting (just get threat model)
llm-audit --target owner/repo --skip-hunt

# Skip both - just slice the codebase
llm-audit --target owner/repo --skip-cve --skip-hunt
```

### Provider Selection

```bash
# Use specific LLM provider
llm-audit --target owner/repo --provider openai --model gpt-4o
llm-audit --target owner/repo --provider anthropic --model claude-sonnet-4-5

# Use OpenRouter with specific model
llm-audit --target owner/repo --provider openrouter --model google/gemini-pro
```

### Bug Bounty Features

```bash
# Analyze with HackerOne program context
llm-audit --target owner/repo --bounty https://hackerone.com/program-name

# Analyze with Bugcrowd program context
llm-audit --target owner/repo --bounty https://bugcrowd.com/vendors/program-name
```

### Output Options

```bash
# Custom output directory
llm-audit --target owner/repo --output /custom/reports/

# JSON output for automation
llm-audit --target owner/repo --format json --output results.json

# Markdown report (default)
llm-audit --target owner/repo --format markdown
```

---

## Configuration

### Configuration File

LLM-Audit uses config/config.json for persistent settings:

```json
{
  "api_model": "anthropic/claude-sonnet-4-5",
  "ai_backend": "api",
  "cli_tool": "claude",
  "cli_model": null
}
```

### Full Configuration (config/default.yaml)

```yaml
# LLM Configuration
api_model: "anthropic/claude-sonnet-4-5"
ai_backend: "api"  # or "cli" for local CLI tools
cli_tool: "claude"  # codex, claude, or aider
cli_model: null

# Provider Settings
providers:
  openrouter:
    default_model: "anthropic/claude-sonnet-4-5"
    api_key_env: "OPENROUTER_API_KEY"
  
  openai:
    default_model: "gpt-4o"
    api_key_env: "OPENAI_API_KEY"
  
  anthropic:
    default_model: "claude-sonnet-4-5"
    api_key_env: "ANTHROPIC_API_KEY"
  
  cli:
    default_tool: "codex"
    available_tools: ["codex", "claude", "aider"]

# Code Slicing Configuration
slicing:
  max_tokens_per_slice: 8000
  security_priority:
    - "auth"
    - "security"
    - "api"
    - "database"
    - "middleware"
    - "core"
    - "services"
    - "config"
    - "utils"
    - "views"
  languages_supported:
    - "py"
    - "js"
    - "ts"
    - "go"
    - "rs"
    - "rb"
    - "java"
    - "cs"
    - "php"
    - "swift"
    - "kt"
    - "scala"
    - "c"
    - "cpp"
    - "h"
    - "hpp"
    - "vue"
    - "svelte"
    - "jsx"
    - "tsx"
```

---

## License

MIT License - See LICENSE file for details.
