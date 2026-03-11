"""Configuration management for llm-audit."""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
import yaml


class Config:
    """Configuration manager for llm-audit."""

    DEFAULT_PROVIDERS = {
        "openai": {
            "model": "gpt-4o",
            "api_key_env": "OPENAI_API_KEY",
        },
        "anthropic": {
            "model": "claude-sonnet-4-20250514",
            "api_key_env": "ANTHROPIC_API_KEY",
        },
        "openrouter": {
            "model": "openrouter/minimax/minimax-m2.5",
            "api_key_env": "OPENROUTER_API_KEY",
        },
        "cli": {
            "model": "codex",  # default CLI tool
            "cli_tools": ["codex", "claude", "aider"],
            "api_key_env": None,  # CLI tools handle auth themselves
        }
    }

    BUG_CLASSES = {
        "critical": [
            "SQL Injection",
            "Remote Code Execution (RCE)",
            "Authentication Bypass",
            "IDOR (Insecure Direct Object Reference)",
            "Path Traversal",
        ],
        "high": [
            "Cross-Site Scripting (XSS)",
            "XML External Entity (XXE)",
            "Server-Side Request Forgery (SSRF)",
            "Deserialization Vulnerability",
            "Command Injection",
        ],
        "medium": [
            "Information Disclosure",
            "CSRF (Cross-Site Request Forgery)",
            "Broken Access Control",
            "Security Misconfiguration",
            "Race Condition",
        ],
        "low": [
            "Weak Cryptography",
            "Debug Mode Enabled",
            "Verbose Error Messages",
            "Missing Security Headers",
            "Logging of Sensitive Data",
        ]
    }

    PRIORITY_BUGS = ["data leaks", "401s", "IDORs", "XSS"]

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration."""
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or defaults."""
        if self.config_path and Path(self.config_path).exists():
            with open(self.config_path) as f:
                return yaml.safe_load(f) or {}

        # Try default config
        default_path = Path(__file__).parent.parent / "config" / "default.yaml"
        if default_path.exists():
            with open(default_path) as f:
                return yaml.safe_load(f) or {}

        return {}

    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration."""
        return self.config.get("llm", {
            "provider": "openrouter",
            "model": "openrouter/minimax/minimax-m2.5",
            "api_key_env": "OPENROUTER_API_KEY",
            "temperature": 0.1,
            "max_tokens": 4000,
        })

    def get_provider(self) -> str:
        """Get LLM provider."""
        return self.get_llm_config().get("provider", "openrouter")

    def get_model(self) -> str:
        """Get LLM model."""
        return self.get_llm_config().get("model", "openrouter/minimax/minimax-m2.5")

    def get_api_key(self) -> Optional[str]:
        """Get API key from environment."""
        config = self.get_llm_config()
        env_var = config.get("api_key_env", "OPENROUTER_API_KEY")
        return os.environ.get(env_var)

    def get_max_file_size(self) -> int:
        """Get max file size for code slicing (bytes)."""
        return self.config.get("slicing", {}).get("max_file_size", 50000)

    def get_slice_tokens(self) -> int:
        """Get target tokens per slice."""
        return self.config.get("slicing", {}).get("target_tokens", 8000)

    def get_output_dir(self) -> Path:
        """Get output directory."""
        return Path(self.config.get("output", {}).get("dir", "reports"))

    def get_gh_token(self) -> Optional[str]:
        """Get GitHub token from environment."""
        return os.environ.get("GITHUB_TOKEN")

    @classmethod
    def get_bug_classes(cls, severity: Optional[str] = None) -> list:
        """Get bug classes, optionally filtered by severity."""
        if severity:
            return cls.BUG_CLASSES.get(severity.lower(), [])
        return [bug for bugs in cls.BUG_CLASSES.values() for bug in bugs]

    @classmethod
    def get_priority_bugs(cls) -> list:
        """Get priority bugs for bug bounty."""
        return cls.PRIORITY_BUGS