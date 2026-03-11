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

    # Desktop application vulnerability classes
    DESKTOP_BUG_CLASSES = {
        "critical": [
            "Buffer Overflow",
            "Deserialization Issues",
            "Improper Input Validation",
            "SQL Injection",
        ],
        "high": [
            "Cryptographic Failures",
            "Broken Access Controls",
            "Insecure Storage",
            "Command Injection",
            "Race Conditions",
        ],
        "medium": [
            "Insecure Design",
            "Information Disclosure",
            "Security Misconfiguration",
            "Path Traversal",
        ],
        "low": [
            "Weak Cryptography",
            "Debug Mode Enabled",
            "Verbose Error Messages",
            "Insecure Logging",
        ]
    }

    # Desktop file extensions for auto-detection
    DESKTOP_EXTENSIONS = {".exe", ".dmg", ".app", ".jar", ".msi", ".deb", ".rpm", ".appimage", ".snap"}

    # Priority bugs for bug bounty hunting
    PRIORITY_BUGS = ["data leaks", "401s", "IDORs", "XSS"]

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration."""
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or defaults."""
        if self.config_path and Path(self.config_path).exists():
            path = Path(self.config_path)
            # Handle JSON files
            if path.suffix == ".json":
                with open(self.config_path) as f:
                    config = json.load(f) or {}
                # Normalize config.json format to match expected structure
                return self._normalize_config(config)
            else:
                return yaml.safe_load(f) or {}

        # Try default config (YAML)
        default_path = Path(__file__).parent.parent / "config" / "default.yaml"
        if default_path.exists():
            with open(default_path) as f:
                return yaml.safe_load(f) or {}

        return {}

    def _normalize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize config from config.json format to internal format."""
        # Handle legacy config.json format with top-level keys
        if "api_model" in config or "cli_tool" in config or "ai_backend" in config:
            # Convert to internal format
            normalized = config.copy()
            
            # Map api_model to llm.model
            if "api_model" in config:
                normalized["llm"] = {
                    "provider": "openrouter",  # default
                    "model": config["api_model"],
                    "api_key_env": "OPENROUTER_API_KEY",
                    "temperature": 0.1,
                    "max_tokens": 4000,
                }
            
            # Handle CLI tool settings
            if "cli_tool" in config:
                normalized.setdefault("llm", {})
                normalized["llm"]["cli_tool"] = config["cli_tool"]
            
            # Handle ai_backend -> provider mapping
            if "ai_backend" in config:
                normalized.setdefault("llm", {})
                if config["ai_backend"] == "api":
                    # Keep default provider
                    pass
                elif config["ai_backend"] == "cli":
                    normalized["llm"]["provider"] = "cli"
            
            return normalized
        
        return config

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

    @classmethod
    def get_bug_classes_by_target_type(cls, target_type: str) -> dict:
        """Get bug classes based on target type (web or desktop)."""
        if target_type == "desktop":
            return cls.DESKTOP_BUG_CLASSES
        return cls.BUG_CLASSES

    @classmethod
    def detect_target_type(cls, target: str) -> str:
        """Auto-detect target type from target string (path or repo)."""
        # Check if it's a local path with desktop file extension
        if os.path.isfile(target):
            ext = os.path.splitext(target)[1].lower()
            if ext in cls.DESKTOP_EXTENSIONS:
                return "desktop"
        
        # Check directory for common desktop app markers
        if os.path.isdir(target):
            # Check for common desktop app indicators
            desktop_indicators = [
                "package.json",  # Electron
                "Cargo.toml",    # Rust
                "pom.xml",       # Java
                "build.gradle",  # Java/Android
                "setup.py",      # Python
                "pyproject.toml", # Python
                "requirements.txt", # Python (could be either)
                "main.swift",    # Swift
                "Podfile",       # iOS/macOS
            ]
            target_path = Path(target)
            for indicator in desktop_indicators:
                if (target_path / indicator).exists():
                    if indicator in ["package.json"]:
                        # Check if it's an Electron app
                        try:
                            pkg = json.load(open(target_path / "package.json"))
                            if "main" in pkg or "electron" in str(pkg).lower():
                                return "desktop"
                        except:
                            pass
                    return "desktop"
        
        # Check for common desktop file extensions in the target name
        target_name = os.path.basename(target).lower()
        for ext in cls.DESKTOP_EXTENSIONS:
            if target_name.endswith(ext):
                return "desktop"
        
        # Default to web
        return "web"

    @classmethod
    def detect_language_from_path(cls, path: str) -> str:
        """Detect programming language from file path."""
        ext = os.path.splitext(path)[1].lower() if '.' in path else ""
        
        # Desktop app frameworks
        if ext == ".py":
            return "python"
        elif ext == ".js" or ext == ".mjs":
            return "javascript"
        elif ext == ".ts" or ext == ".tsx":
            return "typescript"
        elif ext == ".java":
            return "java"
        elif ext == ".rs":
            return "rust"
        elif ext == ".go":
            return "go"
        elif ext in [".swift"]:
            return "swift"
        elif ext in [".kt", ".kts"]:
            return "kotlin"
        elif ext in [".cpp", ".cc", ".cxx", ".c++"]:
            return "cpp"
        elif ext == ".c" or ext == ".h":
            return "c"
        elif ext == ".cs":
            return "csharp"
        
        # Generic
        return "code"