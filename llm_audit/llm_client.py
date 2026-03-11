"""LLM client for vulnerability hunting."""

import os
import json
import re
import shutil
import subprocess
import requests
from typing import Optional, Dict, Any, List
from .config import Config


class LLMClient:
    """Unified LLM client supporting multiple providers."""

    PROVIDER_ENDPOINTS = {
        "openai": "https://api.openai.com/v1/chat/completions",
        "anthropic": "https://api.anthropic.com/v1/messages",
        "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    }

    # CLI tools that can be used as providers
    CLI_TOOLS = ["codex", "claude", "aider"]

    def __init__(self, config: Optional[Config] = None):
        """Initialize LLM client."""
        self.config = config or Config()
        self.llm_config = self.config.get_llm_config()
        self.provider = self.config.get_provider()
        self.model = self.config.get_model()
        self.api_key = self.config.get_api_key()
        
        # Detect available CLI tools if provider is cli
        self.available_cli_tools = []
        if self.provider == "cli":
            self.available_cli_tools = self._detect_cli_tools()
            # Auto-select CLI tool based on model if not already set
            if self.model in self.CLI_TOOLS:
                self.cli_tool = self.model
            elif self.available_cli_tools:
                self.cli_tool = self.available_cli_tools[0]
            else:
                self.cli_tool = None

    @staticmethod
    def _detect_cli_tools() -> List[str]:
        """Detect which CLI tools are available on the system."""
        available = []
        for tool in LLMClient.CLI_TOOLS:
            if shutil.which(tool):
                available.append(tool)
        return available

    def is_cli_available(self, tool: Optional[str] = None) -> bool:
        """Check if a CLI tool is available."""
        if tool:
            return tool in self.available_cli_tools
        return len(self.available_cli_tools) > 0

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Send completion request to LLM."""
        if self.provider == "openai":
            return self._openai_complete(prompt, system, **kwargs)
        elif self.provider == "anthropic":
            return self._anthropic_complete(prompt, system, **kwargs)
        elif self.provider == "openrouter":
            return self._openrouter_complete(prompt, system, **kwargs)
        elif self.provider == "cli":
            return self._cli_complete(prompt, system, **kwargs)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _openai_complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """OpenAI API completion."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.llm_config.get("temperature", 0.1)),
            "max_tokens": kwargs.get("max_tokens", self.llm_config.get("max_tokens", 4000)),
        }

        response = requests.post(
            self.PROVIDER_ENDPOINTS["openai"],
            headers=headers,
            json=data,
            timeout=120
        )

        if response.status_code != 200:
            raise Exception(f"OpenAI API error: {response.text}")

        return response.json()["choices"][0]["message"]["content"]

    def _anthropic_complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Anthropic API completion."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        # Anthropic uses system prompt differently
        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": full_prompt}],
            "temperature": kwargs.get("temperature", self.llm_config.get("temperature", 0.1)),
            "max_tokens": kwargs.get("max_tokens", self.llm_config.get("max_tokens", 4000)),
        }

        response = requests.post(
            self.PROVIDER_ENDPOINTS["anthropic"],
            headers=headers,
            json=data,
            timeout=120
        )

        if response.status_code != 200:
            raise Exception(f"Anthropic API error: {response.text}")

        return response.json()["content"][0]["text"]

    def _openrouter_complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """OpenRouter API completion."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/ghost/llm-audit",
            "X-Title": "LLM-Audit"
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.llm_config.get("temperature", 0.1)),
            "max_tokens": kwargs.get("max_tokens", self.llm_config.get("max_tokens", 4000)),
        }

        response = requests.post(
            self.PROVIDER_ENDPOINTS["openrouter"],
            headers=headers,
            json=data,
            timeout=120
        )

        if response.status_code != 200:
            raise Exception(f"OpenRouter API error: {response.text}")

        result = response.json()
        if "choices" in result:
            return result["choices"][0]["message"]["content"]
        elif "outputs" in result:
            return result["outputs"][0]["text"]
        else:
            return str(result)

    def _cli_complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """CLI-based completion using local CLI tools (codex, claude, aider)."""
        if not self.cli_tool:
            available = self._detect_cli_tools()
            if not available:
                raise ValueError("No CLI tools (codex, claude, aider) found on system. Please install one.")
            raise ValueError(f"No CLI tool selected. Available tools: {available}. Use --model to specify one.")

        # Check if the selected CLI tool is available
        if self.cli_tool not in self.available_cli_tools:
            raise ValueError(f"CLI tool '{self.cli_tool}' not found. Available: {self.available_cli_tools}")

        # Build the full prompt with system message if provided
        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        try:
            if self.cli_tool == "codex":
                return self._codex_complete(full_prompt, **kwargs)
            elif self.cli_tool == "claude":
                return self._claude_complete(full_prompt, **kwargs)
            elif self.cli_tool == "aider":
                return self._aider_complete(full_prompt, **kwargs)
            else:
                raise ValueError(f"Unsupported CLI tool: {self.cli_tool}")
        except Exception as e:
            raise Exception(f"CLI ({self.cli_tool}) error: {e}")

    def _codex_complete(self, prompt: str, **kwargs) -> str:
        """Execute prompt using codex CLI."""
        # Use --dangerously-bypass-approvals-and-sandbox for non-interactive use
        # and capture only the final response
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
            timeout=kwargs.get("timeout", 180),
            cwd=kwargs.get("workdir", os.getcwd())
        )

        # Read the output file
        try:
            with open("/tmp/codex_output.txt", "r") as f:
                output = f.read()
        except FileNotFoundError:
            output = result.stdout

        # Parse the last line as the actual response (codex outputs extra info)
        lines = output.strip().split('\n')
        if lines:
            # Look for the last non-empty line that might be the response
            for line in reversed(lines):
                line = line.strip()
                if line and not line.startswith('tokens used'):
                    return line
        return output.strip()

    def _claude_complete(self, prompt: str, **kwargs) -> str:
        """Execute prompt using claude CLI."""
        # Use -p for print mode (non-interactive)
        # Use --dangerously-skip-permissions to run without prompts
        cmd = ["claude", "-p", "--dangerously-skip-permissions", prompt]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=kwargs.get("timeout", 180),
            cwd=kwargs.get("workdir", os.getcwd())
        )

        if result.returncode != 0:
            raise Exception(f"Claude CLI error: {result.stderr}")

        # Claude -p outputs the response directly
        return result.stdout.strip()

    def _aider_complete(self, prompt: str, **kwargs) -> str:
        """Execute prompt using aider CLI."""
        # Aider can be used with --read or just as a chat interface
        # Use --no-auto-commits and --pretty to get clean output
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
            timeout=kwargs.get("timeout", 180),
            cwd=kwargs.get("workdir", os.getcwd())
        )

        # Aider outputs to stdout
        return result.stdout.strip()

    def complete_with_context(self, prompt: str, code_context: str, bug_class: str, **kwargs) -> str:
        """Complete with code context for vulnerability hunting."""
        hunting_prompt = f"""You are a vulnerability researcher analyzing code for security issues.

TARGET BUG CLASS: {bug_class}

CODE CONTEXT:
```{code_context}
```

Analyze this code for {bug_class} vulnerabilities. For each potential finding:

1. File/location
2. Description of the issue
3. Severity assessment (Critical/High/Medium/Low)
4. Proof of concept or exploitation scenario

Respond in JSON format:
{{
  "findings": [
    {{
      "location": "file:line or function",
      "description": "issue description",
      "severity": "High",
      "poc": "how to exploit"
    }}
  ],
  "summary": "overall assessment"
}}

If no vulnerabilities found, respond with:
{{"findings": [], "summary": "No {bug_class} vulnerabilities found in this code slice."}}
"""

        return self.complete(hunting_prompt, **kwargs)


def create_llm_client(provider: str = "openrouter", model: Optional[str] = None, api_key: Optional[str] = None) -> LLMClient:
    """Factory function to create LLM client."""
    config = Config()
    if provider:
        config.config["llm"] = {"provider": provider, "model": model or config.get_model()}
    if api_key:
        os.environ["OPENROUTER_API_KEY"] = api_key
    return LLMClient(config)