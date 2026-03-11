"""Codebase slicer - break code into manageable chunks."""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from .config import Config


class CodeSlicer:
    """Slice codebase into manageable chunks for LLM analysis."""

    IGNORE_DIRS = {
        '.git', '.github', 'node_modules', '__pycache__', '.venv', 'venv',
        'dist', 'build', '.idea', '.vscode', 'vendor', 'target', 'coverage',
        '.tox', 'env', '.env', 'static', 'media', 'uploads', 'cache'
    }

    IGNORE_FILES = {
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
        'Pipfile.lock', 'requirements.txt', 'composer.lock', 'Cargo.lock',
        '.gitignore', '.env', '.env.example', '*.min.js', '*.min.css'
    }

    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.rb',
        '.php', '.cs', '.cpp', '.c', '.h', '.swift', '.kt', '.scala',
        '.vue', '.svelte', '.html', '.htm', '.css', '.scss', '.less'
    }

    def __init__(self, config: Optional[Config] = None):
        """Initialize code slicer."""
        self.config = config or Config()
        self.max_file_size = self.config.get_max_file_size()

    def slice_target(self, target: str) -> List[Dict[str, Any]]:
        """Slice a target (GitHub repo or local path) into chunks."""
        if self._is_github(target):
            return self._slice_github(target)
        else:
            return self._slice_local(target)

    def _is_github(self, target: str) -> bool:
        """Check if target is GitHub URL or owner/repo."""
        return 'github.com' in target or re.match(r'^[\w-]+/[\w-]+$', target)

    def _slice_github(self, target: str) -> List[Dict[str, Any]]:
        """Slice GitHub repository (clone and slice)."""
        # Parse owner/repo
        match = re.search(r'github\.com[/:]([\w-]+)/([\w-]+?)(?:\.git)?$', target)
        if match:
            owner, repo = match.group(1), match.group(2)
        else:
            owner, repo = target.split('/')

        # Clone to temp directory
        import tempfile
        import subprocess

        temp_dir = tempfile.mkdtemp()
        clone_url = f"https://github.com/{owner}/{repo}.git"

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, temp_dir],
                capture_output=True,
                timeout=120
            )
            return self._slice_directory(Path(temp_dir), f"github:{owner}/{repo}")
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _slice_local(self, target: str) -> List[Dict[str, Any]]:
        """Slice local directory."""
        path = Path(target)
        if not path.exists():
            raise ValueError(f"Path does not exist: {target}")

        if path.is_file():
            return [self._slice_file(path, "local")]

        return self._slice_directory(path, "local")

    def _slice_directory(self, directory: Path, source: str) -> List[Dict[str, Any]]:
        """Slice directory into code chunks."""
        slices = []

        # Walk directory tree
        for root, dirs, files in os.walk(directory):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]

            root_path = Path(root)

            # Group files by directory for logical slicing
            dir_slices = {}
            for file in files:
                file_path = root_path / file
                if not self._should_include(file_path):
                    continue

                try:
                    if file_path.stat().st_size > self.max_file_size:
                        # Split large files
                        slices.extend(self._split_large_file(file_path, source))
                    else:
                        # Group by directory
                        rel_dir = str(file_path.parent.relative_to(directory))
                        if rel_dir not in dir_slices:
                            dir_slices[rel_dir] = []
                        dir_slices[rel_dir].append(self._read_file(file_path))
                except Exception:
                    continue

            # Create slices from directory groups
            for dir_path, contents in dir_slices.items():
                if contents:
                    combined = self._combine_contents(contents)
                    slices.append({
                        "source": source,
                        "path": dir_path,
                        "type": "directory",
                        "content": combined,
                        "file_count": len(contents)
                    })

        # Also create per-file slices for key files
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            root_path = Path(root)
            for file in files:
                file_path = root_path / file
                if not self._should_include(file_path):
                    continue
                if file_path.stat().st_size <= self.max_file_size:
                    slices.append(self._slice_file(file_path, source))

        return slices

    def _should_include(self, path: Path) -> bool:
        """Check if file should be included."""
        # Check extension
        if path.suffix not in self.CODE_EXTENSIONS:
            return False

        # Check ignored files
        if path.name in self.IGNORE_FILES:
            return False

        # Check for ignored patterns
        for pattern in self.IGNORE_FILES:
            if '*' in pattern and path.match(pattern):
                return False

        return True

    def _read_file(self, path: Path) -> str:
        """Read file content."""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""

    def _slice_file(self, path: Path, source: str) -> Dict[str, Any]:
        """Slice a single file."""
        content = self._read_file(path)
        return {
            "source": source,
            "path": str(path),
            "type": "file",
            "content": content,
            "lines": len(content.splitlines())
        }

    def _split_large_file(self, path: Path, source: str, chunk_size: int = 500) -> List[Dict[str, Any]]:
        """Split large file into chunks."""
        content = self._read_file(path)
        lines = content.splitlines()
        chunks = []

        for i in range(0, len(lines), chunk_size):
            chunk_lines = lines[i:i + chunk_size]
            chunks.append({
                "source": source,
                "path": f"{path}:{i+1}-{i+len(chunk_lines)}",
                "type": "file_chunk",
                "content": "\n".join(chunk_lines),
                "lines": len(chunk_lines)
            })

        return chunks

    def _combine_contents(self, contents: List[str]) -> str:
        """Combine multiple file contents."""
        return "\n\n".join(contents)

    def get_slice_summary(self, slices: List[Dict[str, Any]]) -> str:
        """Get summary of slices."""
        total_lines = sum(s.get("lines", 0) for s in slices)
        file_count = sum(1 for s in slices if s.get("type") == "file")
        dir_count = sum(1 for s in slices if s.get("type") == "directory")

        return f"Created {len(slices)} slices ({file_count} files, {dir_count} directories, ~{total_lines} lines)"


def slice_codebase(target: str, config: Optional[Config] = None) -> List[Dict[str, Any]]:
    """Convenience function to slice codebase."""
    slicer = CodeSlicer(config)
    return slicer.slice_target(target)