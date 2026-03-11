"""Intelligent codebase slicer - smart chunking for LLM analysis.

This module provides intelligent code slicing that:
- Understands project structure (MVC, microservices, API-first)
- Slices by logical boundaries (auth, API, DB, middleware, utils)
- Preserves context (cross-slice dependencies)
- Handles multiple languages
- Prioritizes security-critical files
- Respects token limits (~4000 tokens default)
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Generator
from collections import defaultdict
from .config import Config


# Token estimation: ~4 characters per token on average
CHARS_PER_TOKEN = 4


class ProjectPattern:
    """Detected project pattern types."""
    MVC = "mvc"
    API_FIRST = "api_first"
    MICROSERVICES = "microservices"
    MONOLITH = "monolith"
    LIBRARY = "library"
    FLAT = "flat"
    UNKNOWN = "unknown"


class LogicalBoundary:
    """Logical boundary types for code slicing."""
    AUTH = "auth"
    API = "api"
    DATABASE = "database"
    MIDDLEWARE = "middleware"
    UTILS = "utils"
    CONFIG = "config"
    MODELS = "models"
    VIEWS = "views"
    CONTROLLERS = "controllers"
    SERVICES = "services"
    ROUTES = "routes"
    SECURITY = "security"
    CORE = "core"
    THIRD_PARTY = "third_party"


# Language detection patterns
LANGUAGE_PATTERNS = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.jsx': 'javascript',
    '.tsx': 'typescript',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.java': 'java',
    '.kt': 'kotlin',
    '.scala': 'scala',
    '.cs': 'csharp',
    '.php': 'php',
    '.swift': 'swift',
    '.c': 'c',
    '.cpp': 'cpp',
    '.h': 'c',
    '.vue': 'vue',
    '.svelte': 'svelte',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
    '.scss': 'scss',
    '.less': 'less',
}

# Directory patterns for logical boundaries
# Use more specific patterns to avoid false positives
BOUNDARY_PATTERNS = {
    LogicalBoundary.AUTH: {
        'auth', 'authentication', 'login', 'session', 'oauth', 'jwt',
        'passport', 'access', 'permissions', 'roles', 'acl'
    },
    LogicalBoundary.API: {
        'api', 'apis', 'endpoint', 'endpoints', 'route', 'routes',
        'controller', 'controllers', 'handler', 'handlers', 'grpc',
        'rest', 'graphql', 'webhook', 'webhooks', 'router'
    },
    LogicalBoundary.DATABASE: {
        'db', 'database', 'datastore', 'repository', 'repositories',
        'migration', 'migrations', 'schema', 'seed', 'seeder',
        'orm', 'dbal', 'query', 'queries', 'dao'
    },
    LogicalBoundary.MIDDLEWARE: {
        'middleware', 'interceptor', 'filter', 'pipeline', 'processor'
    },
    LogicalBoundary.UTILS: {
        'util', 'utils', 'helper', 'helpers', 'lib', 'libs',
        'common', 'shared', 'extensions', 'tool', 'tools'
    },
    LogicalBoundary.CONFIG: {
        'config', 'configuration', 'settings', 'env', 'environment',
        '.env', 'ini'
    },
    LogicalBoundary.SERVICES: {
        'service', 'services', 'business', 'logic', 'domain', 'usecase',
        'use-case', 'feature', 'features', 'module', 'modules'
    },
    LogicalBoundary.VIEWS: {
        'view', 'views', 'page', 'pages', 'template', 'templates',
        'component', 'components', 'ui', 'frontend', 'client'
    },
    LogicalBoundary.SECURITY: {
        'security', 'crypto', 'crypt', 'encryption', 'validation',
        'sanitization', 'sanitize', 'xss', 'csrf', 'cors'
    },
}

# Security-priority file patterns (files more likely to contain vulnerabilities)
SECURITY_PRIORITY_PATTERNS = [
    # Authentication & Authorization
    r'(?:auth|login|oauth|jwt|session|permission|role|access).*\.(py|js|ts|go|rb|php)$',
    r'.*(?:auth|login|oauth|jwt|session|permission|role|access)\.(py|js|ts|go|rb|php)$',
    
    # Database queries
    r'(?:query|repository|dao|orm|model).*\.(py|js|ts|go|rb|php)$',
    r'.*(?:sql|query|database|db)\.(py|js|ts|go|rb|php)$',
    
    # API endpoints
    r'(?:api|endpoint|route|controller|handler).*\.(py|js|ts|go|rb|php)$',
    
    # File operations
    r'(?:file|upload|download|path|upload).*\.(py|js|ts|go|rb|php)$',
    
    # External calls
    r'(?:http|request|fetch|curl|wget|axios|ajax).*\.(py|js|ts|go|rb|php)$',
    
    # Serialization
    r'(?:serial|deserialize|unserialize|parse|yaml|json).*\.(py|js|ts|go|rb|php)$',
    
    # Command execution
    r'(?:exec|shell|command|system|spawn|popen).*\.(py|js|ts|go|rb|php)$',
]

# Cross-slice dependency indicators (imports, requires, includes)
DEPENDENCY_PATTERNS = {
    'python': [
        r'^\s*from\s+[\w.]+\s+import',
        r'^\s*import\s+[\w.]+',
    ],
    'javascript': [
        r'^\s*require\s*\(',
        r'^\s*import\s+.*from',
        r'^\s*import\s+[\'"{]',
    ],
    'typescript': [
        r'^\s*require\s*\(',
        r'^\s*import\s+.*from',
        r'^\s*import\s+[\'"{]',
    ],
    'go': [
        r'^\s*import\s+',
    ],
    'ruby': [
        r'^\s*require\s+',
        r'^\s*include\s+',
    ],
    'java': [
        r'^\s*import\s+',
    ],
}


class IntelligentSlicer:
    """Intelligent code slicer with smart chunking strategies."""

    IGNORE_DIRS = {
        '.git', '.github', 'node_modules', '__pycache__', '.venv', 'venv',
        'dist', 'build', '.idea', '.vscode', 'vendor', 'target', 'coverage',
        '.tox', 'env', '.env', 'static', 'media', 'uploads', 'cache', 'logs',
        '.next', '.nuxt', '.sveltekit', 'gatsby', '.webpack', 'bundle',
        'test', 'tests', '__tests__', 'spec', 'mock', 'fixtures'
    }

    IGNORE_FILES = {
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
        'Pipfile.lock', 'requirements.txt', 'composer.lock', 'Cargo.lock',
        '.gitignore', '.env', '.env.example', '*.min.js', '*.min.css',
        '*.md', '*.txt', '*.json', '*.yaml', '*.yml', '*.xml',
    }

    CODE_EXTENSIONS = set(LANGUAGE_PATTERNS.keys())

    def __init__(self, config: Optional[Config] = None):
        """Initialize intelligent code slicer."""
        self.config = config or Config()
        self.max_file_size = self.config.get_max_file_size()
        self.target_tokens = self.config.get_slice_tokens()
        
        # Cache for project analysis
        self._file_deps: Dict[str, Set[str]] = {}
        self._boundary_map: Dict[str, LogicalBoundary] = {}
        self._project_pattern: Optional[str] = None

    def slice_target(self, target: str) -> List[Dict[str, Any]]:
        """Slice a target (GitHub repo or local path) into intelligent chunks."""
        if self._is_github(target):
            return self._slice_github(target)
        else:
            return self._slice_local(target)

    def _is_github(self, target: str) -> bool:
        """Check if target is GitHub URL or owner/repo."""
        return 'github.com' in target or re.match(r'^[\w-]+/[\w-]+$', target)

    def _slice_github(self, target: str) -> List[Dict[str, Any]]:
        """Slice GitHub repository."""
        match = re.search(r'github\.com[/:]([\w-]+)/([\w-]+?)(?:\.git)?$', target)
        if match:
            owner, repo = match.group(1), match.group(2)
        else:
            owner, repo = target.split('/')

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
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _slice_local(self, target: str) -> List[Dict[str, Any]]:
        """Slice local directory."""
        path = Path(target)
        if not path.exists():
            raise ValueError(f"Path does not exist: {target}")

        if path.is_file():
            return [self._create_file_slice(path, "local")]

        return self._slice_directory(path, "local")

    def _slice_directory(self, directory: Path, source: str) -> List[Dict[str, Any]]:
        """Slice directory with intelligent strategies."""
        slices = []
        
        # Phase 1: Analyze project structure
        self._analyze_project_structure(directory)
        
        # Phase 2: Collect all code files
        code_files = self._collect_code_files(directory)
        
        # Phase 3: Detect logical boundaries
        self._detect_logical_boundaries(code_files, directory)
        
        # Phase 4: Build slices based on patterns
        slices = self._build_slices(code_files, directory, source)
        
        # Phase 5: Add dependency context to slices
        slices = self._enrich_with_dependencies(slices, code_files, directory)
        
        # Phase 6: Filter and limit by size
        slices = self._apply_size_limits(slices)
        
        # Sort by security priority
        slices = self._sort_by_priority(slices)
        
        return slices

    def _analyze_project_structure(self, directory: Path) -> None:
        """Analyze and detect project structure pattern."""
        subdirs = {d.name.lower() for d in directory.iterdir() if d.is_dir() and d.name not in self.IGNORE_DIRS}
        files = {f.name.lower() for f in directory.iterdir() if f.is_file()}
        
        # Check for MVC pattern
        mvc_indicators = {'models', 'views', 'controllers', 'model', 'view', 'controller'}
        if len(mvc_indicators & subdirs) >= 2:
            self._project_pattern = ProjectPattern.MVC
            return
        
        # Check for microservices
        microservice_indicators = {'services', 'service', 'gateway', 'registry', 'config'}
        if len(microservice_indicators & subdirs) >= 2:
            self._project_pattern = ProjectPattern.MICROSERVICES
            return
        
        # Check for API-first project
        api_indicators = {'api', 'apis', 'routes', 'endpoints', 'handlers'}
        if len(api_indicators & subdirs) >= 1:
            self._project_pattern = ProjectPattern.API_FIRST
            return
        
        # Check for library/package
        library_indicators = {'src', 'lib', 'package.json', 'setup.py', 'pyproject.toml', 'Cargo.toml'}
        if library_indicators & files or 'src' in subdirs:
            self._project_pattern = ProjectPattern.LIBRARY
            return
        
        # Check for flat structure (minimal subdirs)
        if len(subdirs) <= 3:
            self._project_pattern = ProjectPattern.FLAT
            return
        
        self._project_pattern = ProjectPattern.MONOLITH

    def _collect_code_files(self, directory: Path) -> List[Tuple[Path, str]]:
        """Collect all code files with their relative paths."""
        code_files = []
        
        for root, dirs, files in os.walk(directory):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            
            root_path = Path(root)
            
            for file in files:
                file_path = root_path / file
                
                if not self._should_include(file_path):
                    continue
                    
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        # Skip large files for now, handle separately
                        continue
                except Exception:
                    continue
                
                rel_path = str(file_path.relative_to(directory))
                code_files.append((file_path, rel_path))
        
        return code_files

    def _detect_logical_boundaries(self, code_files: List[Tuple[Path, str]], base_path: Path) -> None:
        """Detect logical boundaries for each file."""
        self._boundary_map.clear()
        
        for file_path, rel_path in code_files:
            # Get directory and file name for pattern matching
            dir_name = file_path.parent.name.lower()
            file_name = file_path.name.lower()
            
            # Try to get relative directory path
            try:
                rel_dir = str(file_path.parent.relative_to(base_path)).lower()
            except ValueError:
                rel_dir = ""
            
            detected = False
            
            # Check directory patterns first
            for boundary, patterns in BOUNDARY_PATTERNS.items():
                if dir_name in patterns or (rel_dir and any(p in rel_dir for p in patterns)):
                    self._boundary_map[rel_path] = boundary
                    detected = True
                    break
            
            # Check file name patterns if no directory match
            if not detected:
                for boundary, patterns in BOUNDARY_PATTERNS.items():
                    # Check if any pattern matches the file name (without extension)
                    file_stem = file_path.stem.lower()
                    if any(p in file_stem for p in patterns):
                        self._boundary_map[rel_path] = boundary
                        detected = True
                        break
            
            # Default to core if no pattern matched
            if not detected:
                self._boundary_map[rel_path] = LogicalBoundary.CORE

    def _build_slices(self, code_files: List[Tuple[Path, str]], directory: Path, source: str) -> List[Dict[str, Any]]:
        """Build slices based on detected patterns and boundaries."""
        slices = []
        
        # Group files by logical boundary
        boundary_groups: Dict[str, List[Tuple[Path, str]]] = defaultdict(list)
        
        for file_path, rel_path in code_files:
            boundary = self._boundary_map.get(rel_path, LogicalBoundary.CORE)
            boundary_groups[boundary].append((file_path, rel_path))
        
        # Build slices from each boundary group
        for boundary, files in boundary_groups.items():
            if not files:
                continue
            
            # Create combined slice for the boundary
            slice_content = self._combine_files_with_headers(files, directory, boundary)
            estimated_tokens = len(slice_content) // CHARS_PER_TOKEN
            
            if estimated_tokens <= self.target_tokens:
                # Fits in one slice
                slices.append({
                    "source": source,
                    "path": f"boundary:{boundary}",
                    "type": "logical_boundary",
                    "boundary": boundary,
                    "content": slice_content,
                    "files": [rel for _, rel in files],
                    "file_count": len(files),
                    "estimated_tokens": estimated_tokens,
                    "security_priority": self._calculate_boundary_priority(boundary)
                })
            else:
                # Need to split this boundary
                slices.extend(self._split_boundary_group(files, directory, source, boundary))
        
        # Add large file chunks as separate slices
        slices.extend(self._handle_large_files(directory, source))
        
        return slices

    def _combine_files_with_headers(self, files: List[Tuple[Path, str]], base_path: Path, boundary: str) -> str:
        """Combine multiple files with file headers for context."""
        combined = []
        
        for file_path, rel_path in files:
            content = self._read_file(file_path)
            if not content:
                continue
            
            # Add file header for context
            header = f"\n# File: {rel_path}\n"
            combined.append(header + content)
        
        return "\n".join(combined)

    def _split_boundary_group(self, files: List[Tuple[Path, str]], directory: Path, source: str, boundary: str) -> List[Dict[str, Any]]:
        """Split a boundary group into smaller slices if needed."""
        slices = []
        
        # Sort files by security priority within the boundary
        sorted_files = sorted(files, key=lambda x: self._get_file_priority(x[1]), reverse=True)
        
        current_slice_files = []
        current_content = ""
        
        for file_path, rel_path in sorted_files:
            content = self._read_file(file_path)
            if not content:
                continue
            
            file_header = f"\n# File: {rel_path}\n{content}\n"
            file_tokens = len(file_header) // CHARS_PER_TOKEN
            
            # Check if this file ALONE exceeds the limit
            if file_tokens > self.target_tokens:
                # Create current slice first if there's content
                if current_slice_files:
                    slices.append({
                        "source": source,
                        "path": f"boundary:{boundary}",
                        "type": "logical_boundary",
                        "boundary": boundary,
                        "content": current_content,
                        "files": [rel for _, rel in current_slice_files],
                        "file_count": len(current_slice_files),
                        "estimated_tokens": len(current_content) // CHARS_PER_TOKEN,
                        "security_priority": self._calculate_boundary_priority(boundary)
                    })
                    current_slice_files = []
                    current_content = ""
                
                # Add this large file as its own slice
                slices.append({
                    "source": source,
                    "path": f"boundary:{boundary}",
                    "type": "logical_boundary",
                    "boundary": boundary,
                    "content": file_header,
                    "files": [rel_path],
                    "file_count": 1,
                    "estimated_tokens": file_tokens,
                    "security_priority": self._get_file_priority(rel_path)
                })
                continue
            
            new_content = current_content + file_header
            new_tokens = len(new_content) // CHARS_PER_TOKEN
            
            if new_tokens > self.target_tokens and current_slice_files:
                # Would exceed limit, create slice with current content
                slices.append({
                    "source": source,
                    "path": f"boundary:{boundary}",
                    "type": "logical_boundary",
                    "boundary": boundary,
                    "content": current_content,
                    "files": [rel for _, rel in current_slice_files],
                    "file_count": len(current_slice_files),
                    "estimated_tokens": len(current_content) // CHARS_PER_TOKEN,
                    "security_priority": self._calculate_boundary_priority(boundary)
                })
                # Start fresh with just this file
                current_slice_files = [(file_path, rel_path)]
                current_content = file_header
            else:
                current_slice_files.append((file_path, rel_path))
                current_content = new_content
        
        # Add remaining files
        if current_slice_files:
            slices.append({
                "source": source,
                "path": f"boundary:{boundary}",
                "type": "logical_boundary",
                "boundary": boundary,
                "content": current_content,
                "files": [rel for _, rel in current_slice_files],
                "file_count": len(current_slice_files),
                "estimated_tokens": len(current_content) // CHARS_PER_TOKEN,
                "security_priority": self._calculate_boundary_priority(boundary)
            })
        
        return slices

    def _handle_large_files(self, directory: Path, source: str) -> List[Dict[str, Any]]:
        """Handle large files by splitting them intelligently."""
        slices = []
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            root_path = Path(root)
            
            for file in files:
                file_path = root_path / file
                
                if not self._should_include(file_path):
                    continue
                
                try:
                    if file_path.stat().st_size <= self.max_file_size:
                        continue
                except Exception:
                    continue
                
                # Split large file intelligently
                slices.extend(self._split_large_file(file_path, source))
        
        return slices

    def _split_large_file(self, path: Path, source: str, chunk_size: int = 400) -> List[Dict[str, Any]]:
        """Split large file into intelligent chunks based on functions/classes."""
        content = self._read_file(path)
        if not content:
            return []
        
        lines = content.splitlines()
        chunks = []
        current_chunk_lines = []
        current_chunk_start = 1
        
        # Try to split at logical boundaries (function/class definitions)
        logical_split_patterns = [
            r'^def\s+', r'^class\s+', r'^function\s+', r'^const\s+', 
            r'^let\s+', r'^var\s+', r'^export\s+', r'^import\s+',
            r'^#\s*=', r'^//\s*===', r'^/\*\*'
        ]
        
        for i, line in enumerate(lines):
            current_chunk_lines.append(line)
            
            # Check if we should split here
            should_split = len(current_chunk_lines) >= chunk_size
            
            if should_split:
                # Check if next line starts a logical block
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    for pattern in logical_split_patterns:
                        if re.match(pattern, next_line.strip()):
                            should_split = True
                            break
                    else:
                        should_split = len(current_chunk_lines) > chunk_size * 1.5
            
            if should_split and current_chunk_lines:
                chunk_content = "\n".join(current_chunk_lines)
                chunks.append({
                    "source": source,
                    "path": f"{path}:{current_chunk_start}-{current_chunk_start + len(current_chunk_lines) - 1}",
                    "type": "file_chunk",
                    "boundary": self._boundary_map.get(str(path), LogicalBoundary.CORE),
                    "content": chunk_content,
                    "lines": len(current_chunk_lines),
                    "estimated_tokens": len(chunk_content) // CHARS_PER_TOKEN,
                    "security_priority": self._get_file_priority(str(path))
                })
                current_chunk_lines = []
                current_chunk_start = i + 2
        
        # Add remaining chunk
        if current_chunk_lines:
            chunk_content = "\n".join(current_chunk_lines)
            chunks.append({
                "source": source,
                "path": f"{path}:{current_chunk_start}-{current_chunk_start + len(current_chunk_lines) - 1}",
                "type": "file_chunk",
                "boundary": self._boundary_map.get(str(path), LogicalBoundary.CORE),
                "content": chunk_content,
                "lines": len(current_chunk_lines),
                "estimated_tokens": len(chunk_content) // CHARS_PER_TOKEN,
                "security_priority": self._get_file_priority(str(path))
            })
        
        return chunks

    def _enrich_with_dependencies(self, slices: List[Dict[str, Any]], code_files: List[Tuple[Path, str]], base_path: Path) -> List[Dict[str, Any]]:
        """Add dependency context to slices for cross-slice understanding."""
        # Build a simple dependency graph based on imports
        deps = self._build_dependency_graph(code_files, base_path)
        
        # Add dependency hints to slices
        for slice_obj in slices:
            files = slice_obj.get("files", [])
            if not files:
                continue
            
            # Find related files (dependencies)
            related = set()
            for f in files:
                if f in deps:
                    related.update(deps[f])
            
            # Filter to files in other slices
            other_files = set()
            for s in slices:
                if s.get("path") != slice_obj.get("path"):
                    other_files.update(s.get("files", []))
            
            relevant_deps = related & other_files
            if relevant_deps:
                slice_obj["depends_on"] = list(relevant_deps)[:5]  # Limit to 5
        
        return slices

    def _build_dependency_graph(self, code_files: List[Tuple[Path, str]], base_path: Path) -> Dict[str, Set[str]]:
        """Build a simple dependency graph from imports."""
        graph = {}
        
        for file_path, rel_path in code_files:
            content = self._read_file(file_path)
            if not content:
                continue
            
            deps = set()
            ext = file_path.suffix
            lang = LANGUAGE_PATTERNS.get(ext, 'unknown')
            
            patterns = DEPENDENCY_PATTERNS.get(lang, [])
            for pattern in patterns:
                matches = re.findall(pattern, content, re.MULTILINE)
                for match in matches:
                    # Extract module name
                    module = re.search(r'([\w.]+)', match)
                    if module:
                        deps.add(module.group(1))
            
            if deps:
                graph[rel_path] = deps
        
        return graph

    def _apply_size_limits(self, slices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter and limit slices by size."""
        filtered = []
        
        for slice_obj in slices:
            tokens = slice_obj.get("estimated_tokens", 0)
            
            # Skip if way over limit
            if tokens > self.target_tokens * 3:
                continue
            
            # Truncate content if slightly over
            if tokens > self.target_tokens:
                content = slice_obj["content"]
                max_chars = self.target_tokens * CHARS_PER_TOKEN
                slice_obj["content"] = content[:max_chars] + "\n# ... (truncated)"
                slice_obj["truncated"] = True
            
            filtered.append(slice_obj)
        
        return filtered

    def _sort_by_priority(self, slices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort slices by security priority."""
        return sorted(slices, key=lambda x: x.get("security_priority", 0), reverse=True)

    def _calculate_boundary_priority(self, boundary: str) -> int:
        """Calculate security priority for a boundary type."""
        priorities = {
            LogicalBoundary.AUTH: 100,
            LogicalBoundary.SECURITY: 95,
            LogicalBoundary.API: 80,
            LogicalBoundary.DATABASE: 75,
            LogicalBoundary.MIDDLEWARE: 60,
            LogicalBoundary.CORE: 50,
            LogicalBoundary.SERVICES: 40,
            LogicalBoundary.CONFIG: 30,
            LogicalBoundary.UTILS: 20,
            LogicalBoundary.VIEWS: 10,
        }
        return priorities.get(boundary, 50)

    def _get_file_priority(self, file_path: str) -> int:
        """Get security priority for a file."""
        path_lower = file_path.lower()
        
        for i, pattern in enumerate(SECURITY_PRIORITY_PATTERNS):
            if re.search(pattern, path_lower):
                # Higher priority for earlier patterns
                return 100 - (i * 5)
        
        # Check boundary-based priority
        boundary = self._boundary_map.get(file_path, LogicalBoundary.CORE)
        return self._calculate_boundary_priority(boundary)

    def _should_include(self, path: Path) -> bool:
        """Check if file should be included."""
        if path.suffix not in self.CODE_EXTENSIONS:
            return False

        if path.name in self.IGNORE_FILES:
            return False

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

    def _create_file_slice(self, path: Path, source: str) -> Dict[str, Any]:
        """Create a slice for a single file."""
        content = self._read_file(path)
        return {
            "source": source,
            "path": str(path),
            "type": "file",
            "content": content,
            "lines": len(content.splitlines()),
            "estimated_tokens": len(content) // CHARS_PER_TOKEN,
            "security_priority": self._get_file_priority(str(path))
        }

    def get_slice_summary(self, slices: List[Dict[str, Any]]) -> str:
        """Get summary of slices."""
        total_tokens = sum(s.get("estimated_tokens", 0) for s in slices)
        boundary_types = defaultdict(int)
        
        for s in slices:
            bt = s.get("boundary", "unknown")
            boundary_types[bt] += 1
        
        boundary_info = ", ".join(f"{k}: {v}" for k, v in boundary_types.items())
        
        return (
            f"Created {len(slices)} intelligent slices "
            f"(~{total_tokens} total tokens). "
            f"Boundaries: {boundary_info}"
        )

    def get_project_pattern(self) -> Optional[str]:
        """Get detected project pattern."""
        return self._project_pattern


def slice_codebase(target: str, config: Optional[Config] = None) -> List[Dict[str, Any]]:
    """Convenience function to slice codebase with intelligent strategy."""
    slicer = IntelligentSlicer(config)
    return slicer.slice_target(target)


# Backward compatibility alias
CodeSlicer = IntelligentSlicer
