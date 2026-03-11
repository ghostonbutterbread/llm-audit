#!/usr/bin/env python3
"""Setup script for llm-audit."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="llm-audit",
    version="1.0.0",
    description="LLM-powered vulnerability research tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Ghost",
    author_email="ghost@example.com",
    url="https://github.com/ghost/llm-audit",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.28.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "llm-audit=llm_audit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
)