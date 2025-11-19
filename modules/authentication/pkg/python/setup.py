#!/usr/bin/env python3
"""
Setup script for Auki Authentication Python bindings.
"""
from setuptools import setup, find_packages
import os

# Read the README file if it exists
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="auki-authentication",
    version="0.1.0",
    description="Auki Network Authentication Library - Python bindings",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Auki Labs",
    author_email="info@aukilabs.com",
    url="https://github.com/aukilabs/experimental-modules",
    packages=["auki_authentication"],
    package_dir={"auki_authentication": "src"},
    package_data={
        "auki_authentication": [
            "bindings/*.py",  # Python bindings
            "bindings/py.typed",  # Type marker
            "bindings/lib/macosx_10_12_x86_64/*.dylib",  # macOS x86_64
            "bindings/lib/macosx_11_0_arm64/*.dylib",  # macOS ARM64
            "bindings/lib/manylinux_2_17_x86_64/*.so",  # Linux x86_64
            "bindings/lib/manylinux_2_17_aarch64/*.so",  # Linux ARM64
            "bindings/lib/win_amd64/*.dll",  # Windows x86_64
        ],
    },
    install_requires=[
        "httpx>=0.24.0",  # For async HTTP requests in high-level client
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Rust",
    ],
    zip_safe=False,
)
