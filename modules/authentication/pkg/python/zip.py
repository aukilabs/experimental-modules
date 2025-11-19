#!/usr/bin/env python3
"""
Create a distributable zip package for the Auki Authentication Python library.

This script packages the built Python library into a zip file that can be
installed with pip. It includes all platform-specific binaries.

Usage:
    python zip.py

This creates: dist/auki-authentication-0.1.0.zip
Install with:  pip install dist/auki-authentication-0.1.0.zip
"""

import os
import shutil
import zipfile
from pathlib import Path


def create_zip():
    """Create a zip distribution package."""

    # Version and package info
    VERSION = "0.1.0"
    PACKAGE_NAME = "auki-authentication"
    ZIP_NAME = f"{PACKAGE_NAME}-{VERSION}.zip"

    # Paths
    script_dir = Path(__file__).parent
    dist_dir = script_dir / "dist"
    src_dir = script_dir / "src"
    zip_path = dist_dir / ZIP_NAME

    # Check that the package has been built
    bindings_dir = src_dir / "bindings"
    if not bindings_dir.exists():
        print("❌ Bindings not found!")
        print("   Run 'make python' from the repository root first.")
        return 1

    # Check for platform libraries
    lib_dir = bindings_dir / "lib"
    if not lib_dir.exists() or not any(lib_dir.iterdir()):
        print("❌ No platform libraries found!")
        print("   Run 'make python' from the repository root first.")
        return 1

    # Count platforms
    platforms = [d.name for d in lib_dir.iterdir() if d.is_dir()]
    print(f"Found {len(platforms)} platform(s):")
    for platform in platforms:
        libs = list((lib_dir / platform).iterdir())
        if libs:
            print(f"  ✓ {platform}: {libs[0].name} ({libs[0].stat().st_size // 1024}KB)")

    # Create dist directory
    dist_dir.mkdir(exist_ok=True)

    # Remove old zip if it exists
    if zip_path.exists():
        zip_path.unlink()

    print(f"\nCreating {ZIP_NAME}...")

    # Create the zip file
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add all Python source files
        for py_file in src_dir.rglob("*.py"):
            arcname = f"auki_authentication/{py_file.relative_to(src_dir)}"
            zf.write(py_file, arcname)
            print(f"  Added: {arcname}")

        # Add all platform libraries
        for lib_file in lib_dir.rglob("*"):
            if lib_file.is_file():
                arcname = f"auki_authentication/bindings/{lib_file.relative_to(bindings_dir)}"
                zf.write(lib_file, arcname)
                # Don't print each lib file to keep output clean

        # Add py.typed marker
        py_typed = bindings_dir / "py.typed"
        if py_typed.exists():
            zf.write(py_typed, "auki_authentication/bindings/py.typed")

        # Add setup files
        for setup_file in ["setup.py", "pyproject.toml", "README.md"]:
            setup_path = script_dir / setup_file
            if setup_path.exists():
                zf.write(setup_path, setup_file)
                print(f"  Added: {setup_file}")

    # Get zip size
    zip_size = zip_path.stat().st_size

    print(f"\n✓ Created: {zip_path}")
    print(f"  Size: {zip_size // 1024}KB ({zip_size // 1024 // len(platforms)}KB per platform)")
    print(f"\nTo install:")
    print(f"  pip install {zip_path}")
    print(f"\nOr to install in editable mode for development:")
    print(f"  pip install -e .")

    return 0


if __name__ == "__main__":
    exit(create_zip())
