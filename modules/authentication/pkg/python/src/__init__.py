"""
Auki Authentication Library

High-level authentication client for the Auki Network.
Handles HTTP requests and event processing internally.
Works with asyncio for async/await patterns.
"""

import platform
import ctypes
from pathlib import Path


def get_lib_path():
    """
    Get the path to the platform-specific native library.

    This function detects the current OS and architecture, then returns
    the path to the appropriate compiled Rust library binary.

    Returns:
        str: Absolute path to the platform-specific library

    Raises:
        RuntimeError: If the platform is unsupported or library not found
    """
    system = platform.system()
    machine = platform.machine()

    # Determine platform string and library name
    if system == "Darwin":  # macOS
        if machine == "arm64":
            platform_str = "macosx_11_0_arm64"
            lib_name = "libauthentication.dylib"
        else:  # x86_64
            platform_str = "macosx_10_12_x86_64"
            lib_name = "libauthentication.dylib"
    elif system == "Linux":
        if machine in ["x86_64", "AMD64"]:
            platform_str = "manylinux_2_17_x86_64"
            lib_name = "libauthentication.so"
        elif machine in ["aarch64", "arm64"]:
            platform_str = "manylinux_2_17_aarch64"
            lib_name = "libauthentication.so"
        else:
            raise RuntimeError(f"Unsupported Linux architecture: {machine}")
    elif system == "Windows":
        if machine in ["AMD64", "x86_64"]:
            platform_str = "win_amd64"
            lib_name = "authentication.dll"
        else:
            raise RuntimeError(f"Unsupported Windows architecture: {machine}")
    else:
        raise RuntimeError(f"Unsupported operating system: {system}")

    # Construct path to library
    lib_dir = Path(__file__).parent / "bindings" / "lib" / platform_str
    lib_path = lib_dir / lib_name

    if not lib_path.exists():
        raise RuntimeError(
            f"Library not found for {system} {machine} at {lib_path}. "
            f"The package may not include binaries for your platform."
        )

    return str(lib_path)


# High-level API
from .client import (
    Client,
    Config,
    Token,
    DomainAccess,
    DomainServer,
    AuthenticationError,
)

# Low-level bindings (for advanced use)
from .bindings.authentication import (
    NativeClient,
    NativeConfig,
    NativeCredentials,
    NativeAuthenticationState,
    NativeDomainServer,
    NativeDomainAccess,
    NativeNetworkAuth,
    NativeDiscoveryAuth,
    current_time_ms,
    is_expired,
    is_near_expiry,
)

__version__ = "0.1.0"

__all__ = [
    # High-level API (recommended)
    "Client",
    "Config",
    "Token",
    "DomainAccess",
    "DomainServer",
    "AuthenticationError",
    # Utility functions
    "current_time_ms",
    "is_expired",
    "is_near_expiry",
    # Low-level API (advanced use)
    "NativeClient",
    "NativeConfig",
    "NativeCredentials",
    "NativeAuthenticationState",
    "NativeDomainServer",
    "NativeDomainAccess",
    "NativeNetworkAuth",
    "NativeDiscoveryAuth",
]
