# Auki Authentication - Python Package

Python client library for authenticating with the Auki Network and accessing the Posemesh.

## Features

- **Async/Await API** - Modern Python async interface with automatic authentication
- **Token Management** - Automatic refresh and caching
- **Multi-Domain Support** - Authenticate to multiple domains with one client
- **Cross-Platform** - Single package works on macOS (Intel & ARM), Linux (x86_64 & ARM64), and Windows
- **Type Hints** - Full type annotations for better IDE support
- **Optimized Binaries** - Small, fast native libraries (~500KB per platform)

## Prerequisites

### For Using the Package

- Python 3.8 or higher
- pip

### For Building from Source

All builds are handled via the root Makefile.

**Requirements:**

- Rust toolchain (cargo) - [Install from rustup.rs](https://rustup.rs)
- uniffi-bindgen - Auto-installed via `make install-tools`
- cross (for multi-platform builds) - Auto-installed via `make install-tools`
- Docker Desktop (for cross-compilation) - [Download here](https://www.docker.com/products/docker-desktop)

## Quick Start

### Building

From the repository root:

```bash
# Install build tools (first time only)
make install-tools

# Build Python package with binaries for all platforms
make python

# The package is ready at: pkg/python/
```

### Creating a Distribution Package

```bash
cd pkg/python

# Create a .tar.gz with all platform binaries
python setup.py sdist

# Or create a wheel
python -m build

# Or create a zip for easy testing
python zip.py
```

### Installation

```bash
# From the built package
pip install dist/auki-authentication-0.1.0.tar.gz

# Or from a zip
pip install dist/auki-authentication-0.1.0.zip

# For development (editable install)
cd pkg/python
pip install -e .
```

## Usage

### High-Level Async API (Recommended)

The high-level API automatically handles the complete authentication flow - you just call `get_domain_access()` and it takes care of network authentication, discovery authentication, and domain access in one step.

```python
import asyncio
from auki_authentication import Client, Config

async def main():
    # Configure the client
    config = Config(
        api_url="https://api.aukiverse.com",
        refresh_url="https://api.aukiverse.com/user/refresh",
        dds_url="https://dds.posemesh.org",
        client_id="my-app",
    )

    # Set up credentials
    credentials = {
        "type": "email",
        "email": "user@example.com",
        "password": "your-password",
    }

    # Use async context manager for automatic cleanup
    async with Client(config, credentials) as client:
        # Get domain access - automatically handles full auth chain
        # No need to call authenticate() or authenticate_discovery() first!
        domain_access = await client.get_domain_access("domain-id-here")

        print(f"Domain: {domain_access.name}")
        print(f"Server: {domain_access.domain_server.url}")
        print(f"Access token: {domain_access.access_token}")

asyncio.run(main())
```

#### Manual Authentication Steps (Optional)

If you need more control, you can authenticate step by step:

```python
async with Client(config, credentials) as client:
    # Step 1: Authenticate to network
    network_token = await client.authenticate()
    print(f"Network token: {network_token.token}")

    # Step 2: Authenticate to discovery service
    discovery_token = await client.authenticate_discovery()
    print(f"Discovery token: {discovery_token.token}")

    # Step 3: Get access to a specific domain
    domain_access = await client.get_domain_access("domain-id-here")
    print(f"Domain access: {domain_access.access_token}")
```

### Token Refresh

The client automatically handles token refresh:

```python
async with Client(config, credentials) as client:
    # Initial authentication
    await client.authenticate()

    # ... time passes ...

    # Calling authenticate() again will:
    # - Return cached token if still valid
    # - Refresh token if near expiry
    # - Re-authenticate if refresh token expired
    await client.authenticate()
```

### Multi-Domain Access

```python
async with Client(config, credentials) as client:
    await client.authenticate()
    await client.authenticate_discovery()

    # Authenticate to multiple domains
    domain1 = await client.get_domain_access("domain-1-id")
    domain2 = await client.get_domain_access("domain-2-id")

    # Access cached domain info
    cached = client.get_cached_domain_access("domain-1-id")
```

### State Persistence

```python
# Save client state (excludes credentials)
state_json = client.save_state()
# Store state_json somewhere (file, database, etc.)

# Later, restore from state
new_client = Client.from_state(state_json, config)
new_client.set_credentials(credentials)  # Re-add credentials
await new_client.authenticate()  # Will use cached tokens if valid
```

### Low-Level API (Raw Bindings)

For advanced use cases where you need full control over the authentication loop and HTTP requests, you can use the raw Rust bindings directly. The bindings use a "sans-I/O" pattern - the core library tells you what HTTP requests to make, and you provide the responses.

```python
import json
import httpx
from auki_authentication import (
    NativeClient,
    NativeConfig,
    NativeCredentials,
    current_time_ms,
)

# Create configuration
config = NativeConfig(
    api_url="https://api.aukiverse.com",
    refresh_url="https://api.aukiverse.com/user/refresh",
    dds_url="https://dds.posemesh.org",
    client_id="my-app",
    refresh_threshold_ms=300000
)

# Create credentials
credentials = NativeCredentials.Email(
    email="user@example.com",
    password="your-password"
)

# Create the native client
client = NativeClient(config)
client.set_credentials(credentials)

# Get domain access using the sans-I/O loop pattern
async def get_domain_access(domain_id: str):
    max_iterations = 10

    for iteration in range(max_iterations):
        # Get current timestamp
        now = current_time_ms()

        # Ask the client what HTTP requests need to be made
        actions_json = client.get_domain_access(domain_id, now)
        actions = json.loads(actions_json)

        if not actions:
            # No more actions - we should have cached access
            access_json = client.get_cached_domain_access(domain_id)
            if access_json:
                return json.loads(access_json)
            raise Exception("No domain access available")

        # Execute each HTTP request
        events = []
        async with httpx.AsyncClient() as http:
            for action in actions:
                if action["type"] == "HttpRequest":
                    req = action["request"]

                    # Make the HTTP request
                    response = await http.request(
                        method=req["method"],
                        url=req["url"],
                        headers=req.get("headers", {}),
                        json=json.loads(req["body"]) if req.get("body") else None,
                    )

                    # Create response event
                    event = {
                        "type": "HttpResponse",
                        "request_id": req["id"],
                        "response": {
                            "status": response.status_code,
                            "body": response.text,
                        }
                    }
                    events.append(event)

        # Feed responses back to the client
        events_json = json.dumps(events)
        client.handle_events(events_json)

        # Check for failures in the events
        for event in events:
            response = event.get("response", {})
            if response.get("status", 0) >= 400:
                raise Exception(f"HTTP error: {response.get('status')}")

    raise Exception("Max iterations exceeded")

# Use it
domain_access = await get_domain_access("domain-id-here")
print(f"Access token: {domain_access['access_token']}")
```

The raw bindings are useful when:

- You need to use a different HTTP client
- You want to implement custom retry logic
- You need to integrate with existing sans-I/O architecture
- You want full control over the authentication flow

## Building

The Python package is built using the root Makefile, which handles all compilation and packaging:

```bash
# From repository root
make python
```

This automatically:

1. Builds optimized Rust binaries for all platforms (macOS, Linux, Windows)
2. Generates Python bindings using uniffi
3. Patches bindings to use the multi-platform loader
4. Copies all platform libraries to the correct locations
5. Validates the build

The result is a complete multi-platform package at `pkg/python/` containing:

- **macOS**: Intel (x86_64) and Apple Silicon (ARM64)
- **Linux**: x86_64 and ARM64
- **Windows**: x86_64

Total size: ~2.7MB for all 5 platforms (~540KB per platform)

### Platform-Specific Details

The build uses:

- **Native cargo** for macOS builds
- **cross + Docker** for Linux and Windows builds
- **LTO and size optimizations** for minimal binary sizes
- **Platform detection at runtime** to load the correct library

## Package Structure

```
pkg/python/
├── src/                       # Package source (version controlled)
│   ├── __init__.py           # Public API exports + platform loader
│   ├── client.py             # High-level async client
│   └── bindings/             # Generated bindings (build artifact)
│       ├── authentication.py # Generated uniffi bindings
│       ├── py.typed          # PEP 561 type marker
│       └── lib/              # Platform-specific libraries
│           ├── macosx_10_12_x86_64/libauthentication.dylib
│           ├── macosx_11_0_arm64/libauthentication.dylib
│           ├── manylinux_2_17_x86_64/libauthentication.so
│           ├── manylinux_2_17_aarch64/libauthentication.so
│           └── win_amd64/authentication.dll
├── examples/                  # Usage examples
│   └── test_auto_auth.py
├── pyproject.toml             # Modern Python packaging
├── setup.py                   # setuptools configuration
├── validate_build.py          # Build validation script
├── zip.py                     # Create distributable zip
└── README.md                  # This file
```

## Development

### Running Examples

```bash
# Set up credentials
cp ../../.env.example ../../.env
# Edit .env with your credentials

# Run the auto-authentication example
cd pkg/python
python3 examples/test_auto_auth.py
```

### Cleaning

From the repository root:

```bash
# Remove all build artifacts (JavaScript + Python)
make clean
```

This removes the entire `src/bindings/` directory.

## API Reference

### High-Level API

- `Client` - Main authentication client (async)
- `Config` - Client configuration
- `Token` - Token information
- `DomainAccess` - Domain access information
- `DomainServer` - Server details
- `AuthenticationError` - Authentication errors

### Utility Functions

- `current_time_ms()` - Get current time in milliseconds
- `is_expired(expires_at, now)` - Check if token is expired
- `is_near_expiry(expires_at, now, threshold_ms)` - Check if token needs refresh

### Low-Level API

For advanced use cases, you can use the generated uniffi bindings directly:

- `NativeClient` - Sans-IO client (you handle HTTP)
- `NativeCredentials` - Credentials enum
- `NativeConfig` - Configuration record
- See `authentication.py` for full low-level API

## Troubleshooting

### ImportError: No module named 'auki_authentication'

The package needs to be built first:

```bash
# From repository root
make python
```

### RuntimeError: Library not found for {platform}

Your platform may not have binaries included. Check which platforms are available:

```bash
ls pkg/python/src/bindings/lib/
```

The package includes: macOS (x86_64, ARM64), Linux (x86_64, ARM64), Windows (x86_64).

### Build tools not found

Install all required tools:

```bash
make install-tools
```

### Docker errors during cross-compilation

Make sure Docker Desktop is running. The build uses Docker for cross-compiling Linux and Windows binaries on macOS.

## License

MIT

## Support

For issues and questions:

- GitHub Issues: https://github.com/aukilabs/experimental-modules/issues
- Documentation: https://github.com/aukilabs/experimental-modules

## Related

- [JavaScript/TypeScript Package](../javascript/README.md)
- [Rust Core Library](../../README.md)
