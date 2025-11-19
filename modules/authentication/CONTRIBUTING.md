# Contributing to Auki Authentication

Thank you for your interest in contributing to the Auki Authentication library! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Coding Standards](#coding-standards)
- [Making Changes](#making-changes)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Release Process](#release-process)

## Getting Started

This library is **experimental** and under active development. We welcome contributions, but please be aware that the API is subject to rapid changes, including breaking changes.

Before contributing:

1. Check existing [issues](https://github.com/aukilabs/experimental-modules/issues) to see if your idea or bug is already being discussed
2. For major changes, open an issue first to discuss your approach
3. For minor fixes or improvements, feel free to submit a PR directly

## Development Setup

### Prerequisites

**Required:**

- [Rust](https://rustup.rs/) 1.70 or higher
- [Node.js](https://nodejs.org/) 18 or higher (for JavaScript/TypeScript bindings)
- [Python](https://www.python.org/) 3.8 or higher (for Python bindings)

**For Cross-Platform Builds:**

- [Docker Desktop](https://www.docker.com/products/docker-desktop) (for cross-compilation)
- Build tools will be auto-installed via `make install-tools`

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/aukilabs/experimental-modules.git
   cd authentication-rust
   ```

2. **Install build tools:**

   ```bash
   make install-tools
   ```

3. **Set up environment variables:**

   ```bash
   cp .env.example .env
   # Edit .env with your test credentials
   ```

4. **Build the project:**

   ```bash
   # Build Rust library
   cargo build

   # Build JavaScript bindings
   make javascript

   # Build Python bindings
   make python
   ```

## Project Structure

```
authentication/
├── src/                          # Rust core library (sans-I/O)
│   ├── lib.rs                   # Main library entry point
│   ├── client.rs                # Core authentication client
│   ├── state.rs                 # State management
│   ├── actions.rs               # Action types (HTTP requests, etc.)
│   ├── events.rs                # Event types (responses, errors)
│   └── platforms/               # Platform-specific bindings
│       ├── web.rs              # WASM bindings for JavaScript
│       └── uniffi.udl          # UniFFI interface for Python
├── pkg/                         # Language bindings
│   ├── javascript/             # JavaScript/TypeScript package
│   │   ├── src/               # High-level wrapper
│   │   ├── examples/          # Usage examples
│   │   └── README.md
│   ├── python/                # Python package
│   │   ├── src/              # High-level wrapper
│   │   ├── examples/         # Usage examples
│   │   └── README.md
│   └── expo/                  # React Native/Expo package
│       ├── ios/              # iOS bindings
│       ├── android/          # Android bindings
│       └── example/          # Example app
├── tests/                     # Rust integration tests
├── examples/                  # Rust examples
├── Makefile                   # Build automation
├── README.md                  # Main documentation
├── ARCHITECTURE.md            # Architecture details
└── CONTRIBUTING.md            # This file
```

## Building the Project

### Rust Core

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run clippy (linting)
cargo clippy

# Format code
cargo fmt
```

### JavaScript/TypeScript

```bash
# Build WASM and JavaScript bindings
make javascript

# Run tests
cd pkg/javascript
npm test

# Run examples
npm run example:basic
npm run example:auto-auth
```

### Python

```bash
# Build bindings for all platforms
make python

# Install for development
cd pkg/python
pip install -e .

# Run tests
python examples/basic.py
python examples/test_auto_auth.py
```

### Clean Build Artifacts

```bash
# Clean everything
make clean

# Clean specific bindings
make clean-javascript
make clean-python
```

## Running Tests

### Rust Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

### JavaScript Tests

```bash
cd pkg/javascript
npm test
npm run test:auto-auth
npm run test:refresh
```

### Python Tests

```bash
cd pkg/python
python examples/test_auto_auth.py
python examples/test_multi_domain.py
python examples/test_refresh.py
```

### Integration Tests

Integration tests require valid credentials in `.env`:

```bash
# Run Rust example with real API
cargo run --example basic

# Run JavaScript example
cd pkg/javascript
npm run example:basic

# Run Python example
cd pkg/python
python examples/basic.py
```

## Coding Standards

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Run `cargo fmt` before committing
- Run `cargo clippy` and address all warnings
- Add tests for new functionality
- Document public APIs with doc comments (`///`)

Example:

````rust
/// Authenticates to the Auki network.
///
/// # Returns
///
/// A vector of actions to execute (typically HTTP requests).
///
/// # Example
///
/// ```
/// let actions = client.authenticate();
/// ```
pub fn authenticate(&mut self) -> Vec<Action> {
    // Implementation
}
````

### JavaScript/TypeScript

- Follow the existing code style
- Use TypeScript for type safety
- Add JSDoc comments for public APIs
- Run examples after making changes
- Keep the high-level wrapper simple and intuitive

Example:

```typescript
/**
 * Authenticates to the Auki network.
 * @returns Promise resolving to a Token
 * @throws {AuthenticationError} If authentication fails
 */
async authenticate(): Promise<Token> {
    // Implementation
}
```

### Python

- Follow [PEP 8](https://pep8.org/)
- Add type hints for all public APIs
- Add docstrings for classes and methods
- Keep examples updated with API changes

Example:

```python
async def authenticate(self) -> Token:
    """
    Authenticates to the Auki network.

    Returns:
        Token: The network authentication token

    Raises:
        AuthenticationError: If authentication fails
    """
    # Implementation
```

### Environment Configuration

All examples should:

- Load configuration from `.env` using `dotenv`
- Use `os.getenv()` with sensible defaults
- Follow the pattern in `examples/basic.py` (Python) or `examples/basic.js` (JavaScript)

Example:

```python
from dotenv import load_dotenv
load_dotenv(dotenv_path="../../.env")

config = Config(
    api_url=os.getenv("API_URL", "https://api.aukiverse.com"),
    refresh_url=os.getenv("REFRESH_URL", "https://api.aukiverse.com/user/refresh"),
    dds_url=os.getenv("DDS_URL", "https://dds.posemesh.org"),
    client_id=os.getenv("CLIENT_ID", "my-app"),
    refresh_threshold_ms=int(os.getenv("REFRESH_THRESHOLD_MS", "300000"))
)
```

## Making Changes

### Branching Strategy

1. Create a feature branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. Make your changes following the coding standards

3. Test your changes thoroughly:

   ```bash
   # Rust
   cargo test
   cargo clippy
   cargo fmt --check

   # JavaScript
   cd pkg/javascript
   npm test
   npm run example:basic

   # Python
   cd pkg/python
   python examples/basic.py
   ```

4. Commit your changes:
   ```bash
   git add .
   git commit -m "feat: add new authentication method"
   # or
   git commit -m "fix: resolve token refresh issue"
   ```

### Commit Message Convention

We use conventional commits:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions or changes
- `chore:` - Build process or tooling changes
- `breaking:` - Breaking changes (major version bump)

Examples:

```
feat: add support for OAuth authentication
fix: resolve race condition in token refresh
docs: update Python README with new API
refactor: simplify state management
test: add integration tests for multi-domain
chore: update dependencies
breaking: change Client constructor signature
```

### Updating Language Bindings

When making changes to the Rust core that affect the API:

1. **Update the core library** (`src/`)
2. **Update platform bindings:**
   - WASM bindings: `src/platforms/web.rs`
   - Python bindings: `src/platforms/uniffi.udl`
3. **Update high-level wrappers:**
   - JavaScript: `pkg/javascript/src/index.ts`
   - Python: `pkg/python/src/client.py`
4. **Update examples** in all languages
5. **Update READMEs** to reflect API changes
6. **Rebuild bindings:**
   ```bash
   make javascript
   make python
   ```
7. **Test all bindings:**

   ```bash
   # Test JavaScript
   cd pkg/javascript && npm run example:basic

   # Test Python
   cd pkg/python && python examples/basic.py
   ```

### API Changes Checklist

When changing the API, ensure you update:

- [ ] Rust core library (`src/`)
- [ ] Rust examples (`examples/`)
- [ ] WASM bindings (`src/platforms/web.rs`)
- [ ] Python bindings (`src/platforms/uniffi.udl`)
- [ ] JavaScript wrapper (`pkg/javascript/src/index.ts`)
- [ ] JavaScript examples (`pkg/javascript/examples/`)
- [ ] JavaScript README (`pkg/javascript/README.md`)
- [ ] Python wrapper (`pkg/python/src/client.py`)
- [ ] Python examples (`pkg/python/examples/`)
- [ ] Python README (`pkg/python/README.md`)
- [ ] Main README (`README.md`)
- [ ] Architecture docs (if applicable)

## Submitting a Pull Request

1. **Push your branch:**

   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:

   - Clear title describing the change
   - Description explaining what changed and why
   - Reference to any related issues
   - Screenshots/examples if applicable

3. **PR Template:**

   ```markdown
   ## Description

   Brief description of the changes

   ## Type of Change

   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing

   - [ ] Rust tests pass (`cargo test`)
   - [ ] JavaScript examples work
   - [ ] Python examples work
   - [ ] All linting passes

   ## Related Issues

   Closes #123
   ```

4. **Address review feedback:**

   - Respond to all comments
   - Make requested changes
   - Push updates to the same branch

5. **Merge requirements:**
   - All tests must pass
   - Code review approval required
   - No merge conflicts with `main`

## Release Process

> **Note:** This section is for maintainers

### Version Bumping

1. Update version numbers:

   - `Cargo.toml` (Rust)
   - `pkg/javascript/package.json`
   - `pkg/python/setup.py`
   - `pkg/python/pyproject.toml`

2. Update CHANGELOG.md with release notes

3. Create a release commit:
   ```bash
   git commit -am "chore: release v0.2.0"
   git tag v0.2.0
   git push origin main --tags
   ```

### Publishing

**JavaScript/NPM:**

```bash
cd pkg/javascript
npm publish
```

**Python/PyPI:**

```bash
cd pkg/python
python -m build
python -m twine upload dist/*
```

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/aukilabs/experimental-modules/issues)
- **Discussions:** [GitHub Discussions](https://github.com/aukilabs/experimental-modules/discussions)
- **Architecture:** See [ARCHITECTURE.md](ARCHITECTURE.md)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and professional
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).

---

Thank you for contributing to Auki Authentication! 🎉
