# Auki Network - Experimental Modules

> **⚠️ EXPERIMENTAL:** This repository contains experimental modules for the Auki Network. These modules are under active development and subject to rapid changes, including breaking changes to the API. Use with caution in production environments and expect frequent updates. We recommend pinning to specific versions and reviewing changelogs before upgrading.

This repository houses experimental SDKs and libraries for building applications on the Auki Network and Posemesh. Each module is designed to be a standalone component that can be integrated into your applications.

## Available Modules

### 🔐 Authentication

Multi-platform authentication library for the Auki Network with support for Rust, JavaScript/TypeScript, Python, and React Native/Expo.

**[View Authentication Module Documentation →](modules/authentication/)**

**Key Features:**

- Sans-I/O core architecture written in Rust
- Automatic token management and refresh
- Multi-domain access support
- Cross-platform bindings (JavaScript, Python, React Native/Expo)

**Quick Links:**

- [JavaScript/TypeScript Package](modules/authentication/pkg/javascript)
- [Python Package](modules/authentication/pkg/python)
- [React Native/Expo Package](modules/authentication/pkg/expo)

### 📐 PnP (Perspective-n-Point)

Pure Rust PnP pose estimation. Estimates the 6-DoF pose (position + orientation) of a calibrated camera from known 3D landmarks and their 2D image observations. No OpenCV dependency.

**[View PnP Module Documentation →](modules/pnp/)**

**Key Features:**

- Three solver methods: EPnP, Iterative (Levenberg-Marquardt), and SQPnP
- `no_std` compatible core library (with `alloc`)
- WASM Component Model interface via WIT
- C FFI with auto-generated header for iOS/Android/desktop embedding
- Numerically validated against OpenCV reference output

**Quick Links:**

- [Rust Core Library](modules/pnp/crates/pnp-core)
- [C FFI Bindings](modules/pnp/crates/pnp-ffi)
- [WASM Component](modules/pnp/crates/pnp-wasm)

## Repository Structure

```
modules/
├── authentication/              # Authentication module
│   ├── src/                    # Rust core library
│   ├── pkg/                    # Language bindings
│   ├── examples/               # Examples
│   ├── README.md               # Module documentation
│   └── ARCHITECTURE.md         # Technical details
├── pnp/                        # PnP pose estimation module
│   ├── crates/
│   │   ├── pnp-core/          # Pure Rust solver (no_std + alloc)
│   │   ├── pnp-wasm/          # WASM Component Model guest
│   │   └── pnp-ffi/           # C FFI layer
│   └── README.md              # Module documentation
├── CONTRIBUTING.md             # Contribution guidelines
└── README.md                   # This file
```

## Getting Started

Each module has its own documentation and setup instructions. See the individual module READMEs for details.

- **Authentication:** [modules/authentication/README.md](modules/authentication/)
- **PnP:** [modules/pnp/README.md](modules/pnp/)

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) 1.70 or higher
- [Node.js](https://nodejs.org/) 18+ (for JavaScript bindings)
- [Python](https://www.python.org/) 3.8+ (for Python bindings)
- [Docker Desktop](https://www.docker.com/products/docker-desktop) (for cross-platform builds)

### Quick Build

```bash
# Clone the repository
git clone https://github.com/aukilabs/experimental-modules.git
cd modules/authentication

# Install build tools (first time only)
make install-tools

# Build JavaScript bindings
make javascript

# Build Python bindings
make python

# Build all
make all
```

See individual module documentation for detailed build instructions.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Before contributing:**

1. Check existing [issues](https://github.com/aukilabs/experimental-modules/issues)
2. For major changes, open an issue first to discuss
3. Follow the coding standards for each language
4. Test all language bindings after API changes

## Documentation

- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute to this project

**Module Documentation:**

- **[Authentication Module](modules/authentication/)** - Authentication for Auki Network
- **[PnP Module](modules/pnp/)** - Perspective-n-Point pose estimation

## Versioning

Each module and language binding is independently versioned. Due to the experimental nature, expect:

- **Frequent patch releases** for bug fixes
- **Minor version bumps** for new features
- **Major version bumps** for breaking changes (which may happen often)

## Support

- **Issues:** [GitHub Issues](https://github.com/aukilabs/experimental-modules/issues)
- **Discussions:** [GitHub Discussions](https://github.com/aukilabs/experimental-modules/discussions)

## License

MIT License - See [LICENSE](LICENSE) for details

---

**Note:** This is an experimental project. APIs will change. Documentation may be incomplete. Use at your own risk, and please report any issues you encounter!
