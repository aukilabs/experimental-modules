# Contributing to Auki Network Experimental Modules

Thank you for your interest in contributing! This repository contains experimental modules for the Auki Network, and we welcome contributions of all kinds.

> **⚠️ Note:** This is an experimental project under active development. The API is subject to rapid changes, including breaking changes. Please keep this in mind when contributing.

## General Guidelines

### Before Contributing

1. **Check existing issues** - Search [GitHub Issues](https://github.com/aukilabs/experimental-modules/issues) to see if your idea or bug is already being discussed
2. **Open an issue first** - For major changes, open an issue to discuss your approach before starting work
3. **Read module-specific guidelines** - Each module has its own detailed contribution guide (see below)

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and professional in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

### Types of Contributions

We welcome:

- **Bug reports** - Help us identify and fix issues
- **Feature requests** - Suggest new capabilities
- **Documentation improvements** - Better docs help everyone
- **Code contributions** - Bug fixes, features, refactoring
- **Examples** - Show others how to use the modules
- **Testing** - Help improve test coverage

## Getting Started

### Prerequisites

**Required for all modules:**

- [Rust](https://rustup.rs/) 1.70 or higher
- Git

**For specific language bindings:**

- [Node.js](https://nodejs.org/) 18+ (JavaScript/TypeScript)
- [Python](https://www.python.org/) 3.8+ (Python)
- [Docker Desktop](https://www.docker.com/products/docker-desktop) (for cross-platform builds)

### Initial Setup

1. **Fork the repository** on GitHub

2. **Clone your fork:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/authentication.git
   cd authentication
   ```

3. **Add upstream remote:**

   ```bash
   git remote add upstream https://github.com/aukilabs/experimental-modules.git
   ```

4. **Install build tools:**

   ```bash
   make install-tools
   ```

5. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your test credentials
   ```

## Module-Specific Guidelines

Each module has detailed contribution guidelines. Please read the relevant guide before contributing:

### Authentication Module

**[View Authentication Contributing Guide →](modules/authentication/CONTRIBUTING.md)**

The authentication module has specific requirements for:

- Rust core library changes
- Language binding updates (JavaScript, Python, Swift, Kotlin)
- API change propagation across all bindings
- Cross-platform testing

## General Workflow

### 1. Create a Branch

Create a descriptive branch from `main`:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Your Changes

- Follow the module-specific coding standards
- Write clear, descriptive commit messages
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

Run tests for all affected modules:

```bash
# Rust core
cargo test
cargo clippy
cargo fmt --check

# JavaScript (if modified)
cd pkg/javascript
npm test

# Python (if modified)
cd pkg/python
python examples/basic.py
```

### 4. Commit Your Changes

Use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat: add new authentication method"
git commit -m "fix: resolve token refresh race condition"
git commit -m "docs: update Python README"
git commit -m "test: add integration tests for multi-domain"
git commit -m "chore: update dependencies"
```

**Commit Types:**

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions or changes
- `chore:` - Build process or tooling changes
- `breaking:` - Breaking changes (major version bump)

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:

- Clear title describing the change
- Description explaining what changed and why
- Reference to any related issues
- Screenshots/examples if applicable

## Pull Request Guidelines

### PR Template

```markdown
## Description

Brief description of the changes

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Module(s) Affected

- [ ] Authentication
- [ ] (Future modules)

## Testing

- [ ] Rust tests pass (`cargo test`)
- [ ] JavaScript examples work (if applicable)
- [ ] Python examples work (if applicable)
- [ ] All linting passes

## Checklist

- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing tests pass locally

## Related Issues

Closes #(issue number)
```

### Review Process

1. **Automated checks** - CI/CD will run tests and linting
2. **Code review** - Maintainers will review your code
3. **Feedback** - Address any requested changes
4. **Approval** - Once approved, your PR will be merged

### Merge Requirements

- All automated checks must pass
- At least one maintainer approval
- No unresolved comments
- No merge conflicts with `main`

## Keeping Your Fork Updated

Regularly sync your fork with upstream:

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main
```

## Issue Guidelines

### Reporting Bugs

When reporting bugs, please include:

- **Clear title** - Summarize the issue
- **Description** - What happened vs what you expected
- **Reproduction steps** - How to reproduce the issue
- **Environment** - OS, language version, module version
- **Code samples** - Minimal code to reproduce
- **Error messages** - Full error output if applicable

### Requesting Features

When requesting features, please include:

- **Use case** - Why is this feature needed?
- **Proposed solution** - How should it work?
- **Alternatives** - Other approaches you've considered
- **Module** - Which module(s) would this affect?

## Documentation

### What to Document

- **Code changes** - Update relevant READMEs
- **API changes** - Update all language binding docs
- **New features** - Add usage examples
- **Breaking changes** - Clearly document migration path

### Documentation Standards

- Use clear, concise language
- Include code examples
- Keep examples up to date with API changes
- Use proper markdown formatting
- Link to related documentation

## Release Process

> **Note:** This section is for maintainers

Releases are managed by maintainers following semantic versioning:

- **Patch** (0.0.x) - Bug fixes, minor improvements
- **Minor** (0.x.0) - New features, non-breaking changes
- **Major** (x.0.0) - Breaking changes

Each module is versioned independently.

## Questions?

- **Issues:** [GitHub Issues](https://github.com/aukilabs/experimental-modules/issues)
- **Discussions:** [GitHub Discussions](https://github.com/aukilabs/experimental-modules/discussions)
- **Module Docs:** See individual module READMEs

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).

---

Thank you for contributing to Auki Network! 🎉
