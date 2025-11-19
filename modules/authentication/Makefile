# Makefile for Auki Authentication Library
# Simplified build system - each target builds its package independently

.PHONY: help install-tools javascript python python-cross expo clean

# Default target
all: help

# Help target
help:
	@echo "Auki Authentication Library - Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make javascript     - Build JavaScript package (WASM + bindings)"
	@echo "  make python         - Build Python package (native architecture)"
	@echo "  make python-cross   - Build Python package (all architectures)"
	@echo "  make expo           - Build Expo module (iOS XCFramework + Android AAR)"
	@echo "  make install-tools  - Install required build tools"
	@echo "  make clean          - Remove all generated bindings and build artifacts"
	@echo ""
	@echo "Building packages:"
	@echo "  make javascript    - Builds WASM, generates bindings, ready for 'npm pack'"
	@echo "  make python        - Builds native library, ready for 'pip install -e .' or 'python -m build'"
	@echo "  make python-cross  - Builds for all platforms, creates universal wheel"
	@echo "  make expo          - Builds iOS XCFramework and Android AAR for Expo module"
	@echo ""

# Install required Rust tools
install-tools:
	@echo "Checking and installing required build tools..."
	@echo ""
	@echo "JavaScript/WASM tools:"
	@if ! command -v wasm-bindgen >/dev/null 2>&1; then \
		echo "  Installing wasm-bindgen-cli..."; \
		cargo install wasm-bindgen-cli; \
	else \
		echo "  ✓ wasm-bindgen-cli already installed"; \
	fi
	@if ! command -v wasm-opt >/dev/null 2>&1; then \
		echo "  Installing wasm-opt (for optimization)..."; \
		cargo install wasm-opt; \
	else \
		echo "  ✓ wasm-opt already installed"; \
	fi
	@echo ""
	@echo "Python tools:"
	@if ! command -v uniffi-bindgen >/dev/null 2>&1; then \
		echo "  Installing uniffi-bindgen..."; \
		cargo install uniffi-bindgen --version 0.30.0; \
	else \
		echo "  ✓ uniffi-bindgen already installed"; \
	fi
	@if ! command -v cross >/dev/null 2>&1; then \
		echo "  Installing cross (for cross-compilation)..."; \
		cargo install cross --git https://github.com/cross-rs/cross; \
	else \
		echo "  ✓ cross already installed"; \
	fi
	@echo ""
	@echo "Android tools:"
	@if ! command -v cargo-ndk >/dev/null 2>&1; then \
		echo "  Installing cargo-ndk..."; \
		cargo install cargo-ndk; \
	else \
		echo "  ✓ cargo-ndk already installed"; \
	fi
	@echo ""
	@echo "✓ All tools ready!"

# Build JavaScript package - complete build from Rust to packaged npm module
# Includes type-checking to catch any import/type errors in the TypeScript wrapper
javascript:
	@echo "========================================="
	@echo "Building JavaScript Package"
	@echo "========================================="
	@echo ""
	@echo "[1/6] Building Rust library to WASM..."
	@cargo build --lib --release --target wasm32-unknown-unknown --features wasm
	@echo ""
	@echo "[2/6] Generating JavaScript bindings..."
	@mkdir -p pkg/javascript/src/bindings
	@wasm-bindgen target/wasm32-unknown-unknown/release/authentication.wasm \
		--out-dir pkg/javascript/src/bindings \
		--typescript
	@echo ""
	@echo "[3/6] Optimizing WASM binary..."
	@if command -v wasm-opt >/dev/null 2>&1; then \
		wasm-opt -Oz pkg/javascript/src/bindings/authentication_bg.wasm \
			-o pkg/javascript/src/bindings/authentication_bg.wasm; \
		echo "✓ WASM optimized"; \
	else \
		echo "⚠ wasm-opt not found (run: make install-tools)"; \
	fi
	@echo ""
	@echo "[4/6] Installing npm dependencies..."
	@if [ ! -d pkg/javascript/node_modules ]; then \
		cd pkg/javascript && npm install; \
	else \
		echo "✓ Dependencies already installed"; \
	fi
	@echo ""
	@echo "[5/6] Type-checking TypeScript wrapper..."
	@cd pkg/javascript && npm run typecheck
	@echo "✓ Type-checking passed"
	@echo ""
	@echo "[6/6] Compiling TypeScript..."
	@cd pkg/javascript && npx tsc && npm run copy-bindings
	@echo ""
	@echo "========================================="
	@echo "✓ JavaScript package ready!"
	@echo "========================================="
	@echo "Location: pkg/javascript/"
	@echo ""
	@echo "Next steps:"
	@echo "  cd pkg/javascript && npm pack"
	@echo "  # Creates: auki-authentication-0.1.0.tgz"
	@echo ""
	@echo "To install in another project:"
	@echo "  npm install /path/to/auki-authentication-0.1.0.tgz"
	@echo ""

# Build Python package - cross-compile for all major architectures
# Includes all platform binaries in the package
python:
	@echo "========================================="
	@echo "Building Python Package (Multi-Platform)"
	@echo "========================================="
	@echo ""
	@echo "Building for all major architectures:"
	@echo "  - macOS: x86_64, aarch64"
	@echo "  - Linux: x86_64, aarch64"
	@echo "  - Windows: x86_64"
	@echo ""
	@echo "[1/9] Building for macOS x86_64..."
	@cargo build --lib --release --target x86_64-apple-darwin --features uniffi-bindings 2>&1 | grep -E "(Compiling|Finished|error)" || true
	@echo ""
	@echo "[2/9] Building for macOS ARM64..."
	@cargo build --lib --release --target aarch64-apple-darwin --features uniffi-bindings 2>&1 | grep -E "(Compiling|Finished|error)" || true
	@echo ""
	@echo "[3/9] Building for Linux x86_64..."
	@if command -v cross >/dev/null 2>&1; then \
		DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --lib --release --target x86_64-unknown-linux-gnu --features uniffi-bindings 2>&1 | grep -E "(Compiling|Finished|error)" || true; \
	else \
		echo "⚠ cross not installed, skipping Linux x86_64"; \
	fi
	@echo ""
	@echo "[4/9] Building for Linux ARM64..."
	@if command -v cross >/dev/null 2>&1; then \
		DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --lib --release --target aarch64-unknown-linux-gnu --features uniffi-bindings 2>&1 | grep -E "(Compiling|Finished|error)" || true; \
	else \
		echo "⚠ cross not installed, skipping Linux ARM64"; \
	fi
	@echo ""
	@echo "[5/9] Building for Windows x86_64..."
	@if command -v cross >/dev/null 2>&1; then \
		DOCKER_DEFAULT_PLATFORM=linux/amd64 cross build --lib --release --target x86_64-pc-windows-gnu --features uniffi-bindings 2>&1 | grep -E "(Compiling|Finished|error)" || true; \
	else \
		echo "⚠ cross not installed, skipping Windows x86_64"; \
	fi
	@echo ""
	@echo "[6/9] Generating Python bindings..."
	@mkdir -p pkg/python/src/bindings
	@if [ -f target/x86_64-apple-darwin/release/libauthentication.dylib ]; then \
		uniffi-bindgen generate \
			--library target/x86_64-apple-darwin/release/libauthentication.dylib \
			--language python \
			--out-dir pkg/python/src/bindings; \
	elif [ -f target/aarch64-apple-darwin/release/libauthentication.dylib ]; then \
		uniffi-bindgen generate \
			--library target/aarch64-apple-darwin/release/libauthentication.dylib \
			--language python \
			--out-dir pkg/python/src/bindings; \
	elif [ -f target/x86_64-unknown-linux-gnu/release/libauthentication.so ]; then \
		uniffi-bindgen generate \
			--library target/x86_64-unknown-linux-gnu/release/libauthentication.so \
			--language python \
			--out-dir pkg/python/src/bindings; \
	else \
		echo "❌ No library found for binding generation!"; \
		exit 1; \
	fi
	@echo "✓ Python bindings generated"
	@echo ""
	@echo "[6.5/9] Patching bindings to use platform loader..."
	@python3 -c "import re; f = open('pkg/python/src/bindings/authentication.py', 'r'); content = f.read(); f.close(); content = re.sub(r'def _uniffi_load_indirect\(\):.*?return lib', 'def _uniffi_load_indirect():\n    from .. import get_lib_path\n    path = get_lib_path()\n    lib = ctypes.cdll.LoadLibrary(path)\n    return lib', content, flags=re.DOTALL); f = open('pkg/python/src/bindings/authentication.py', 'w'); f.write(content); f.close()"
	@echo "✓ Bindings patched to use multi-platform loader (from src/__init__.py)"
	@echo ""
	@echo "[7/9] Copying platform-specific libraries..."
	@mkdir -p pkg/python/src/bindings/lib/macosx_10_12_x86_64
	@mkdir -p pkg/python/src/bindings/lib/macosx_11_0_arm64
	@mkdir -p pkg/python/src/bindings/lib/manylinux_2_17_x86_64
	@mkdir -p pkg/python/src/bindings/lib/manylinux_2_17_aarch64
	@mkdir -p pkg/python/src/bindings/lib/win_amd64
	@if [ -f target/x86_64-apple-darwin/release/libauthentication.dylib ]; then \
		cp target/x86_64-apple-darwin/release/libauthentication.dylib pkg/python/src/bindings/lib/macosx_10_12_x86_64/; \
		echo "  ✓ macOS x86_64"; \
	fi
	@if [ -f target/aarch64-apple-darwin/release/libauthentication.dylib ]; then \
		cp target/aarch64-apple-darwin/release/libauthentication.dylib pkg/python/src/bindings/lib/macosx_11_0_arm64/; \
		echo "  ✓ macOS ARM64"; \
	fi
	@if [ -f target/x86_64-unknown-linux-gnu/release/libauthentication.so ]; then \
		cp target/x86_64-unknown-linux-gnu/release/libauthentication.so pkg/python/src/bindings/lib/manylinux_2_17_x86_64/; \
		echo "  ✓ Linux x86_64"; \
	fi
	@if [ -f target/aarch64-unknown-linux-gnu/release/libauthentication.so ]; then \
		cp target/aarch64-unknown-linux-gnu/release/libauthentication.so pkg/python/src/bindings/lib/manylinux_2_17_aarch64/; \
		echo "  ✓ Linux ARM64"; \
	fi
	@if [ -f target/x86_64-pc-windows-gnu/release/authentication.dll ]; then \
		cp target/x86_64-pc-windows-gnu/release/authentication.dll pkg/python/src/bindings/lib/win_amd64/; \
		echo "  ✓ Windows x86_64"; \
	fi
	@echo ""
	@echo "[8/9] Creating package structure..."
	@touch pkg/python/src/bindings/py.typed
	@echo "✓ Package structure created (platform loader in src/bindings/__init__.py)"
	@echo ""
	@echo "[9/9] Validating multi-platform package..."
	@cd pkg/python && python3 validate_build.py
	@echo ""
	@echo "========================================="
	@echo "✓ Python package ready (Multi-Platform)!"
	@echo "========================================="
	@echo "Location: pkg/python/"
	@echo ""
	@echo "Included platforms:"
	@ls -d pkg/python/src/bindings/lib/*/ 2>/dev/null | xargs -n1 basename | sed 's/^/  - /' || echo "  (check lib/ directory)"
	@echo ""
	@echo "Next steps:"
	@echo "  cd pkg/python"
	@echo ""
	@echo "To create a distributable package:"
	@echo "  python setup.py sdist  # Creates .tar.gz with all platforms"
	@echo "  python -m build        # Creates wheel (platform-specific)"
	@echo ""
	@echo "To install in another project:"
	@echo "  pip install dist/auki_authentication-*.tar.gz"
	@echo ""

# Build Python package - cross-compile for all platforms
python-cross:
	@echo "========================================="
	@echo "Building Python Package (Cross-Platform)"
	@echo "========================================="
	@echo ""
	@echo "This will build for all supported platforms:"
	@echo "  - macOS (x86_64, ARM64)"
	@echo "  - Linux (x86_64, ARM64)"
	@echo "  - Windows (x86_64)"
	@echo ""
	@if ! command -v cross >/dev/null 2>&1; then \
		echo "❌ 'cross' not found. Install with:"; \
		echo "   cargo install cross --git https://github.com/cross-rs/cross"; \
		exit 1; \
	fi
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "❌ Docker not found. cross requires Docker."; \
		echo "   Install from: https://www.docker.com/products/docker-desktop"; \
		exit 1; \
	fi
	@cd pkg/python && python3 build_cross.py

# Build Expo module - iOS XCFramework and Android AAR
expo:
	@echo "========================================="
	@echo "Building Expo Module"
	@echo "========================================="
	@echo ""
	@echo "Building native bindings for:"
	@echo "  - iOS: XCFramework (device + simulator)"
	@echo "  - Android: AAR"
	@echo ""
	@echo "[1/2] Building iOS XCFramework..."
	@./create-xcframework.sh
	@echo ""
	@echo "[2/2] Building Android AAR..."
	@if [ -s create-aar.sh ]; then \
		./create-aar.sh; \
	else \
		echo "⚠ create-aar.sh is empty - skipping Android build"; \
		echo "  (Android support coming soon)"; \
	fi
	@echo ""
	@echo "========================================="
	@echo "✓ Expo module build complete!"
	@echo "========================================="
	@echo ""
	@echo "iOS XCFramework:"
	@echo "  Location: pkg/expo/ios/bindings-xcframework/"
	@if [ -d pkg/expo/ios/bindings-xcframework/AukiAuthentication.xcframework ]; then \
		echo "  ✓ AukiAuthentication.xcframework"; \
	fi
	@if [ -f pkg/expo/ios/authentication.swift ]; then \
		echo "  ✓ authentication.swift"; \
	fi
	@echo ""
	@echo "Android AAR:"
	@if [ -d pkg/expo/android/src/main/jniLibs ] && [ "$(ls -A pkg/expo/android/src/main/jniLibs 2>/dev/null)" ]; then \
		echo "  ✓ Native libraries in pkg/expo/android/src/main/jniLibs/"; \
		echo "  ✓ Kotlin bindings in pkg/expo/android/src/main/kotlin/"; \
	else \
		echo "  ⚠ Not built yet (run 'make expo' to build)"; \
	fi
	@echo ""
	@echo "Next steps:"
	@echo "  cd pkg/expo/example"
	@echo "  npm install"
	@echo "  npm run ios       # Run on iOS simulator"
	@echo ""

# Clean all generated bindings and build artifacts
clean:
	@echo "Cleaning package artifacts..."
	@echo "  JavaScript..."
	@rm -rf pkg/javascript/src/bindings
	@rm -rf pkg/javascript/dist
	@rm -rf pkg/javascript/node_modules
	@rm -f pkg/javascript/*.tgz
	@echo "  Python..."
	@rm -rf pkg/python/src/bindings
	@rm -rf pkg/python/src/__pycache__
	@rm -rf pkg/python/auki_authentication
	@rm -rf pkg/python/dist
	@rm -rf pkg/python/build
	@rm -rf pkg/python/*.egg-info
	@rm -rf pkg/python/__pycache__
	@rm -f pkg/python/*.whl
	@rm -f pkg/python/*.tar.gz
	@echo "  Expo..."
	@rm -rf pkg/expo/ios/bindings-xcframework
	@rm -f pkg/expo/ios/authentication.swift
	@rm -f pkg/expo/ios/authenticationFFI.h
	@rm -f pkg/expo/ios/authenticationFFI.modulemap
	@rm -rf bindings
	@rm -f Info.plist.template
	@echo "  Android AAR build..."
	@rm -rf build-android
	@rm -rf bindings-android
	@echo "✓ Clean complete!"
