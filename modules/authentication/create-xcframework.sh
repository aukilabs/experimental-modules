#!/bin/bash

# Exit on any error
set -e

# Configuration
LIB_NAME="authentication"
FRAMEWORK_NAME="AukiAuthentication"
OUTPUT_DIR="pkg/expo/ios/bindings-xcframework"
BINDINGS_DIR="bindings"

echo "========================================="
echo "Building iOS XCFramework for ${LIB_NAME}"
echo "========================================="
echo ""

# Ensure Rust targets are installed
echo "[1/7] Checking iOS targets..."
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build the Rust library for each iOS target
echo ""
echo "[2/7] Building Rust library for iOS targets..."
echo "  Building for aarch64-apple-ios (device)..."
cargo build --lib --release --target aarch64-apple-ios --features uniffi-bindings

echo "  Building for aarch64-apple-ios-sim (simulator ARM64)..."
cargo build --lib --release --target aarch64-apple-ios-sim --features uniffi-bindings

echo "  Building for x86_64-apple-ios (simulator x86_64)..."
cargo build --lib --release --target x86_64-apple-ios --features uniffi-bindings

# Verify .dylib files exist
echo ""
echo "[3/7] Verifying libraries..."
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  lib_path="target/$target/release/lib${LIB_NAME}.dylib"
  if [ ! -f "$lib_path" ]; then
    echo "❌ Error: $lib_path not found"
    exit 1
  fi
  size=$(ls -lh "$lib_path" | awk '{print $5}')
  echo "  ✓ $target: $size"
done

# Generate UniFFI bindings for Swift
echo ""
echo "[4/7] Generating Swift bindings..."
mkdir -p "$BINDINGS_DIR"
uniffi-bindgen generate \
  --library "target/aarch64-apple-ios/release/lib${LIB_NAME}.dylib" \
  --language swift \
  --out-dir "$BINDINGS_DIR"

# Verify bindings exist
if [ ! -f "$BINDINGS_DIR/${LIB_NAME}FFI.h" ]; then
  echo "❌ Error: ${BINDINGS_DIR}/${LIB_NAME}FFI.h not found"
  exit 1
fi

echo "  ✓ Generated ${LIB_NAME}FFI.h"
echo "  ✓ Generated ${LIB_NAME}FFI.modulemap"
echo "  ✓ Generated ${LIB_NAME}.swift"

# Create Clang modulemap for the C FFI module
echo ""
echo "[5/7] Creating framework structure..."
cat << EOF > "$BINDINGS_DIR/module.modulemap"
module ${LIB_NAME}FFI {
  header "${LIB_NAME}FFI.h"
  export *
}
EOF

# Create Info.plist template
cat << EOF > Info.plist.template
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>\${FRAMEWORK_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.aukilabs.\${FRAMEWORK_NAME}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>\${FRAMEWORK_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
EOF

# Create framework directories
mkdir -p "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/Headers"
mkdir -p "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/Modules"
mkdir -p "target/ios-simulator/release"
mkdir -p "target/ios-simulator/${FRAMEWORK_NAME}.framework/Headers"
mkdir -p "target/ios-simulator/${FRAMEWORK_NAME}.framework/Modules"

# Populate framework for iOS device (arm64)
echo "  Creating device framework..."
cp "$BINDINGS_DIR"/*.h "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/Headers/"
cp "$BINDINGS_DIR/module.modulemap" "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/Modules/module.modulemap"
cp "target/aarch64-apple-ios/release/lib${LIB_NAME}.dylib" "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

# Set framework-relative install_name for device
install_name_tool -id "@rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}" \
  "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

FRAMEWORK_NAME="$FRAMEWORK_NAME" envsubst < Info.plist.template > \
  "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework/Info.plist"

# Create fat binary for simulator (arm64 + x86_64)
echo "  Creating simulator universal binary..."
lipo -create \
  "target/aarch64-apple-ios-sim/release/lib${LIB_NAME}.dylib" \
  "target/x86_64-apple-ios/release/lib${LIB_NAME}.dylib" \
  -output "target/ios-simulator/release/lib${LIB_NAME}.dylib"

cp "$BINDINGS_DIR"/*.h "target/ios-simulator/${FRAMEWORK_NAME}.framework/Headers/"
cp "$BINDINGS_DIR/module.modulemap" "target/ios-simulator/${FRAMEWORK_NAME}.framework/Modules/module.modulemap"
cp "target/ios-simulator/release/lib${LIB_NAME}.dylib" "target/ios-simulator/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

# Set framework-relative install_name for simulator
install_name_tool -id "@rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}" \
  "target/ios-simulator/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

FRAMEWORK_NAME="$FRAMEWORK_NAME" envsubst < Info.plist.template > \
  "target/ios-simulator/${FRAMEWORK_NAME}.framework/Info.plist"

# Clean up template
rm Info.plist.template

# Create output directory
echo ""
echo "[6/7] Creating Expo module structure..."
mkdir -p "$OUTPUT_DIR"
IOS_DIR="pkg/expo/ios"

# Copy Swift bindings to ios directory (same level as podspec)
cp "$BINDINGS_DIR/${LIB_NAME}.swift" "$IOS_DIR/"

# Copy FFI header to ios directory
cp "$BINDINGS_DIR/${LIB_NAME}FFI.h" "$IOS_DIR/"

# Create modulemap in ios directory (not in XCFramework)
cat << EOF > "$IOS_DIR/${LIB_NAME}FFI.modulemap"
module ${LIB_NAME}FFI {
    header "${LIB_NAME}FFI.h"
    export *
    use "Darwin"
    use "_Builtin_stdbool"
    use "_Builtin_stdint"
}
EOF

# Create shim header in bindings dir for reference (optional)
cat << EOF > "${OUTPUT_DIR}/${LIB_NAME}FFI.h"
#pragma once
#include <${FRAMEWORK_NAME}/${LIB_NAME}FFI.h>
EOF

# Create XCFramework
echo ""
echo "[7/7] Creating XCFramework..."
rm -rf "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"

xcodebuild -create-xcframework \
  -framework "target/aarch64-apple-ios/${FRAMEWORK_NAME}.framework" \
  -framework "target/ios-simulator/${FRAMEWORK_NAME}.framework" \
  -output "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"

# Verify the result
echo ""
echo "========================================="
echo "✅ XCFramework created successfully!"
echo "========================================="
echo ""
echo "Verifying architectures..."
echo "  Device:"
lipo -info "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"
echo "  Simulator:"
lipo -info "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64_x86_64-simulator/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

echo ""
echo "Verifying headers..."
ls -lh "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64/${FRAMEWORK_NAME}.framework/Headers/"

echo ""
echo "Verifying modulemaps..."
ls -lh "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64/${FRAMEWORK_NAME}.framework/Modules/"

echo ""
echo "Verifying install_name..."
otool -D "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"
otool -D "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework/ios-arm64_x86_64-simulator/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}"

echo ""
echo "Output location: ${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"
echo "Swift bindings:  ${OUTPUT_DIR}/${LIB_NAME}.swift"
echo "Shim header:     ${OUTPUT_DIR}/${LIB_NAME}FFI.h"
echo ""
