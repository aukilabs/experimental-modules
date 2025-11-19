#!/bin/bash

# Exit on any error
set -e

# Configuration
LIB_NAME="authentication"
PACKAGE_NAME="com.aukilabs.authentication"
BUILD_DIR="build-android"
BINDINGS_DIR="bindings-android"
LIBS_DIR="pkg/expo/android/libs"

echo "========================================="
echo "Building Android AAR for ${LIB_NAME}"
echo "========================================="
echo ""

# Ensure required tools are installed
echo "[1/9] Checking required tools..."
if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "❌ Error: cargo-ndk not found. Install with: cargo install cargo-ndk"
  exit 1
fi

if ! command -v uniffi-bindgen >/dev/null 2>&1; then
  echo "❌ Error: uniffi-bindgen not found. Install with: cargo install uniffi-bindgen"
  exit 1
fi

# Ensure Android Rust targets are installed
echo ""
echo "[2/9] Installing Android Rust targets..."
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Android ABIs mapping (parallel arrays for bash 3.2 compatibility)
TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "x86_64-linux-android"
  "i686-linux-android"
)

ABIS=(
  "arm64-v8a"
  "armeabi-v7a"
  "x86_64"
  "x86"
)

# Create output directories
echo ""
echo "[3/9] Creating output directories..."
mkdir -p "${BUILD_DIR}/src/main/jniLibs"
mkdir -p "${BUILD_DIR}/src/main/kotlin"
mkdir -p "${BINDINGS_DIR}"

# Build Rust library for each Android target
echo ""
echo "[4/9] Building Rust libraries for Android targets..."
for i in "${!TARGETS[@]}"; do
  target="${TARGETS[$i]}"
  abi="${ABIS[$i]}"
  echo "  Building for ${target} (${abi})..."
  cargo ndk -t "${abi}" -o "${BUILD_DIR}/src/main/jniLibs" build --release --features uniffi-bindings
done

# Verify .so files exist
echo ""
echo "[5/9] Verifying libraries..."
for i in "${!ABIS[@]}"; do
  abi="${ABIS[$i]}"
  lib_path="${BUILD_DIR}/src/main/jniLibs/${abi}/lib${LIB_NAME}.so"
  if [ ! -f "$lib_path" ]; then
    echo "❌ Error: $lib_path not found"
    exit 1
  fi
  size=$(ls -lh "$lib_path" | awk '{print $5}')
  echo "  ✓ ${abi}: $size"
done

# Generate UniFFI bindings for Kotlin
echo ""
echo "[6/9] Generating Kotlin bindings..."

# Build a host platform library for generating bindings (uniffi-bindgen needs to load the library)
echo "  Building host platform library for binding generation..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS - build for host architecture
  cargo build --release --features uniffi-bindings
  HOST_LIB="target/release/lib${LIB_NAME}.dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  # Linux
  cargo build --release --features uniffi-bindings
  HOST_LIB="target/release/lib${LIB_NAME}.so"
else
  echo "❌ Error: Unsupported platform for binding generation"
  exit 1
fi

if [ ! -f "$HOST_LIB" ]; then
  echo "❌ Error: Host library not found at $HOST_LIB"
  exit 1
fi

uniffi-bindgen generate \
  --library "${HOST_LIB}" \
  --language kotlin \
  --out-dir "${BINDINGS_DIR}"

# Move generated Kotlin files to the proper package structure
echo ""
echo "[7/9] Organizing Kotlin bindings..."
PACKAGE_PATH=$(echo "${PACKAGE_NAME}" | tr '.' '/')
mkdir -p "${BUILD_DIR}/src/main/kotlin/${PACKAGE_PATH}"

# Move UniFFI generated files
if [ -f "${BINDINGS_DIR}/uniffi/${LIB_NAME}/${LIB_NAME}.kt" ]; then
  cp "${BINDINGS_DIR}/uniffi/${LIB_NAME}/${LIB_NAME}.kt" "${BUILD_DIR}/src/main/kotlin/${PACKAGE_PATH}/"
  echo "  ✓ Copied ${LIB_NAME}.kt"
else
  echo "⚠️  Warning: ${BINDINGS_DIR}/uniffi/${LIB_NAME}/${LIB_NAME}.kt not found"
  echo "  Checking for alternative locations..."
  find "${BINDINGS_DIR}" -name "*.kt" -exec echo "  Found: {}" \;
fi

# Create settings.gradle if it doesn't exist
if [ ! -f "${BUILD_DIR}/settings.gradle" ]; then
  echo ""
  echo "[8/9] Creating Gradle configuration..."
  cat << 'EOF' > "${BUILD_DIR}/settings.gradle"
pluginManagement {
  repositories {
    google()
    gradlePluginPortal()
    mavenCentral()
  }
  plugins {
    id 'com.android.library' version '8.1.0'
    id 'org.jetbrains.kotlin.android' version '1.9.0'
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
  repositories {
    google()
    mavenCentral()
  }
}

rootProject.name = 'authentication'
EOF
fi

# Create build.gradle if it doesn't exist
if [ ! -f "${BUILD_DIR}/build.gradle" ]; then
  cat << 'EOF' > "${BUILD_DIR}/build.gradle"
plugins {
    id 'com.android.library'
    id 'org.jetbrains.kotlin.android'
}

android {
    namespace 'com.aukilabs.authentication'
    compileSdk 34

    defaultConfig {
        minSdk 23
        targetSdk 34
        versionCode 1
        versionName "0.1.0"
    }

    buildTypes {
        release {
            minifyEnabled false
        }
    }

    sourceSets {
        main {
            java.srcDirs += 'src/main/kotlin'
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}

dependencies {
    implementation 'net.java.dev.jna:jna:5.13.0@aar'
}
EOF
fi

# Create AndroidManifest.xml if it doesn't exist
if [ ! -f "${BUILD_DIR}/src/main/AndroidManifest.xml" ]; then
  mkdir -p "${BUILD_DIR}/src/main"
  cat << 'EOF' > "${BUILD_DIR}/src/main/AndroidManifest.xml"
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application/>
</manifest>
EOF
fi

# Clean up bindings directory
rm -rf "${BINDINGS_DIR}"

# Build AAR with Gradle
echo ""
echo "[9/9] Building AAR with Gradle..."

# Create local.properties with Android SDK location
if [ -z "$ANDROID_HOME" ]; then
  if [ -d "/Users/$USER/Library/Android/sdk" ]; then
    ANDROID_SDK="/Users/$USER/Library/Android/sdk"
  elif [ -d "$HOME/Android/Sdk" ]; then
    ANDROID_SDK="$HOME/Android/Sdk"
  else
    echo "  ⚠️  Warning: Android SDK not found. Set ANDROID_HOME or ensure SDK is in standard location"
  fi
else
  ANDROID_SDK="$ANDROID_HOME"
fi

if [ -n "$ANDROID_SDK" ]; then
  echo "sdk.dir=$ANDROID_SDK" > "${BUILD_DIR}/local.properties"
fi

# Ensure Gradle wrapper exists
if [ ! -f "${BUILD_DIR}/gradlew" ]; then
  echo "  Creating Gradle wrapper (version 8.9)..."
  if command -v gradle >/dev/null 2>&1; then
    (cd "${BUILD_DIR}" && gradle wrapper --gradle-version 8.9)
  else
    echo "  ❌ Error: gradle not found. Install with: brew install gradle"
    exit 1
  fi
fi

# Build the AAR
echo "  Building AAR..."
(cd "${BUILD_DIR}" && ./gradlew assembleRelease)

# Copy AAR to libs directory
AAR_OUT="${BUILD_DIR}/build/outputs/aar"
if [ -d "$AAR_OUT" ]; then
  AAR_FILE=$(ls "$AAR_OUT"/*.aar 2>/dev/null | head -n1 || true)
  if [ -n "$AAR_FILE" ]; then
    mkdir -p "${LIBS_DIR}"
    cp "$AAR_FILE" "${LIBS_DIR}/${LIB_NAME}.aar"
    echo "  ✓ AAR built and copied to ${LIBS_DIR}/${LIB_NAME}.aar"
  else
    echo "  ❌ Error: AAR file not found in $AAR_OUT"
    exit 1
  fi
else
  echo "  ❌ Error: AAR output directory not found"
  exit 1
fi

echo ""
echo "========================================="
echo "✅ Android AAR build complete!"
echo "========================================="
echo ""
echo "Native libraries:"
for i in "${!ABIS[@]}"; do
  abi="${ABIS[$i]}"
  lib_path="${BUILD_DIR}/src/main/jniLibs/${abi}/lib${LIB_NAME}.so"
  if [ -f "$lib_path" ]; then
    size=$(ls -lh "$lib_path" | awk '{print $5}')
    echo "  ✓ ${abi}: $size"
  fi
done

echo ""
if [ -f "${LIBS_DIR}/${LIB_NAME}.aar" ]; then
  AAR_SIZE=$(ls -lh "${LIBS_DIR}/${LIB_NAME}.aar" | awk '{print $5}')
  echo "AAR output:"
  echo "  ✓ ${LIBS_DIR}/${LIB_NAME}.aar ($AAR_SIZE)"
fi
echo ""
