# pnp

Pure Rust [PnP (Perspective-n-Point)](https://en.wikipedia.org/wiki/Perspective-n-Point) pose estimation. Estimates the 6-DoF pose (position + orientation) of a calibrated camera from known 3D landmarks and their 2D image observations.

No OpenCV dependency. All math is implemented in pure Rust using [nalgebra](https://nalgebra.org/).

## Features

- **Three solver methods**: EPnP, Iterative (Levenberg-Marquardt), and SQPnP
- **`no_std` compatible** core library (with `alloc`)
- **WASM Component Model** interface via WIT (`auki:pnp@0.1.0`)
- **C FFI** with auto-generated header for embedding in iOS/Android/desktop apps
- **Numerically validated** against OpenCV's `cv::solvePnP` reference output

## Workspace Structure

```
crates/
  pnp-core/    Pure Rust solver library (no_std + alloc)
  pnp-wasm/    WASM Component Model guest (wit-bindgen)
  pnp-ffi/     C FFI layer with cbindgen-generated header
```

## Quick Start

### Prerequisites

**Required** (for core builds and tests):

- [Rust](https://rustup.rs/) 1.75+
- [just](https://github.com/casey/just): `cargo install just`
- [cbindgen](https://github.com/mozilla/cbindgen): `cargo install cbindgen`

**For cross-compilation targets** (install only what you need):

| Target | Rust target | Extra dependency |
|--------|-------------|------------------|
| iOS device | `aarch64-apple-ios` | Xcode |
| iOS Simulator | `aarch64-apple-ios-sim` | Xcode |
| Android arm64 | `aarch64-linux-android` | [Android NDK](#android-ndk) |
| Android x86_64 | `x86_64-linux-android` | [Android NDK](#android-ndk) |
| WASM | `wasm32-wasip2` | [cargo-component](https://github.com/bytecodealliance/cargo-component) |

Add Rust targets with `rustup target add <target>`.

**Verify your setup:**

```bash
just setup    # checks all tools, targets, and NDK — tells you what's missing
```

### Android NDK

Android cross-compilation requires the [Android NDK](https://developer.android.com/ndk) for the linker toolchain. Install it via:

- **Android Studio**: SDK Manager > SDK Tools > "NDK (Side by side)"
- **Command line**: `sdkmanager --install "ndk;27.1.12297006"`

The build recipes auto-detect the NDK from `ANDROID_NDK_HOME` or `~/Library/Android/sdk/ndk/`. Builds target API 24 (Android 7.0+) by default.

### Build & Test

```bash
# Verify your environment
just setup

# Run all tests
just test

# Build everything (release)
just build-release

# Platform-specific FFI builds
just build-ffi              # macOS
just build-ios              # iOS (aarch64)
just build-android          # Android (arm64 + x86_64)
just build-android-arm64    # Android arm64 only

# WASM
just build-wasm-release     # WASM component
just transpile              # WASM + transpile to browser JS

# Verify no_std compatibility
just check-nostd
```

## Usage

### Rust

Add `pnp-core` to your `Cargo.toml`:

```toml
[dependencies]
pnp-core = { path = "crates/pnp-core" }
```

```rust
use pnp_core::types::*;

// Define 3D landmarks (known positions in world space)
let landmarks = vec![
    Landmark { id: "0".into(), position: Vector3::new(-0.15, -0.15, 0.0) },
    Landmark { id: "1".into(), position: Vector3::new( 0.15, -0.15, 0.0) },
    Landmark { id: "2".into(), position: Vector3::new( 0.15,  0.15, 0.0) },
    Landmark { id: "3".into(), position: Vector3::new(-0.15,  0.15, 0.0) },
];

// Define 2D observations (detected positions in the image)
let observations = vec![
    LandmarkObservation { id: "0".into(), position: Vector2::new(849.36, 461.76) },
    LandmarkObservation { id: "1".into(), position: Vector2::new(1070.64, 461.76) },
    LandmarkObservation { id: "2".into(), position: Vector2::new(1096.90, 636.80) },
    LandmarkObservation { id: "3".into(), position: Vector2::new(823.10, 636.80) },
];

// Camera intrinsics: fx, fy, cx, cy
let camera = Matrix3x3::camera_matrix(815.85, 815.85, 960.0, 540.0);

// Solve for pose (returns position + quaternion in OpenGL coordinates)
let pose = pnp_core::solve_pnp(
    &landmarks,
    &observations,
    &camera,
    SolvePnpMethod::Iterative,
).unwrap();

println!("Position: ({}, {}, {})", pose.position.x, pose.position.y, pose.position.z);
println!("Rotation: ({}, {}, {}, {})", pose.rotation.x, pose.rotation.y, pose.rotation.z, pose.rotation.w);

// Get camera pose (inverse of object pose)
let camera_pose = pnp_core::solve_pnp_camera_pose(
    &landmarks,
    &observations,
    &camera,
    SolvePnpMethod::Iterative,
).unwrap();
```

### C / Swift / Kotlin (via FFI)

Include the generated header and link against the static library:

```c
#include "pnp.h"

pnp_landmark_t landmarks[] = {
    { "0", { -0.15, -0.15, 0.0 } },
    { "1", {  0.15, -0.15, 0.0 } },
    { "2", {  0.15,  0.15, 0.0 } },
    { "3", { -0.15,  0.15, 0.0 } },
};

pnp_landmark_observation_t observations[] = {
    { "0", { 849.36, 461.76 } },
    { "1", { 1070.64, 461.76 } },
    { "2", { 1096.90, 636.80 } },
    { "3", { 823.10, 636.80 } },
};

// Column-major: [fx, 0, 0, 0, fy, 0, cx, cy, 1]
pnp_matrix3x3_t camera = { .m = { 815.85, 0, 0, 0, 815.85, 0, 960, 540, 1 } };

pnp_result_t result = pnp_solve(
    landmarks, 4,
    observations, 4,
    &camera,
    PNP_METHOD_ITERATIVE
);

if (result.error == PNP_OK) {
    printf("Position: (%f, %f, %f)\n",
        result.pose.position.x,
        result.pose.position.y,
        result.pose.position.z);
}
```

For **Android (Kotlin/Java)**, build the `.so` with `just build-android-arm64` and place it in your app's `jniLibs/arm64-v8a/` directory. Access through JNI or a Kotlin/Java wrapper around the C API.

### JavaScript / TypeScript (via WASM)

Transpile the WASM component to browser-ready JS:

```bash
just transpile
# or: jco transpile target/wasm32-wasip1/release/pnp_wasm.wasm -o dist/wasm
```

```typescript
import { solver } from './dist/wasm/pnp_wasm.js';

const pose = solver.solvePnp(
  [
    { id: "0", position: { x: -0.15, y: -0.15, z: 0.0 } },
    { id: "1", position: { x:  0.15, y: -0.15, z: 0.0 } },
    { id: "2", position: { x:  0.15, y:  0.15, z: 0.0 } },
    { id: "3", position: { x: -0.15, y:  0.15, z: 0.0 } },
  ],
  [
    { id: "0", position: { x: 849.36, y: 461.76 } },
    { id: "1", position: { x: 1070.64, y: 461.76 } },
    { id: "2", position: { x: 1096.90, y: 636.80 } },
    { id: "3", position: { x: 823.10, y: 636.80 } },
  ],
  { m00: 815.85, m01: 0, m02: 0, m10: 0, m11: 815.85, m12: 0, m20: 960, m21: 540, m22: 1 },
  "iterative"
);
```

## Solver Methods

| Method | Min Points | Best For | Notes |
|--------|-----------|----------|-------|
| **EPnP** | 4 | Fast initial estimate | O(n), handles coplanar and non-coplanar points |
| **Iterative** | 4 | High accuracy | Levenberg-Marquardt refinement, uses EPnP as initial estimate |
| **SQPnP** | 3 | General purpose | Globally optimal on SO(3), state-of-the-art accuracy |

For most applications, use **Iterative** (best accuracy) or **SQPnP** (works with as few as 3 points).

## Coordinate Conventions

- **Matrix3x3** uses column-major storage: `m[col * 3 + row]`. Field naming follows `M<col><row>` (e.g., `m00` = column 0, row 0).
- **Camera matrix** K = `[[fx, 0, cx], [0, fy, cy], [0, 0, 1]]` stored column-major.
- **`solve_pnp`** returns poses in **OpenGL** coordinates (right-handed, Y-up).
- **Quaternions** use Hamilton convention: `(x, y, z, w)`.

## Build Artifacts

| Target | Command | Output |
|--------|---------|--------|
| macOS static lib | `just build-ffi` | `target/release/libpnp_ffi.a` |
| macOS dynamic lib | `just build-ffi` | `target/release/libpnp_ffi.dylib` |
| iOS device | `just build-ios` | `target/aarch64-apple-ios/release/libpnp_ffi.a` |
| iOS Simulator | `just build-ios-sim` | `target/aarch64-apple-ios-sim/release/libpnp_ffi.a` |
| Android arm64 | `just build-android-arm64` | `target/aarch64-linux-android/release/libpnp_ffi.{a,so}` |
| Android x86_64 | `just build-android-x86_64` | `target/x86_64-linux-android/release/libpnp_ffi.{a,so}` |
| WASM Component | `just build-wasm-release` | `target/wasm32-wasip1/release/pnp_wasm.wasm` |
| Browser JS+WASM | `just transpile` | `dist/wasm/` |
| C header | `just generate-header` | `crates/pnp-ffi/include/pnp.h` |

## References

- Lepetit, Moreno-Noguer, Fua. *EPnP: An Accurate O(n) Solution to the PnP Problem.* IJCV 2009.
- Terzakis, Lourakis. *A Consistently Fast and Globally Optimal Solution to the Perspective-n-Point Problem.* ECCV 2020.

## License

[MIT](LICENSE)
