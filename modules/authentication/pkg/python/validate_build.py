#!/usr/bin/env python3
"""
Validate that the Python package build completed successfully.
Checks that bindings were generated and platform-specific libraries exist.
"""
import sys
import os
import platform as plat

def main():
    bindings_dir = 'src/bindings'

    # Determine expected platform
    system = plat.system()
    machine = plat.machine()

    if system == 'Darwin':
        platform_str = 'macosx_11_0_arm64' if machine == 'arm64' else 'macosx_10_12_x86_64'
        lib_name = 'libauthentication.dylib'
    elif system == 'Linux':
        platform_str = 'manylinux_2_17_aarch64' if machine in ['aarch64', 'arm64'] else 'manylinux_2_17_x86_64'
        lib_name = 'libauthentication.so'
    elif system == 'Windows':
        platform_str = 'win_amd64'
        lib_name = 'authentication.dll'
    else:
        print(f'❌ Unsupported platform: {system}')
        return 1

    # Check if bindings were generated
    bindings_file = os.path.join(bindings_dir, 'authentication.py')
    if not os.path.exists(bindings_file):
        print(f'❌ Bindings not found: {bindings_file}')
        return 1
    print('✓ Python bindings generated')

    # Check if current platform's library exists
    lib_path = os.path.join(bindings_dir, 'lib', platform_str, lib_name)
    if os.path.exists(lib_path):
        print(f'✓ Platform library exists: {platform_str}/{lib_name}')
    else:
        print(f'⚠ Platform library not found: {lib_path}')

    # List all available platform libraries
    lib_base = os.path.join(bindings_dir, 'lib')
    if os.path.exists(lib_base):
        platforms = []
        for platform_dir in os.listdir(lib_base):
            platform_path = os.path.join(lib_base, platform_dir)
            if os.path.isdir(platform_path):
                libs = os.listdir(platform_path)
                if libs:
                    platforms.append(platform_dir)

        if platforms:
            print(f'✓ Built for {len(platforms)} platform(s): {", ".join(platforms)}')
        else:
            print('⚠ No platform libraries found')

    return 0

if __name__ == '__main__':
    sys.exit(main())
