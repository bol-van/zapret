# MacOS Refactoring Changelog

## Overview
This changelog documents the refactoring changes made to improve MacOS compatibility for both x86_64 and Apple Silicon (ARM64) architectures.

## Changes Made

### 1. GitHub Actions (.github/workflows/build.yml)
- **Added**: Matrix build support for both MacOS architectures
- **Added**: Separate builds for x86_64 (macos-12) and ARM64 (macos-13)
- **Added**: Architecture-specific environment variables
- **Added**: Better artifact naming with architecture suffixes

### 2. Main Makefile
- **Added**: Automatic MacOS target detection using `uname -m`
- **Added**: `MACOS_TARGET` environment variable support
- **Added**: New `mac-universal` target for universal binary compilation
- **Added**: Better logging for MacOS builds
- **Added**: Architecture-specific build support

### 3. Component Makefiles
#### tpws/Makefile
- **Added**: `MACOS_TARGET` variable support
- **Added**: Single architecture build target with automatic detection
- **Added**: Universal binary build target (`mac-universal`)
- **Added**: Better architecture-specific compilation
- **Improved**: Clean target to remove temporary files

#### ip2net/Makefile
- **Added**: `MACOS_TARGET` variable support
- **Added**: Single architecture build target
- **Added**: Universal binary build target
- **Improved**: Clean target

#### mdig/Makefile
- **Added**: `MACOS_TARGET` variable support
- **Added**: Single architecture build target
- **Added**: Universal binary build target
- **Improved**: Clean target
- **Fixed**: Source file specification

#### nfq/Makefile
- **Added**: `MACOS_TARGET` variable support
- **Added**: Single architecture build target
- **Added**: Universal binary build target
- **Improved**: Clean target
- **Simplified**: Library definitions

### 4. Binary Installation (install_bin.sh)
- **Added**: `detect_macos_arch()` function for automatic architecture detection
- **Added**: Support for `mac64-arm64` binary directory
- **Added**: Intelligent binary selection based on detected architecture
- **Added**: Better error messages for MacOS compilation
- **Improved**: Architecture detection logic for MacOS

### 5. Easy Installer (install_easy.sh)
- **Added**: Automatic MacOS architecture detection during compilation
- **Added**: Environment variable setup for `MACOS_TARGET`
- **Added**: Better logging for architecture detection
- **Improved**: MacOS compilation workflow

### 6. New Scripts
#### scripts/macos_arch_detect.sh
- **New**: Utility script for MacOS architecture management
- **Added**: Architecture detection functions
- **Added**: Target string generation
- **Added**: Symbolic link creation
- **Added**: Build automation functions
- **Added**: Help system

#### scripts/test_macos_arch.sh
- **New**: Test script for verifying MacOS architecture detection
- **Added**: System compatibility checks
- **Added**: Build system verification
- **Added**: Binary directory validation
- **Added**: Compilation readiness tests

### 7. Documentation
#### docs/MACOS_REFACTORING.md
- **New**: Comprehensive guide for MacOS refactoring
- **Added**: Architecture detection explanation
- **Added**: Build target documentation
- **Added**: Usage examples
- **Added**: Troubleshooting guide
- **Added**: Development guidelines

#### docs/readme.en.md
- **Updated**: MacOS section with new capabilities
- **Added**: Reference to MacOS refactoring guide
- **Added**: Information about improved architecture support

## New Build Targets

### Single Architecture
```bash
make mac                    # Build for current architecture
MACOS_TARGET="arm64-apple-macos10.8" make mac    # Build for ARM64
MACOS_TARGET="x86_64-apple-macos10.8" make mac  # Build for x86_64
```

### Universal Binary
```bash
make mac-universal         # Build universal binary (x86_64 + ARM64)
```

## Environment Variables

- `MACOS_TARGET`: Override target architecture
  - `x86_64-apple-macos10.8` for Intel Macs
  - `arm64-apple-macos10.8` for Apple Silicon

## Binary Naming Convention

- `mac64`: x86_64 binaries (legacy support)
- `mac64-arm64`: ARM64 binaries
- Universal binaries created using `lipo` tool

## Compatibility

### Supported Architectures
- ✅ x86_64 (Intel Macs)
- ✅ arm64 (Apple Silicon M1, M2, etc.)
- ✅ Universal binaries

### Supported MacOS Versions
- Minimum: macOS 10.8 (Mountain Lion)
- Recommended: macOS 11+ (Big Sur)

## Testing

### Manual Testing
```bash
# Test architecture detection
./scripts/test_macos_arch.sh

# Test architecture management
./scripts/macos_arch_detect.sh detect
./scripts/macos_arch_detect.sh build
./scripts/macos_arch_detect.sh universal
```

### Automated Testing
- GitHub Actions now test both architectures
- Separate build matrices for x86_64 and ARM64
- Architecture-specific artifact generation

## Benefits

1. **Automatic Detection**: No manual configuration needed
2. **Cross-Architecture Support**: Works on both Intel and Apple Silicon
3. **Universal Binaries**: Single binary works on both architectures
4. **Better Performance**: Architecture-specific optimizations
5. **Easier Development**: Simplified build process
6. **CI/CD Integration**: Automated testing for both architectures

## Future Improvements

- [ ] Support for newer MacOS target versions
- [ ] Automatic universal binary detection
- [ ] Architecture-specific optimization flags
- [ ] Cross-compilation from Linux to MacOS
- [ ] Performance benchmarking tools
- [ ] Automated architecture testing

## Breaking Changes

None. All changes are backward compatible.

## Migration Guide

No migration required. Existing installations will continue to work.
New features are automatically available when using updated scripts.