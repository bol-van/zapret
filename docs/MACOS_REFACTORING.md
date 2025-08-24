# MacOS Refactoring Guide

This document describes the refactoring changes made to improve MacOS compatibility for both x86_64 and Apple Silicon (ARM64) architectures.

## Overview

The refactoring includes:
- Automatic architecture detection for MacOS
- Support for both x86_64 and ARM64 architectures
- Universal binary compilation support
- Improved build system for cross-compilation
- Better binary detection and installation

## Architecture Detection

### Automatic Detection
The system now automatically detects the MacOS architecture:
- **x86_64**: Intel-based Macs
- **arm64**: Apple Silicon (M1, M2, etc.)

### Environment Variables
- `MACOS_TARGET`: Override the target architecture (e.g., `x86_64-apple-macos10.8`)

## Build Targets

### Single Architecture Build
```bash
# Build for current architecture
make mac

# Build for specific architecture
MACOS_TARGET="arm64-apple-macos10.8" make mac
MACOS_TARGET="x86_64-apple-macos10.8" make mac
```

### Universal Binary Build
```bash
# Build universal binary (x86_64 + ARM64)
make mac-universal
```

## New Scripts

### macos_arch_detect.sh
A utility script for MacOS architecture management:

```bash
# Detect architecture
./scripts/macos_arch_detect.sh detect

# Create architecture-specific links
./scripts/macos_arch_detect.sh links

# Build for current architecture
./scripts/macos_arch_detect.sh build

# Build universal binary
./scripts/macos_arch_detect.sh universal
```

## GitHub Actions

The CI/CD pipeline now supports both architectures:
- **macos-12**: x86_64 builds
- **macos-13**: ARM64 builds

## Binary Naming Convention

- `mac64`: x86_64 binaries (legacy)
- `mac64-arm64`: ARM64 binaries
- Universal binaries are created using `lipo` tool

## Installation

### Easy Install
The installer automatically detects the architecture and installs appropriate binaries:

```bash
./install_easy.sh
```

### Manual Build
```bash
# For current architecture
make mac

# For universal binary
make mac-universal
```

## Troubleshooting

### Architecture Mismatch
If you encounter architecture mismatch errors:

1. Check current architecture:
   ```bash
   uname -m
   ```

2. Set correct target:
   ```bash
   export MACOS_TARGET="arm64-apple-macos10.8"  # for Apple Silicon
   export MACOS_TARGET="x86_64-apple-macos10.8" # for Intel
   ```

3. Rebuild:
   ```bash
   make clean
   make mac
   ```

### Universal Binary Issues
If universal binary creation fails:

1. Ensure both architectures are available
2. Check `lipo` tool availability
3. Verify target strings are correct

## Development

### Adding New Components
When adding new components that need MacOS support:

1. Add `mac` target to Makefile
2. Add `mac-universal` target if needed
3. Use `$(MACOS_TARGET)` variable for architecture-specific builds

### Testing
Test on both architectures:
- Intel Mac: `MACOS_TARGET="x86_64-apple-macos10.8" make mac`
- Apple Silicon: `MACOS_TARGET="arm64-apple-macos10.8" make mac`
- Universal: `make mac-universal`

## Compatibility

### Supported MacOS Versions
- Minimum: macOS 10.8 (Mountain Lion)
- Recommended: macOS 11+ (Big Sur)

### Architecture Support
- ✅ x86_64 (Intel)
- ✅ arm64 (Apple Silicon)
- ✅ Universal binaries

## Performance Considerations

- Single architecture binaries are smaller and faster
- Universal binaries work on both architectures but are larger
- ARM64 binaries may be faster on Apple Silicon due to native optimization

## Future Improvements

- [ ] Add support for newer MacOS target versions
- [ ] Implement automatic universal binary detection
- [ ] Add architecture-specific optimization flags
- [ ] Support for cross-compilation from Linux to MacOS