#!/bin/sh

# Test script for MacOS architecture detection
# This script helps verify that the refactoring works correctly

echo "=== MacOS Architecture Test ==="
echo ""

# Check if we're on MacOS
if [ "$(uname)" != "Darwin" ]; then
    echo "This script is designed for MacOS only."
    echo "Current system: $(uname)"
    exit 1
fi

echo "System: $(uname)"
echo "Architecture: $(uname -m)"
echo "Kernel version: $(uname -r)"
echo ""

# Test architecture detection
echo "=== Architecture Detection Test ==="
case "$(uname -m)" in
    x86_64)
        echo "✅ Detected Intel (x86_64) architecture"
        echo "   Target: x86_64-apple-macos10.8"
        ;;
    arm64)
        echo "✅ Detected Apple Silicon (ARM64) architecture"
        echo "   Target: arm64-apple-macos10.8"
        ;;
    *)
        echo "❌ Unknown architecture: $(uname -m)"
        ;;
esac
echo ""

# Test environment variable
echo "=== Environment Variable Test ==="
if [ -n "$MACOS_TARGET" ]; then
    echo "✅ MACOS_TARGET is set: $MACOS_TARGET"
else
    echo "ℹ️  MACOS_TARGET is not set (will use auto-detection)"
fi
echo ""

# Test build system
echo "=== Build System Test ==="
if [ -f "../Makefile" ]; then
    echo "✅ Makefile found"
    
    # Check if mac target exists
    if grep -q "^mac:" ../Makefile; then
        echo "✅ 'mac' target found in Makefile"
    else
        echo "❌ 'mac' target not found in Makefile"
    fi
    
    # Check if mac-universal target exists
    if grep -q "^mac-universal:" ../Makefile; then
        echo "✅ 'mac-universal' target found in Makefile"
    else
        echo "❌ 'mac-universal' target not found in Makefile"
    fi
else
    echo "❌ Makefile not found"
fi
echo ""

# Test binary directories
echo "=== Binary Directory Test ==="
BINS="../binaries"
if [ -d "$BINS" ]; then
    echo "✅ Binaries directory found: $BINS"
    
    # Check for architecture-specific directories
    for arch in mac64 mac64-arm64; do
        if [ -d "$BINS/$arch" ]; then
            echo "✅ Found $arch directory"
            ls -la "$BINS/$arch" | head -5
        else
            echo "ℹ️  $arch directory not found"
        fi
    done
else
    echo "ℹ️  Binaries directory not found: $BINS"
fi
echo ""

# Test compilation readiness
echo "=== Compilation Readiness Test ==="
if command -v make >/dev/null 2>&1; then
    echo "✅ 'make' command available"
else
    echo "❌ 'make' command not available"
fi

if command -v cc >/dev/null 2>&1; then
    echo "✅ 'cc' compiler available"
elif command -v clang >/dev/null 2>&1; then
    echo "✅ 'clang' compiler available"
elif command -v gcc >/dev/null 2>&1; then
    echo "✅ 'gcc' compiler available"
else
    echo "❌ No C compiler found"
fi

if command -v lipo >/dev/null 2>&1; then
    echo "✅ 'lipo' tool available (for universal binaries)"
else
    echo "❌ 'lipo' tool not available"
fi
echo ""

echo "=== Test Complete ==="
echo ""
echo "To test compilation, run:"
echo "  make mac                    # Build for current architecture"
echo "  make mac-universal         # Build universal binary"
echo "  ./macos_arch_detect.sh     # Use architecture detection script"