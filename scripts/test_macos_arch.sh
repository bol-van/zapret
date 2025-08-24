#!/bin/sh

# Enhanced test script for MacOS architecture detection
# This script helps verify that the refactoring works correctly

echo "=== Enhanced MacOS Architecture Test ==="
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
        echo "   Target: x86_64-apple-macos$(sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo '10.8')"
        ;;
    arm64)
        echo "✅ Detected Apple Silicon (ARM64) architecture"
        echo "   Target: arm64-apple-macos$(sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo '10.8')"
        ;;
    *)
        echo "❌ Unknown architecture: $(uname -m)"
        ;;
esac
echo ""

# Test MacOS version detection
echo "=== MacOS Version Detection Test ==="
if command -v sw_vers >/dev/null 2>&1; then
    local_version=$(sw_vers -productVersion 2>/dev/null)
    major_version=$(echo "$local_version" | cut -d. -f1,2)
    echo "✅ MacOS version detected: $local_version"
    echo "   Major version: $major_version"
    echo "   Build version: $(sw_vers -buildVersion 2>/dev/null || echo 'Unknown')"
else
    echo "❌ Could not detect MacOS version (sw_vers not available)"
    local_version="10.8"
    major_version="10.8"
fi
echo ""

# Test environment variables
echo "=== Environment Variable Test ==="
if [ -n "$MACOS_TARGET" ]; then
    echo "✅ MACOS_TARGET is set: $MACOS_TARGET"
else
    echo "ℹ️  MACOS_TARGET is not set (will use auto-detection)"
fi

if [ -n "$MACOS_VERSION" ]; then
    echo "✅ MACOS_VERSION is set: $MACOS_VERSION"
else
    echo "ℹ️  MACOS_VERSION is not set (will use auto-detection)"
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
    
    # Check if mac-auto target exists
    if grep -q "^mac-auto:" ../Makefile; then
        echo "✅ 'mac-auto' target found in Makefile"
    else
        echo "ℹ️  'mac-auto' target not found in Makefile"
    fi
    
    # Check if mac-info target exists
    if grep -q "^mac-info:" ../Makefile; then
        echo "✅ 'mac-info' target found in Makefile"
    else
        echo "ℹ️  'mac-info' target not found in Makefile"
    fi
else
    echo "❌ Makefile not found"
fi
echo ""

# Test component Makefiles
echo "=== Component Makefiles Test ==="
components="tpws ip2net mdig nfq"
for comp in $components; do
    if [ -f "../$comp/Makefile" ]; then
        echo "✅ $comp Makefile found"
        
        # Check for mac target
        if grep -q "^mac:" "../$comp/Makefile"; then
            echo "   ✅ 'mac' target available"
        else
            echo "   ❌ 'mac' target not available"
        fi
        
        # Check for mac-universal target
        if grep -q "^mac-universal:" "../$comp/Makefile"; then
            echo "   ✅ 'mac-universal' target available"
        else
            echo "   ❌ 'mac-universal' target not available"
        fi
        
        # Check for mac-info target
        if grep -q "^mac-info:" "../$comp/Makefile"; then
            echo "   ✅ 'mac-info' target available"
        else
            echo "   ❌ 'mac-info' target not available"
        fi
    else
        echo "❌ $comp Makefile not found"
    fi
done
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
            echo "   Contents:"
            ls -la "$BINS/$arch" | head -5 | sed 's/^/     /'
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
local_ready=true

if command -v make >/dev/null 2>&1; then
    echo "✅ 'make' command available: $(which make)"
else
    echo "❌ 'make' command not available"
    local_ready=false
fi

if command -v cc >/dev/null 2>&1; then
    echo "✅ 'cc' compiler available: $(which cc)"
elif command -v clang >/dev/null 2>&1; then
    echo "✅ 'clang' compiler available: $(which clang)"
elif command -v gcc >/dev/null 2>&1; then
    echo "✅ 'gcc' compiler available: $(which gcc)"
else
    echo "❌ No C compiler found"
    local_ready=false
fi

if command -v lipo >/dev/null 2>&1; then
    echo "✅ 'lipo' tool available: $(which lipo)"
else
    echo "❌ 'lipo' tool not available"
    local_ready=false
fi

if command -v strip >/dev/null 2>&1; then
    echo "✅ 'strip' tool available: $(which strip)"
else
    echo "❌ 'strip' tool not available"
    local_ready=false
fi

if [ "$local_ready" = "true" ]; then
    echo "✅ System is ready for compilation"
else
    echo "❌ System is not ready for compilation"
    echo "   Install Xcode Command Line Tools: xcode-select --install"
fi
echo ""

# Test architecture detection script
echo "=== Architecture Detection Script Test ==="
if [ -f "./macos_arch_detect.sh" ]; then
    echo "✅ Architecture detection script found"
    
    # Test basic functionality
    if ./macos_arch_detect.sh detect >/dev/null 2>&1; then
        echo "✅ Script runs successfully"
        
        # Test info command
        if ./macos_arch_detect.sh info >/dev/null 2>&1; then
            echo "✅ 'info' command works"
        else
            echo "❌ 'info' command failed"
        fi
        
        # Test check command
        if ./macos_arch_detect.sh check >/dev/null 2>&1; then
            echo "✅ 'check' command works"
        else
            echo "❌ 'check' command failed"
        fi
    else
        echo "❌ Script failed to run"
    fi
else
    echo "❌ Architecture detection script not found"
fi
echo ""

# Test MacOS specific features
echo "=== MacOS Specific Features Test ==="

# Check for PF (Packet Filter)
if command -v pfctl >/dev/null 2>&1; then
    echo "✅ PF (Packet Filter) available: $(which pfctl)"
    pfctl -v 2>/dev/null | head -1 | sed 's/^/   /'
else
    echo "❌ PF (Packet Filter) not available"
fi

# Check for launchd
if command -v launchctl >/dev/null 2>&1; then
    echo "✅ launchd available: $(which launchctl)"
else
    echo "❌ launchd not available"
fi

# Check for system integrity protection
if csrutil status 2>/dev/null | grep -q "enabled"; then
    echo "⚠️  System Integrity Protection (SIP) is enabled"
    echo "   This may affect some operations"
else
    echo "✅ System Integrity Protection (SIP) is disabled or not available"
fi
echo ""

echo "=== Test Complete ==="
echo ""
echo "To test compilation, run:"
echo "  make mac                    # Build for current architecture"
echo "  make mac-universal         # Build universal binary"
echo "  make mac-auto              # Auto-detect and build"
echo "  make mac-info              # Show build information"
echo "  ./macos_arch_detect.sh     # Use architecture detection script"
echo ""
echo "For more information:"
echo "  ./macos_arch_detect.sh help"
echo "  make mac-info"
echo "  ./macos_arch_detect.sh info"