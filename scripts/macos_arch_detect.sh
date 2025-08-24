#!/bin/sh

# Enhanced script to detect MacOS architecture and create appropriate symbolic links
# This script helps with cross-compilation and universal binary support

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
BINS=binaries
BINDIR="$EXEDIR/$BINS"

# Function to detect MacOS architecture
detect_macos_arch()
{
	local arch
	case "$(uname -m)" in
		x86_64)
			arch="x86_64"
			;;
		arm64)
			arch="arm64"
			;;
		*)
			arch="unknown"
			;;
	esac
	echo "$arch"
}

# Function to get MacOS version
detect_macos_version()
{
	local version
	if command -v sw_vers >/dev/null 2>&1; then
		version=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1,2)
	else
		version="10.8"
	fi
	echo "$version"
}

# Function to get MacOS target string
get_macos_target()
{
	local arch=$(detect_macos_arch)
	local version=$(detect_macos_version)
	case "$arch" in
		x86_64)
			echo "x86_64-apple-macos$version"
			;;
		arm64)
			echo "arm64-apple-macos$version"
			;;
		*)
			echo "unknown"
			;;
	esac
}

# Function to check if universal binary is available
check_universal_binary()
{
	local exe="$1"
	if [ -f "$exe" ] && [ -x "$exe" ]; then
		# Check if it's a universal binary
		if file "$exe" | grep -q "universal binary"; then
			echo "yes"
		else
			echo "no"
		fi
	else
		echo "no"
	fi
}

# Function to create architecture-specific links
create_arch_links()
{
	local arch=$(detect_macos_arch)
	local target=$(get_macos_target)
	local version=$(detect_macos_version)
	
	echo "Detected MacOS architecture: $arch"
	echo "MacOS version: $version"
	echo "Target string: $target"
	
	# Set environment variable for Makefiles
	export MACOS_TARGET="$target"
	export MACOS_VERSION="$version"
	
	# Create symbolic links for architecture-specific binaries
	if [ -d "$BINDIR/mac64" ]; then
		echo "Found mac64 binaries directory"
		if [ "$arch" = "arm64" ] && [ -d "$BINDIR/mac64-arm64" ]; then
			echo "Creating links for ARM64 architecture"
			ln -sf "$BINDIR/mac64-arm64" "$BINDIR/current"
		else
			echo "Creating links for x86_64 architecture"
			ln -sf "$BINDIR/mac64" "$BINDIR/current"
		fi
	fi
}

# Function to build for current architecture
build_current_arch()
{
	local target=$(get_macos_target)
	local version=$(detect_macos_version)
	echo "Building for current architecture with target: $target"
	echo "MacOS version: $version"
	export MACOS_TARGET="$target"
	export MACOS_VERSION="$version"
	make mac
}

# Function to build universal binary
build_universal()
{
	local version=$(detect_macos_version)
	echo "Building universal binary for MacOS (x86_64 + arm64)"
	echo "MacOS version: $version"
	export MACOS_VERSION="$version"
	make mac-universal
}

# Function to build for specific MacOS version
build_specific_version()
{
	local version="$1"
	if [ -z "$version" ]; then
		echo "Error: Please specify a MacOS version (e.g., 11.0, 12.0, 13.0)"
		exit 1
	fi
	
	local target=$(get_macos_target)
	echo "Building for MacOS $version with target: $target"
	export MACOS_TARGET="$target"
	export MACOS_VERSION="$version"
	make "mac-$version"
}

# Function to show system information
show_system_info()
{
	echo "MacOS System Information"
	echo "======================="
	echo "System: $(uname)"
	echo "Architecture: $(detect_macos_arch)"
	echo "MacOS Version: $(detect_macos_version)"
	echo "Target: $(get_macos_target)"
	echo "Compiler: $(which cc 2>/dev/null || which clang 2>/dev/null || echo "Not found")"
	echo "Make: $(which make 2>/dev/null || echo "Not found")"
	echo "Lipo: $(which lipo 2>/dev/null || echo "Not found")"
	echo ""
	
	# Check for required tools
	echo "Required Tools Check:"
	echo "===================="
	local missing_tools=""
	
	if ! command -v make >/dev/null 2>&1; then
		missing_tools="$missing_tools make"
	fi
	
	if ! command -v cc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
		missing_tools="$missing_tools compiler(cc/clang)"
	fi
	
	if ! command -v lipo >/dev/null 2>&1; then
		missing_tools="$missing_tools lipo"
	fi
	
	if [ -n "$missing_tools" ]; then
		echo "❌ Missing tools: $missing_tools"
		echo "   Install Xcode Command Line Tools: xcode-select --install"
	else
		echo "✅ All required tools are available"
	fi
}

# Function to check build readiness
check_build_readiness()
{
	echo "Build Readiness Check"
	echo "===================="
	
	# Check if we're on MacOS
	if [ "$(uname)" != "Darwin" ]; then
		echo "❌ This script is designed for MacOS only"
		echo "   Current system: $(uname)"
		return 1
	fi
	
	# Check for required tools
	local ready=true
	
	if ! command -v make >/dev/null 2>&1; then
		echo "❌ 'make' command not available"
		ready=false
	fi
	
	if ! command -v cc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
		echo "❌ No C compiler found (cc or clang)"
		ready=false
	fi
	
	if ! command -v lipo >/dev/null 2>&1; then
		echo "❌ 'lipo' tool not available"
		ready=false
	fi
	
	if [ "$ready" = "true" ]; then
		echo "✅ System is ready for building"
		return 0
	else
		echo "❌ System is not ready for building"
		echo "   Install Xcode Command Line Tools: xcode-select --install"
		return 1
	fi
}

# Function to show help
show_help()
{
	echo "Usage: $0 [OPTION]"
	echo ""
	echo "Options:"
	echo "  detect     Detect MacOS architecture and show info"
	echo "  info       Show detailed system information"
	echo "  check      Check if system is ready for building"
	echo "  links      Create architecture-specific symbolic links"
	echo "  build      Build for current architecture"
	echo "  universal  Build universal binary (x86_64 + arm64)"
	echo "  version V  Build for specific MacOS version (e.g., 11.0, 12.0)"
	echo "  help       Show this help message"
	echo ""
	echo "Environment variables:"
	echo "  MACOS_TARGET   Override target string (e.g., x86_64-apple-macos10.8)"
	echo "  MACOS_VERSION  Override MacOS version (e.g., 11.0, 12.0)"
	echo ""
	echo "Examples:"
	echo "  $0 detect                    # Detect architecture"
	echo "  $0 build                     # Build for current architecture"
	echo "  $0 universal                 # Build universal binary"
	echo "  $0 version 12.0              # Build for MacOS 12.0"
	echo "  MACOS_TARGET=x86_64-apple-macos11.0 $0 build  # Override target"
}

# Main script logic
case "${1:-detect}" in
	detect)
		echo "MacOS Architecture Detection"
		echo "=========================="
		echo "Architecture: $(detect_macos_arch)"
		echo "Version: $(detect_macos_version)"
		echo "Target: $(get_macos_target)"
		echo "Universal binary available: $(check_universal_binary "$BINDIR/mac64/tpws" 2>/dev/null || echo 'unknown')"
		;;
	info)
		show_system_info
		;;
	check)
		check_build_readiness
		;;
	links)
		create_arch_links
		;;
	build)
		check_build_readiness && build_current_arch
		;;
	universal)
		check_build_readiness && build_universal
		;;
	version)
		check_build_readiness && build_specific_version "$2"
		;;
	help|--help|-h)
		show_help
		;;
	*)
		echo "Unknown option: $1"
		echo "Use '$0 help' for usage information"
		exit 1
		;;
esac