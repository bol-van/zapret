#!/bin/sh

# Script to detect MacOS architecture and create appropriate symbolic links
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

# Function to get MacOS target string
get_macos_target()
{
	local arch=$(detect_macos_arch)
	case "$arch" in
		x86_64)
			echo "x86_64-apple-macos10.8"
			;;
		arm64)
			echo "arm64-apple-macos10.8"
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
	
	echo "Detected MacOS architecture: $arch"
	echo "Target string: $target"
	
	# Set environment variable for Makefiles
	export MACOS_TARGET="$target"
	
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
	echo "Building for current architecture with target: $target"
	export MACOS_TARGET="$target"
	make mac
}

# Function to build universal binary
build_universal()
{
	echo "Building universal binary for MacOS (x86_64 + arm64)"
	make mac-universal
}

# Function to show help
show_help()
{
	echo "Usage: $0 [OPTION]"
	echo ""
	echo "Options:"
	echo "  detect     Detect MacOS architecture and show info"
	echo "  links      Create architecture-specific symbolic links"
	echo "  build      Build for current architecture"
	echo "  universal  Build universal binary (x86_64 + arm64)"
	echo "  help       Show this help message"
	echo ""
	echo "Environment variables:"
	echo "  MACOS_TARGET  Override target string (e.g., x86_64-apple-macos10.8)"
	echo ""
}

# Main script logic
case "${1:-detect}" in
	detect)
		echo "MacOS Architecture Detection"
		echo "=========================="
		echo "Architecture: $(detect_macos_arch)"
		echo "Target: $(get_macos_target)"
		echo "Universal binary available: $(check_universal_binary "$BINDIR/mac64/tpws" 2>/dev/null || echo 'unknown')"
		;;
	links)
		create_arch_links
		;;
	build)
		build_current_arch
		;;
	universal)
		build_universal
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