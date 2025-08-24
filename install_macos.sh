#!/bin/sh

# Enhanced MacOS installation script for zapret
# This script provides improved MacOS support with automatic architecture detection

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE=${ZAPRET_BASE:-"$EXEDIR"}
ZAPRET_TARGET=${ZAPRET_TARGET:-/opt/zapret}
ZAPRET_TARGET_RW=${ZAPRET_RW:-"$ZAPRET_TARGET"}
ZAPRET_TARGET_CONFIG="$ZAPRET_TARGET_RW/config"
ZAPRET_RW=${ZAPRET_RW:-"$ZAPRET_BASE"}
ZAPRET_CONFIG=${ZAPRET_CONFIG:-"$ZAPRET_RW/config"}
ZAPRET_CONFIG_DEFAULT="$ZAPRET_BASE/config.default"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color="$1"
    local message="$2"
    printf "${color}${message}${NC}\n"
}

# Function to check if we're on MacOS
check_macos() {
    if [ "$(uname)" != "Darwin" ]; then
        print_status $RED "Error: This script is designed for MacOS only"
        print_status $RED "Current system: $(uname)"
        exit 1
    fi
    print_status $GREEN "✅ MacOS detected: $(uname -m)"
}

# Function to detect MacOS architecture
detect_architecture() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "x86_64"
            ;;
        arm64)
            echo "arm64"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Function to detect MacOS version
detect_version() {
    if command -v sw_vers >/dev/null 2>&1; then
        sw_vers -productVersion 2>/dev/null | cut -d. -f1,2
    else
        echo "10.8"
    fi
}

# Function to check build tools
check_build_tools() {
    print_status $BLUE "Checking build tools..."
    
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
        print_status $RED "❌ Missing required tools: $missing_tools"
        print_status $YELLOW "Installing Xcode Command Line Tools..."
        xcode-select --install
        print_status $YELLOW "Please complete the installation and run this script again"
        exit 1
    fi
    
    print_status $GREEN "✅ All required build tools are available"
}

# Function to show system information
show_system_info() {
    print_status $BLUE "System Information:"
    echo "========================"
    echo "System: $(uname)"
    echo "Architecture: $(detect_architecture)"
    echo "MacOS Version: $(detect_version)"
    echo "Target: $(detect_architecture)-apple-macos$(detect_version)"
    echo "Compiler: $(which cc 2>/dev/null || which clang 2>/dev/null)"
    echo "Make: $(which make)"
    echo "Lipo: $(which lipo)"
    echo ""
}

# Function to build zapret
build_zapret() {
    local arch=$(detect_architecture)
    local version=$(detect_version)
    
    print_status $BLUE "Building zapret for MacOS..."
    echo "Architecture: $arch"
    echo "Version: $version"
    echo ""
    
    # Set environment variables
    export MACOS_TARGET="$(detect_architecture)-apple-macos$(detect_version)"
    export MACOS_VERSION="$version"
    
    # Build for current architecture
    print_status $YELLOW "Building for current architecture..."
    if make mac; then
        print_status $GREEN "✅ Build completed successfully"
    else
        print_status $RED "❌ Build failed"
        exit 1
    fi
}

# Function to build universal binary
build_universal() {
    local version=$(detect_version)
    
    print_status $BLUE "Building universal binary for MacOS..."
    echo "Version: $version"
    echo ""
    
    # Set environment variables
    export MACOS_VERSION="$version"
    
    # Build universal binary
    print_status $YELLOW "Building universal binary (x86_64 + arm64)..."
    if make mac-universal; then
        print_status $GREEN "✅ Universal binary build completed successfully"
    else
        print_status $RED "❌ Universal binary build failed"
        exit 1
    fi
}

# Function to install binaries
install_binaries() {
    print_status $BLUE "Installing binaries..."
    
    # Check if binaries were built
    if [ ! -d "$EXEDIR/binaries/my" ]; then
        print_status $RED "❌ Binaries not found. Please build first."
        exit 1
    fi
    
    # Create target directory
    if [ ! -d "$ZAPRET_TARGET" ]; then
        print_status $YELLOW "Creating target directory: $ZAPRET_TARGET"
        sudo mkdir -p "$ZAPRET_TARGET"
    fi
    
    # Copy binaries
    print_status $YELLOW "Copying binaries to $ZAPRET_TARGET..."
    sudo cp -r "$EXEDIR/binaries/my"/* "$ZAPRET_TARGET/"
    
    # Set permissions
    print_status $YELLOW "Setting permissions..."
    sudo chown -R root:wheel "$ZAPRET_TARGET"
    sudo chmod -R 755 "$ZAPRET_TARGET"
    
    print_status $GREEN "✅ Binaries installed successfully"
}

# Function to install configuration
install_config() {
    print_status $BLUE "Installing configuration..."
    
    # Create config directory
    if [ ! -d "$(dirname "$ZAPRET_TARGET_CONFIG")" ]; then
        sudo mkdir -p "$(dirname "$ZAPRET_TARGET_CONFIG")"
    fi
    
    # Copy default config if not exists
    if [ ! -f "$ZAPRET_TARGET_CONFIG" ]; then
        print_status $YELLOW "Installing default configuration..."
        sudo cp "$ZAPRET_CONFIG_DEFAULT" "$ZAPRET_TARGET_CONFIG"
        sudo chown root:wheel "$ZAPRET_TARGET_CONFIG"
        sudo chmod 644 "$ZAPRET_TARGET_CONFIG"
    else
        print_status $YELLOW "Configuration already exists, skipping..."
    fi
    
    print_status $GREEN "✅ Configuration installed successfully"
}

# Function to install init scripts
install_init_scripts() {
    print_status $BLUE "Installing init scripts..."
    
    # Copy init scripts
    if [ -d "$EXEDIR/init.d/macos" ]; then
        print_status $YELLOW "Installing MacOS init scripts..."
        sudo cp -r "$EXEDIR/init.d/macos" "$ZAPRET_TARGET/init.d/"
        sudo chown -R root:wheel "$ZAPRET_TARGET/init.d/macos"
        sudo chmod -R 755 "$ZAPRET_TARGET/init.d/macos"
    fi
    
    # Copy launchd plist
    if [ -f "$EXEDIR/init.d/macos/zapret.plist" ]; then
        print_status $YELLOW "Installing launchd plist..."
        sudo cp "$EXEDIR/init.d/macos/zapret.plist" "/Library/LaunchDaemons/"
        sudo chown root:wheel "/Library/LaunchDaemons/zapret.plist"
        sudo chmod 644 "/Library/LaunchDaemons/zapret.plist"
    fi
    
    print_status $GREEN "✅ Init scripts installed successfully"
}

# Function to install documentation
install_docs() {
    print_status $BLUE "Installing documentation..."
    
    # Copy documentation
    if [ -d "$EXEDIR/docs" ]; then
        sudo cp -r "$EXEDIR/docs" "$ZAPRET_TARGET/"
        sudo chown -R root:wheel "$ZAPRET_TARGET/docs"
        sudo chmod -R 644 "$ZAPRET_TARGET/docs"
        sudo find "$ZAPRET_TARGET/docs" -type d -exec chmod 755 {} \;
    fi
    
    print_status $GREEN "✅ Documentation installed successfully"
}

# Function to create symbolic links
create_symlinks() {
    print_status $BLUE "Creating symbolic links..."
    
    # Create symlinks in /usr/local/bin
    if [ ! -d "/usr/local/bin" ]; then
        sudo mkdir -p "/usr/local/bin"
    fi
    
    for binary in tpws ip2net mdig; do
        if [ -f "$ZAPRET_TARGET/$binary" ]; then
            print_status $YELLOW "Creating symlink for $binary..."
            sudo ln -sf "$ZAPRET_TARGET/$binary" "/usr/local/bin/$binary"
        fi
    done
    
    print_status $GREEN "✅ Symbolic links created successfully"
}

# Function to show post-installation information
show_post_install_info() {
    print_status $GREEN "🎉 Installation completed successfully!"
    echo ""
    print_status $BLUE "Post-installation information:"
    echo "================================"
    echo "Installation directory: $ZAPRET_TARGET"
    echo "Configuration file: $ZAPRET_TARGET_CONFIG"
    echo "Control script: $ZAPRET_TARGET/init.d/macos/zapret"
    echo ""
    echo "Available commands:"
    echo "  tpws --help              # Show tpws help"
    echo "  ip2net --help            # Show ip2net help"
    echo "  mdig --help              # Show mdig help"
    echo ""
    echo "Service management:"
    echo "  sudo $ZAPRET_TARGET/init.d/macos/zapret start    # Start service"
    echo "  sudo $ZAPRET_TARGET/init.d/macos/zapret stop     # Stop service"
    echo "  sudo $ZAPRET_TARGET/init.d/macos/zapret status   # Show status"
    echo ""
    echo "Documentation:"
    echo "  $ZAPRET_TARGET/docs/README_MACOS_REFACTORING.md"
    echo "  $ZAPRET_TARGET/docs/bsd.en.md"
    echo ""
    print_status $YELLOW "Note: nfq component is not fully supported on MacOS"
    print_status $YELLOW "      Use tpws for DPI bypass functionality"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  build       Build for current architecture (default)"
    echo "  universal   Build universal binary (x86_64 + arm64)"
    echo "  install     Install built binaries and configuration"
    echo "  full        Build and install everything"
    echo "  info        Show system information"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build                    # Build for current architecture"
    echo "  $0 universal                # Build universal binary"
    echo "  $0 install                  # Install built binaries"
    echo "  $0 full                     # Build and install everything"
}

# Main script logic
main() {
    # Check if we're on MacOS
    check_macos
    
    # Show system information
    show_system_info
    
    # Check build tools
    check_build_tools
    
    case "${1:-build}" in
        build)
            build_zapret
            ;;
        universal)
            build_universal
            ;;
        install)
            install_binaries
            install_config
            install_init_scripts
            install_docs
            create_symlinks
            show_post_install_info
            ;;
        full)
            build_zapret
            install_binaries
            install_config
            install_init_scripts
            install_docs
            create_symlinks
            show_post_install_info
            ;;
        info)
            # Already shown above
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
}

# Run main function
main "$@"