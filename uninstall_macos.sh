#!/bin/sh

# MacOS uninstall script for zapret
# This script removes zapret installation from MacOS

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_TARGET=${ZAPRET_TARGET:-/opt/zapret}

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

# Function to check if zapret is installed
check_installation() {
    if [ ! -d "$ZAPRET_TARGET" ]; then
        print_status $YELLOW "⚠️  zapret installation not found at $ZAPRET_TARGET"
        print_status $YELLOW "Nothing to uninstall"
        exit 0
    fi
    
    print_status $BLUE "Found zapret installation at: $ZAPRET_TARGET"
}

# Function to stop services
stop_services() {
    print_status $BLUE "Stopping zapret services..."
    
    # Stop launchd service if running
    if launchctl list | grep -q "zapret"; then
        print_status $YELLOW "Stopping launchd service..."
        sudo launchctl unload "/Library/LaunchDaemons/zapret.plist" 2>/dev/null || true
    fi
    
    # Stop running daemons
    if [ -f "$ZAPRET_TARGET/init.d/macos/zapret" ]; then
        print_status $YELLOW "Stopping zapret daemons..."
        sudo "$ZAPRET_TARGET/init.d/macos/zapret" stop 2>/dev/null || true
    fi
    
    # Kill any remaining zapret processes
    local pids=$(pgrep -f "zapret\|tpws\|dvtws" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        print_status $YELLOW "Killing remaining zapret processes..."
        echo "$pids" | xargs sudo kill -9 2>/dev/null || true
    fi
    
    print_status $GREEN "✅ Services stopped"
}

# Function to remove firewall rules
remove_firewall_rules() {
    print_status $BLUE "Removing firewall rules..."
    
    # Remove PF anchors
    if [ -f "/etc/pf.anchors/zapret" ]; then
        print_status $YELLOW "Removing PF anchors..."
        sudo rm -f "/etc/pf.anchors/zapret"*
    fi
    
    # Restore original pf.conf if backup exists
    if [ -f "/etc/pf.conf.zapret.backup" ]; then
        print_status $YELLOW "Restoring original pf.conf..."
        sudo cp "/etc/pf.conf.zapret.backup" "/etc/pf.conf"
        sudo rm -f "/etc/pf.conf.zapret.backup"
    else
        # Try to remove zapret references from pf.conf
        print_status $YELLOW "Removing zapret references from pf.conf..."
        sudo sed -i '' -e '/^rdr-anchor "zapret"$/d' \
                       -e '/^anchor "zapret"$/d' \
                       -e '/^set limit table-entries/d' \
                       "/etc/pf.conf" 2>/dev/null || true
    fi
    
    # Reload PF
    if command -v pfctl >/dev/null 2>&1; then
        print_status $YELLOW "Reloading PF configuration..."
        sudo pfctl -f /etc/pf.conf 2>/dev/null || true
    fi
    
    print_status $GREEN "✅ Firewall rules removed"
}

# Function to remove symbolic links
remove_symlinks() {
    print_status $BLUE "Removing symbolic links..."
    
    # Remove symlinks from /usr/local/bin
    for binary in tpws ip2net mdig; do
        if [ -L "/usr/local/bin/$binary" ]; then
            print_status $YELLOW "Removing symlink: /usr/local/bin/$binary"
            sudo rm -f "/usr/local/bin/$binary"
        fi
    done
    
    print_status $GREEN "✅ Symbolic links removed"
}

# Function to remove launchd plist
remove_launchd() {
    print_status $BLUE "Removing launchd configuration..."
    
    # Unload service if running
    if launchctl list | grep -q "zapret"; then
        sudo launchctl unload "/Library/LaunchDaemons/zapret.plist" 2>/dev/null || true
    fi
    
    # Remove plist file
    if [ -f "/Library/LaunchDaemons/zapret.plist" ]; then
        print_status $YELLOW "Removing launchd plist..."
        sudo rm -f "/Library/LaunchDaemons/zapret.plist"
    fi
    
    print_status $GREEN "✅ Launchd configuration removed"
}

# Function to remove installation directory
remove_installation() {
    print_status $BLUE "Removing installation directory..."
    
    if [ -d "$ZAPRET_TARGET" ]; then
        print_status $YELLOW "Removing: $ZAPRET_TARGET"
        sudo rm -rf "$ZAPRET_TARGET"
    fi
    
    print_status $GREEN "✅ Installation directory removed"
}

# Function to remove cron jobs
remove_cron_jobs() {
    print_status $BLUE "Removing cron jobs..."
    
    # Check for zapret cron jobs
    if crontab -l 2>/dev/null | grep -q "zapret"; then
        print_status $YELLOW "Removing zapret cron jobs..."
        crontab -l 2>/dev/null | grep -v "zapret" | crontab -
    fi
    
    print_status $GREEN "✅ Cron jobs removed"
}

# Function to show uninstall summary
show_uninstall_summary() {
    print_status $GREEN "🎉 Uninstallation completed successfully!"
    echo ""
    print_status $BLUE "What was removed:"
    echo "=================="
    echo "• zapret binaries and configuration"
    echo "• Firewall rules and PF anchors"
    echo "• Launchd service configuration"
    echo "• Symbolic links in /usr/local/bin"
    echo "• Cron jobs (if any)"
    echo ""
    print_status $YELLOW "Note: Your original pf.conf has been restored"
    print_status $YELLOW "      You may need to restart networking services"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --force     Force uninstallation without confirmation"
    echo "  --help      Show this help message"
    echo ""
    echo "This script will:"
    echo "• Stop all zapret services"
    echo "• Remove firewall rules"
    echo "• Remove installation files"
    echo "• Restore original system configuration"
    echo ""
    echo "Warning: This will completely remove zapret from your system!"
}

# Function to confirm uninstallation
confirm_uninstallation() {
    if [ "$1" != "--force" ]; then
        echo ""
        print_status $RED "⚠️  WARNING: This will completely remove zapret from your system!"
        echo ""
        echo "The following will be removed:"
        echo "• All zapret binaries and configuration"
        echo "• Firewall rules and PF anchors"
        echo "• Launchd service configuration"
        echo "• Symbolic links and cron jobs"
        echo ""
        echo "Your original pf.conf will be restored from backup."
        echo ""
        read -p "Are you sure you want to continue? (yes/no): " confirm
        
        if [ "$confirm" != "yes" ]; then
            print_status $YELLOW "Uninstallation cancelled"
            exit 0
        fi
    fi
}

# Function to backup configuration
backup_config() {
    print_status $BLUE "Creating backup of current configuration..."
    
    local backup_dir="$EXEDIR/zapret_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup configuration files
    if [ -f "$ZAPRET_TARGET/config" ]; then
        cp "$ZAPRET_TARGET/config" "$backup_dir/"
    fi
    
    # Backup PF configuration
    if [ -f "/etc/pf.conf" ]; then
        cp "/etc/pf.conf" "$backup_dir/pf.conf"
    fi
    
    # Backup PF anchors
    if [ -d "/etc/pf.anchors" ]; then
        cp -r "/etc/pf.anchors" "$backup_dir/"
    fi
    
    print_status $GREEN "✅ Backup created at: $backup_dir"
}

# Main uninstall function
main_uninstall() {
    print_status $BLUE "Starting zapret uninstallation..."
    echo ""
    
    # Check if we're on MacOS
    check_macos
    
    # Check if zapret is installed
    check_installation
    
    # Confirm uninstallation
    confirm_uninstallation "$1"
    
    # Create backup
    backup_config
    
    # Stop services
    stop_services
    
    # Remove firewall rules
    remove_firewall_rules
    
    # Remove symbolic links
    remove_symlinks
    
    # Remove launchd configuration
    remove_launchd
    
    # Remove cron jobs
    remove_cron_jobs
    
    # Remove installation directory
    remove_installation
    
    # Show summary
    show_uninstall_summary
}

# Main script logic
case "${1:-}" in
    --help|-h|help)
        show_help
        ;;
    --force|force)
        main_uninstall "$1"
        ;;
    "")
        main_uninstall
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use '$0 --help' for usage information"
        exit 1
        ;;
esac