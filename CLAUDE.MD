# CLAUDE.MD - AI Assistant Development Guide for zapret (MacOS Edition)

## 🎯 Project Overview

**zapret** is a DPI (Deep Packet Inspection) circumvention tool that has been **fully refactored for MacOS** with native support for both **Intel (x86_64)** and **Apple Silicon (ARM64)** architectures.

### Core Purpose
- Bypass DPI-based censorship and network filtering
- Provide transparent HTTP/HTTPS proxy capabilities
- Support both Linux and **MacOS (Darwin)** systems
- Native MacOS integration with PF (Packet Filter) and launchd

### Critical Design Principle
⚠️ **IMPORTANT**: macOS is **NOT BSD**! While it shares some BSD heritage, it is a unique hybrid system (XNU kernel = Mach + BSD + Apple components). This project correctly treats Darwin as a distinct platform with its own requirements.

## 📁 Project Structure

```
zapret/
├── tpws/              # Transparent proxy WebSocket (main component for MacOS)
├── ip2net/            # IP network tools
├── mdig/              # DNS tools
├── nfq/               # Network filtering queue (limited MacOS support)
├── scripts/           # MacOS-specific utilities
│   ├── macos_arch_detect.sh    # Architecture detection and build management
│   └── test_macos_arch.sh      # Comprehensive system testing
├── init.d/macos/      # launchd service scripts
├── install_macos.sh   # MacOS installation script
├── uninstall_macos.sh # MacOS uninstallation script
├── Makefile           # Enhanced build system with MacOS targets
└── docs/              # Documentation
```

## 🏗️ Architecture: MacOS Support

### Supported Architectures
1. **x86_64** (Intel Macs)
   - Target: `x86_64-apple-macos<version>`
   - Minimum: macOS 10.8 (Mountain Lion)
   - Recommended: macOS 11.0+ (Big Sur)

2. **ARM64** (Apple Silicon: M1, M2, M3+)
   - Target: `arm64-apple-macos<version>`
   - Minimum: macOS 11.0 (Big Sur)
   - Native ARM64 optimization

3. **Universal Binaries**
   - Single binary containing both architectures
   - Automatic selection at runtime
   - Best for distribution

### MacOS-Specific Components

#### Build System (Makefile)
```makefile
# Key variables
DIRS_MAC := tpws ip2net mdig  # MacOS-compatible components
MACOS_TARGET                  # Architecture target (auto-detected)
MACOS_VERSION                 # MacOS version (auto-detected)
IS_MACOS                      # Darwin detection flag
```

**New Makefile Targets for MacOS:**
- `make mac` - Build for current architecture (auto-detected)
- `make mac-universal` - Build universal binary (both architectures)
- `make mac-auto` - Auto-detect and build
- `make mac-info` - Display build information
- `make mac-clean` - Clean MacOS-specific builds

#### Architecture Detection Script
**Location:** `scripts/macos_arch_detect.sh`

**Functions:**
- `detect` - Detect current architecture
- `info` - Display system information
- `check` - Verify build readiness
- `build` - Build for current architecture
- `universal` - Build universal binary
- `version <ver>` - Set MacOS version target

**Usage:**
```bash
./scripts/macos_arch_detect.sh detect
./scripts/macos_arch_detect.sh info
./scripts/macos_arch_detect.sh build
./scripts/macos_arch_detect.sh universal
```

#### Testing Script
**Location:** `scripts/test_macos_arch.sh`

Performs comprehensive system testing:
- System information gathering
- Architecture detection validation
- Build tools verification
- Compilation test
- MacOS-specific feature checks

## 🔧 Development Workflow for Claude

### When Making Changes

1. **Architecture Awareness**
   - Always test on both x86_64 and ARM64 if possible
   - Use universal binary builds for distribution
   - Respect architecture-specific optimizations

2. **MacOS vs BSD vs Linux**
   - **NEVER** assume BSD compatibility
   - **ALWAYS** use Darwin-specific checks
   - **PREFER** MacOS-native APIs and tools

3. **Build System**
   - Modify component Makefiles in `tpws/`, `ip2net/`, `mdig/`
   - Update main `Makefile` for cross-component changes
   - Test with `make mac` and `make mac-universal`

4. **Testing Protocol**
   ```bash
   # Step 1: Clean build
   make mac-clean

   # Step 2: Build current architecture
   make mac

   # Step 3: Test functionality
   ./scripts/test_macos_arch.sh

   # Step 4: Build universal binary
   make mac-universal

   # Step 5: Verify installation
   ./install_macos.sh info
   ```

### Key Files to Modify

#### For Build System Changes
- `Makefile` - Main build orchestration
- `tpws/Makefile` - Transparent proxy build
- `ip2net/Makefile` - IP tools build
- `mdig/Makefile` - DNS tools build
- `scripts/macos_arch_detect.sh` - Architecture management

#### For Installation Changes
- `install_macos.sh` - MacOS installer
- `uninstall_macos.sh` - MacOS uninstaller
- `install_bin.sh` - Binary installation (cross-platform)

#### For Service Management
- `init.d/macos/zapret` - launchd service script
- `init.d/macos/zapret.plist` - launchd configuration

#### For Documentation
- `CLAUDE.MD` - This file (AI development guide)
- `TODO` - Task tracking
- `README_MACOS_FINAL.md` - Comprehensive MacOS guide
- `docs/MACOS_VS_BSD.md` - Critical Darwin vs BSD differences

## 🔍 Common Tasks for Claude

### Task 1: Add Support for New MacOS Version

1. Update version detection in `scripts/macos_arch_detect.sh`
2. Update `MACOS_VERSION` variable in `Makefile`
3. Test build on new version
4. Update documentation

### Task 2: Fix Architecture-Specific Bug

1. Identify architecture (x86_64 or ARM64)
2. Reproduce on specific architecture
3. Add architecture-specific fix in component Makefile
4. Test on both architectures
5. Verify universal binary works

### Task 3: Add New Component

1. Create component directory
2. Add component Makefile with MacOS targets
3. Update main `Makefile` DIRS_MAC variable
4. Test with `make mac`
5. Update documentation

### Task 4: Improve Build System

1. Modify relevant Makefile(s)
2. Test incremental builds
3. Test clean builds
4. Test universal binary builds
5. Update `make mac-info` output

### Task 5: Enhance Installation

1. Modify `install_macos.sh`
2. Test installation process
3. Test uninstallation with `uninstall_macos.sh`
4. Verify service integration
5. Update documentation

## ⚠️ Important Constraints

### What NOT to Do

❌ **Do NOT treat macOS as BSD**
- Different system calls
- Different networking stack
- Different firewall (PF with Apple modifications)
- Different service management (launchd, not rc)

❌ **Do NOT assume Linux compatibility**
- No iptables (use PF instead)
- No systemd (use launchd instead)
- No /proc filesystem
- Different socket behavior

❌ **Do NOT ignore architecture differences**
- x86_64 and ARM64 have different optimizations
- Endianness may differ in edge cases
- System libraries may vary

❌ **Do NOT skip testing**
- Always run `./scripts/test_macos_arch.sh`
- Always test both architectures when possible
- Always verify installation and uninstallation

### Security Considerations

🔒 **System Integrity Protection (SIP)**
- Some operations require SIP awareness
- Never instruct users to disable SIP permanently
- Prefer SIP-compatible solutions

🔒 **Code Signing**
- Binaries may need signing for distribution
- Respect notarization requirements
- Document signing requirements

🔒 **Permissions**
- Use appropriate file ownership (root:wheel)
- Respect privilege separation
- Document permission requirements

## 📚 Reference Documentation

### MacOS-Specific Docs
- `README_MACOS_FINAL.md` - Complete MacOS guide
- `README_MACOS_ENHANCED.md` - Enhanced features
- `README_MACOS_REFACTORING.md` - Technical details
- `QUICK_START_MACOS.md` - Quick start guide
- `docs/MACOS_VS_BSD.md` - Darwin vs BSD differences

### General Documentation
- `docs/readme.en.md` - General project documentation
- `docs/bsd.en.md` - BSD reference (NOT for macOS!)
- `CHANGELOG_MACOS_COMPLETE.md` - Complete changelog
- `CHANGELOG_MACOS_REFACTORING.md` - Refactoring details

## 🛠️ Development Tools

### Required Tools (MacOS)
- Xcode Command Line Tools or full Xcode
- clang/LLVM compiler
- make (BSD make is fine)
- git
- sw_vers (system version info)
- uname (architecture detection)

### Optional Tools
- Homebrew (for dependencies)
- lldb (debugging)
- Instruments (profiling)

### Verification Commands
```bash
# Check compiler
clang --version

# Check make
make --version

# Check system
sw_vers
uname -a

# Check architecture
uname -m
arch

# Full system test
./scripts/test_macos_arch.sh
```

## 🚀 Quick Start for Development

### Initial Setup
```bash
# 1. Clone repository (if not already)
git clone <repo-url>
cd zapret

# 2. Verify system
./scripts/macos_arch_detect.sh info

# 3. Test build system
make mac-info

# 4. Build
make mac

# 5. Test
./scripts/test_macos_arch.sh
```

### Making Changes
```bash
# 1. Create feature branch
git checkout -b feature/my-macos-feature

# 2. Make changes to code

# 3. Clean build
make mac-clean

# 4. Test build
make mac

# 5. Run tests
./scripts/test_macos_arch.sh

# 6. Build universal (if needed)
make mac-universal

# 7. Commit
git add .
git commit -m "Description of MacOS changes"

# 8. Push
git push -u origin feature/my-macos-feature
```

## 📊 Project Status

### Completed ✅
- Full x86_64 (Intel) support
- Full ARM64 (Apple Silicon) support
- Universal binary support
- Automatic architecture detection
- Enhanced build system
- MacOS-specific installation
- Service integration (launchd)
- Firewall integration (PF)
- Comprehensive testing tools
- Complete documentation

### In Progress 🔄
- See `TODO` file for current tasks

### Future Enhancements 🔮
- macOS 15.0+ support
- Performance benchmarking
- Homebrew package
- Cross-compilation from Linux
- Automated testing framework

## 💡 Tips for Claude

1. **Always Read First**: Before modifying any file, read it completely
2. **Understand Context**: Check related files and documentation
3. **Test Thoroughly**: Use provided testing scripts
4. **Document Changes**: Update relevant documentation
5. **Consider Architecture**: Think about both x86_64 and ARM64
6. **Respect MacOS**: Don't treat it as Linux or BSD
7. **Check TODO**: See `TODO` file for planned work
8. **Use Scripts**: Leverage `scripts/macos_arch_detect.sh` and `scripts/test_macos_arch.sh`
9. **Build Incremental**: Test changes incrementally
10. **Think Security**: Consider SIP, permissions, and signing

## 🔗 Quick Reference

### Build Commands
```bash
make mac              # Build current arch
make mac-universal    # Build universal
make mac-clean        # Clean MacOS builds
make mac-info         # Show build info
make mac-auto         # Auto build
```

### Script Commands
```bash
./scripts/macos_arch_detect.sh detect     # Detect arch
./scripts/macos_arch_detect.sh info       # System info
./scripts/macos_arch_detect.sh check      # Build check
./scripts/macos_arch_detect.sh build      # Build current
./scripts/macos_arch_detect.sh universal  # Build universal
./scripts/test_macos_arch.sh              # Full test
```

### Installation Commands
```bash
./install_macos.sh build      # Build only
./install_macos.sh install    # Install only
./install_macos.sh full       # Build + install
./install_macos.sh info       # System info
./uninstall_macos.sh          # Uninstall
```

### Service Commands
```bash
sudo /opt/zapret/init.d/macos/zapret start
sudo /opt/zapret/init.d/macos/zapret stop
sudo /opt/zapret/init.d/macos/zapret restart
sudo /opt/zapret/init.d/macos/zapret status
```

## 🎯 Goal for Claude

When working on this project, Claude should:

1. **Understand** the MacOS-specific architecture
2. **Respect** the differences between macOS, BSD, and Linux
3. **Test** changes on both architectures when possible
4. **Document** all changes clearly
5. **Maintain** backward compatibility
6. **Follow** MacOS best practices
7. **Use** provided tools and scripts
8. **Keep** the TODO file updated
9. **Ensure** security and permissions are correct
10. **Deliver** production-ready code

---

**Project Type**: DPI Circumvention Tool
**Primary Platform**: macOS (Darwin)
**Secondary Platform**: Linux
**Architectures**: x86_64, ARM64, Universal
**Status**: Production Ready ✅
**Last Updated**: 2025-12-10

**Remember**: macOS is a unique hybrid system - treat it with the respect it deserves!
