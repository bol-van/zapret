# Quick Start Guide for MacOS

## 🚀 Get Started in 3 Steps

### 1. **Clone and Navigate**
```bash
git clone <repository-url>
cd zapret
```

### 2. **Test Your System**
```bash
# Test architecture detection
./scripts/test_macos_arch.sh

# Test architecture management
./scripts/macos_arch_detect.sh detect
```

### 3. **Build and Install**
```bash
# Build for your architecture (automatic detection)
make mac

# Or build universal binary for both architectures
make mac-universal

# Install
./install_easy.sh
```

## 🔍 What Happens Automatically

- **Architecture Detection**: Scripts detect Intel vs Apple Silicon
- **Target Setting**: Correct compilation targets are set
- **Binary Selection**: Appropriate binaries are installed
- **Configuration**: System is configured for your MacOS version

## 🛠️ Manual Override (Optional)

If you want to build for a specific architecture:

```bash
# For Intel Macs
export MACOS_TARGET="x86_64-apple-macos10.8"
make mac

# For Apple Silicon
export MACOS_TARGET="arm64-apple-macos10.8"
make mac
```

## 📱 Supported MacOS Versions

- **Minimum**: macOS 10.8 (Mountain Lion)
- **Recommended**: macOS 11+ (Big Sur)
- **Latest**: macOS 14+ (Sonoma)

## 🧪 Testing Your Installation

```bash
# Check if binaries are working
./binaries/my/tpws --version
./binaries/my/ip2net --help

# Test the service
sudo /opt/zapret/init.d/macos/zapret start
sudo /opt/zapret/init.d/macos/zapret status
```

## 🆘 Troubleshooting

### Common Issues

1. **"Command not found: make"**
   ```bash
   xcode-select --install
   ```

2. **"Permission denied"**
   ```bash
   chmod +x scripts/*.sh
   ```

3. **"Architecture mismatch"**
   ```bash
   make clean
   make mac
   ```

### Get Help

- **Documentation**: `docs/MACOS_REFACTORING.md`
- **Test Script**: `./scripts/test_macos_arch.sh`
- **Architecture Script**: `./scripts/macos_arch_detect.sh help`

## 🎯 What You Get

- ✅ **Automatic Detection** - No manual configuration
- ✅ **Cross-Architecture** - Works on Intel and Apple Silicon
- ✅ **Universal Support** - Single binary for both architectures
- ✅ **Performance Optimized** - Native for your architecture
- ✅ **Easy Installation** - One-command setup

## 🔄 Next Steps

After successful installation:

1. **Configure**: Edit `/opt/zapret/config`
2. **Start Service**: `sudo /opt/zapret/init.d/macos/zapret start`
3. **Test**: Verify traffic is being processed
4. **Customize**: Add custom rules as needed

---

**Need More Details?** See `docs/MACOS_REFACTORING.md` for comprehensive information.