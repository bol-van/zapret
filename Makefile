DIRS := nfq tpws ip2net mdig
DIRS_MAC := tpws ip2net mdig
TGT := binaries/my

# MacOS target detection with improved compatibility
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

# Detect MacOS version for better compatibility
MACOS_VERSION ?= $(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1,2 || echo "10.8")

# Check if we're on MacOS
IS_MACOS := $(shell [ "$(shell uname)" = "Darwin" ] && echo "1" || echo "0")

all:	clean
	@mkdir -p "$(TGT)"; \
	for dir in $(DIRS); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		$(MAKE) -C "$$dir" || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

systemd: clean
	@mkdir -p "$(TGT)"; \
	for dir in $(DIRS); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		$(MAKE) -C "$$dir" systemd || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

android: clean
	@mkdir -p "$(TGT)"; \
	for dir in $(DIRS); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		$(MAKE) -C "$$dir" android || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

bsd:	clean
	@mkdir -p "$(TGT)"; \
	for dir in $(DIRS); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		$(MAKE) -C "$$dir" bsd || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

mac:	clean
	@mkdir -p "$(TGT)"; \
	echo "Building for MacOS with target: $(MACOS_TARGET)"; \
	echo "MacOS version: $(MACOS_VERSION)"; \
	# Check if nfq is available (it's not supported on MacOS) \
	if [ "$(IS_MACOS)" = "1" ]; then \
		echo "Note: nfq component is not supported on MacOS (no NFQUEUE support)"; \
		echo "Building only: $(DIRS_MAC)"; \
	fi; \
	for dir in $(DIRS_MAC); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		MACOS_TARGET="$(MACOS_TARGET)" MACOS_VERSION="$(MACOS_VERSION)" $(MAKE) -C "$$dir" mac || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

# Universal binary build for MacOS (both architectures)
mac-universal: clean
	@mkdir -p "$(TGT)"; \
	echo "Building universal binary for MacOS (x86_64 + arm64)"; \
	echo "MacOS version: $(MACOS_VERSION)"; \
	# Check if nfq is available (it's not supported on MacOS) \
	if [ "$(IS_MACOS)" = "1" ]; then \
		echo "Note: nfq component is not supported on MacOS (no NFQUEUE support)"; \
		echo "Building only: $(DIRS_MAC)"; \
	fi; \
	for dir in $(DIRS_MAC); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		MACOS_TARGET="$(MACOS_TARGET)" MACOS_VERSION="$(MACOS_VERSION)" $(MAKE) -C "$$dir" mac-universal || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

# MacOS specific build with architecture detection
mac-auto: clean
	@mkdir -p "$(TGT)"; \
	echo "Auto-detecting MacOS architecture and building..."; \
	if [ "$(IS_MACOS)" = "1" ]; then \
		MACOS_TARGET="$(MACOS_TARGET)" MACOS_VERSION="$(MACOS_VERSION)" $(MAKE) mac; \
	else \
		echo "Error: This target is only available on MacOS"; \
		exit 1; \
	fi

clean:
	@[ -d "$(TGT)" ] && rm -rf "$(TGT)" ; \
	for dir in $(DIRS); do \
		$(MAKE) -C "$$dir" clean; \
	done

# MacOS specific clean
mac-clean:
	@[ -d "$(TGT)" ] && rm -rf "$(TGT)" ; \
	for dir in $(DIRS_MAC); do \
		$(MAKE) -C "$$dir" clean; \
	done

# Show MacOS build information
mac-info:
	@echo "MacOS Build Information:"; \
	echo "========================"; \
	echo "System: $(shell uname)"; \
	echo "Architecture: $(shell uname -m)"; \
	echo "MacOS Version: $(MACOS_VERSION)"; \
	echo "Target: $(MACOS_TARGET)"; \
	echo "Is MacOS: $(IS_MACOS)"; \
	echo "Supported components: $(DIRS_MAC)"; \
	echo "Unsupported components: nfq (no NFQUEUE support)"; \
	echo ""; \
	echo "Available targets:"; \
	echo "  make mac           - Build for current architecture"; \
	echo "  make mac-universal - Build universal binary (x86_64 + arm64)"; \
	echo "  make mac-auto      - Auto-detect and build"; \
	echo "  make mac-clean     - Clean MacOS builds only"; \
	echo "  make mac-info      - Show this information"
