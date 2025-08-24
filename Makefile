DIRS := nfq tpws ip2net mdig
DIRS_MAC := tpws ip2net mdig
TGT := binaries/my

# MacOS target detection
MACOS_TARGET ?= $(shell uname -m | sed 's/x86_64/x86_64-apple-macos10.8/;s/arm64/arm64-apple-macos10.8/')

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
	for dir in $(DIRS_MAC); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		MACOS_TARGET="$(MACOS_TARGET)" $(MAKE) -C "$$dir" mac || exit; \
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
	for dir in $(DIRS_MAC); do \
		find "$$dir" -type f  \( -name "*.c" -o -name "*.h" -o -name "*akefile" \) -exec chmod -x {} \; ; \
		$(MAKE) -C "$$dir" mac-universal || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

clean:
	@[ -d "$(TGT)" ] && rm -rf "$(TGT)" ; \
	for dir in $(DIRS); do \
		$(MAKE) -C "$$dir" clean; \
	done
