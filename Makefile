DIRS := nfq tpws ip2net mdig
TGT := binaries/my

all:	clean
	mkdir -p "$(TGT)"; \
	for dir in $(DIRS); do \
		chmod -x "$$dir/"*; \
		$(MAKE) -C "$$dir" || exit; \
		for exe in "$$dir/"*; do \
			if [ -f "$$exe" ] && [ -x "$$exe" ]; then \
				mv -f "$$exe" "${TGT}" ; \
				ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
			fi \
		done \
	done

clean:
	[ -d "$(TGT)" ] && rm -r "$(TGT)" ; \
	for dir in $(DIRS); do \
		$(MAKE) -C "$$dir" clean; \
	done
