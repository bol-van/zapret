DIRS := nfq tpws ip2net mdig
TGT := binaries/my

all:	clean
	mkdir -p "$(@D)/$(TGT)"; \
	for dir in $(DIRS); do \
		chmod -x "$(@D)/$$dir/"*; \
		$(MAKE) -C "$(@D)/$$dir" || exit; \
	done ; \
	for exe in $$(find ${DIRS} -type f -executable); do \
		mv -f "$(@D)/$$exe" "$(@D)/${TGT}" ; \
		ln -fs "../${TGT}/$$(basename "$$exe")" "$$exe" ; \
	done

clean:
	for dir in $(DIRS); do \
		$(MAKE) -C "$(@D)/$$dir" clean; \
	done
