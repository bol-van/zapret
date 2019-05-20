#

include $(TOPDIR)/rules.mk

PKG_NAME:=nfqws
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/nfqws
	SECTION:=net
	CATEGORY:=Network
	TITLE:=nfqws
	SUBMENU:=Zapret
 	DEPENDS:=+libnetfilter-queue +libcap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./nfq/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/nfqws/install
	$(INSTALL_DIR) $(1)/opt/zapret/nfq
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nfqws $(1)/opt/zapret/nfq
endef

$(eval $(call BuildPackage,nfqws))


