#

include $(TOPDIR)/rules.mk

PKG_NAME:=mdig
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/mdig
	SECTION:=net
	CATEGORY:=Network
	TITLE:=mdig
	SUBMENU:=Zapret
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./mdig/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/mdig/install
	$(INSTALL_DIR) $(1)/opt/zapret/binaries/my
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mdig $(1)/opt/zapret/binaries/my
endef

$(eval $(call BuildPackage,mdig))

