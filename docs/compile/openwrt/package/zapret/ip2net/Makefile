#

include $(TOPDIR)/rules.mk

PKG_NAME:=ip2net
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ip2net
	SECTION:=net
	CATEGORY:=Network
	TITLE:=ip2net
	SUBMENU:=Zapret
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./ip2net/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/ip2net/install
	$(INSTALL_DIR) $(1)/opt/zapret/ip2net
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ip2net $(1)/opt/zapret/ip2net
endef

$(eval $(call BuildPackage,ip2net))

