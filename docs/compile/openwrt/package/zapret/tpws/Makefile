#

include $(TOPDIR)/rules.mk

PKG_NAME:=tpws
PKG_RELEASE:=1.1

include $(INCLUDE_DIR)/package.mk

define Package/tpws
	SECTION:=net
	CATEGORY:=Network
	TITLE:=tpws
	SUBMENU:=Zapret
 	DEPENDS:=+zlib +libcap +zlib +libcap +iptables

endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./tpws/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/tpws/conffiles
/etc/config/zapret
endef

define Package/tpws/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/zapret.conf $(1)/etc/config/zapret
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/zapret.init $(1)/etc/init.d/zapret
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/zapret.hotplug $(1)/etc/hotplug.d/iface/90-zapret
	$(INSTALL_DIR) $(1)/opt/zapret/tpws
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tpws $(1)/opt/zapret/tpws
endef

$(eval $(call BuildPackage,tpws))

