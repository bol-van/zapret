# Copyright Zapret
# This is free software, licensed under the GNU General Public License v2.

include $(TOPDIR)/rules.mk

PKG_NAME:=tpws
PKG_VERSION:=1.4
PKG_RELEASE:=3

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Zapret

include $(INCLUDE_DIR)/package.mk

define Package/tpws
	SECTION:=net
	CATEGORY:=Network
	TITLE:=TPWS DPI bypass proxy server
	SUBMENU:=Zapret
 	DEPENDS:=+zlib +libcap +libcap
endef

define Package/tpws/description
DPI bypass proxy
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
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tpws $(1)/usr/bin
endef

$(eval $(call BuildPackage,tpws))
