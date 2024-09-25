# Copyright 2024
# This is free software, licensed under the GNU General Public License v2.

include $(TOPDIR)/rules.mk

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Zapret
PKG_VERSION:=0.1.7

LUCI_TITLE:=Zapret TPWS Web UI
LUCI_DESCRIPTION:=Provides Web UI for Zapret tpws transparent proxy
LUCI_DEPENDS:=+luci-compat +luci-mod-admin-full +tpws
LUCI_PKGARCH:=all

include ../../../feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
