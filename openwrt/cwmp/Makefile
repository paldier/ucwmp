include $(TOPDIR)/rules.mk

PKG_NAME:=cwmp
PKG_VERSION:=2014-05-28
PKG_RELEASE=1

CMAKE_INSTALL:=1

PKG_FILE_DEPENDS:=$(CURDIR)/../..

PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=Felix Fietkau <nbd@openwrt.org>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/ucwmp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Tiny CWMP (TR-069) client
  ABI_VERSION:=$(PKG_VERSION)
  DEPENDS:=+libubox +uhttpd +libroxml +libuci +libuclient +uclient-fetch \
	+libustream-mbedtls +ca-certificates \
	+UCWMP_BACKEND_SCAL:scal-plugin-json \
	+UCWMP_BACKEND_USP:uspd
endef

define Package/ucwmp/config
config UCWMP_BACKEND_SCAL
	bool "Use scald as backend"
	default n

config UCWMP_BACKEND_USP
	bool "Use uspd as backend"
	default y
endef

ifeq ($(CONFIG_UCWMP_BACKEND_SCAL),y)
	CMAKE_OPTIONS += -DBACKEND=scal
else
	CMAKE_OPTIONS += -DBACKEND=usp
endif

define Package/ucwmp/conffiles
/etc/config/cwmp
/etc/cwmp-cache.json
/etc/cwmp-startup.json
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	ln -s $(CURDIR)/../../.git $(PKG_BUILD_DIR)/
	(cd $(PKG_BUILD_DIR); git checkout .)
endef

define Package/ucwmp/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/libexec
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/* $(1)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/libexec/* $(1)/usr/libexec/
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,ucwmp))
