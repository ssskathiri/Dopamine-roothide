TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = lsd cfprefsd
FINALPACKAGE = 1
ARCHS = arm64e

THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = roothidehooks

roothidehooks_FILES = $(wildcard *.x) $(wildcard *.c) $(wildcard *.m)
roothidehooks_CFLAGS = -Werror -fobjc-arc
roothidehooks_LDFLAGS = -rpath @loader_path/.jbroot/Library/Frameworks -rpath @loader_path/fallback

lsd.x_CFLAGS = -fno-objc-arc #lsd using mrc

include $(THEOS_MAKE_PATH)/tweak.mk

after-roothidehooks-all::
	install_name_tool -change @loader_path/.jbroot/usr/lib/libsubstrate.dylib @rpath/CydiaSubstrate.framework/CydiaSubstrate $(THEOS_OBJ_DIR)/roothidehooks.dylib
	ldid -S $(THEOS_OBJ_DIR)/roothidehooks.dylib
