#
# iOS SSL Pinning Bypass - Theos Makefile
#
# 使用方式:
#   1. 确保已安装 Theos (https://theos.dev)
#   2. 设置环境变量 $THEOS (例如 export THEOS=/opt/theos)
#   3. 执行: make package
#   4. 产物: ./packages/*.deb
#
# 手动编译 dylib (无需 Theos):
#   1. 使用 Xcode 的 clang
#   2. 见 standalone.mk
#

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SSLBypass

# 源文件
SSLBypass_FILES = Tweak.xm SSLBypass.mm

# 链接框架
SSLBypass_FRAMEWORKS = Foundation Security CFNetwork

# 私有框架（可选，用于更底层 Hook）
SSLBypass_PRIVATE_FRAMEWORKS = 

# 链接库
SSLBypass_LIBRARIES = substrate

# 编译架构 (arm64 为 iOS 现代设备)
SSLBypass_ARCHS = arm64 arm64e

# 最低 iOS 版本
SSLBypass_TARGET = iphone:14.0:14.0

# 编译标志
SSLBypass_CFLAGS = -fobjc-arc -O2
SSLBypass_LDFLAGS = -lsubstrate -F$(THEOS)/vendor/lib

# 优化级别
GOFLAGS = -O2

include $(THEOS_MAKE_PATH)/tweak.mk

# 打包后自动安装到已连接的越狱设备
after-install::
	install.exec "killall -9 王者营地" || true
	install.exec "killall -9 SpringBoard" || true
