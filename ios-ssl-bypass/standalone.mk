#
# standalone.mk - 无需 Theos 的手动 dylib 编译
#
# 使用方式 (在 macOS 上):
#   make -f standalone.mk
#
# 产物: ./SSLBypass.dylib
#
# 注入方式:
#   optool install -c load -p @executable_path/SSLBypass.dylib -t Payload/王者营地.app/王者营地
#   或使用 insert_dylib:
#   insert_dylib @executable_path/SSLBypass.dylib Payload/王者营地.app/王者营地
#

# Xcode 工具链
CC = xcrun -sdk iphoneos clang++
CODESIGN = ldid

# 目标架构
ARCHS = arm64
MIN_IOS = 14.0

# 编译标志
CFLAGS = -arch $(ARCHS) \
         -miphoneos-version-min=$(MIN_IOS) \
         -isysroot $(shell xcrun -sdk iphoneos --show-sdk-path) \
         -fobjc-arc \
         -O2 \
         -Wall \
         -Wextra \
         -undefined dynamic_lookup

LDFLAGS = -arch $(ARCHS) \
          -miphoneos-version-min=$(MIN_IOS) \
          -isysroot $(shell xcrun -sdk iphoneos --show-sdk-path) \
          -dynamiclib \
          -install_name @executable_path/SSLBypass.dylib \
          -Xlinker -dead_strip \
          -framework Foundation \
          -framework Security \
          -framework CFNetwork

# 源文件
SOURCES = SSLBypass.mm
OBJECTS = $(SOURCES:.mm=.o)

# 输出
OUTPUT = SSLBypass.dylib

.PHONY: all clean sign

all: $(OUTPUT)

# 编译为 dylib
$(OUTPUT): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "========================================="
	@echo "✅ 编译成功: $@"
	@echo "📦 文件大小: $$(du -h $@ | cut -f1)"
	@echo "========================================="

# 编译目标文件
%.o: %.mm
	$(CC) $(CFLAGS) -c $< -o $@

# 签名 (需要有效的 iOS 开发证书或 ldid)
sign: $(OUTPUT)
	@echo "🔑 签名中..."
	-codesign -f -s "iPhone Developer" $(OUTPUT) 2>/dev/null || \
	ldid -S $(OUTPUT)
	@echo "✅ 签名完成"

# 注入到 IPA
inject: $(OUTPUT)
	@echo "📦 注入到王者营地..."
	@echo "请先解压 IPA: unzip 王者营地.ipa -d Payload"
	cp $(OUTPUT) Payload/王者营地.app/
	optool install -c load -p "@executable_path/SSLBypass.dylib" \
		-t Payload/王者营地.app/王者营地 2>/dev/null || \
	insert_dylib --all-yes "@executable_path/SSLBypass.dylib" \
		Payload/王者营地.app/王者营地 Payload/王者营地.app/王者营地_patched
	@echo "✅ 注入完成"
	@echo "重新打包: cd Payload && zip -r ../王者营地_patched.ipa Payload/王者营地.app"

# 清理
clean:
	rm -f $(OBJECTS) $(OUTPUT)
	@echo "🧹 清理完成"

# 查看符号
nm-check: $(OUTPUT)
	nm -g $(OUTPUT) | grep -i "hook\|SecTrust\|bypass"
