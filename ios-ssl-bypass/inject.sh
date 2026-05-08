#!/bin/bash
#
# inject.sh - iOS SSL Pinning Bypass dylib 自动注入脚本
#
# 使用方法:
#   chmod +x inject.sh
#   ./inject.sh 王者营地.ipa
#
# 依赖: optool 或 insert_dylib, ldid 或 codesign
#

set -e

DYLIB_NAME="SSLBypass.dylib"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DYLIB_PATH="${SCRIPT_DIR}/${DYLIB_NAME}"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  iOS SSL Pinning Bypass - IPA 注入工具${NC}"
echo -e "${BLUE}============================================${NC}"

# 检查参数
if [ $# -lt 1 ]; then
    echo -e "${RED}❌ 用法: $0 <王者营地.ipa>${NC}"
    echo -e "   $0 王者营地.ipa"
    exit 1
fi

IPA_PATH="$1"

if [ ! -f "${IPA_PATH}" ]; then
    echo -e "${RED}❌ 文件不存在: ${IPA_PATH}${NC}"
    exit 1
fi

if [ ! -f "${DYLIB_PATH}" ]; then
    echo -e "${YELLOW}⚠️  dylib 不存在，请先编译: make -f standalone.mk${NC}"
    exit 1
fi

echo -e "${GREEN}[1/5]${NC} 解压 IPA..."
TMP_DIR=$(mktemp -d)
unzip -q "${IPA_PATH}" -d "${TMP_DIR}/Payload"
PAYLOAD_DIR="${TMP_DIR}/Payload"

# 查找 .app 目录
APP_DIR=$(find "${PAYLOAD_DIR}" -name "*.app" -type d | head -1)
if [ -z "${APP_DIR}" ]; then
    echo -e "${RED}❌ 未找到 .app 目录${NC}"
    rm -rf "${TMP_DIR}"
    exit 1
fi

APP_NAME=$(basename "${APP_DIR}")
EXECUTABLE=$(defaults read "${APP_DIR}/Info.plist" CFBundleExecutable 2>/dev/null || \
             plutil -p "${APP_DIR}/Info.plist" 2>/dev/null | grep CFBundleExecutable | awk -F'"' '{print $4}')

echo -e "${GREEN}[2/5]${NC} App: ${APP_NAME}"
echo -e "       可执行文件: ${EXECUTABLE}"

# 复制 dylib
echo -e "${GREEN}[3/5]${NC} 复制 dylib 到 App 目录..."
cp "${DYLIB_PATH}" "${APP_DIR}/"

# 注入 dylib
echo -e "${GREEN}[4/5]${NC} 注入 dylib 到可执行文件..."
BINARY_PATH="${APP_DIR}/${EXECUTABLE}"

# 尝试 optool
if command -v optool &> /dev/null; then
    echo -e "        使用 optool..."
    optool install -c load -p "@executable_path/${DYLIB_NAME}" -t "${BINARY_PATH}"
# 尝试 insert_dylib
elif command -v insert_dylib &> /dev/null; then
    echo -e "        使用 insert_dylib..."
    insert_dylib --all-yes "@executable_path/${DYLIB_NAME}" "${BINARY_PATH}" "${BINARY_PATH}_patched"
    mv "${BINARY_PATH}_patched" "${BINARY_PATH}"
else
    echo -e "${RED}❌ 未找到 optool 或 insert_dylib${NC}"
    echo -e "请安装: brew install optool"
    rm -rf "${TMP_DIR}"
    exit 1
fi

# 签名
echo -e "${GREEN}[5/5]${NC} 重新签名..."

# 尝试多种签名方式
if command -v codesign &> /dev/null; then
    # 移除旧签名
    rm -rf "${APP_DIR}/_CodeSignature"
    # 使用 ad-hoc 签名
    codesign -f -s - "${APP_DIR}/${DYLIB_NAME}" 2>/dev/null || true
    codesign -f -s - --entitlements "${APP_DIR}/embedded.mobileprovision" "${BINARY_PATH}" 2>/dev/null || \
    codesign -f -s - "${BINARY_PATH}" 2>/dev/null || true
    
    echo -e "        使用 codesign (ad-hoc)..."
elif command -v ldid &> /dev/null; then
    echo -e "        使用 ldid..."
    # 尝试获取 entitlements
    if [ -f "${APP_DIR}/embedded.mobileprovision" ]; then
        security cms -D -i "${APP_DIR}/embedded.mobileprovision" > /tmp/provision.plist 2>/dev/null
        /usr/libexec/PlistBuddy -x -c "Print :Entitlements" /tmp/provision.plist > "${APP_DIR}/entitlements.plist" 2>/dev/null
        ldid -S"${APP_DIR}/entitlements.plist" "${BINARY_PATH}" 2>/dev/null || \
        ldid -S "${BINARY_PATH}"
    else
        ldid -S "${BINARY_PATH}"
    fi
fi

# 打包
echo -e "${GREEN}📦${NC} 重新打包 IPA..."
OUTPUT_IPA="$(dirname "${IPA_PATH}")/$(basename "${IPA_PATH}" .ipa)_patched.ipa"
cd "${PAYLOAD_DIR}"
zip -qr "${OUTPUT_IPA}" .
cd - > /dev/null

# 清理
rm -rf "${TMP_DIR}"

echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✅ 注入完成!${NC}"
echo -e "📦 输出: ${OUTPUT_IPA}"
echo -e "💉 Dylib: ${DYLIB_NAME}"
echo -e ""
echo -e "📱 安装方式:"
echo -e "   1. AltStore / SideStore - 直接安装 IPA"
echo -e "   2. TrollStore - 直接安装 IPA"  
echo -e "   3. ideviceinstaller -i ${OUTPUT_IPA}"
echo -e ""
echo -e "🔓 启动后配合 Fiddler/Charles 即可抓包"
echo -e "${BLUE}============================================${NC}"
