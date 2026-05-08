# wzydssl-bypass - iOS SSL Pinning Bypass Dylib

[![Build & Release](https://github.com/cduang/wzydssl-bypass/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/cduang/wzydssl-bypass/actions/workflows/build-and-release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#)
[![Platform](https://img.shields.io/badge/platform-iOS%2014.0+-brightgreen)](#)
[![Arch](https://img.shields.io/badge/arch-arm64%20%7C%20arm64e-blue)](#)
[![Release](https://img.shields.io/github/v/release/cduang/wzydssl-bypass)](https://github.com/cduang/wzydssl-bypass/releases)

> 通用 iOS SSL Pinning 绕过动态库，专为 iOS 抓包调试设计  
> 灵感来源于 [王者营地 Android Frida SSL Pinning Bypass](https://kohcamp.qq.com/honor/ranklist) 实战

## 📋 概述

本项目提供了一个 iOS **动态库 (dylib)**，注入后可绕过 iOS App 的 SSL Pinning（证书锁定）检测，配合抓包工具（如 Fiddler、Charles、Burp Suite）即可解密 HTTPS 流量。

**核心原理**：通过 fishhook 在 C 函数级别挂钩 [`Security.framework`](https://developer.apple.com/documentation/security) 的 [`SecTrustEvaluate`](https://developer.apple.com/documentation/security/1395768-sectrustevaluate) / [`SecTrustEvaluateAsync`](https://developer.apple.com/documentation/security/1395531-sectrustevaluateasync)，使所有证书验证自动返回通过。

### 与 Android Frida 方案的对比

| 环节 | Android (Frida) | iOS (本 dylib) |
|------|----------------|----------------|
| 运行时 | Frida 动态插桩 | dylib 注入 + Method Swizzling |
| Hook 目标 | `TrustManagerImpl.checkTrustedRecursive` | `SecTrustEvaluate` / `SecTrustEvaluateAsync` |
| 网络库 | OkHttp 4.9.1 | `NSURLSession` / `CFNetwork` |
| 优势 | 无需修改 App | 更底层，覆盖所有网络框架 |
| 劣势 | 需 Root + Frida 环境 | 需越狱或砸壳后注入 |

## 🏗 项目结构

```
ios-ssl-bypass/
├── Tweak.xm          # Logos 语法的越狱插件（Theos 项目主文件）
├── SSLBypass.mm      # 核心 hook 实现（fishhook + Objective-C）
├── Makefile          # Theos 编译配置
├── standalone.mk     # 手动编译（无需 Theos）
├── control           # Deb 包控制文件
├── README.md         # 本文件
└── inject.sh         # 注入脚本
```

## 🤖 CI/CD (GitHub Actions)

项目配置了自动化的 GitHub Actions 工作流，位于 [`.github/workflows/build-and-release.yml`](.github/workflows/build-and-release.yml)。

### 触发方式

| 事件 | 行为 |
|------|------|
| `git push` (main/master) | 自动编译 arm64 + arm64e，上传为 Artifact |
| `git tag v1.0.0 && git push origin v1.0.0` | 编译 + 创建 GitHub Release，上传 dylib |
| GitHub UI → Actions → 手动运行 | 可选择编译类型和架构 |

### Release 产物

推送 tag 后自动生成的 Release 包含：

| 文件 | 说明 |
|------|------|
| `SSLBypass.dylib` | arm64 单架构 (iPhone 5s - X) |
| `SSLBypass-arm64e.dylib` | arm64e 单架构 (iPhone XS+) |
| `SSLBypass-universal.dylib` | 通用胖二进制 (arm64 + arm64e) |
| `checksums.txt` | SHA256 校验和 |

### 使用方式

```bash
# 1. 推送 tag 即可自动触发 Release
git tag v1.0.0
git push origin v1.0.0

# 2. 在 GitHub Releases 页面下载编译好的 dylib
# 3. 下载后先验证校验和
sha256sum SSLBypass.dylib
```

> ⚠️ **注意**：Workflow 需要在 GitHub repo 中配置。本仓库 `cduang/wzydssl-bypass` 已配置完成，推送 tag 即可自动触发 Release。

## 🔧 编译方法

### 方法一：使用 Theos（推荐，用于越狱设备）

1. **安装 Theos**（如果尚未安装）：
   ```bash
   # macOS
   sudo mkdir -p /opt/theos
   sudo chown $(whoami) /opt/theos
   git clone --recursive https://github.com/theos/theos.git /opt/theos
   
   # 下载 iOS SDK（可选，可用 Xcode 内置）
   curl -L https://github.com/theos/sdks/archive/master.zip -o sdks.zip
   unzip sdks.zip -d /opt/theos/sdks
   ```

2. **编译**：
   ```bash
   cd ios-ssl-bypass
   export THEOS=/opt/theos
   make package
   ```

3. **产物**：生成的 `.deb` 包位于 `packages/` 目录，可通过 Cydia/Sileo 安装。

### 方法二：手动编译（用于非越狱 IPA 注入）

```bash
# macOS 上执行
make -f standalone.mk
```

产物 `SSLBypass.dylib` 可直接注入到 IPA 中使用。

## 💉 注入方式

### 方式一：越狱设备（Tweak 模式）

通过 Cydia/Sileo 安装 `com.sslbypass.ios` deb 包，自动注入所有进程。  
可在 `/Library/MobileSubstrate/DynamicLibraries/` 配置仅对王者营地生效：

```bash
# 编辑 plist 过滤
cat > /Library/MobileSubstrate/DynamicLibraries/SSLBypass.plist << EOF
{
    Filter = {
        Bundles = (
            "com.tencent.hlwzs"  # 王者营地 Bundle ID
        );
    };
}
EOF
```

### 方式二：非越狱设备（IPA 注入）

1. **获取王者营地 IPA**：
   ```bash
   # 方法 A: 从已越狱设备提取
   # 方法 B: 从 App Store 下载后使用 bagbak/frida-ios-dump 砸壳
   frida-ios-dump com.tencent.hlwzs
   ```

2. **注入 dylib**：
   ```bash
   # 解压 IPA
   unzip 王者营地.ipa -d Payload
   
   # 复制 dylib 到 App 目录
   cp SSLBypass.dylib Payload/王者营地.app/
   
   # 方式 A: 使用 optool
   optool install -c load -p @executable_path/SSLBypass.dylib \
       -t Payload/王者营地.app/王者营地
   
   # 方式 B: 使用 insert_dylib
   insert_dylib --all-yes @executable_path/SSLBypass.dylib \
       Payload/王者营地.app/王者营地 \
       Payload/王者营地.app/王者营地_patched
   mv Payload/王者营地.app/王者营地_patched Payload/王者营地.app/王者营地
   
   # 重新签名并打包
   cd Payload && zip -r ../王者营地_patched.ipa Payload/王者营地.app
   ```

3. **安装到设备**（使用 AltStore / SideStore / TrollStore 等）。

## 🚀 使用流程（配合抓包）

### iOS 端配置

1. **安装根证书**：
   - 将 Fiddler/Charles 的根证书导出并发送到 iPhone
   - 设置 → 通用 → VPN 与设备管理 → 安装证书
   - 设置 → 通用 → 关于本机 → 证书信任设置 → 启用信任

2. **设置 HTTP 代理**：
   - 设置 → 无线局域网 → 当前 WiFi → HTTP 代理
   - 填写电脑 IP 和代理端口（Fiddler: 8888, Charles: 8888）

3. **启动 App**：
   - 打开已注入 dylib 的王者营地
   - 导航到「工具箱」→「荣耀榜」
   - 选择英雄和地区

### 电脑端抓包

**Fiddler 配置**：
```
Tools → Options → HTTPS
  ✓ Capture HTTPS CONNECTs
  ✓ Decrypt HTTPS traffic
  ✓ ...from remote clients only (推荐)
```

**Charles 配置**：
```
Proxy → SSL Proxying Settings
  ✓ Enable SSL Proxying
  Add: kohcamp.qq.com (端口 443)
```

### 预期抓取到的接口

| 接口 | 说明 |
|------|------|
| `POST https://kohcamp.qq.com/honor/ranklist` | 英雄战力榜单 |
| `POST https://kohcamp.qq.com/honor/herolist` | 英雄列表 |

**请求示例**：
```http
POST https://kohcamp.qq.com/honor/ranklist HTTP/1.1
Host: kohcamp.qq.com
token: eyJhbGciOiJIUzI1NiIs...
userId: 123456789
openid: oABC123...
appid: 1104466820
version: 8.94.0417
Content-Type: application/json

{
    "adcode": "310000",
    "roleId": "116581781",
    "areaId": "3",
    "heroId": "146",
    "recommendPrivacy": 0
}
```

## 🔬 技术原理详解

### Hook 层级

```
应用层 (王者营地 App)
    ↓ 使用 NSURLSession / CFNetwork
传输层 (Security.framework)
    ↓ 通过 SecTrustEvaluate 验证
内核层 (Security.framework 内部实现)
```

本 dylib 在 **传输层** 进行 Hook，覆盖所有使用 iOS Security.framework 的网络请求：

1. **`SecTrustEvaluate`** → 同步证书验证，强制返回 `kSecTrustResultProceed`
2. **`SecTrustEvaluateAsync`** → 异步证书验证，通过 dispatch_async 回调成功
3. **`SecTrustCreateWithCertificates`** → 证书链创建，透传但允许所有证书
4. **`NSURLSession:didReceiveChallenge:`** → HTTP 认证挑战处理，自动签发信任凭证

### 与文章中的 Frida 方案对比

| 项目 | Android Frida | iOS dylib |
|------|--------------|-----------|
| Hook 技术 | Frida JS 动态插桩 | fishhook + Method Swizzling |
| 核心 Hook | `TrustManagerImpl.checkTrustedRecursive()` | `SecTrustEvaluate()` |
| 辅助 Hook | `CertificatePinner.check()` | `NSURLSession` delegate |
| 网络层 | OkHttp / Java SSLSocket | NSURLSession / CFNetwork |
| 绕过强度 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ (更底层) |

### fishhook 工作原理

fishhook 通过修改 Mach-O 二进制文件的 **懒加载符号表** (`__la_symbol_ptr`) 和 **非懒加载符号表** (`__nl_symbol_ptr`)，将 Security.framework 的函数指针重定向到我们的 Hook 函数。

```
原始: pointers[SecTrustEvaluate] → Security.framework 的真实 SecTrustEvaluate
修改后: pointers[SecTrustEvaluate] → 我们的 hook_SecTrustEvaluate
                                   └→ 可选择性调用原始的 orig_SecTrustEvaluate
```

## ⚠️ 注意事项

### 兼容性
- **iOS 版本**: 13.0 - 17.x 全版本兼容
- **设备**: arm64 (iPhone 5s 及以上) / arm64e (iPhone XS 及以上)
- **目标 App**: 理论上通杀所有使用 NSURLSession/CFNetwork 的 App

### 排查指南

| 现象 | 可能原因 | 解决方案 |
|------|---------|---------|
| 仍然抓不到 HTTPS 包 | 证书未信任 | 检查 iOS 证书信任设置 |
| App 闪退 | 签名问题 | 重新签名 IPA |
| dylib 未加载 | 注入失败 | 检查 `insert_dylib` 是否成功 |
| 部分接口能抓到 | 该接口未使用 SSL Pinning | 正常现象 |
| 王者营地白屏/闪退 | 版本不兼容 | 尝试其他版本或等待更新 |

### 法律声明
- 本工具仅用于 **学习研究** 和 **安全测试**
- 请勿用于商业用途或恶意攻击
- 抓取到的用户凭证请勿泄露
- 遵守相关法律法规

## 📚 参考

- [王者营地英雄战力数据抓包实战](https://kohcamp.qq.com/honor/ranklist) - Android Frida 方案
- [fishhook](https://github.com/facebook/fishhook) - Facebook 的 Mach-O 符号重建库
- [Theos](https://theos.dev) - iOS 越狱开发工具链
- [optool](https://github.com/alexzielenski/optool) - Mach-O 二进制编辑工具

## 📄 许可

仅供学习研究使用。
