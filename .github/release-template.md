# iOS SSL Pinning Bypass Dylib

## 📦 下载

| 文件 | 架构 | 说明 |
|------|------|------|
| `SSLBypass.dylib` | arm64 | iPhone 5s - X (A7-A11) |
| `SSLBypass-arm64e.dylib` | arm64e | iPhone XS 及以上 (A12+) |
| `SSLBypass-universal.dylib` | arm64 + arm64e | 通用胖二进制 |

## 🔧 使用方法

```bash
# 1. 解压王者营地 IPA
unzip 王者营地.ipa -d Payload

# 2. 注入 dylib
cp SSLBypass.dylib Payload/王者营地.app/
insert_dylib --all-yes @executable_path/SSLBypass.dylib \
    Payload/王者营地.app/王者营地 \
    Payload/王者营地.app/王者营地_patched

# 3. 重签名并安装
```

## 🔒 功能

- Hook `SecTrustEvaluate` / `SecTrustEvaluateAsync` 绕过证书验证
- Hook `NSURLSession` delegate 处理认证挑战
- 兼容王者营地 `kohcamp.qq.com` 接口
- iOS 14.0+ 全版本兼容

> ⚠️ 仅供学习研究使用
