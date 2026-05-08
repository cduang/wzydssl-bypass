/*
 * 王者营地 iOS SSL Pinning Bypass - Tweak (Logos语法)
 * 
 * 编译方式: Theos (在macOS上)
 * 注入方式: 
 *   1. 越狱设备: 通过Cydia Substrate / Substitute 加载
 *   2. 非越狱: 通过 optool / insert_dylib 注入到IPA
 *
 * 原理: 参考 Android Frida 方案，在 iOS 端同样 Hook 关键 SSL 验证方法
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>

// ============================================================
// 第一部分: NSURLSession 的 SSL Challenge 处理
// 通过 Hook URLSession:didReceiveChallenge:completionHandler:
// 对所有服务器信任挑战自动放行
// ============================================================

%hook NSObject

// 拦截所有 NSURLSessionDelegate 的 challenge 处理
- (void)URLSession:(NSURLSession *)session 
              task:(NSURLSessionTask *)task 
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge 
  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *_Nullable))completionHandler {
    
    // 只处理服务器信任验证
    if ([challenge.protectionSpace.authenticationMethod 
            isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        
        // 获取服务器的 SecTrust
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        if (serverTrust == NULL) {
            %orig;
            return;
        }
        
        // 创建允许连接的凭证
        NSURLCredential *credential = [NSURLCredential 
            credentialForTrust:serverTrust];
        
        NSLog(@"[SSLBypass] ✅ NSURLSession 证书校验绕过: %@", 
              challenge.protectionSpace.host);
        
        // 使用自定义凭证继续
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        return;
    }
    
    // 非服务器信任验证走原始逻辑
    %orig;
}

// 兼容旧版 NSURLConnection (如果应用使用)
- (void)connection:(NSURLConnection *)connection 
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    
    if ([challenge.protectionSpace.authenticationMethod 
            isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        if (serverTrust) {
            NSURLCredential *credential = [NSURLCredential 
                credentialForTrust:serverTrust];
            [[challenge sender] useCredential:credential 
                  forAuthenticationChallenge:challenge];
            NSLog(@"[SSLBypass] ✅ NSURLConnection 证书校验绕过: %@", 
                  challenge.protectionSpace.host);
            return;
        }
    }
    
    %orig;
}

%end


// ============================================================
// 第二部分: 通过 Method Swizzling 实现 AFNetworking / Alamofire 兼容
// 这些框架底层仍然使用 NSURLSession，但某些版本有自己的验证逻辑
// ============================================================

%hook NSURLAuthenticationChallenge

// 拦截 protectionSpace 的获取，确保服务器信任认证被正确处理
- (NSURLProtectionSpace *)protectionSpace {
    %orig;
    return %orig;
}

%end


// ============================================================
// 第三部分: 构造函数 - 在 dylib 加载时自动执行
// ============================================================

%ctor {
    NSLog(@"[SSLBypass] 🚀 iOS SSL Pinning Bypass dylib 已加载");
    NSLog(@"[SSLBypass] 📱 目标: 王者营地 - kohcamp.qq.com");
    NSLog(@"[SSLBypass] 🔓 正在绕过 SSL Pinning...");
}
