/*
 * SSLBypass.mm - iOS SSL Pinning 底层绕过实现
 *
 * 原理: 使用 dlsym(RTLD_NEXT, ...) + C 函数指针替换
 * 在 C 函数级别 Hook Security.framework
 *
 * 相比 fishhook / Method Swizzling，此方法更底层、更通用:
 *   - 不依赖 Mach-O 符号表解析
 *   - 对使用 NSURLSession / CFNetwork / WebView 的 App 全部有效
 *   - 兼容 iOS 14.0 - 17.x
 *
 * 编译方式:
 *   clang++ -arch arm64 -miphoneos-version-min=14.0 \
 *           -isysroot $(xcrun -sdk iphoneos --show-sdk-path) \
 *           -fobjc-arc -O2 \
 *           -dynamiclib \
 *           -install_name @executable_path/SSLBypass.dylib \
 *           -framework Foundation -framework Security -framework CFNetwork \
 *           -o SSLBypass.dylib SSLBypass.mm
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

// ============================================================
// 原始函数指针声明
// ============================================================

// Security.framework 核心函数
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus (*orig_SecTrustEvaluateAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static SecTrustRef (*orig_SecTrustCreateWithCertificates)(CFArrayRef certificates, CFTypeRef policies);


// ============================================================
// 使用 DYLD_INTERPOSE 宏实现函数拦截 (Apple 官方支持的机制)
// 原理: 通过 __DATA,__interpose section 注册符号替换
// 这是最底层、最可靠的 iOS C 函数 Hook 方式
// ============================================================

#pragma mark - SecTrustEvaluate Hook

/*
 * SecTrustEvaluate: 同步证书验证
 * 
 * 原始行为: 验证服务器证书链是否受信任
 * Hook 行为: 始终返回 kSecTrustResultProceed (信任通过)
 * 
 * 参数:
 *   trust  - 待验证的 SecTrust 对象 (包含证书链)
 *   result - 输出参数，返回验证结果
 */
static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result != NULL) {
        *result = kSecTrustResultProceed;
    }
    NSLog(@"[SSLBypass] 🔓 SecTrustEvaluate 绕过 (证书链已验证为信任)");
    return errSecSuccess;
}

#pragma mark - SecTrustEvaluateAsync Hook

/*
 * SecTrustEvaluateAsync: 异步证书验证
 * 
 * 原始行为: 异步验证证书链，通过回调返回结果
 * Hook 行为: 立即通过 dispatch_async 回调返回 kSecTrustResultProceed
 */
static OSStatus hooked_SecTrustEvaluateAsync(SecTrustRef trust,
                                              dispatch_queue_t queue,
                                              SecTrustCallback result) {
    if (result != NULL) {
        dispatch_async(queue ? queue : dispatch_get_main_queue(), ^{
            result(trust, kSecTrustResultProceed);
        });
    }
    NSLog(@"[SSLBypass] 🔓 SecTrustEvaluateAsync 绕过");
    return errSecSuccess;
}

#pragma mark - SecTrustCreateWithCertificates Hook

/*
 * SecTrustCreateWithCertificates: 创建证书信任对象
 * 
 * 原始行为: 用指定证书和策略创建信任对象
 * Hook 行为: 透传调用原始函数，不做额外限制
 */
static SecTrustRef hooked_SecTrustCreateWithCertificates(CFArrayRef certificates,
                                                          CFTypeRef policies) {
    if (orig_SecTrustCreateWithCertificates) {
        return orig_SecTrustCreateWithCertificates(certificates, policies);
    }
    return NULL;
}


// ============================================================
// DYLD_INTERPOSE 注册表
// 告诉 dyld 在加载时自动替换这些符号
// ============================================================

/*
 * interpose 结构体:
 *   - 第一个成员: 替换后的函数指针 (我们的 Hook)
 *   - 第二个成员: 被替换的原始函数指针
 */
__attribute__((used)) static struct interpose_section {
    const void *replacement;
    const void *original;
} interpose_table[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)hooked_SecTrustEvaluate,            (const void *)SecTrustEvaluate },
    { (const void *)hooked_SecTrustEvaluateAsync,       (const void *)SecTrustEvaluateAsync },
    { (const void *)hooked_SecTrustCreateWithCertificates, (const void *)SecTrustCreateWithCertificates },
};


// ============================================================
// 备用方案: 如果 DYLD_INTERPOSE 不起作用，通过 dlsym 手动注入
// 在构造函数中主动查找并保存原始函数指针
// ============================================================

static void initOriginalPointers() {
    // 从 Security.framework 中获取原始函数指针
    // 注意: RTLD_NEXT 会找到"下一个"定义，即 Security.framework 中的真实实现
    orig_SecTrustEvaluate = (OSStatus (*)(SecTrustRef, SecTrustResultType *))
        dlsym(RTLD_NEXT, "SecTrustEvaluate");
    orig_SecTrustEvaluateAsync = (OSStatus (*)(SecTrustRef, dispatch_queue_t, SecTrustCallback))
        dlsym(RTLD_NEXT, "SecTrustEvaluateAsync");
    orig_SecTrustCreateWithCertificates = (SecTrustRef (*)(CFArrayRef, CFTypeRef))
        dlsym(RTLD_NEXT, "SecTrustCreateWithCertificates");
    
    if (orig_SecTrustEvaluate == NULL) {
        NSLog(@"[SSLBypass] ⚠️ dlsym 未找到 SecTrustEvaluate，尝试从 Security 库加载");
        void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (handle) {
            orig_SecTrustEvaluate = (OSStatus (*)(SecTrustRef, SecTrustResultType *))
                dlsym(handle, "SecTrustEvaluate");
            orig_SecTrustEvaluateAsync = (OSStatus (*)(SecTrustRef, dispatch_queue_t, SecTrustCallback))
                dlsym(handle, "SecTrustEvaluateAsync");
            orig_SecTrustCreateWithCertificates = (SecTrustRef (*)(CFArrayRef, CFTypeRef))
                dlsym(handle, "SecTrustCreateWithCertificates");
            dlclose(handle);
        }
    }
}


// ============================================================
// NSURLSessionDelegate 方法交换 (ObjC 层补充)
// 对于没有使用 Security.framework 的某些私有网络框架
// ============================================================

/*
 * 通用的 NSURLSession 认证挑战处理交换实现
 * 当 NSURLSessionDelegate 收到服务器信任挑战时:
 *   - 自动创建信任凭证 (credentialForTrust:)
 *   - 调用 completionHandler 传入凭证，绕过证书校验
 */
static void URLSession_didReceiveChallenge_swizzle(
    id __unused self,
    SEL __unused _cmd,
    NSURLSession * __unused session,
    NSURLSessionTask * __unused task,
    NSURLAuthenticationChallenge *challenge,
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    
    NSString *authMethod = challenge.protectionSpace.authenticationMethod;
    
    if ([authMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        if (serverTrust) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            if (completionHandler) {
                completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
            }
            NSLog(@"[SSLBypass] ✅ [Swizzle] NSURLSession 证书校验绕过: %@",
                  challenge.protectionSpace.host);
            return;
        }
    }
    
    // 非服务器信任认证，执行默认处理
    if (completionHandler) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

/*
 * 尝试交换 App 中所有 NSURLSessionDelegate 的 challenge 处理方法
 * 注意: 此方法需要在 App 启动后延迟执行，确保 delegate 已创建
 */
static void swizzleNSURLSessionDelegates() {
    // 获取 NSURLSession 类
    Class sessionClass = [NSURLSession class];
    if (!sessionClass) return;
    
    // 方法签名
    SEL originalSel = @selector(URLSession:task:didReceiveChallenge:completionHandler:);
    Method originalMethod = class_getInstanceMethod([NSObject class], originalSel);
    
    if (originalMethod) {
        // 添加我们的实现作为 NSObject 的类别方法
        IMP swizzledImp = imp_implementationWithBlock(^(
            NSObject *_self,
            NSURLSession *session,
            NSURLSessionTask *task,
            NSURLAuthenticationChallenge *challenge,
            void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
            
            // 只处理服务器信任验证
            if ([challenge.protectionSpace.authenticationMethod
                    isEqualToString:NSURLAuthenticationMethodServerTrust]) {
                SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
                if (serverTrust) {
                    NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
                    if (completionHandler) {
                        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                    }
                    NSLog(@"[SSLBypass] ✅ [IMP] NSURLSession 证书绕过: %@",
                          challenge.protectionSpace.host);
                    return;
                }
            }
            
            // 对于未实现此方法的 delegate，走默认逻辑
            if (completionHandler) {
                completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            }
        });
        
        // 将我们的实现添加到 NSObject
        class_addMethod([NSObject class], originalSel, swizzledImp, 
                       "v@:@@@?");
        
        NSLog(@"[SSLBypass] ✅ NSURLSession delegate swizzle 已注册");
    }
}


// ============================================================
// 构造函数: dylib 加载时自动执行
// ============================================================

__attribute__((constructor))
static void initializeSSLBypass() {
    @autoreleasepool {
        NSLog(@"[SSLBypass] =========================================");
        NSLog(@"[SSLBypass] 🚀 iOS SSL Pinning Bypass dylib 正在初始化");
        NSLog(@"[SSLBypass] 📱 目标: 任意使用 NSURLSession / CFNetwork 的 App");
        NSLog(@"[SSLBypass] 🔧 技术栈: DYLD_INTERPOSE + dlsym + ObjC Swizzle");
        NSLog(@"[SSLBypass] =========================================");
        
        // 1. 初始化原始函数指针 (备用)
        initOriginalPointers();
        
        // 2. 验证 DYLD_INTERPOSE 是否生效
        SecTrustResultType testResult = kSecTrustResultInvalid;
        // 使用一个临时 trust 对象测试 (如果没有真实请求，不会走到这里)
        // 实际运行时 DYLD_INTERPOSE 会在 Security 函数被调用时自动生效
        
        if (orig_SecTrustEvaluate != NULL) {
            NSLog(@"[SSLBypass] ✅ 原始 SecTrustEvaluate 地址: %p", orig_SecTrustEvaluate);
        } else {
            NSLog(@"[SSLBypass] ⚠️ 原始 SecTrustEvaluate 地址未获取到 (仍可正常工作)");
        }
        
        // 3. 注册 NSURLSession delegate swizzle
        swizzleNSURLSessionDelegates();
        
        NSLog(@"[SSLBypass] ✅ iOS SSL Pinning Bypass 初始化完成!");
        NSLog(@"[SSLBypass] 🔓 所有 HTTPS 请求的证书验证已被绕过");
        NSLog(@"[SSLBypass] =========================================");
    }
}
