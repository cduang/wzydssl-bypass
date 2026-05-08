/*
 * SSLBypass.mm - iOS SSL Pinning Bypass Dylib
 *
 * 多层绕过策略:
 *
 * 第1层: fishhook (C函数级)
 *   直接修改调用方 Mach-O 的 __la_symbol_ptr / __nl_symbol_ptr
 *   将 Security.framework 函数指针替换为Hook函数
 *   覆盖使用 NSURLSession / CFNetwork 的标准场景
 *
 * 第2层: Method Swizzling (ObjC级)
 *   运行时扫描所有已加载的类，找到实现了
 *   URLSession:task:didReceiveChallenge:completionHandler: 的类
 *   替换其实现，强制放行服务器信任挑战
 *   覆盖 App 自定义 NSURLSessionDelegate 的场景
 *
 * 第3层: 定时重扫 (动态加载)
 *   App 可能延迟加载某些类/库
 *   在 1s、3s、8s 后重新执行第2层的扫描
 *
 * 编译:
 *   clang++ -arch arm64 -miphoneos-version-min=14.0 \
 *           -isysroot $(xcrun -sdk iphoneos --show-sdk-path) \
 *           -fobjc-arc -O2 \
 *           -dynamiclib \
 *           -install_name @executable_path/SSLBypass.dylib \
 *           -framework Foundation -framework Security \
 *           -o SSLBypass.dylib \
 *           SSLBypass.mm fishhook.c
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "fishhook.h"

#pragma mark - 原始函数指针

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus (*orig_SecTrustEvaluateAsync)(SecTrustRef, dispatch_queue_t, SecTrustCallback);
static SecTrustRef (*orig_SecTrustCreateWithCertificates)(CFArrayRef, CFTypeRef);

#pragma mark - 第1层: C函数 Hook

static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    NSLog(@"[SSLBypass][L1] 🔓 SecTrustEvaluate bypassed");
    return errSecSuccess;
}

static OSStatus hook_SecTrustEvaluateAsync(SecTrustRef trust,
                                            dispatch_queue_t queue,
                                            SecTrustCallback callback) {
    if (callback) {
        dispatch_async(queue ?: dispatch_get_main_queue(), ^{
            callback(trust, kSecTrustResultProceed);
        });
    }
    NSLog(@"[SSLBypass][L1] 🔓 SecTrustEvaluateAsync bypassed");
    return errSecSuccess;
}

static SecTrustRef hook_SecTrustCreateWithCertificates(CFArrayRef certs, CFTypeRef policies) {
    if (orig_SecTrustCreateWithCertificates)
        return orig_SecTrustCreateWithCertificates(certs, policies);
    return NULL;
}

/// 注册 fishhook，替换 Security.framework 符号指针
static void hook_security_functions() {
    struct fishhook_rebinding rebindings[] = {
        {"SecTrustEvaluate",             hook_SecTrustEvaluate,             (void **)&orig_SecTrustEvaluate},
        {"SecTrustEvaluateAsync",        hook_SecTrustEvaluateAsync,        (void **)&orig_SecTrustEvaluateAsync},
        {"SecTrustCreateWithCertificates", hook_SecTrustCreateWithCertificates, (void **)&orig_SecTrustCreateWithCertificates},
    };
    
    int r = fishhook_rebind_symbols(rebindings, sizeof(rebindings)/sizeof(rebindings[0]));
    NSLog(@"[SSLBypass][L1] fishhook rebind: %d (0=success)", r);
}

#pragma mark - 第2层: ObjC Method Swizzling

/// 通用的 challenge 处理函数 (会被替换到各个 delegate 类中)
static void generic_challenge_handler(id __unused self,
                                       SEL __unused _cmd,
                                       NSURLSession * __unused session,
                                       NSURLSessionTask * __unused task,
                                       NSURLAuthenticationChallenge *challenge,
                                       void (^completion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    
    if ([challenge.protectionSpace.authenticationMethod
            isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        if (trust && completion) {
            completion(NSURLSessionAuthChallengeUseCredential,
                      [NSURLCredential credentialForTrust:trust]);
            NSLog(@"[SSLBypass][L2] ✅ 证书绕过: %@", challenge.protectionSpace.host);
            return;
        }
    }
    if (completion)
        completion(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

/// 扫描所有已加载类，找到实现 challenge 方法的类并替换
static void swizzle_all_delegates() {
    SEL challengeSel = @selector(URLSession:task:didReceiveChallenge:completionHandler:);
    IMP hookImp = imp_implementationWithBlock(^(id self,
                                                 NSURLSession *session,
                                                 NSURLSessionTask *task,
                                                 NSURLAuthenticationChallenge *challenge,
                                                 void (^completion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
        generic_challenge_handler(self, challengeSel, session, task, challenge, completion);
    });
    
    int numClasses;
    Class *classes = NULL;
    
    // 获取类列表
    numClasses = objc_getClassList(NULL, 0);
    if (numClasses > 0) {
        classes = (Class *)malloc(sizeof(Class) * numClasses);
        numClasses = objc_getClassList(classes, numClasses);
    }
    
    int swizzled = 0;
    for (int i = 0; i < numClasses; i++) {
        Class cls = classes[i];
        // 跳过元类
        if (class_isMetaClass(cls)) continue;
        
        Method m = class_getInstanceMethod(cls, challengeSel);
        if (m) {
            // 获取当前实现
            IMP currentImp = method_getImplementation(m);
            
            // 检查是否已经被我们 swizzle 过
            // 通过检查是否指向我们的 block 来判断
            // 这里简单通过方法名判断
            
            // 替换实现
            method_setImplementation(m, hookImp);
            swizzled++;
            
            const char *clsName = class_getName(cls);
            NSLog(@"[SSLBypass][L2] swizzled [%s] %s", clsName, sel_getName(challengeSel));
        }
    }
    
    free(classes);
    
    if (swizzled == 0) {
        NSLog(@"[SSLBypass][L2] ⚠️ 未找到任何实现了 challenge 的类，添加兜底实现到 NSObject");
        // 兜底: 添加到 NSObject (仅对未实现此方法的类有效)
        class_addMethod([NSObject class], challengeSel, hookImp,
                       "v@:@@@?");
    }
    
    NSLog(@"[SSLBypass][L2] swizzled %d 个类", swizzled);
}

#pragma mark - 构造函数

__attribute__((constructor))
static void init() {
    @autoreleasepool {
        NSLog(@"[SSLBypass] =========================================");
        NSLog(@"[SSLBypass] 🚀 iOS SSL Pinning Bypass 初始化");
        NSLog(@"[SSLBypass] 📱 PID: %d", getpid());
        NSLog(@"[SSLBypass] =========================================");
        
        // ======== 第1层: Security.framework C函数 ========
        hook_security_functions();
        
        // ======== 第2层: ObjC 运行时 Method Swizzle ========
        swizzle_all_delegates();
        
        // ======== 第3层: 定时重扫 (动态加载) ========
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NSLog(@"[SSLBypass][L3] 🔄 1s 延迟重扫...");
            swizzle_all_delegates();
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NSLog(@"[SSLBypass][L3] 🔄 3s 延迟重扫...");
            swizzle_all_delegates();
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            NSLog(@"[SSLBypass][L3] 🔄 8s 延迟重扫 (最终)");
            swizzle_all_delegates();
        });
        
        NSLog(@"[SSLBypass] ✅ 初始化完成，所有层已部署");
        NSLog(@"[SSLBypass] =========================================");
    }
}
