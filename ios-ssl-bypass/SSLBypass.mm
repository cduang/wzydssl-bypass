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
 *           -framework Foundation -framework Security -framework UIKit \
 *           -o SSLBypass.dylib \
 *           SSLBypass.mm fishhook.c
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "fishhook.h"

#pragma mark - Bark 推送通知

#define BARK_KEY @"DfxenieixXvRF6iMGFDUz7"
#define BARK_BASE_URL @"https://api.day.app/" BARK_KEY
#define BARK_GROUP @"SSLBypass"

/// 发送 Bark 推送 (GET 请求，不阻塞)
static void bark_push(NSString *title, NSString *body) {
    // 对 body 进行 URL 编码
    NSString *encodedBody = [body stringByAddingPercentEncodingWithAllowedCharacters:
                             [NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *encodedTitle = [title stringByAddingPercentEncodingWithAllowedCharacters:
                              [NSCharacterSet URLQueryAllowedCharacterSet]];
    
    // 宏已包含 @""，直接使用宏名即可
    NSString *urlStr = [NSString stringWithFormat:@"%@/%@/%@?group=%@",
                        BARK_BASE_URL, encodedTitle, encodedBody, BARK_GROUP];
    
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) return;
    
    // 异步 GET 请求，不阻塞当前线程
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        NSURLSessionDataTask *task = [NSURLSession.sharedSession
                                      dataTaskWithURL:url
                                      completionHandler:^(NSData * _Nullable data,
                                                          NSURLResponse * _Nullable resp,
                                                          NSError * _Nullable err) {
            if (err) {
                NSLog(@"[SSLBypass][Bark] ❌ 推送失败: %@", err.localizedDescription);
            } else {
                NSString *reply = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSLog(@"[SSLBypass][Bark] ✅ 推送成功: %@", reply);
            }
        }];
        [task resume];
    });
}

/// Bark 推送 + 设备信息 (首次触发时调用)
static void bark_hook_activated(NSString *layer, NSString *detail) {
    UIDevice *dev = UIDevice.currentDevice;
    NSString *title = [NSString stringWithFormat:@"🔓 SSLBypass %@ 已触发", layer];
    NSString *body = [NSString stringWithFormat:@"%@ | %@ %@ | PID:%d",
                      detail, dev.systemName, dev.systemVersion, getpid()];
    bark_push(title, body);
}

#pragma mark - 原始函数指针

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus (*orig_SecTrustEvaluateAsync)(SecTrustRef, dispatch_queue_t, SecTrustCallback);
static SecTrustRef (*orig_SecTrustCreateWithCertificates)(CFArrayRef, CFTypeRef);

#pragma mark - 第1层: C函数 Hook

// dispatch_once_t 静态变量默认初始化为 0 (未触发)
static dispatch_once_t once_L1_Evaluate;
static dispatch_once_t once_L1_EvaluateAsync;
static dispatch_once_t once_L2_Challenge;

static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    NSLog(@"[SSLBypass][L1] 🔓 SecTrustEvaluate bypassed");
    dispatch_once(&once_L1_Evaluate, ^{
        bark_hook_activated(@"L1", @"SecTrustEvaluate ✅ 证书验证已绕过");
    });
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
    dispatch_once(&once_L1_EvaluateAsync, ^{
        bark_hook_activated(@"L1", @"SecTrustEvaluateAsync ✅ 异步证书验证已绕过");
    });
    return errSecSuccess;
}

static SecTrustRef hook_SecTrustCreateWithCertificates(CFArrayRef certs, CFTypeRef policies) {
    if (orig_SecTrustCreateWithCertificates)
        return orig_SecTrustCreateWithCertificates(certs, policies);
    return NULL;
}

/// 注册 fishhook，替换 Security.framework 符号指针
static void hook_security_functions() {
    // C++ 需要显式 cast 函数指针 → void*
    struct fishhook_rebinding rebindings[] = {
        {"SecTrustEvaluate",             (void *)hook_SecTrustEvaluate,             (void **)&orig_SecTrustEvaluate},
        {"SecTrustEvaluateAsync",        (void *)hook_SecTrustEvaluateAsync,        (void **)&orig_SecTrustEvaluateAsync},
        {"SecTrustCreateWithCertificates", (void *)hook_SecTrustCreateWithCertificates, (void **)&orig_SecTrustCreateWithCertificates},
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
            
            dispatch_once(&once_L2_Challenge, ^{
                bark_hook_activated(@"L2", [NSString stringWithFormat:@"URLSession DidReceiveChallenge ✅ %@", challenge.protectionSpace.host]);
            });
            
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
            // 替换实现为我们的通用 handler
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
        
        // dylib 加载成功的 Bark 通知 (确认注入成功)
        bark_push(@"📦 SSLBypass 已注入",
                  [NSString stringWithFormat:@"PID:%d | 等待 L1/L2 触发", getpid()]);
        
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
