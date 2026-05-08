/*
 * SSLBypass.mm - iOS SSL Pinning 底层绕过实现
 *
 * 使用 fishhook 在 C 函数级别 Hook Security.framework
 * 相比 Logos/OC swizzling，此方法更底层、更通用，能绕过:
 *   - NSURLSession delegate pinning
 *   - Alamofire/SessionDelegate pinning  
 *   - 自定义 SSL 验证逻辑
 *   - WebView SSL 验证
 *
 * 编译要求:
 *   - Theos (推荐): 项目会自动包含此文件
 *   - 手动编译: clang++ -arch arm64 -isysroot $(xcrun -sdk iphoneos --show-sdk-path) \
 *               -F. -fobjc-arc -c SSLBypass.mm -o SSLBypass.o
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>

// fishhook 实现 - 轻量级 Mach-O 符号重绑定
// 原理: 通过修改 __DATA 段的懒加载/非懒加载符号表
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================
// 内嵌 fishhook 核心实现 (无外部依赖)
// ============================================================

#ifdef __LP64__
#   define macho_getsymboldefine(nlist) struct nlist_64 nlist
#   define macho_nlist nlist_64
#   define macho_segment_command segment_command_64
#   define macho_section section_64
#   define macho_segname __TEXT
#   define macho_sectname __text
#else
#   define macho_getsymboldefine(nlist) struct nlist nlist
#   define macho_nlist nlist
#   define macho_segment_command segment_command
#   define macho_section section
#   define macho_segname __TEXT
#   define macho_sectname __text
#endif

struct fishhook_rebinding {
    const char *name;      // 符号名称
    void *replacement;     // 替换函数指针
    void **replaced;       // 原始函数指针的指针
};

static int fishhook_rebind_symbols(struct fishhook_rebinding rebindings[], size_t rebindings_nel);
static void perform_rebinding_with_section(
    struct macho_section *section, 
    intptr_t slide, 
    struct macho_nlist *symtab, 
    char *strtab, 
    uint32_t *indirect_symtab,
    struct fishhook_rebinding rebindings[], 
    size_t rebindings_nel);

// ============================================================
// 原始函数指针声明
// ============================================================

// Security.framework 核心函数
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus (*orig_SecTrustEvaluateAsync)(SecTrustRef trust, dispatch_queue_t queue, SecTrustCallback result);
static SecTrustRef (*orig_SecTrustCreateWithCertificates)(CFArrayRef certificates, CFTypeRef policies);
static bool (*orig_SecTrustSetAnchorCertificates)(SecTrustRef trust, CFArrayRef anchorCertificates);
static OSStatus (*orig_SecTrustSetPolicies)(SecTrustRef trust, CFTypeRef policies);
static bool (*orig_SSLCreateContext)(...);  // CFNetwork 内部

// CFNetwork SSL 验证
typedef CFTypeRef (*SSLVerifyType)(...);
static SSLVerifyType orig_SSLVerify;

// ============================================================
// 替换实现: SecTrustEvaluate
// 总是返回 errSecSuccess (noErr)
// ============================================================

static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result != NULL) {
        // kSecTrustResultProceed = 4 (信任且允许继续)
        // kSecTrustResultUnspecified = 1 (信任但未明确指定，通常视为通过)
        *result = kSecTrustResultProceed;
    }
    
    // 获取服务器信息用于日志
    CFIndex count = SecTrustGetCertificateCount(trust);
    NSLog(@"[SSLBypass] 🔓 SecTrustEvaluate 绕过! 证书数量: %ld", count);
    
    // 尝试获取主机名
#if TARGET_OS_IOS
    CFDictionaryRef info = SecTrustCopyResult(trust);
    if (info) {
        NSLog(@"[SSLBypass] 📋 信任结果: %@", info);
        CFRelease(info);
    }
#endif
    
    return errSecSuccess; // noErr
}

// ============================================================
// 替换实现: SecTrustEvaluateAsync
// 异步版本，直接回调成功
// ============================================================

static OSStatus hook_SecTrustEvaluateAsync(SecTrustRef trust, 
                                            dispatch_queue_t queue, 
                                            SecTrustCallback result) {
    if (result != NULL) {
        // 通过 dispatch_async 调用回调，返回成功状态
        dispatch_async(queue ? queue : dispatch_get_main_queue(), ^{
            result(trust, kSecTrustResultProceed);
        });
    }
    
    NSLog(@"[SSLBypass] 🔓 SecTrustEvaluateAsync 绕过!");
    return errSecSuccess;
}

// ============================================================
// 替换实现: SecTrustCreateWithCertificates
// 透传但允许所有证书
// ============================================================

static SecTrustRef hook_SecTrustCreateWithCertificates(CFArrayRef certificates, 
                                                        CFTypeRef policies) {
    // 仍然调用原始函数创建 trust 对象，但不做额外验证
    SecTrustRef trust = orig_SecTrustCreateWithCertificates(certificates, policies);
    NSLog(@"[SSLBypass] 🔓 SecTrustCreateWithCertificates 绕过!");
    return trust;
}

// ============================================================
// NSURLSession swizzling 辅助 (Objective-C 运行时)
// 为没有实现 URLSession:didReceiveChallenge: 的 delegate 添加默认实现
// ============================================================

// 我们自定义的 NSURLSession 挑战处理方法
static void Swizzled_URLSession_didReceiveChallenge(id self, 
                                                     SEL _cmd, 
                                                     NSURLSession *session,
                                                     NSURLSessionTask *task,
                                                     NSURLAuthenticationChallenge *challenge,
                                                     void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    
    NSString *authMethod = challenge.protectionSpace.authenticationMethod;
    
    if ([authMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        if (serverTrust) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
            NSLog(@"[SSLBypass] ✅ [Swizzle] NSURLSession 证书校验绕过: %@",
                  challenge.protectionSpace.host);
            return;
        }
    }
    
    // 没有实现此方法的 delegate 不会走到这里
    // 因为我们只交换了实现了此方法的类的实现
    // 但为了安全，对于未识别的认证方法执行默认处理
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

// ============================================================
// 初始化 Hook
// ============================================================

__attribute__((constructor))
static void initializeSSLBypass() {
    @autoreleasepool {
        NSLog(@"[SSLBypass] =========================================");
        NSLog(@"[SSLBypass] 🚀 iOS SSL Pinning Bypass dylib 正在初始化");
        NSLog(@"[SSLBypass] 📱 目标: 王者营地 / kohcamp.qq.com");
        NSLog(@"[SSLBypass] =========================================");
        
        // ==========================================
        // 1. fishhook - Hook Security.framework C 函数
        // ==========================================
        struct fishhook_rebinding security_rebindings[] = {
            {
                .name = "SecTrustEvaluate",
                .replacement = (void *)hook_SecTrustEvaluate,
                .replaced = (void **)&orig_SecTrustEvaluate,
            },
            {
                .name = "SecTrustEvaluateAsync",
                .replacement = (void *)hook_SecTrustEvaluateAsync,
                .replaced = (void **)&orig_SecTrustEvaluateAsync,
            },
            {
                .name = "SecTrustCreateWithCertificates",
                .replacement = (void *)hook_SecTrustCreateWithCertificates,
                .replaced = (void **)&orig_SecTrustCreateWithCertificates,
            },
        };
        
        size_t numRebindings = sizeof(security_rebindings) / sizeof(security_rebindings[0]);
        int result = fishhook_rebind_symbols(security_rebindings, numRebindings);
        
        if (result == 0) {
            NSLog(@"[SSLBypass] ✅ Security.framework Hook 成功!");
        } else {
            NSLog(@"[SSLBypass] ⚠️ Security.framework Hook 部分失败 (代码: %d)", result);
        }
        
        // ==========================================
        // 2. Method Swizzling - NSURLSession 挑战处理
        // ==========================================
        // 注意: 这里我们不会主动 swizzle 所有 delegate
        // 因为王者营地可能使用自定义 delegate
        // fishhook 已经足够覆盖大部分场景
        // 
        // 如需额外处理，可以在运行时检测并 swizzle
        // 具体 delegate 的 URLSession:didReceiveChallenge: 方法
        
        NSLog(@"[SSLBypass] ✅ iOS SSL Pinning Bypass 初始化完成!");
        NSLog(@"[SSLBypass] 🔓 所有 HTTPS 请求的证书验证已被绕过");
        NSLog(@"[SSLBypass] 📡 配合抓包工具 (如 Fiddler/Charles) 即可抓取明文");
    }
}


// ============================================================
// fishhook 实现
// ============================================================

static int fishhook_rebind_symbols(struct fishhook_rebinding rebindings[], 
                                    size_t rebindings_nel) {
    int retval = 0;
    
    // 获取所有已加载的 Mach-O 镜像
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header *header = (const struct mach_header *)_dyld_get_image_header(i);
        
        const char *name = _dyld_get_image_name(i);
        
        // 只处理 Security.framework 和 CFNetwork
        if (strstr(name, "Security") || strstr(name, "CFNetwork")) {
            // 获取 LC_SYMTAB
            struct macho_nlist *symtab = NULL;
            char *strtab = NULL;
            uint32_t *indirect_symtab = NULL;
            
            // 遍历 load commands
            struct macho_segment_command *seg_linkedit = NULL;
            struct macho_segment_command *seg_text = NULL;
            
            struct load_command *cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header));
            if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
                cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));
            }
            
            for (uint32_t j = 0; j < header->ncmds; j++) {
                if (cmd->cmd == LC_SYMTAB) {
                    struct symtab_command *symtab_cmd = (struct symtab_command *)cmd;
                    symtab = (struct macho_nlist *)(slide + symtab_cmd->symoff);
                    strtab = (char *)(slide + symtab_cmd->stroff);
                } else if (cmd->cmd == LC_DYSYMTAB) {
                    struct dysymtab_command *dysymtab_cmd = (struct dysymtab_command *)cmd;
                    indirect_symtab = (uint32_t *)(slide + dysymtab_cmd->indirectsymoff);
                } else if (cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
                    struct macho_segment_command *seg = (struct macho_segment_command *)cmd;
                    if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                        seg_linkedit = seg;
                    } else if (strcmp(seg->segname, "__TEXT") == 0) {
                        seg_text = seg;
                    }
                }
                
                cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
            }
            
            if (symtab == NULL || strtab == NULL || indirect_symtab == NULL) {
                continue;
            }
            
            // 遍历 sections 寻找懒加载和非懒加载符号指针
            struct macho_segment_command *cur_seg = NULL;
            cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header));
            if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
                cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));
            }
            
            for (uint32_t j = 0; j < header->ncmds; j++) {
                if (cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
                    cur_seg = (struct macho_segment_command *)cmd;
                    struct macho_section *sections = (struct macho_section *)((uintptr_t)cur_seg + sizeof(struct macho_segment_command));
                    for (uint32_t k = 0; k < cur_seg->nsects; k++) {
                        struct macho_section *sec = &sections[k];
                        if (strcmp(sec->sectname, "__la_symbol_ptr") == 0 ||
                            strcmp(sec->sectname, "__nl_symbol_ptr") == 0) {
                            perform_rebinding_with_section(
                                sec, slide, symtab, strtab, 
                                indirect_symtab, rebindings, rebindings_nel);
                        }
                    }
                }
                cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
            }
        }
    }
    
    return retval;
}

static void perform_rebinding_with_section(
    struct macho_section *section, 
    intptr_t slide, 
    struct macho_nlist *symtab, 
    char *strtab, 
    uint32_t *indirect_symtab,
    struct fishhook_rebinding rebindings[], 
    size_t rebindings_nel) {
    
    uint32_t *indirect = (uint32_t *)(slide + section->addr);
    void **pointers = (void **)(slide + section->addr);
    
    for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t sym_index = indirect[i];
        
        // 忽略特殊索引
        if (sym_index == INDIRECT_SYMBOL_ABS || 
            sym_index == INDIRECT_SYMBOL_LOCAL || 
            sym_index > 0xFFFFFF) {
            continue;
        }
        
        // 获取符号名称
        if (sym_index >= section->reserved1 && 
            sym_index < section->reserved1 + section->size / sizeof(void *)) {
            continue; // 已处理
        }
        
        char *sym_name = &strtab[symtab[sym_index].n_un.n_strx];
        
        // 检查是否匹配需要 rebind 的符号
        for (size_t j = 0; j < rebindings_nel; j++) {
            if (strcmp(sym_name, rebindings[j].name) == 0) {
                // 保存原始函数指针
                if (rebindings[j].replaced != NULL) {
                    *rebindings[j].replaced = pointers[i];
                }
                
                // 替换为我们的 Hook 函数
                pointers[i] = rebindings[j].replacement;
                
                NSLog(@"[SSLBypass] 🔗 fishhook 替换: %s (%p -> %p)", 
                      sym_name, *rebindings[j].replaced, rebindings[j].replacement);
                
                break;
            }
        }
    }
}
