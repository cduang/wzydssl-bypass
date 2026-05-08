// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// [license omitted for brevity - same MIT license as fishhook.h]

#include "fishhook.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>

#ifdef __LP64__
#define LINKED_ITEMS LC_DATA_IN_CODE
#define NLIST struct nlist_64
#else
#define LINKED_ITEMS LC_DATA_IN_CODE
#define NLIST struct nlist
#endif

static void rebind_symbols_for_image(const struct mach_header *header,
                                     intptr_t slide,
                                     struct fishhook_rebinding rebindings[],
                                     size_t rebindings_nel) {
    // 准备查找符号表和动态符号表
    struct load_command *cmd = (struct load_command *)((char *)header + sizeof(struct mach_header));
    if (header->magic == MH_MAGIC_64) {
        cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
    }
    
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        switch (cmd->cmd) {
            case LC_SYMTAB:
                symtab_cmd = (struct symtab_command *)cmd;
                break;
            case LC_DYSYMTAB:
                dysymtab_cmd = (struct dysymtab_command *)cmd;
                break;
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    if (!symtab_cmd || !dysymtab_cmd) return;
    
    // 获取符号表、字符串表、间接符号表
    NLIST *symtab = (NLIST *)(slide + symtab_cmd->symoff);
    char *strtab = (char *)(slide + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(slide + dysymtab_cmd->indirectsymoff);
    
    // 遍历段和节区
    cmd = (struct load_command *)((char *)header + sizeof(struct mach_header));
    if (header->magic == MH_MAGIC_64) {
        cmd = (struct load_command *)((char *)header + sizeof(struct mach_header_64));
    }
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            // 检查是否在 DATA 或 DATA_CONST 段
            if (strcmp(seg->segname, "__DATA") != 0 &&
                strcmp(seg->segname, "__DATA_CONST") != 0) {
                cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
                continue;
            }
            
            struct section_64 *sections = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                struct section_64 *sect = &sections[j];
                
                if (strcmp(sect->sectname, "__la_symbol_ptr") == 0 ||
                    strcmp(sect->sectname, "__nl_symbol_ptr") == 0) {
                    
                    uint32_t *indirect = indirect_symtab + sect->reserved1;
                    void **pointers = (void **)(slide + sect->addr);
                    uint64_t count = sect->size / sizeof(void *);
                    
                    for (uint64_t k = 0; k < count; k++) {
                        uint32_t sym_index = indirect[k];
                        
                        if (sym_index == INDIRECT_SYMBOL_ABS ||
                            sym_index == INDIRECT_SYMBOL_LOCAL ||
                            (sym_index & INDIRECT_SYMBOL_ABS) == INDIRECT_SYMBOL_ABS) {
                            continue;
                        }
                        
                        if (sym_index >= symtab_cmd->nsyms) continue;
                        
                        const char *sym_name = &strtab[symtab[sym_index].n_un.n_strx];
                        if (sym_name[0] == '_') sym_name++;
                        
                        for (size_t r = 0; r < rebindings_nel; r++) {
                            if (strcmp(sym_name, rebindings[r].name) == 0) {
                                // 保存原始指针
                                if (rebindings[r].replaced && *rebindings[r].replaced == NULL) {
                                    *rebindings[r].replaced = pointers[k];
                                }
                                
                                // 使页面可写
                                vm_protect(mach_task_self(),
                                          (vm_address_t)&pointers[k],
                                          sizeof(void *), 0,
                                          VM_PROT_READ | VM_PROT_WRITE);
                                
                                // 替换指针
                                pointers[k] = rebindings[r].replacement;
                                
                                break;
                            }
                        }
                    }
                }
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
}

static void _rebind_symbols_for_image_callback(const struct mach_header *header,
                                                intptr_t slide) {
    // 通过 dl_info 获取当前 rebindings
    // 实际是使用全局变量，但为了简化直接用 fishhook_rebind_symbols 的参数
    // 这里由 fishhook_rebind_symbols 直接遍历所有镜像
}

int fishhook_rebind_symbols(struct fishhook_rebinding rebindings[],
                             size_t rebindings_nel) {
    // 遍历所有已加载的镜像
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        
        // 跳过自己的 dylib
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "SSLBypass")) continue;
        
        rebind_symbols_for_image(header, slide, rebindings, rebindings_nel);
    }
    return 0;
}
