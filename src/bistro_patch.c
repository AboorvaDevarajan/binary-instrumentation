#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <pthread.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include "shared.h"

#define DEBUG

#ifdef DEBUG
#define debug_printf printf
#else
#define debug_printf(x, ...)
#endif

#define BIT(i) (1ul << (i))

#define _MEM_JMP 0xE9
#define _MEM_JMP_RAX 0xFF, 0xE0
#define _MEM_JMP_EAX 0xFF, 0xE0
#define _MEM_CALL 0xE8
#define _MEM_CALL_EAX 0xFF, 0xD0
#define _MEM_CALL_RAX 0xFF, 0xD0
#define _MEM_MOVABS_RAX 0x48, 0xB8
#define _MEM_MOV_EAX 0xB8
#define _MEM_PUSH 0x68
#define _MEM_PUSH_RAX 0x50
#define _MEM_PUSH_EAX 0x50
#define _MEM_RET 0xC3
#define _MEM_BYTE 0x0
#define _MEM_WORD 0x0, 0x0
#define _MEM_DWORD 0x0, 0x0, 0x0, 0x0
#define _MEM_QWORD 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

uint8_t MEM_MOV_REGAX[] = {_MEM_MOVABS_RAX};

#define MMAP_RELOC_ENTRY(_name)    \
    {                              \
        .symbol = #_name,          \
        .original_ptr = &_name,    \
        .value = override_##_name, \
        .prev_value = _name        \
    }

#define typeof(_type) \
    __typeof__(_type)

/* Helper macro for address arithmetic in bytes */
#define PTR_BYTE_OFFSET(_ptr, _offset) \
    ((void *)((intptr_t)(_ptr) + (intptr_t)(_offset)))

/* Helper macro to calculate an address with offset equal to size of _type */
#define PTR_TYPE_OFFSET(_ptr, _type) \
    ((void *)((typeof(_type) *)(_ptr) + 1))

/* Helper macro to calculate ptr difference (_end - _start) */
#define PTR_BYTE_DIFF(_start, _end) \
    ((ptrdiff_t)((uintptr_t)(_end) - (uintptr_t)(_start)))

#define PTR_BYTE_DIFF(_start, _end) \
    ((ptrdiff_t)((uintptr_t)(_end) - (uintptr_t)(_start)))

#define align_down(_n, _alignment) \
    ((_n) - ((_n) % (_alignment)))

/* Binary instrumentation patching : Definitions */
typedef enum
{
    OK = 0,
    INPROGRESS = 1,
    ERR_BUSY = 3,
    INVALID_ADDR = 4,
    NO_DEVICE = 5,
    ERR_INVALID_PARAM = 6
} status_t;

typedef struct bistro_jmp_rax_patch
{
    uint8_t mov_rax[2]; /* mov %rax, addr */
    void *ptr;
    uint8_t jmp_rax[2]; /* jmp rax        */
} bistro_jmp_rax_patch_t;

typedef struct bistro_jmp_near_patch
{
    uint8_t jmp_rel; /* opcode: JMP rel32          */
    int32_t disp;    /* operand: jump displacement */
 }  __attribute__((packed)) bistro_jmp_near_patch_t;

struct bistro_restore_point
{
    void *addr;       /* address of function to restore */
    size_t patch_len; /* patch length */
    char orig[0];     /* orig func code */
};

typedef struct bistro_restore_point bistro_restore_point_t;

typedef struct reloc_patch
{
    const char *symbol;
    void *original_ptr;
    void *value;
    void *prev_value;
} reloc_patch_t;

typedef enum event_type
{
    EVENT_NONE = 0,
    EVENT_FOO = BIT(0),
    EVENT_BAR = BIT(1)
} event_type_t;

typedef struct func
{
    reloc_patch_t patch;
    event_type_t event_type;
    event_type_t deps;
} func_t;

/* Test functions */
void *override_bar(void)
{
    debug_printf("override: in override_bar()..\n");
    return NULL;
}
void bar(void)
{
    debug_printf("original: in bar()..\n");
}

void *override_foo(void)
{
    debug_printf("override: in override_foo()..\n");
    return NULL;
}
void foo(void)
{
    debug_printf("original: in foo()..\n");
}

static func_t funcs[] = {
    {MMAP_RELOC_ENTRY(foo), EVENT_FOO, EVENT_NONE},
    {MMAP_RELOC_ENTRY(bar), EVENT_BAR, EVENT_NONE},
    {{NULL, NULL, NULL}, EVENT_NONE}};

size_t get_page_size();
size_t get_page_size()
{
    static long page_size = -1;
    long value;

    if (page_size == -1)
    {
        value = sysconf(_SC_PAGESIZE);
        if (value < 0)
        {
            page_size = 4096;
        }
        else
        {
            page_size = value;
        }
    }
    return page_size;
}

static void *bistro_page_align_ptr(void *ptr)
{
    return (void *)align_down((uintptr_t)ptr, get_page_size());
}

static status_t bistro_protect(void *addr, size_t len, int prot)
{
    void *aligned = bistro_page_align_ptr(addr);
    size_t size = PTR_BYTE_DIFF(aligned, addr) + len;
    int res;

    res = mprotect(aligned, size, prot);
    if (res)
    {
        debug_printf("bistro_protect: Failed to change page protection: %d\n", res);
        return ERR_INVALID_PARAM;
    }
    return OK;
}

static inline void clear_cache(void *start, void *end)
{
    __clear_cache(start, end);
}

status_t bistro_apply_patch(void *dst, void *patch, size_t len)
{
    status_t status;

    status = bistro_protect(dst, len, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (status != OK)
    {
        return status;
    }
    memcpy(dst, patch, len);
    return status;
}

status_t bistro_patch(void *func_ptr, void *hook, const char *symbol, void **orig_func_p,
                      bistro_restore_point_t **rp)
{
    bistro_jmp_near_patch_t jmp_near = {
        .jmp_rel = 0xe9
    };

    void *patch, *jmp_base;
    status_t status;
    ptrdiff_t jmp_disp;
    size_t patch_len;    

    jmp_base = PTR_BYTE_OFFSET(func_ptr, sizeof(jmp_near));
    jmp_disp = PTR_BYTE_DIFF(jmp_base, hook);

    if (labs(jmp_disp) < INT32_MAX) {
        /* if 32-bit near jump is possible, use it, since it's a short 5-byte
         * instruction which reduces the chances of racing with other thread
         */
        jmp_near.disp = (uint32_t) jmp_disp;
        patch         = &jmp_near;
        patch_len     = sizeof(jmp_near);
    }    
    return bistro_apply_patch(func_ptr, patch, patch_len);
}

status_t far_patch(void *src, void *dst, size_t size)
{
    uint8_t far_patch_buffer[] = {_MEM_MOVABS_RAX, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, _MEM_JMP_RAX};
    *(uintptr_t *)((uintptr_t)far_patch_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)dst;
    memcpy(src, far_patch_buffer, sizeof(far_patch_buffer));
}

int main(int argc, char **argv)
{

    debug_printf("main: Started Binary Instrumentation (bistro) Patching...\n");
    debug_printf("main: Initializing patching structures..\n");

    func_t *entry;
    void *func_ptr;
    status_t status = OK;

    debug_printf("main: Before applying binary instrumentation patch...\n");
    foo();
    bar();
    shared_foo();
    for (entry = funcs; entry->patch.symbol != NULL; ++entry)
    {
        debug_printf("main: mmap: installing bistro hook for %s = %p for event 0x%x orig : %p\n",
                     entry->patch.symbol, entry->patch.value,
                     entry->event_type, entry->patch.original_ptr);

        if (func_ptr == NULL)
        {
            debug_printf("main: return value is NULL\n");
        }
        else
        {
            status = bistro_patch(entry->patch.original_ptr, entry->patch.value,
                                  entry->patch.symbol, NULL, NULL);
        }
        debug_printf("main: bistro patch applied...\n");
        if (status != OK)
        {
            debug_printf("main: failed to install hook for '%s'\n",
                         entry->patch.symbol);
            return status;
        }
        else
        {
            debug_printf("main: success.. done\n");
            debug_printf("main: calling original functions\n");
        }
    }

    far_patch(shared_foo, override_shared_foo, 12);

    debug_printf("main: After applying binary instrumentation patch...\n");
    foo();
    bar();
    shared_foo();
    return 0;
}
