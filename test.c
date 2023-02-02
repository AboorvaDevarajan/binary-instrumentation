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
#include "foo.h"

#define BIT(i)               (1ul << (i))

/* Binary instrumentation patching : Definitions */
typedef enum {
    OK = 0,
    INPROGRESS = 1,
    ERR_BUSY = 3,
    INVALID_ADDR = 4,
    NO_DEVICE = 5
} status_t;

typedef struct bistro_jmp_rax_patch {
    uint8_t mov_rax[2];  /* mov %rax, addr */
    void    *ptr;
    uint8_t jmp_rax[2];  /* jmp rax        */
} bistro_jmp_rax_patch_t;

typedef struct bistro_jmp_near_patch {
    uint8_t jmp_rel; /* opcode:  JMP rel32          */
    int32_t disp;    /* operand: jump displacement */
} bistro_jmp_near_patch_t;

struct bistro_restore_point {
    void               *addr;     /* address of function to restore */
    size_t             patch_len; /* patch length */
    char               orig[0];   /* orig func code */
};

typedef struct bistro_restore_point bistro_restore_point_t;

typedef struct reloc_patch {
    const char       *symbol;
    void             *value;
    void             *prev_value;
} reloc_patch_t;

typedef enum event_type {
    /* Default initialization value */
    EVENT_NONE            = 0,
    /* Native events */
    EVENT_MMAP            = BIT(0),
    EVENT_MUNMAP          = BIT(1),
    EVENT_MREMAP          = BIT(2),
    EVENT_SHMAT           = BIT(3),
    EVENT_SHMDT           = BIT(4),
    EVENT_SBRK            = BIT(5),
    EVENT_MADVISE         = BIT(6),
    EVENT_BRK             = BIT(7),

    /* Aggregate events */
    EVENT_VM_MAPPED       = BIT(16),
    EVENT_VM_UNMAPPED     = BIT(17),

    /* Non-accessible memory alloc/free events */
    EVENT_MEM_TYPE_ALLOC  = BIT(20),
    EVENT_MEM_TYPE_FREE   = BIT(21),
    /* Add event handler, but don't install new hooks */
    EVENT_FLAG_NO_INSTALL = BIT(24),
    /* When the event handler is added, generate approximated events for
     * existing memory allocations.
     * Currently implemented only for @ref EVENT_MEM_TYPE_ALLOC.
     */
    EVENT_FLAG_EXISTING_ALLOC = BIT(25)
} event_type_t;

typedef struct mmap_func {
    reloc_patch_t    patch;
    event_type_t     event_type;
    event_type_t     deps;
} mmap_func_t;

void *override_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int override_munmap(void *addr, size_t length);
void *override_mremap(void *old_address, size_t old_size, size_t new_size, int flags);
void *override_shmat(int shmid, const void *shmaddr, int shmflg);
int override_shmdt(const void *shmaddr);
void *override_sbrk(intptr_t increment);
int override_brk(void *addr);
int override_madvise(void *addr, size_t length, int advice);
void *override_test_m(void);
void override_malloc(size_t);

void *override_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	mmap(addr, length, prot, flags, fd, offset);
}

void *override_test_m(void) {
	printf("hooked test_m function\n");
}

void override_malloc(size_t size) {
 	malloc(size);
}

#define MMAP_RELOC_ENTRY(_name) \
    { \
        .symbol     = #_name, \
        .value      = override_##_name, \
        .prev_value = _name \
    }
static mmap_func_t mmap_funcs[] = {
    { MMAP_RELOC_ENTRY(malloc), EVENT_MMAP,    EVENT_NONE},
/*  { MMAP_RELOC_ENTRY(mmap),    EVENT_MMAP,    EVENT_NONE},
    { MMAP_RELOC_ENTRY(munmap),  EVENT_MUNMAP,  EVENT_NONE},
    { MMAP_RELOC_ENTRY(shmat),   EVENT_SHMAT,   EVENT_NONE},
    { MMAP_RELOC_ENTRY(shmdt),   EVENT_SHMDT,   EVENT_SHMAT},
    { MMAP_RELOC_ENTRY(sbrk),    EVENT_SBRK,    EVENT_NONE},
    { MMAP_RELOC_ENTRY(brk),     EVENT_BRK,     EVENT_NONE},
    { MMAP_RELOC_ENTRY(madvise), EVENT_MADVISE, EVENT_NONE},*/
    { {NULL, NULL, NULL}, EVENT_NONE}
};
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


typedef struct {
    void *jmp_addr;
    char code[];
} bistro_orig_func_t;


typedef struct {
    uint8_t opcode; /* 0xff */
    uint8_t modrm; /* 0x25 */
    int32_t displ;
} bistro_jmp_indirect_t;


typedef struct {
    uint8_t  push_rax;
    uint8_t  movabs_rax[2];
    uint64_t rax_value;
    uint8_t  cmp_dptr_rax[2];
    uint32_t cmp_value;
    uint8_t  pop_rax;
} bistro_cmp_xlt_t;

typedef struct {
    uint8_t jmp_rel[2];
    uint8_t jmp_out[2];
    struct {
        uint8_t  push_imm;
        uint32_t value;
    } hi, lo;
    uint8_t        ret;
} bistro_jcc_xlt_t;


#define max(_a, _b) \
({ \
    typeof(_a) _max_a = (_a); \
    typeof(_b) _max_b = (_b); \
    (_max_a > _max_b) ? _max_a : _max_b; \
})

#define min(_a, _b) \
({ \
    typeof(_a) _min_a = (_a); \
    typeof(_b) _min_b = (_b); \
    (_min_a < _min_b) ? _min_a : _min_b; \
})



#define SYS_PARAGRAPH_SIZE     16
#define KBYTE    (1ull << 10)
//#define MAP_FAILED ((void*)-1)

#define align_down_pow2(_n, _alignment) \
    ( (_n) & ~((_alignment) - 1) )

#define align_up_pow2(_n, _alignment) \
    align_down_pow2((_n) + (_alignment) - 1, _alignment)

size_t get_page_size();
size_t get_page_size()
{
    static long page_size = -1;
    long value;

    if (page_size == -1) {
        value = sysconf(_SC_PAGESIZE);
        if (value < 0) {
            page_size = 4096;
        } else {
            page_size = value;
        }
    }
    return page_size;
}
void *bistro_allocate_code(size_t size)
{
    static const size_t mmap_size = 16 * KBYTE;
    static pthread_mutex_t mutex  = PTHREAD_MUTEX_INITIALIZER;
    static void *mem_area         = MAP_FAILED;
    static size_t alloc_offset    = 0;
    size_t alloc_size;
    void *result;

    pthread_mutex_lock(&mutex);

    if (mem_area == MAP_FAILED) {
        /* Allocate executable memory block once, and reuse it for
         * subsequent allocations. We assume bistro would not really need
         * more than 'mmap_size' in total, since it's used for limited number
         * of library functions. Also, the memory is never really released, so
         * our allocator is very simple.
         */
        mem_area = mmap(NULL, align_up_pow2(mmap_size, get_page_size()),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (mem_area == MAP_FAILED) {
            printf("failed to allocated executable memory of %zu bytes: %m\n",
                      mmap_size);
            result = NULL;
            goto out;
        }
    }

    alloc_size = align_up_pow2(size, SYS_PARAGRAPH_SIZE);
    if ((alloc_size + alloc_offset) > mmap_size) {
        result = NULL;
        goto out;
    }

    /* Allocate next memory block in the mmap-ed area */
    result        = PTR_BYTE_OFFSET(mem_area, alloc_offset);
    alloc_offset += alloc_size;

out:
    pthread_mutex_unlock(&mutex);
    return result;
}

typedef struct {
    const void *src_p;   /* Pointer to current source instruction */
    const void *src_end; /* Upper limit for source instructions */
    void       *dst_p;   /* Pointer to current destination instruction */
    void       *dst_end; /* Upper limit for destination instructions */
} bistro_relocate_context_t;



#define serialize_next_raw(_iter, _type, _offset) \
    ({ \
        _type *_result = (_type*)(*(_iter)); \
        *(_iter)       = PTR_BYTE_OFFSET(*(_iter), _offset); \
        _result; \
    })


#define serialize_next(_iter, _type) \
    serialize_next_raw(_iter, _type, sizeof(_type))

#define BISTRO_X86_REX_MASK  0xF0 /* Mask */
#define BISTRO_X86_REX       0x40 /* Value */


#define BISTRO_X86_REX_W     0x48 /* REX.W value */
#define BISTRO_X86_REX_B     0x41 /* REX.B value */

/* PUSH general register
 * "push $reg"
 */
#define BISTRO_X86_PUSH_R_MASK 0xF0 /* Mask */
#define BISTRO_X86_PUSH_R      0x50 /* Value */

/* Immediate Grp 1(1A), Ev, Iz */
#define BISTRO_X86_IMM_GRP1_EV_IZ 0x81

/* MOV Ev,Gv */
#define BISTRO_X86_MOV_EV_GV 0x89

/* MOV immediate word or double into word, double, or quad register
 * "mov $imm32, %reg"
 */
#define BISTRO_X86_MOV_IR_MASK 0xF8 /* Mask */
#define BISTRO_X86_MOV_IR      0xB8 /* Value */

/* ModR/M encoding:
 * [ mod | reg   | r/m   ]
 * [ 7 6 | 5 4 3 | 2 1 0 ]
 */
#define BISTRO_X86_MODRM_MOD_SHIFT 6 /* mod */
#define BISTRO_X86_MODRM_REG_SHIFT 3 /* reg */
#define BISTRO_X86_MODRM_RM_BITS   3 /* r/m */

/* Table 2-2 */
#define BISTRO_X86_MODRM_MOD_DISP8  1 /* 0b01 */
#define BISTRO_X86_MODRM_MOD_DISP32 2 /* 0b10 */
#define BISTRO_X86_MODRM_MOD_REG    3 /* 0b11 */
#define BISTRO_X86_MODRM_RM_SIB     4 /* 0b100 */

/* ModR/M encoding for SUB RSP
 * mod=0b11, reg=0b101 (SUB as opcode extension), r/m=0b100
 */
#define BISTRO_X86_MODRM_SUB_SP 0xEC /* 11 101 100 */

/* ModR/M encoding for EBP/BP/CH/MM5/XMM5, AH/SP/ESP/MM4/XMM4 */
#define BISTRO_X86_MODRM_BP_SP 0xE5 /* 11 100 101 */

/* ModR/M encoding for CMP [RIP+x], Imm32 */
#define BISTRO_X86_MODRM_CMP_RIP 0x3D /* 11 111 101 */

/* Jcc (conditional jump) opcodes range */
#define BISTRO_X86_JCC_FIRST 0x70
#define BISTRO_X86_JCC_LAST  0x7F

#define MASK(i)              (BIT(i) - 1)


status_t bistro_relocate_one(bistro_relocate_context_t *ctx)
{
    const void *copy_src     = ctx->src_p;
    bistro_cmp_xlt_t cmp = {
        .push_rax     = 0x50,
        .movabs_rax   = {0x48, 0xb8},
        .cmp_dptr_rax = {0x81, 0x38},
        .pop_rax      = 0x58
    };
    bistro_jcc_xlt_t jcc = {
        .jmp_rel = {0x00, 0x02},
        .jmp_out = {0xeb, 0x0b},
        .hi      = {0x68, 0},
        .lo      = {0x68, 0},
        .ret     = 0xc3
    };
    uint8_t rex, opcode, modrm, mod;
    size_t dst_length;
    uint64_t jmpdest;
    int32_t disp32;
    uint32_t imm32;
    int8_t disp8;

    /* Check opcode and REX prefix */
    opcode = *serialize_next(&ctx->src_p, const uint8_t);
    if ((opcode & BISTRO_X86_REX_MASK) == BISTRO_X86_REX) {
        rex    = opcode;
        opcode = *serialize_next(&ctx->src_p, const uint8_t);
    } else {
        rex = 0;
    }

    if (((rex == 0) || rex == BISTRO_X86_REX_B) &&
        ((opcode & BISTRO_X86_PUSH_R_MASK) == BISTRO_X86_PUSH_R)) {
        /* push reg */
        goto out_copy_src;
    } else if ((rex == BISTRO_X86_REX_W) &&
               (opcode == BISTRO_X86_IMM_GRP1_EV_IZ)) {
        modrm = *serialize_next(&ctx->src_p, const uint8_t);
        if (modrm == BISTRO_X86_MODRM_SUB_SP) {
            /* sub $imm32, %rsp */
            serialize_next(&ctx->src_p, const uint32_t);
            goto out_copy_src;
        }
    } else if ((rex == BISTRO_X86_REX_W) &&
               (opcode == BISTRO_X86_MOV_EV_GV)) {
        modrm = *serialize_next(&ctx->src_p, const uint8_t);
        mod   = modrm >> BISTRO_X86_MODRM_MOD_SHIFT;
        if (modrm == BISTRO_X86_MODRM_BP_SP) {
            /* mov %rsp, %rbp */
            goto out_copy_src;
        }

        if ((mod != BISTRO_X86_MODRM_MOD_REG) &&
            ((modrm & MASK(BISTRO_X86_MODRM_RM_BITS)) ==
             BISTRO_X86_MODRM_RM_SIB)) {
            /* r/m = 0b100, mod = 0b00/0b01/0b10 */
            serialize_next(&ctx->src_p, const uint8_t); /* skip SIB */
            if (mod == BISTRO_X86_MODRM_MOD_DISP8) {
                serialize_next(&ctx->src_p, const uint8_t); /* skip disp8 */
                goto out_copy_src;
            } else if (mod == BISTRO_X86_MODRM_MOD_DISP32) {
                serialize_next(&ctx->src_p, const uint32_t); /* skip disp32 */
                goto out_copy_src;
            }
        }
    } else if ((rex == 0) && ((opcode & BISTRO_X86_MOV_IR_MASK) ==
                              BISTRO_X86_MOV_IR)) {
        /* mov $imm32, %reg */
        serialize_next(&ctx->src_p, const uint32_t);
        goto out_copy_src;
    } else if ((rex == 0) && (opcode == BISTRO_X86_IMM_GRP1_EV_IZ)) {
        modrm = *serialize_next(&ctx->src_p, const uint8_t);
        if (modrm == BISTRO_X86_MODRM_CMP_RIP) {
            /*
             * Since we can't assume the new code will be within 32-bit
             * range of the global variable argument, we need to translate
             * the code from:
             *   cmpl $imm32, $disp32(%rip)
             * to:
             *   push %rax
             *   movq $addr64, %rax ; $addr64 is $disp32+%rip
             *   cmpl $imm32, (%rax)
             *   pop %rax
             */
            disp32        = *serialize_next(&ctx->src_p, const int32_t);
            imm32         = *serialize_next(&ctx->src_p, const uint32_t);
            cmp.rax_value = (uintptr_t)PTR_BYTE_OFFSET(ctx->src_p, disp32);
            cmp.cmp_value = imm32;
            copy_src      = &cmp;
            dst_length    = sizeof(cmp);
            goto out_copy;
        }
    } else if ((rex == 0) && (opcode >= BISTRO_X86_JCC_FIRST) &&
               (opcode <= BISTRO_X86_JCC_LAST)) {
        /*
         * Since we can't assume the new code will be within 32-bit range of the
         * jump destination, we need to translate the code from:
         *        jCC $disp8
         * to:
         *        jCC L1
         *    L1: jmp L2        ; condition 'CC' did not hold
         *        push $addrhi
         *        push $addrlo
         *        ret           ; 64-bit jump to destination
         *    L2:               ; continue execution
         */
        disp8          = *serialize_next(&ctx->src_p, const int8_t);
        jmpdest        = (uintptr_t)PTR_BYTE_OFFSET(ctx->src_p, disp8);
        jcc.jmp_rel[0] = opcode; /* keep original jump condition */
        jcc.hi.value   = jmpdest >> 32;
        jcc.lo.value   = jmpdest & MASK(32);
        copy_src       = &jcc;
        dst_length     = sizeof(jcc);
        /* Prevent patching past jump target */
        ctx->src_end   = min(ctx->src_end, (void*)jmpdest);
        goto out_copy;
    }

    /* Could not recognize the instruction */
    printf("could not recognize inst\n");
    return 1;

out_copy_src:
    dst_length = PTR_BYTE_DIFF(copy_src, ctx->src_p);
out_copy:
    if (PTR_BYTE_OFFSET(ctx->dst_p, dst_length) > ctx->dst_end) {
	printf("large size\n");
        return 1;
    }

    /* Copy 'dst_length' bytes to ctx->dst_p and advance it */
    memcpy(serialize_next_raw(&ctx->dst_p, void, dst_length), copy_src,
           dst_length);
    return OK;
}

static const char *
bistro_dump_code(const void *code, size_t length, char *str, size_t max)
{
    const void *code_p = code;
    char *p            = str;
    char *endp         = str + max;

    while (code_p < PTR_BYTE_OFFSET(code, length)) {
        snprintf(p, endp - p, " %02X",
                 *serialize_next(&code_p, const uint8_t));
        p += strlen(p);
    }

    return str;
}



status_t
bistro_relocate_code(void *dst, const void *src, size_t min_src_length,
                         size_t max_dst_length, size_t *dst_length_p,
                         size_t *src_length_p, const char *symbol,
                         bistro_relocate_context_t *ctx)
{
    status_t status;
    char code_buf[64];
    int dladdr_ret;
    Dl_info dli;

    ctx->src_p   = src;
    ctx->dst_p   = dst;
    ctx->dst_end = PTR_BYTE_OFFSET(dst, max_dst_length);
    ctx->src_end = (void*)UINTPTR_MAX;

    while (ctx->src_p < PTR_BYTE_OFFSET(src, min_src_length)) {
        status = bistro_relocate_one(ctx);
        if (status != OK) {
	    printf("error 1\n");
            goto err;
        }

        if (ctx->src_p > ctx->src_end) {
            status = 1;
            goto err;
        }
    }

    *src_length_p = PTR_BYTE_DIFF(src, ctx->src_p);
    *dst_length_p = PTR_BYTE_DIFF(dst, ctx->dst_p);
    return OK;

err:
    dladdr_ret = dladdr(src, &dli);
    printf("failed to patch '%s' from %s length %zu code:%s\n", symbol,
             (dladdr_ret != 0) ? dli.dli_fname : "(unknown)", min_src_length,
             bistro_dump_code(src, 16, code_buf, sizeof(code_buf)));
    return status;
}


static status_t
bistro_construct_orig_func(const void *func_ptr, size_t patch_len,
                               const char *symbol, void **orig_func_p)
{
    size_t code_len, prefix_len, max_code_len;
    bistro_jmp_indirect_t *jmp_back;
    bistro_orig_func_t *orig_func;
    status_t status;
    char code_buf[64];
    int dladdr_ret;
    Dl_info dli;
    bistro_relocate_context_t ctx;
    

    max_code_len = max(patch_len + sizeof(bistro_cmp_xlt_t) +
                                   sizeof(bistro_jcc_xlt_t),
                           64);
    orig_func    = bistro_allocate_code(sizeof(*orig_func) + max_code_len +
                                            sizeof(*jmp_back));
    
    if (orig_func == NULL) {
        return 1;
    }

    /* Copy and translate code from 'func_ptr' to 'orig_func->code'.
       'code_len' is the code size at destination buffer, and 'prefix_len' is
       how many bytes were translated from 'func_ptr'. */
    status = bistro_relocate_code(orig_func->code, func_ptr, patch_len,
                                      max_code_len, &code_len, &prefix_len,
                                      symbol, &ctx);
    if (status != OK) {
        return status;
    }

    printf("print %s at %p code length %zu/%zu prefix length %zu\n", symbol,
              func_ptr, code_len, patch_len, prefix_len);

    /* Indirect jump to *orig_func->jmp_address */
    orig_func->jmp_addr = PTR_BYTE_OFFSET(func_ptr, prefix_len);
    jmp_back            = PTR_BYTE_OFFSET(orig_func->code, code_len);
    jmp_back->opcode    = 0xff;
    jmp_back->modrm     = 0x25;
    jmp_back->displ     = PTR_BYTE_DIFF(jmp_back + 1, &orig_func->jmp_addr);
    *orig_func_p        = orig_func->code;


    return OK;
}
status_t bistro_patch(void *func_ptr, void *hook, const char *symbol, void **orig_func_p,
                      bistro_restore_point_t **rp) {
    bistro_jmp_rax_patch_t jmp_rax   = {
        .mov_rax = {0x48, 0xb8},
        .jmp_rax = {0xff, 0xe0}
    };
    bistro_jmp_near_patch_t jmp_near = {
        .jmp_rel = 0xe9
    };

    void *patch, *jmp_base;
    status_t status;
    ptrdiff_t jmp_disp;
    size_t patch_len;
    
    jmp_base = PTR_BYTE_OFFSET(func_ptr, sizeof(jmp_near));
    jmp_disp = PTR_BYTE_DIFF(jmp_base, hook);

    printf("bistro patching implementation 1\n");

    if (labs(jmp_disp) < INT32_MAX) {
      printf("jmp near\n");
      jmp_near.disp = jmp_disp;
      patch         = &jmp_near;
      patch_len     = sizeof(jmp_near);
    } else {
      printf("jmp far\n");
      jmp_rax.ptr = hook;
      patch       = &jmp_rax;
      patch_len   = sizeof(jmp_rax);
    }   

    if (orig_func_p != NULL) { 
        status = bistro_construct_orig_func(func_ptr, patch_len, symbol,
                                                orig_func_p);
        if (status != OK) {
            return status;
        }
    } else {
        printf("else\n");
    }
    return OK;
}


static void*
reloc_get_orig(const char *symbol, void *replacement)
{
    const char *error;
    void *func_ptr;

    func_ptr = dlsym(RTLD_NEXT, symbol);
    if (func_ptr == NULL) {
        (void)dlerror();
        func_ptr = dlsym(RTLD_DEFAULT, symbol);
        if (func_ptr == replacement) {
            error = dlerror();
            printf("could not find address of original %s(): %s\n", symbol,
                      error ? error : "Unknown error");
        }
    }

    printf("original %s() is at %p\n", symbol, func_ptr);
    return func_ptr;
}

int main(int argc, char **argv) {

    printf("Started Binary Instrumentation (bistro) Patching...\n");
    printf("Initializing patching structures..\n");

    mmap_func_t *entry;
    void *func_ptr;
    status_t status = OK;

    for (entry = mmap_funcs; entry->patch.symbol != NULL; ++entry) {
         printf("mmap: installing bistro hook for %s = %p for event 0x%x\n",
                  entry->patch.symbol, entry->patch.value,
                  entry->event_type);
         func_ptr = reloc_get_orig(entry->patch.symbol,
                                          entry->patch.value);

	 if (func_ptr == NULL) {
		 printf("return value is NULL\n");
	 } else{ 
                status = bistro_patch(func_ptr, entry->patch.value,
                                          entry->patch.symbol, func_ptr, NULL);
	 }
        if (status != OK) {
            printf("failed to install hook for '%s'\n",
                     entry->patch.symbol);
            return status;
        }
    }
    return 0;
}

