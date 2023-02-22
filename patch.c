#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "foo.h"
#define PAGE_SIZE 4096

void trace_fn() {
	printf("Successfully Hooked... \n");
	printf("In trace function\n");
}

void test_hook() {
	printf("In testing hook function... \n");
}


int far_orig() {

	printf("In far original function... \n");
	return 0;
}   


#define _MEM_JMP        0xE9
#define _MEM_JMP_RAX    0xFF, 0xE0
#define _MEM_JMP_EAX    0xFF, 0xE0
#define _MEM_CALL       0xE8
#define _MEM_CALL_EAX   0xFF, 0xD0
#define _MEM_CALL_RAX   0xFF, 0xD0
#define _MEM_MOVABS_RAX 0x48, 0xB8
#define _MEM_MOV_EAX    0xB8
#define _MEM_PUSH       0x68
#define _MEM_PUSH_RAX   0x50
#define _MEM_PUSH_EAX   0x50
#define _MEM_RET        0xC3
#define _MEM_BYTE       0x0
#define _MEM_WORD       0x0, 0x0
#define _MEM_DWORD      0x0, 0x0, 0x0, 0x0
#define _MEM_QWORD      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

uint8_t MEM_MOV_REGAX[]  = {_MEM_MOVABS_RAX};

void detour(void *src, void *dst, size_t size) {
		uint8_t detour_buffer[] = {_MEM_MOVABS_RAX, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, _MEM_JMP_RAX};
		*(uintptr_t*)((uintptr_t)detour_buffer + sizeof(MEM_MOV_REGAX)) = (uintptr_t)dst;
		memcpy(src, detour_buffer, sizeof(detour_buffer));
}

int main() {

    printf("------------------------------------\n");
    printf("Hooking function...\n");
    printf("------------------------------------\n");
    printf("before hooking the test_hook() function\n");
    printf("calling test_hook()...\n");
    test_shared();
    printf("returned from test_hook()...\n");	
    
    printf("------------------------------------\n");
    printf("Patching the test_hook() function using binary instrumentation\n");
    printf("------------------------------------\n");
    
    uint8_t jmp = 0xe9;

    /* Get the function pointers of trace function and the test_hook function */
    void *main_fn = &test_shared;
    void *hook_fn = &override_test_shared;
    printf("address of main function : %p hook function : %p\n", main_fn, hook_fn);
        
    uint32_t jump_address = (uint32_t)(((uintptr_t)hook_fn) - ((uintptr_t)main_fn)) - 5;
    printf("jmp address: %x\n", jump_address);
    
    uint8_t jump_patch[8];
    memcpy(&jump_patch[0], &jmp, sizeof(uint8_t));
    memcpy(&jump_patch[1], &jump_address, sizeof(uint32_t));
    printf("jump patch: %p\n", *((void **)&jump_patch));
    printf("relative jmp address from jump_patch: %x\n", *((uint32_t *)&jump_patch[1]));    

   // memcpy(&jump_patch[5], main_fn + 5, 3);
    printf("jump_patch: %p\n", *((void **)&jump_patch));

    void *nearest_page = (void *)((uintptr_t)main_fn & ~((1 << 22) - 1));
    printf("nearest page from main_fn %p: %p\n", main_fn, nearest_page);

    int ret = mprotect(nearest_page, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    if (ret != 0) {
        char *error = strerror(errno);
        printf("mprotect failed: %s\n", error);
    }

    /* Patch the original function to use do the trampoline */
    memcpy(main_fn, &jump_patch, 8);

    test_shared();


    //far jump
    printf("\nfar jump \n");
    far_orig();
	detour(&far_orig, &far_hook, 12);	
	
    int ret1 = far_orig();
    printf("return : %d\n", ret1);

	return 0;
}
