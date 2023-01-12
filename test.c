#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

int trace_fn() {
	printf("Successfully Hooked... \n");
	printf("In trace function\n");
}

int test_hook() {

	printf("In testing hook function... \n");
}

int main() {

    printf("------------------------------------\n");
	printf("Hooking function...\n");
	printf("------------------------------------\n");
	printf("before hooking the test_hook() function\n");
	printf("calling test_hook()...\n");
	test_hook();
	printf("returned from test_hook()...\n");	

    
    printf("------------------------------------\n");
    printf("Patching the test_hook() function using binary instrumentation\n");
    printf("------------------------------------\n");
    
    uint8_t jmp = 0xe9;

    /* Get the function pointers of trace function and the test_hook function */
    void *main_fn = &test_hook;
    void *hook_fn = &trace_fn;    
        
    uint32_t jump_address = (uint32_t)(((uintptr_t)hook_fn) - ((uintptr_t)main_fn)) - 5;
    printf("jmp address: %x\n", jump_address);
    
    uint8_t jump_patch[8];
    memcpy(&jump_patch[0], &jmp, sizeof(uint8_t));
    memcpy(&jump_patch[1], &jump_address, sizeof(uint32_t));
    printf("jump patch: %p\n", *((void **)&jump_patch));
    printf("relative jmp address from jump_patch: %x\n", *((uint32_t *)&jump_patch[1]));    

    memcpy(&jump_patch[5], main_fn + 5, 3);
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

    test_hook();

	return 0;
}
