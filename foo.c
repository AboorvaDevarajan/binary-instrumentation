#include <stdio.h>
 
void test_shared(void);
void *override_test_shared(void);


void *override_test_shared(void)
{
    
    puts("Hello, I am a hooked function in shared library");
}


void test_shared(void)
{
    puts("Hello, I am a shared library");
}

int *far_hook() {

	printf("In far hooked function... \n");
	return 55;
}   
