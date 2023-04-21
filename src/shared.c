#include <stdio.h>
 
void shared_foo(void);
void *override_shared_foo(void);


void *override_shared_foo(void)
{
    puts("override : in override_shared_foo()..");
}
void shared_foo(void)
{
    puts("original : in shared_foo()..");
}