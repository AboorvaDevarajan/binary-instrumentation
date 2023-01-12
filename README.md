# Binary Instrumentation Patching

```
------------------------------------
Hooking function...
------------------------------------
before hooking the test_hook() function
calling test_hook()...
In testing hook function... 
returned from test_hook()...
------------------------------------
Patching the test_hook() function using binary instrumentation
------------------------------------
jmp address: ffffffe0
jump patch: 0xffffffe0e9
relative jmp address from jump_patch: ffffffe0
jump_patch: 0x4009c2ffffffe0e9
nearest page from main_fn 0x400741: 0x400000
Successfully Hooked... 
In trace function
```


