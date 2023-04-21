Binary Instrumentation Patching Implementation

```
main: Started Binary Instrumentation (bistro) Patching...
main: Initializing patching structures..
main: Before applying binary instrumentation patch...
original: in foo()..
original: in bar()..
original : in shared_foo()..
main: mmap: installing bistro hook for foo = 0x40083c for event 0x1 orig : 0x400851
main: return value is NULL
main: bistro patch applied...
main: success.. done
main: calling original functions
main: mmap: installing bistro hook for bar = 0x400816 for event 0x2 orig : 0x40082b
main: return value is NULL
main: bistro patch applied...
main: success.. done
main: calling original functions
main: mmap: installing bistro hook for shared_foo = 0x7fb8b0e615e9 for event 0x2 orig : 0x4006f0
main: return value is NULL
main: bistro patch applied...
main: success.. done
main: calling original functions
main: After applying binary instrumentation patch...
original: in foo()..
original: in bar()..
original : in shared_foo()..                                                         6ms
```
