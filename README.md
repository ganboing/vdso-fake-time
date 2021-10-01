# vdso-fake-time

Apply an -offset to `CLOCK_REALTIME` via vdso hooking. It works by relocating the `[vvar]` and `[vdso]` VMA to a different address, shadow the original `[vdso]` and patch instructions on the shadowed `[vdso]`.

Compile/link as shared library and load via `LD_AUDIT` or `LD_PRELOAD`. offset in seconds is passed via `MY_VDSO_CFG` variable.

```
$ date
Fri Oct  1 00:00:00 PDT 2021

$ MY_VDSO_CFG=31536000 LD_PRELOAD=hook.so date
Fri Oct  1 00:00:00 PDT 2020
```
