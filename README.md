
## Introduction
This repository contains the toolchians of RapidPatch. 
```
-------------\
  | - CppVerifier, The cpp version eBPF verifier.   
  | - FiedPatchInstument, A tool for instrumenting the RTOS source code to add the fixed patch points.   
  | - PatchGenerator,  A tool for compiling eBPF source code.   
  | - PatchPresence, A tool for checking if target firmware have the same vulnerability with the sample RTOS/Library.  
  | - PatchVerifier, The RapidPatch's eBPF verifier.   
  | - test-files, Test eBPF codes.   
```

## Usage

### Run eBPF Patch Generator
You can run it with the following commands,   
``` bash
python3 main.py gen test-files/patches/test1.c test-files/bin/test1.bin
```
You can find more examples in RapidPatch-Runtime/update_server/patch_code.   

If you failed to run the commends with this error message, you need to install a llvm with bpf target, i.e., the newest llvm.   
``` bash
/bin/sh: llc: command not found
```
Patch Generator need eBPF llvm backend to compile the eBPF code with the following command,    
``` bash
clang -O2 -emit-llvm -c {src} -o - | llc -march=bpf -filetype=obj -o code.o
```

### Run eBPF Verifier
You can run it with the following command,   
``` bash
python3 main.py verify test-files/bin/test1.bin
```
It will tell you if the patch is a filter-patch,
```bash
# test1.bin
There are unsafe operations that need to be constrained by SFI:
Dangerous -> Jump to Register, Inst: 109 At Inst: 5
Dangerous -> Jump to Register, Inst: 109 At Inst: 27
----> Cheers. Current Patch is a filter-patch!!!

# test2.bin
Unsafe -> Writing to memory!!! Inst: 99 At Inst: 1
----> Warning. Current Patch is not a filter-patch!!!
```

