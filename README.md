
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


## About SFI
Our first version SFI is implemented directly in the libebpf. However, it seesm to be deleted durbing branch merging. [Git History](github.com/IoTAccessControl/RapidPatch-Runtime-AE/blob/448fe8fdac6fa14b600257ddc85656af6f56e3a3/libebpf/src/ebpf_vm.c#L520).   

Now, to make it easier to use, we have added a new SFI post process compiling pass for our toolchain and you can now get the eBPF bytecode with SFI for the filter patches with unbounded loop.  The maxium loop iterations is 2048 (set in PatchVerify/sfi_post_process.py:10)

To compile it,
```
python3 main.py gen test-files/patches/test3.c test-files/bin/test3.bin
python3 main.py verify test-files/bin/test3.bin

# then you need to copy the output bytecode to:
Runtime/hotpatch/src/ebpf_test.c:329
```

To test it,  
```
Start Qemu Test
IoTPatch Cli Usage: run [idx] | trigger [cve] | patch [cve] | vm [vid]
run 0: Test FPB breakpoint add
run 1: Test FPB patch trigger
run 2: Clear all bpkt and patch
run 3: Run eva test
run 4: Start patch service
run 5: Invoke the vulnerable function for CVE-2020-10062
run 6: Load patch at the fixed patch point for CVE-2020-10062
run 7: Invoke the vulnerable function for CVE-2020-17445 (Unbounded loop test)
$ vm 13

# the result is OP=1 Ret=0
```

Use fixed patch points to test SFI,  
```
$ run 7
run cmd: 7 {Invoke the vulnerable function for CVE-2020-17445 (Unbounded loop test)}
init_patch_sys: 1
start to load patch: 3
load fixed patch AMNESIA33_cve_2020_17445 dummy_pico_ipv6_process_destopt_patch success!
addr ground-truth bug:0x08002b91 test:0x08002c2d 
Patch instruction num 41
try to get patch at: 0xfffffffc
ret:0xffffffff
op code:0x00000001 
FILTER_DROP
The return code of the buggy function is 0
```

The command for compiling the bytecode with SFI.
```
# compile: 
python3 main.py verify test-files/bin/cve.bin
# copy to Runtime/hotpatch/src/fixed_patch_load.c:73
```
