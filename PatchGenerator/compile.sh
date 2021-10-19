#!/bin/bash
fi=$1
python3 tools/compile_code.py -s patch_code/${fi}.ebpf.c -o patch_bin/${fi}.bin