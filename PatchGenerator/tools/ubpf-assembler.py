#!/usr/bin/env python
"""
eBPF assembler

Very simple single-pass assembler. Only exists to assemble testcases
for the interpreter.
"""

import argparse
import os
import sys

ROOT_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
if os.path.exists(os.path.join(ROOT_DIR, "ubpf")):
    # Running from source tree
    sys.path.insert(0, ROOT_DIR)

import ubpf.assembler

def bytes_to_str_escape(bys):
    return "".join('\\x{:02x}'.format(c) for c in bys)

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', type=argparse.FileType('r'), default='-', nargs='?')
    parser.add_argument('output', type=argparse.FileType('wb'), default='-', nargs='?')
    args = parser.parse_args()

    if args.output.name == "<stdout>" and hasattr(args.output, "buffer"):
        # python 3
        args.output.buffer.write(ubpf.assembler.assemble(args.input.read()))
    else:
        code = ubpf.assembler.assemble(args.input.read())
        args.output.write(code)

if __name__ == "__main__":
    main()
