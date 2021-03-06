# encoding: utf8
import os
import sys
import logging


def usage():
	print("Patch Generator need two arguments [src=code_path, dst=bin_path]!")
	print("Usage: python3 PatchGenerator/main.py code.c code.bin")


def parse_args():
	if len(sys.argv) < 3:
		usage()
		return
	return sys.argv[1], sys.argv[2]


def main(code, dst):
	from PatchGenerator.tools.compile_code import do_compile
	from PatchGenerator.parse_conf import gen_patch_deploy_conf
	logging.info("Start to compile eBPF source code file: %s  Save to: %s", code, dst)
	do_compile(code, dst)
	conf = code.replace(".c", ".yaml")
	if os.path.exists(conf):
		gen_patch_deploy_conf(dst, conf)


if __name__ == "__main__":
	code_fi, dst_fi = parse_args()
	main(code_fi, dst_fi)
