# encoding: utf8
import sys
import logging


def usage():
	print("Usage: python3 PatchVerifier/main.py code.bin")


def parse_args():
	if len(sys.argv) < 2:
		usage()
		return
	return sys.argv[1]


def main(ebpf_bytes):
	logging.info("Start to verify eBPF bytecode: %s", ebpf_bytes)
	from .ebpf_verify import do_verify
	do_verify(ebpf_bytes)


if __name__ == "__main__":
	ebpf_bin = parse_args()
	main(ebpf_bin)
