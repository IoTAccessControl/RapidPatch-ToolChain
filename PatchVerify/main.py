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


def main(ebpf_bin_file):
	logging.info("Start to verify eBPF bytecode: %s", ebpf_bin_file)
	from .ebpf_verify import do_verify
	not_filter = do_verify(ebpf_bin_file)

	if not not_filter:
		from .sfi_post_process import do_sfi_pass
		out_fi = ebpf_bin_file.replace(".bin", "_sfi.bin")
		do_sfi_pass(ebpf_bin_file, out_fi)


if __name__ == "__main__":
	ebpf_bin = parse_args()
	main(ebpf_bin)
