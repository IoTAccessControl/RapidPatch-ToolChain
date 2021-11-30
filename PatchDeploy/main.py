# coding: utf-8
import sys


def usage():
	print("Usage: python3 PatchDeploy/main.py serial-port")


def parse_args():
	if len(sys.argv) < 2:
		usage()
		return
	return sys.argv[1]


def main(serial_port):
	from PatchDeploy.usart_cmd import run_monitor
	run_monitor(serial_port)


if __name__ == "__main__":
	main(parse_args())
