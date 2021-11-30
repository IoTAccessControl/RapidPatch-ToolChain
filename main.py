# encoding: utf8
import sys
import logging

CMD_GEN = "gen"
CMD_VERIFY = "verify"
CMD_MONITOR = "monitor"


def usage():
	print("Usage: python3 main.py [gen code.c out.bin | verify code.bin | monior serial-port]")


def init_logger():
	logging.basicConfig(level=logging.INFO, format='%(name)s -> %(message)s')


def main():
	if len(sys.argv) < 3:
		usage()
		return
	init_logger()
	cmd, args = sys.argv[1], sys.argv[2:]
	if cmd == CMD_GEN:
		import PatchGenerator.main as generator
		if len(args) < 2:
			generator.usage()
			return
		generator.main(args[0], args[1])
	elif cmd == CMD_VERIFY:
		import PatchVerify.main as verifier
		verifier.main(args[0])
	elif cmd == CMD_MONITOR:
		import PatchDeploy.main as deploy
		deploy.main(args[0])


if __name__ == "__main__":
	main()
