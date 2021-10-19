#-*-coding:utf-8-*-
import os
import sys
import capstone
import binascii

"""
https://www.capstone-engine.org/lang_python.html
"""

DEFAULT_FILE = "jit.bin"

def disassemble(code):
	cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN)
	cs.detail = True
	data = binascii.a2b_hex(code)
	for i in cs.disasm(data, 0):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def dism(s):
	try:
		disassemble(s)
	except Exception as ex:
		import traceback
		traceback.print_exc()

def main():
	while True:
		cmd = sys.stdin.readline()
		cmd = cmd.strip().split(' ')
		if cmd[0] == 'q':
			return
		if cmd[0] == 'r':
			with open(DEFAULT_FILE, "r") as fp:
				code = fp.read().strip()
				dism(code)
				# print(code)
		else:
			dism(cmd[0])

if __name__ == "__main__":
	main()
