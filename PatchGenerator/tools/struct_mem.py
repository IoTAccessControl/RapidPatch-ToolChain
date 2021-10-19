# encoding: utf-8
import os
import sys
from ctypes import *
from elftools.elf.elffile import ELFFile
from capstone import *
import ubpf.disassembler

""""
struct skb_buf {
	u32 protocol;
	u32 len;
	u32 pkt[10];
};

"""

# https://docs.python.org/3/library/ctypes.html
class SkbBuf(Structure):
	_fields_ = [('protocol', c_uint), ('len', c_uint), ('pkt', c_uint)]

# https://medium.com/sector443/python-for-reverse-engineering-1-elf-binaries-e31e92c33732
def dump_elf_text(prog):
	# 从clang编译的二进制中导出prog
	with open(prog, "rb") as fp:
		elf = ELFFile(fp)
		for section in elf.iter_sections():
			print(hex(section['sh_addr']), section.name)
		code = elf.get_section_by_name('.text')
		ops = code.data()
		print(code.data())
		# addr = code['sh_addr']
		# md = Cs(CS_ARCH_X86, CS_MODE_64)
		# for i in md.disasm(ops, addr):        
			# print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
		out = "prog.bin"
		with open(out, "wb") as fp:
			fp.write(ops)
		print("write binary to ", out)
		write_binary(ops)

def write_binary(ops):
	with open("prog.bin", "wb") as fp:
		fp.write(ops)
	print("disassemble: ")
	print(ubpf.disassembler.disassemble(ops))

def compile(prog):
	code = "code.o"
	cmd = " clang -O2 -target bpf -c {} -o {}".format(prog, code)
	os.system(cmd)
	print("compile", cmd)
	return code

def main(prog):
	code = compile(prog)
	dump_elf_text(code)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage py ebpf.o")
		exit(0)
	main(sys.argv[1])
