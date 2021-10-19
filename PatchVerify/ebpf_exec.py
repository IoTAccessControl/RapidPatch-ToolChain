# coding: utf-8
from ebpf_inst import *
import ebpf_args
import ctypes
import utils

def ptr_val(buf):
	"""
	Little Edian
	:param buf:
	:return:
	"""
	val = 0
	b = 1
	for p in buf:
		val += int(p) * b
		b *= 10
	return int(val)


class WriteInstVisitor:

	def visit_write_inst(self):
		pass

	def on_write_mem(self):
		pass

	def on_read_mem(self):
		pass


class Interpreter:
	def __init__(self, insts):
		self.insts = insts
		self.pc = 0
		self.result = 0
		self.reg = [0] * 512  # reg + stack
		self.error_exit = False
		self.has_error = False
		self.is_exit = False
		self.mem = [0]
		self.mem_size = 0

	def reset(self):
		self.pc = 0
		self.result = 0
		self.reg = [0] * 512  # reg + stack
		# print(self.reg)

	def exec(self, mem, mem_size):
		self.reset()
		self.mem = mem
		self.mem_size = mem_size
		while self.pc < len(self.insts):
			self.__interpret()
			self.pc += 1

			# finish or coredump
			if self.is_exit:
				break
			if self.error_exit and self.has_error:
				break
		return self.result

	@property
	def DST(self):
		return self.reg[self.cur_inst.dst]

	@DST.setter
	def DST(self, val):
		# self.reg[self.cur_inst.dst] = 0 if val is None else val
		self.reg[self.cur_inst.dst] = val

	@property
	def SRC(self):
		return self.reg[self.cur_inst.src]

	@SRC.setter
	def SRC(self, val):
		self.reg[self.cur_inst.src] = val

	@property
	def IMM(self):
		return self.cur_inst.imm

	@property
	def OFF(self):
		return self.cur_inst.offset

	@property
	def cur_inst(self):
		return self.insts[self.pc]

	@property
	def next_inst(self):
		return self.insts[self.pc + 1]

	@property
	def log_inst(self):
		return f"pc={self.pc} src={self.cur_inst.src} dst={self.cur_inst.dst}"

	def check_div_zero(self, val):
		if val == 0:
			return False
		return True

	def __OP_LE(self):
		pass

	def __OP_BE(self):
		pass

	def read_mem_ptr(self, ptr, sz):
		val = None
		if sz == EBPF_SIZE_DW:
			val = ptr_val(self.mem[ptr:ptr + 8])
		elif sz == EBPF_SIZE_W:
			val = ptr_val(self.mem[ptr:ptr + 4])
		elif sz == EBPF_SIZE_H:
			val = ptr_val(self.mem[ptr:ptr + 2])
		elif sz == EBPF_SIZE_B:
			val = ptr_val(self.mem[ptr:ptr + 1])
		# if val is None:
		# 	print(ptr, sz)
		# utils.log_print("mem_ptr ret", ptr, sz, self.mem[ptr:ptr + 8], val, self.log_inst)
		return val

	def write_mem_ptr(self, ptr, val, sz):
		if len(self.mem) > ptr + sz:
			for i in range(sz):
				self.mem[ptr + i] = val % 256
				val /= 256

	def __interpret(self):
		opcode = self.cur_inst.opcode
		if opcode == EBPF_OP_ADD_IMM:
			self.DST = u32(u32(self.DST) + u32(self.IMM))
		elif opcode == EBPF_OP_ADD_REG:
			self.DST = u32(u32(self.DST) + u32(self.SRC))
		elif opcode == EBPF_OP_SUB_IMM:
			self.DST = u32(u32(self.DST) - u32(self.IMM))
		elif opcode == EBPF_OP_SUB_REG:
			self.DST = u32(u32(self.DST) - u32(self.SRC))
		elif opcode == EBPF_OP_MUL_IMM:
			self.DST = u32(u32(self.DST) * u32(self.IMM))
		elif opcode == EBPF_OP_MUL_REG:
			self.DST = u32(u32(self.DST) * u32(self.SRC))
		elif opcode == EBPF_OP_DIV_IMM:
			if self.check_div_zero(self.IMM):
				self.DST = u32(u32(self.DST) / u32(self.IMM))
		elif opcode == EBPF_OP_DIV_REG:
			if self.check_div_zero(self.SRC):
				self.DST = u32(u32(self.DST) / u32(self.SRC))
		elif opcode == EBPF_OP_OR_IMM:
			self.DST = u32(u32(self.DST) | u32(self.IMM))
		elif opcode == EBPF_OP_OR_REG:
			self.DST = u32(u32(self.DST) | u32(self.SRC))
		elif opcode == EBPF_OP_AND_IMM:
			self.DST = u32(u32(self.DST) & u32(self.IMM))
		elif opcode == EBPF_OP_AND_REG:
			self.DST = u32(u32(self.DST) & u32(self.SRC))
		elif opcode == EBPF_OP_LSH_IMM:
			self.DST = u32(u32(self.DST) << u32(self.IMM))
		elif opcode == EBPF_OP_LSH_REG:
			self.DST = u32(u32(self.DST) << u32(self.SRC))
		elif opcode == EBPF_OP_RSH_IMM:
			self.DST = u32(u32(self.DST) >> u32(self.IMM))
		elif opcode == EBPF_OP_RSH_REG:
			self.DST = u32(u32(self.DST) >> u32(self.SRC))
		elif opcode == EBPF_OP_NEG:
			self.DST = u32(-self.DST)
		elif opcode == EBPF_OP_MOD_IMM:
			self.DST = u32(u32(self.DST) % u32(self.IMM))
		elif opcode == EBPF_OP_MOD_REG:
			self.DST = u32(u32(self.DST) % u32(self.SRC))
		elif opcode == EBPF_OP_XOR_IMM:
			self.DST = u32(u32(self.DST) ^ u32(self.IMM))
		elif opcode == EBPF_OP_XOR_REG:
			self.DST = u32(u32(self.DST) ^ u32(self.SRC))
		elif opcode == EBPF_OP_MOV_IMM:
			self.DST = u32(self.IMM)
		elif opcode == EBPF_OP_MOV_REG:
			self.DST = u32(self.SRC)
		elif opcode == EBPF_OP_ARSH_IMM:
			self.DST = u64(u32(s32(self.DST) >> self.IMM))
		elif opcode == EBPF_OP_ARSH_REG:
			self.DST = u64(u32(s32(self.DST) >> u32(self.SRC)))
		elif opcode == EBPF_OP_LE:
			self.__OP_LE()
		elif opcode == EBPF_OP_BE:
			self.__OP_BE()
		if opcode == EBPF_OP_ADD64_IMM:
			self.DST = u64(u64(self.DST) + u64(self.IMM))
		elif opcode == EBPF_OP_ADD64_REG:
			self.DST = u64(u64(self.DST) + u64(self.SRC))
		elif opcode == EBPF_OP_SUB64_IMM:
			self.DST = u64(u64(self.DST) - u64(self.IMM))
		elif opcode == EBPF_OP_SUB64_REG:
			self.DST = u64(u64(self.DST) - u64(self.SRC))
		elif opcode == EBPF_OP_MUL64_IMM:
			self.DST = u64(u64(self.DST) * u64(self.IMM))
		elif opcode == EBPF_OP_MUL64_REG:
			self.DST = u64(u64(self.DST) * u64(self.SRC))
		elif opcode == EBPF_OP_DIV64_IMM:
			if self.check_div_zero(self.IMM):
				self.DST = u64(u64(self.DST) / u64(self.IMM))
		elif opcode == EBPF_OP_DIV64_REG:
			if self.check_div_zero(self.SRC):
				self.DST = u64(u64(self.DST) / u64(self.SRC))
		elif opcode == EBPF_OP_OR64_IMM:
			self.DST = u64(u64(self.DST) | u64(self.IMM))
		elif opcode == EBPF_OP_OR64_REG:
			self.DST = u64(u64(self.DST) | u64(self.SRC))
		elif opcode == EBPF_OP_AND64_IMM:
			self.DST = u64(u64(self.DST) & u64(self.IMM))
		elif opcode == EBPF_OP_AND64_REG:
			self.DST = u64(u64(self.DST) & u64(self.SRC))
		elif opcode == EBPF_OP_LSH64_IMM:
			self.DST = u64(u64(self.DST) << u64(self.IMM))
		elif opcode == EBPF_OP_LSH64_REG:
			self.DST = u64(u64(self.DST) << u64(self.SRC))
		elif opcode == EBPF_OP_RSH64_IMM:
			self.DST = u64(u32(self.DST) >> u64(self.IMM))
		elif opcode == EBPF_OP_RSH64_REG:
			self.DST = u64(u64(self.DST) >> u64(self.SRC))
		elif opcode == EBPF_OP_NEG64:
			self.DST = u64(-self.DST)
		elif opcode == EBPF_OP_MOD64_IMM:
			self.DST = u64(u32(self.DST) % u32(self.IMM))
		elif opcode == EBPF_OP_MOD64_REG:
			self.DST = u64(u32(self.DST) % u32(self.SRC))
		elif opcode == EBPF_OP_XOR64_IMM:
			self.DST = u64(u32(self.DST) ^ u32(self.IMM))
		elif opcode == EBPF_OP_XOR64_REG:
			self.DST = u64(u32(self.DST) ^ u32(self.SRC))
		elif opcode == EBPF_OP_MOV64_IMM:
			self.DST = u64(self.IMM)
		elif opcode == EBPF_OP_MOV64_REG:
			self.DST = u64(self.SRC)
		elif opcode == EBPF_OP_ARSH64_IMM:
			self.DST = u64(s64(self.DST) >> self.IMM)
		elif opcode == EBPF_OP_ARSH64_REG:
			self.DST = u64(s64(self.DST) >> u64(self.SRC))
		elif opcode == EBPF_OP_LDXDW or opcode == EBPF_OP_LDXW \
				or opcode == EBPF_OP_LDXH or opcode == EBPF_OP_LDXB:
			# utils.log_print(self.SRC, self.cur_inst.src, self.reg, self.OFF)
			ptr = u32(u32(self.SRC) + u32(self.OFF))
			self.DST = self.read_mem_ptr(ptr, BPF_SIZE(opcode))
		elif opcode == EBPF_OP_STDW or opcode == EBPF_OP_STXW \
				or opcode == EBPF_OP_STXH or opcode == EBPF_OP_STXB:
			ptr = u32(u32(self.DST) + u32(self.OFF))
			self.write_mem_ptr(ptr, self.SRC, BPF_SIZE(opcode))
		elif opcode == EBPF_OP_LDDW:
			self.DST = u64(u32(self.IMM) | u64(u32(self.next_inst.imm)) << 32)

		# JMP instructions
		elif opcode == EBPF_OP_JA:
			self.pc += self.OFF
		elif opcode == EBPF_OP_JEQ_REG:
			if self.DST == self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JEQ_IMM:
			if self.DST == self.IMM:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JGT_IMM:
			if self.DST > u32(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JGT_REG:
			if self.DST > self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JLT_IMM:
			if self.DST < u32(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JLT_REG:
			if self.DST < self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JLE_IMM:
			if self.DST <= u32(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JLE_REG:
			if self.DST <= self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSET_IMM:
			if self.DST & self.IMM:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSET_REG:
			if self.DST & self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JNE_IMM:
			if self.DST != self.IMM:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JNE_REG:
			if self.DST != self.SRC:
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSGT_IMM:
			if s64(self.DST) > s64(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSGT_REG:
			if s64(self.DST) > s64(self.SRC):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSGE_IMM:
			if s64(self.DST) >= s64(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSGE_REG:
			if s64(self.DST) >= s64(self.SRC):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSLT_IMM:
			if s64(self.DST) < s64(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSLT_REG:
			if s64(self.DST) < s64(self.SRC):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSLE_IMM:
			if s64(self.DST) <= s64(self.IMM):
				self.pc += self.OFF
		elif opcode == EBPF_OP_JSLE_REG:
			if s64(self.DST) <= s64(self.SRC):
				self.pc += self.OFF
		elif opcode == EBPF_OP_CALL:
			pass
		elif opcode == EBPF_OP_EXIT:
			self.result = self.reg[0]
			self.is_exit = True
		else:
			utils.log_print("Unsupported Inst", self.log_inst)


def main():
	inst = EbpfInst()
	# print(ctypes.sizeof(EbpfInst))
	# print(EbpfInst.opcode, EbpfInst.src, EbpfInst.dst, EbpfInst.offset, EbpfInst.imm)
	# print(inst.size())
	# print(inst.size())
	bin_fi = "../test-files/ebpf.bin"
	insts = load_ebpf_bin(bin_fi)
	# for inst in insts:
	# 	print(inst.opcode, inst.src)
	from ebpf_test import code2 as code
	insts = load_ebpf_code(code)
	# print(3 & 5, 3 | 9, 1 << 2, 8 >> 2)
	mem = ebpf_args.get_test_arg()
	res = Interpreter(insts).exec(mem, 200)
	print(res)


if __name__ == "__main__":
	main()
