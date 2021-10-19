# encoding: utf8
from .ebpf_inst import *
import ctypes
import PatchVerify.utils as utils


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


class BaseChecker:

	def __init__(self):
		self.insts = None
		self.pc = 0
		self.result = 0
		self.reg = [0] * 512  # reg + stack
		self.error_exit = False
		self.has_error = False
		self.is_exit = False
		self.mem = [0]
		self.mem_size = 0
		self.safe = True
		self.errors = []

	def reset(self):
		self.pc = 0
		self.result = 0
		self.reg = [0] * 512  # reg + stack

	def check(self, insts, mem=None, mem_size=None):
		self.reset()
		self.insts = insts
		self.mem = mem
		self.mem_size = mem_size
		while self.pc < len(self.insts):
			self._interpret()
			self.pc += 1

			# finish or coredump
			if self.is_exit:
				break
			if self.error_exit and self.has_error:
				break
		return self.result

	def summary_result(self):
		pass

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

	def is_dangerous(self, msg):
		self.errors.append("Dangerous -> " + msg)

	def is_unsafe(self, msg):
		self.safe = False
		self.errors.append("Unsafe -> " + msg)

	def _interpret(self):
		opcode = self.cur_inst.opcode
		print("Not Implement!", self.pc, opcode)

	def get_result(self):
		return self.safe, "\n".join(self.errors)


class DangerousInstWarningChecker(BaseChecker):

	def __init__(self):
		super().__init__()
		self.last_mem_op = None

	def _interpret(self):
		opcode = self.cur_inst.opcode
		if opcode == EBPF_OP_STDW or opcode == EBPF_OP_STXW or \
			opcode == EBPF_OP_STXH or opcode == EBPF_OP_STXB:
			# TODO: precisely identify the border with abstract interpreter
			# ptr = u32(u32(self.DST) + u32(self.OFF))
			# if ptr > self.stack:
			# 	pass
			self.is_unsafe("Writing to memory!!! Inst: " + str(opcode) + " At Inst: " + str(self.pc))


class LoopChecker(BaseChecker):

	def __init__(self):
		super().__init__()
		self.errors = []

	def _interpret(self):
		opcode = self.cur_inst.opcode
		if opcode == EBPF_OP_JSGT_REG or opcode == EBPF_OP_JLE_REG or \
				opcode == EBPF_OP_JEQ_REG or opcode == EBPF_OP_JSET_REG or \
				opcode == EBPF_OP_JNE_REG or opcode == EBPF_OP_JSGT_REG or \
				opcode == EBPF_OP_JSGE_REG or opcode == EBPF_OP_JSLT_REG or \
				opcode == EBPF_OP_JSLE_REG:
			self.is_dangerous("Jump to Register!!! Inst: " + str(opcode) + " At Inst: " + str(self.pc))
		elif self.OFF < 0:
			self.is_dangerous("Contains Loops. Backward Jump!")

	def get_result(self):
		if len(self.errors) > 0:
			print("===========================> LoopChecker")
			print("There are unsafe operations that need to be constrained by SFI:")
			print("\n".join(self.errors))
		return True, None


class Verifier:

	def __init__(self, insts):
		self.insts = insts
		self.checkers = []

	def do_verify(self):
		for checker in self.checkers:
			checker.check(self.insts)

	def add_checker(self, *checker: BaseChecker):
		for ch in checker:
			print("Setup Checker", type(ch))
			self.checkers.append(ch)

	def report(self):
		failed = False
		for checker in self.checkers:
			res, report = checker.get_result()
			if not res:
				failed = True
				print(report)

		if failed:
			print("----> Warning. Current Patch is not a filter-patch!!!")
		else:
			print("----> Cheers. Current Patch is a filter-patch!!!")


def do_verify(ebpf_bytes):
	insts = load_ebpf_bin(ebpf_bytes)
	verifier = Verifier(insts)
	verifier.add_checker(DangerousInstWarningChecker(), LoopChecker())
	verifier.do_verify()
	verifier.report()
