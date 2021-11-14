# encoding: utf8
from .ebpf_inst import *
import ctypes
import PatchVerify.utils as utils
import PatchGenerator.tools.ubpf.disassembler as dissam

R0 = 0
R9 = 9
R10 = 10
MAX_ITERS = 2048
OP_STOP = 1


class InstWrapper:

	def __init__(self, inst, li):
		self.inst = inst
		self.li = li
		self.sub_insts = []


class SFIBasePass:

	def __init__(self):
		pass


class LoopLimitPass:

	def __init__(self):
		self.out_insts = []
		self.intro_insts = []
		self.stack_used = 80 # sfi stack variable
		self.store_reg = 0 # sfi store reg
		self.max_iteration = MAX_ITERS
		self.processed = False

	def do_pass(self, insts):
		# for idx, inst in enumerate(insts):
		# 	self.intro_insts.append(InstWrapper(inst, idx))
		if not self.check_need_process(insts):
			print("Do not need to perform SFI Loop Pass")
			return [], False
		print("Start to perform SFI Loop Pass...")
		self.set_sfi_reg(insts)
		for idx, inst in enumerate(insts):
			winst = InstWrapper(inst, idx)
			if self.is_backward_jump(inst):
				winst.sub_insts.extend(self.add_sfi_insts())
				self.processed = True
			self.intro_insts.append(winst)
		self.set_sfi_head_tail()
		return self.out_insts, self.processed

	@staticmethod
	def is_jump(inst):
		if BPF_CLASS(inst.opcode) == EBPF_CLS_JMP and inst.opcode != EBPF_OP_EXIT:
			return True
		return False

	@staticmethod
	def is_backward_jump(inst):
		if BPF_CLASS(inst.opcode) == EBPF_CLS_JMP and inst.offset < 0:
			return True
		return False

	def check_need_process(self, insts):
		for inst in insts:
			if self.is_backward_jump(inst):
				return True
		return False

	def set_sfi_reg(self, insts):
		reg_used = 0
		stack_used = 0
		for inst in insts:
			if inst.dst < R10 and inst.src < R10:
				reg_used = max(inst.src, reg_used, inst.dst)
			if BPF_CLASS(inst.opcode) == EBPF_CLS_STX and inst.dst == R10:
				stack_used = max(stack_used, inst.imm)
		reg_used += 1
		stack_used += 16
		if reg_used < R10:
			self.store_reg = reg_used
		else:
			self.store_reg = R0
		self.stack_used = stack_used

	def set_sfi_head_tail(self):
		# set stack initial value
		initial_inst = self.add_sfi_initial()
		print(initial_inst, self.store_reg)
		if initial_inst and len(self.intro_insts) > 0:
			self.intro_insts[0].sub_insts.append(initial_inst)

		# set sfi exit
		sfi_exit = [
			EbpfInst(opcode=EBPF_OP_MOV64_IMM, dst=R0, imm=OP_STOP),
			EbpfInst(opcode=EBPF_OP_LSH64_IMM, dst=R0, imm=32)
		]
		winst = InstWrapper(EbpfInst(opcode=EBPF_OP_EXIT), len(self.intro_insts))
		winst.sub_insts.extend(sfi_exit)
		self.intro_insts.append(winst)
		self.adjust_offset()

	def store_inst(self, stack, reg):
		# https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
		# stxdw [r10-40], r0
		return EbpfInst(opcode=EBPF_OP_STXDW, src=reg, dst=R10, offset=-stack)

	def load_inst(self, stack, reg):
		# ldxdw r0, [r10-40]
		return EbpfInst(opcode=EBPF_OP_LDXDW, dst=reg, src=R10, offset=-stack)

	def add_sfi_initial(self):
		if self.store_reg == R0:
			return EbpfInst(opcode=EBPF_OP_STDW, dst=R10, offset=-self.stack_used, imm=0)
		else:
			return EbpfInst(opcode=EBPF_OP_MOV64_IMM, dst=self.store_reg, imm=0)

	def add_sfi_insts(self):
		if self.store_reg != R0:
			sfi_insts = [
				EbpfInst(opcode=EBPF_OP_ADD64_IMM, dst=self.store_reg, imm=1),
				EbpfInst(opcode=EBPF_OP_JSGT_IMM, dst=self.store_reg, imm=self.max_iteration, offset=0),
			]
		else:
			sfi_insts = [
				self.store_inst(self.stack_used + 8, self.store_reg),
				self.load_inst(self.stack_used, self.store_reg),
				EbpfInst(opcode=EBPF_OP_ADD64_IMM, dst=self.store_reg, imm=1),
				EbpfInst(opcode=EBPF_OP_JSGT_IMM, dst=self.store_reg, imm=self.max_iteration, offset=0),
				self.store_inst(self.stack_used, self.store_reg),
				self.load_inst(self.stack_used + 8, self.store_reg),
			]
		return sfi_insts

	@staticmethod
	def forward_off(cur, jmp):
		# jmp = pc + off + 1
		return jmp - cur - 1

	def search_jmp_off(self, inst, pos):
		assert BPF_CLASS(inst.opcode) == EBPF_CLS_JMP
		# print(len(self.intro_insts), inst.offset, pos + inst.offset + 1)
		jmp_to = self.intro_insts[pos + inst.offset + 1]
		jmp_off = inst.offset
		if inst.offset < 0:
			for i in range(pos, jmp_to.li, -1):
				if len(self.intro_insts[i].sub_insts) > 0:
					jmp_off -= len(self.intro_insts[i].sub_insts)
		else:
			for i in range(pos + 1, jmp_to.li):
				if len(self.intro_insts[i].sub_insts) > 0:
					jmp_off += len(self.intro_insts[i].sub_insts)

		return jmp_off

	def adjust_offset(self):
		exit_pos = len(self.intro_insts)

		# pass 1, normal jump
		for winst in self.intro_insts:
			if self.is_jump(winst.inst):
				winst.inst.offset = self.search_jmp_off(winst.inst, winst.li)
			if len(winst.sub_insts) > 0:
				exit_pos += len(winst.sub_insts)
		exit_pos -= len(self.intro_insts[-1].sub_insts)
		# pass 2, sfi jump, put into output
		cur_pos = 0
		for winst in self.intro_insts:
			if len(winst.sub_insts) > 0:
				for li, inst in enumerate(winst.sub_insts):
					if inst.opcode == EBPF_OP_JSGT_IMM:
						pos = cur_pos + (li + 1)
						# print("exit jmp: ", pos, li, winst.li, exit_pos)
						inst.offset = self.forward_off(pos, exit_pos)
					self.out_insts.append(inst)
				cur_pos += len(winst.sub_insts)
			cur_pos += 1
			self.out_insts.append(winst.inst)


class SFIPostProcess:

	def __init__(self, insts):
		self.insts = insts
		self.passes = []
		self.out_insts = None
		self.__setup_passes()

	def __setup_passes(self):
		self.passes.append(LoopLimitPass())

	def process(self):
		in_insts = self.insts
		processed = False
		for pas in self.passes:
			out_insts, pre = pas.do_pass(in_insts)
			in_insts = out_insts
			processed |= pre
		self.out_insts = in_insts
		return processed

	def disassemble(self, out_path):
		with open(out_path, "rb") as fp:
			byte_code = fp.read()
			print(dissam.disassemble(byte_code))
			print("Please paste the following ebpf bytecode to Runtime:")
			dump_ebpf_code(byte_code)

	def save_sfi_bin(self, out_fi):
		with open(out_fi, "wb") as fp:
			for inst in self.out_insts:
				fp.write(inst)
		self.disassemble(out_fi)


def verify_sfi(out_fi):
	pass


def do_sfi_pass(in_fi, out_fi):
	insts = load_ebpf_bin(in_fi)
	sfi = SFIPostProcess(insts)
	ret = sfi.process()
	if ret:
		print(f"Add SFI Post process to the eBPF bytecode: {out_fi}")
		sfi.save_sfi_bin(out_fi)
		verify_sfi(out_fi)
