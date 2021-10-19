# coding: utf-8
__author__ = "fripSide"

import ctypes

class EbpfArgFrame(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		("r0", ctypes.c_uint32),
		("r1", ctypes.c_uint32),
		("r2", ctypes.c_uint32),
		("r3", ctypes.c_uint32),
		("r12", ctypes.c_uint32),
		("lr", ctypes.c_uint32),
		("pc", ctypes.c_uint32),
		("xpsr", ctypes.c_uint32),
	]

	def setup(self):
		pass

class EbpfMem:
	"""
	将ebpf_args根据type annotation转成一块mem，将周围标成redzone
	 shadow mem
	"""
	@staticmethod
	def c_array_mem(arr: list):
		pass


def get_test_arg():
	arg = EbpfArgFrame()
	arg.r0 = 1
	arg.r1 = 2
	arr = bytearray(arg)
	mem = []
	for b in arr:
		mem.append(b)
	return mem