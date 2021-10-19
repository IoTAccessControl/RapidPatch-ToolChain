# coding: utf-8

import os
import z3
import sys
from multiprocessing import Lock

"""
Tiny symbolic executor from xwang
"""

solver = z3.Solver()
lock = Lock()

def mc_log(s):
	# "atomic" print; less concern about performance
	with lock:
		print("[%s] %s" % (os.getpid(), s), file=sys.stderr)

def mc_assume(b):
	return solver.add(b)

def mc_model_repr(self):
	decls = sorted(self.decls(), key=str)
	return ", ".join(["%s = %s" % (k, self[k]) for k in decls])

def sched_fork(self):
	pid = os.fork()
	if pid:
		solver.add(self)
		r = True
		mc_log("assume (%s)" % (str(self),))
	else:
		solver.add(z3.Not(self))
		r = False
		mc_log("assume ¬(%s)" % (str(self),))
	if solver.check() != z3.sat:
		mc_log("unreachable")
		sys.exit(0)
	return r

setattr(z3.BoolRef, "__bool__", sched_fork)
setattr(z3.BoolRef, "__nonzero__", getattr(z3.BoolRef, "__bool__"))

def fun_cmp():
	def ffs_newlib(x):
		if x == 0:
			return 0
		i = 0
		while True:
			t = (1 << i) & x
			i = i + 1
			if t != 0:
				return i

	def ffs_uclibc(i):
		n = 1
		if (i & 0xffff) == 0:
			n = n + 16
			i = i >> 16
		if (i & 0xff) == 0:
			n = n + 8
			i = i >> 8
		if (i & 0x0f) == 0:
			n = n + 4
			i = i >> 4
		if (i & 0x03) == 0:
			n = n + 2
			i = i >> 2
		if i != 0:
			return n + ((i + 1) & 0x01)
		return 0

	x = z3.BitVec("x", 32)
	print(ffs_newlib(x))
	assert ffs_newlib(x) == ffs_uclibc(x)

def my_test():
	x = z3.BitVec("x", 32)
	y = z3.BitVec("y", 32)
	def test_me(x, y):
		z = 2 * x
		if z == y:
			if y == x + 10:
				# assert False
				return 0
		return 1
	t = test_me(x, y)
	if solver.check() == sat and t == 0:
		print(solver.model())

from z3 import *
# https://theory.stanford.edu/~nikolaj/programmingz3.html
def lz3():
	x = Real('x')
	y = Real('y')
	s = Solver()
	s.add(x + y > 5, x > 1, y > 1)
	print(s.check())
	print(s.model())

def lz2():
	x, y = Ints('x y')
	s = Solver()
	s.add((x % 4) + 3 * (y / 2) > x - y)
	print(s.sexpr())
	print(s.check())
	print(s.model())

if __name__ == "__main__":
	# my_test()
	# lz3()
	lz2()
	# fun_cmp()
	if solver.check() == z3.sat:
		msg = "%s: %s" % ("finish", solver.model())