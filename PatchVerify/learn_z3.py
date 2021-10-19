# coding: utf-8

from z3 import *
# https://theory.stanford.edu/~nikolaj/programmingz3.html
def lz3():
	x = Real('x')
	y = Real('y')
	s = Solver()
	s.add(x + y > 5, x > 1, y > 1, x < 0)
	print(s.check())
	if s.check() == sat:
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
	lz3()
	# lz1()
	lz2()