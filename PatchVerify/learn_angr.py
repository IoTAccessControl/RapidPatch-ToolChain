# coding: utf-8
import angr
import claripy

"""
https://kqueue.org/blog/2015/05/26/mini-mc/

https://github.com/xiw/mini-mc/blob/master/ffs_eqv.py

https://github.com/fiberx/fiber

"""

def run1():
	"""
	https://reverseengineering.stackexchange.com/questions/20570/angr-solve-for-function-return-value
	:return:
	"""
	proj = angr.Project("../test-files/bin/c1", auto_load_libs=False)
	filter_func = 0x0100003ee0
	arg = claripy.BVS('arg', 3 * 8)
	state = proj.factory.entry_state(addr=filter_func, args=arg)
	st = proj.factory.blank_state(addr=filter_func, symbolic_sp=True)
	print(st.arch.registers["eax"])
	st.options.add(angr.options.CALLLESS)
	state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
	print(state.solver.eval(arg))
	simgr = proj.factory.simulation_manager(state)
	states = []
	sm = proj.factory.simgr(thing=states)
	print(filter_func == simgr.active[0].addr)

	val = angr.types.parse_types("struct args { char *s; char *e; int len;};")
	func =proj.factory.callable(filter_func)
	angr.types.register_types(val)
	# print(func, val)
	# print(func(val))
	print(state.mem[filter_func])
	@proj.hook(proj.entry)
	def my_hook(state):
		print("Welcome to execution!")
	simgr.use_technique(angr.exploration_techniques.DFS())
	simgr.explore(num_find=3)
	# simgr.run()
	# simgr.deadended[0].solver.add(simgr.deadended[0].regs.eax == 1)

	print(simgr.deadended[0].solver.eval(arg, cast_to=bytes))
	print(simgr.found)


def main():
	print("run angr learn")
	run1()


if __name__ == "__main__":
	main()
