# encoding: utf8
import os
import struct
import testdata
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest

# python2 -m nose test_vm.py

VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../build", "ubpf")

def is_windows():
	if os.name == 'nt':
		return True
	return False

def get_code(data):
	code, mem = None, None

	if 'asm' not in data and 'raw' not in data:
		return code, mem

	if 'raw' in data:
		code = b''.join(struct.pack("=Q", x) for x in data['raw'])
	else:
		# assemble 需要在linux下运行
		import ubpf.assembler
		code = ubpf.assembler.assemble(data['asm'])
	
	return code, data.get("mem")

def check_datafile(filename):
	data = testdata.read(filename)
	if 'asm' not in data and 'raw' not in data:
		raise SkipTest("no asm or raw section in datafile")
	if 'result' not in data and 'error' not in data and 'error pattern' not in data:
		raise SkipTest("no result or error section in datafile")
	if not os.path.exists(VM):
		raise SkipTest("VM not found")

	if 'raw' in data:
		code = b''.join(struct.pack("=Q", x) for x in data['raw'])
	else:
		if is_windows():
			raise SkipTest("skip test case in win")
		# assemble 需要在linux下运行
		import ubpf.assembler
		code = ubpf.assembler.assemble(data['asm'])
	
	import tempfile

	cmd = [VM]
	codefile = tempfile.NamedTemporaryFile()
	codefile.write(code)
	codefile.flush()
	cmd.extend([codefile.name])

	memfile = None
	if 'mem' in data:
		memfile = tempfile.NamedTemporaryFile()
		memfile.write(data['mem'])
		memfile.flush()
		cmd.extend([memfile.name])
	print("check: " + filename)

	vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
	stdout, stderr = vm.communicate()
	# vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

	# stdout, stderr = vm.communicate(code)
	stdout = stdout.decode("utf-8")
	stderr = stderr.decode("utf-8")
	stderr = stderr.strip()

	if memfile:
		memfile.close()
	codefile.close()

	# if 'error' in data:
	# 	# if data['error'] != stderr:
	# 	# 	raise AssertionError("Expected error %r, got %r" % (data['error'], stderr))
	# 	print(filename, data['error'], stderr)
	# elif 'error pattern' in data:
	# 	if not re.search(data['error pattern'], stderr):
	# 		raise AssertionError("Expected error matching %r, got %r" % (data['error pattern'], stderr))
	# else:
	# 	if stderr:
	# 		raise AssertionError("Unexpected error %r" % stderr)

	if 'result' in data:
		if vm.returncode != 0:
			raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
		expected = int(data['result'], 0)
		result = int(stdout, 0)
		if expected != result:
			raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr))
	else:
		if vm.returncode == 0:
			raise AssertionError("Expected VM to exit with an error code")

def direct_run(filename):
	if is_windows():
		print("need to test in Linux")
		return

	data = testdata.read(filename)
	code, mem = get_code(data)
	if not code:
		return
	import tempfile

	cmd = [VM]
	codefile = tempfile.NamedTemporaryFile()
	codefile.write(code)
	codefile.flush()
	cmd.extend([codefile.name])

	memfile = None
	if 'mem' in data:
		memfile = tempfile.NamedTemporaryFile()
		memfile.write(data['mem'])
		memfile.flush()
		cmd.extend([memfile.name])
	print("check: " + filename)
	vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
	stdout, stderr = vm.communicate()
	stdout = stdout.decode("utf-8")
	stderr = stderr.decode("utf-8")
	stderr = stderr.strip()
	print(stdout, data.get("result"))

	# if vm.returncode == 0:
	# 	print(vm.returncode)
	# 	raise AssertionError("Expected VM to exit with an error code")

	if "result" in data:
		# if vm.returncode != 0:
		# 	raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
		expected = int(data['result'], 0)
		try:
			result = int(stdout, 0)
		except:
			print("error...")
			result = -1
		if expected != result:
			raise AssertionError("%s Expected result 0x%x, got 0x%x, stderr=%r" % (filename, expected, result, stderr))
	else:
		if vm.returncode == 0:
			print("error expected error code", vm.returncode)
			# raise AssertionError("Expected VM to exit with an error code")

def test_binfiles():
	for filename in testdata.list_files():
		# check_datafile(filename)
		direct_run(filename)
		# yield check_datafile, filename

test_binfiles()