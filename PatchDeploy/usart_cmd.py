# coding: utf-8
import sys
import io
import os
import json
import logging
import ctypes
import struct
from serial.tools import list_ports
import serial.tools.miniterm as miniterm

import serial

logger = logging.getLogger('DeployTool')


class CMD:
	QUIT = 'q'
	INSTALL = 'install'


class PatchPacket(ctypes.Structure):
	pack = 2
	_fields_ = [
		('patch_type', ctypes.c_ushort),
		('code_len', ctypes.c_ushort),
		('patch_point', ctypes.c_uint), # addr or patch id
		# ('code', ctypes) # ebpf bytecode
	]

	@staticmethod
	def from_conf(conf):
		pkt = PatchPacket(conf["trigger_type"], len(conf["bin"]), conf["install_addr"])
		return bytearray(pkt) + conf["bin"]


class MyTerm(miniterm.Miniterm):

	def __init__(self, ser):
		super(MyTerm, self).__init__(ser, echo=True)

	def writer(self):
		text = ''
		try:
			while self.alive:
				try:
					c = self.console.getkey()
				except KeyboardInterrupt:
					self.exit()
				if not self.alive:
					break
				if c == self.exit_character:
					self.stop()  # exit app
					break
				else:
					text += c
					if c == '\n':
						self.handle_command(text)
						text = ''

					if self.echo:
						echo_text = c
						for transformation in self.tx_transformations:
							echo_text = transformation.echo(echo_text)
						self.console.write(echo_text)
		except:
			self.alive = False
			raise

	def install_patch(self, patch_path, text):
		if not os.path.exists(patch_path):
			self.console.write(f"\n[PY]: Failed: patch conf {patch_path} is not exist!")
			return False
		self.console.write(f"\n[PY]: start to install patch: {patch_path}")
		self.send_text(text)
		patch = self.load_patch(patch_path)
		data = self.get_patch_bytes(patch)
		pos = 0
		send_size = 50
		self.console.write(f"\nTotal Data: {len(data)}\n")
		while pos + send_size < len(data):
			# print("size:" + str(len(data)) + "   " + str(int(data[0])) + " " + str(int(data[1])))
			self.serial.write(data[pos:pos+send_size])
			self.serial.flush()
			pos += send_size
		self.serial.write(data[pos:pos + send_size])
		self.serial.flush()
		# for by in data:
		# 	print("send: " + chr(by))

	def load_patch(self, patch_path):
		with open(patch_path, "r") as fp:
			conf = json.load(fp)
		bin_path = conf["bin"]
		conf["bin"] = self.read_bin(bin_path)
		sz = len(conf["bin"])
		self.console.write(f"\nPatch Size: {sz}\n")
		pkt = PatchPacket.from_conf(conf)
		return bytearray(pkt) + conf["bin"]

	def read_bin(self, bin_path):
		# logger.info(f"\nload bin file: {bin_path}\n")
		with open(bin_path, "rb") as fp:
			return fp.read()

	def get_patch_bytes(self, patch):
		sz = len(patch)
		# little endian
		bys = struct.pack('B', int(sz / 256))
		bys += struct.pack('B', sz % 256)
		bys += patch
		return bys

	def handle_command(self, text):
		cmds = text.split()
		if len(cmds) > 1:
			cmd, args = cmds[0], cmds[1:]
		elif len(cmds) == 1:
			cmd, args = cmds[0], []
		else:
			self.console.write("[PY]: Please enter command! Press h to show help!")
			return
		if cmd == CMD.QUIT:
			self.exit()
		elif cmd == CMD.INSTALL and len(args) > 0:
			self.install_patch(args[0], text)
			return

		self.send_text(text)

	def send_text(self, text):
		for transformation in self.tx_transformations:
			text = transformation.tx(text)
		text = self.tx_encoder.encode(text)
		self.serial.write(text)

	def exit(self):
		self.stop()
		exit(-1)


def run_monitor(serial_port):
	ports = list(list_ports.grep(serial_port))
	if len(ports) < 1:
		ava_ports = '\n\t'.join([str(item) for item in list_ports.comports()])
		logger.error(f"Available ports: \n\t{ava_ports}")
		logger.error(f"Failed to open serial port: {serial_port}")
		exit(-1)
	port = ports[0]
	ser = serial.serial_for_url(port.device, 115200, timeout=1, do_not_open=True)
	logger.info(f"Connect to port: {port}")
	ser.open()

	myterm = MyTerm(ser)
	myterm.raw = False
	myterm.exit_character = miniterm.unichr(myterm.exit_character)
	myterm.menu_character = miniterm.unichr(myterm.menu_character)
	myterm.set_rx_encoding('UTF-8')
	myterm.set_tx_encoding('UTF-8')

	sys.stderr.write('--- MyTerm on {p.name}  {p.baudrate},{p.bytesize},{p.parity},{p.stopbits} ---\n'.format(
		p=myterm.serial))
	sys.stderr.write('--- Quit: {} | Menu: {} | Help: {} followed by {} ---\n'.format(
		miniterm.key_description(myterm.exit_character),
		miniterm.key_description(myterm.menu_character),
		miniterm.key_description(myterm.menu_character),
		miniterm.key_description('\x08')))

	myterm.start()
	try:
		myterm.join(True)
	except KeyboardInterrupt:
		pass
	sys.stderr.write("\n--- exit ---\n")
	myterm.join()
	myterm.close()

	# sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser, 1), encoding='ascii', newline=u'\n')
	# sio.write("h")
	# sio.flush()
	# print(sio.readline()[:-1])
