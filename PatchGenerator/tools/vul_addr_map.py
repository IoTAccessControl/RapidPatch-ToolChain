#-*-coding:utf-8-*-
import os
import sys

"""
DONE:

TODO:
- read conf from yaml
- parse .lst and .map to find address of variable or function
- modify the MARCO in code
- compile the code

"""

def get_vul_func_addr(file_name, func_name):
	file_name = os.path.abspath(file_name)
	tag = "<{}>:".format(func_name)
	with open(file_name, "r") as fp:
		for idx, li in enumerate(fp):
			if tag in li:
				print("find line: ", idx, li)
				addr = li.split(" ")
				print("{} addr: 0x{}".format(func_name, addr[0]))

	return addr

def replace_marcos():
	pass

def main():
	if len(sys.argv) < 3:
		print("usage: python update_server/addr.py ..\\..\\VulDevices\\zephyr-app\\build\\zephyr\\zephyr.lst coap_packet_parse")
		return
	list_file = sys.argv[1]
	func = sys.argv[2]
	# print(list_file, func)
	get_vul_func_addr(list_file, func)

if __name__ == "__main__":
	main()
