import re
import os

# ctags -x --c-kinds=f --_xformat="%N %S" -R --languages=c > result.txt
# ctags -x --c-kinds=f --_xformat="%t %N %S %F" -R --languages=c > zephyr_1141_func.txt
# cscope -d -f db.csc -L -2 '.*' -v
# cscope -b -u -k -f db.csc -R

# include_strs = ['#include "hotpatch/include/fixed_patch_points.h"\n',\
#                     '#include "hotpatch/include/iotpatch.h"\n',\
#                     '#include "hotpatch/include/fixed_patch_point_def.h"\n']

include_strs = ["extern int fixed_patch_point_hanlder();\n", \
				'#define FIXED_OP_PASS 0x00010000 \n', \
				'#define PATCH_FUNCTION_ERR_CODE \\ \n', \
				'\tint _ret_code_ = fixed_patch_point_hanlder();\\ \n', \
				'\tif (_ret_code_ == FIXED_OP_PASS) {\\ \n', \
				'\treturn _ret_code_;\\ \n', \
				'\t} \n', \
				]

MACRO_str = '\tPATCH_FUNCTION_ERR_CODE;\n'


def takeSecond(elem):
	return elem[1]


def takeFirst(elem):
	return elem[0]


instrumented_func_num = 0
removed_func_num = 0

cur_file_path = ""
cur_file_instruments = []
return_black_list = ["esp_pthread_cfg_t", "pthread_t", 'XML_Expat_Version', "search_result", "nghttp2_hd_nv", "nghttp2_vec", "mallinfo"]
white_list = ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"]
ret_types = set()


def add_instrument(funclist_file_path, path_cons, ret_type_cons, ret_cons=True, remove=False):
	global instrumented_func_num
	global cur_file_path
	global cur_file_instruments
	instrumented_func_num = 0
	with open(funclist_file_path, "r", encoding='utf-8') as ifile:
		instrumented_func_num = 0
		lines = ifile.readlines()
		line_cnt = 0
		tmp_cnt = 0
		for line in lines:
			line_cnt += 1
			line = line.strip("\n")
			function_name = ""
			paras = ""
			file_path = ""
			return_type = ""

			# parameter
			if "(" in line:
				# print(line)
				# print("------>" + line[0])
				# m = re.search(r'^(\S+) (\S+) (\S+)( \S+)? (\S+) \((.*?)\)', line)
				m = re.search(r'(\S+) (\S+) (\S+) (.+ )?(\S+) \((.*?)\)', line)
				if m:
					# print((m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)))
					file_path = m.group(1)
					line_number = int(m.group(2))
					if m.group(4):
						return_type = m.group(3) + m.group(4)
					else:
						return_type = m.group(3)

					# if "__asm" in return_type:
					#     print(return_type)

					function_name = m.group(5)
					paras = m.group(6)
			# print((function_name, paras, file_path))
			else:
				continue

			met_path_cons = False
			for con in path_cons:
				if con in file_path:
					met_path_cons = True
					break

			if not met_path_cons:
				continue

			# met_path_cons = True
			# for con in path_cons:
			# if con in file_path:
			# met_path_cons = False
			# break
			# if not met_path_cons:
			# continue

			tmp_cnt += 1

			# returntype
			if "typename:" in line or "struct:" in line:
				m = None
				if "typename:" in line:
					m = re.search(r'typename:(\S+)( *)?', line)
				elif "struct:" in line:
					m = re.search(r'struct:(\S+)( *)?', line)
				if m:
					return_type = m.group(1) + m.group(2)
					# if "INLINE" in return_type or "*" in return_type or "asm" in return_type:
					#     continue
					if "INLINE" in return_type or "asm" in return_type:
						continue
				else:
					continue
			else:
				continue

			met_ret_type_cons = False
			return_type = return_type.strip()

			for con in ret_type_cons:
				if con in return_type:
					met_ret_type_cons = True
					break

			if not ret_cons:
				met_ret_type_cons = True

			for block in return_black_list:
				if block in return_type:
					met_ret_type_cons = False
					break

			if return_type not in white_list:
				if "_t" in return_type and "*" not in return_type:
					met_ret_type_cons = False

			if not met_ret_type_cons:
				continue
			ret_types.add(return_type)
			if cur_file_path == "":
				cur_file_path = file_path
				cur_file_instruments = []
				cur_file_instruments.append([line_number, function_name])
			elif cur_file_path == file_path:
				cur_file_instruments.append([line_number, function_name])
				if line_cnt == len(lines):
					do_instrument(remove)
			else:
				do_instrument(remove)
				cur_file_path = file_path
				cur_file_instruments = []
				cur_file_instruments.append([line_number, function_name])
				if line_cnt == len(lines):
					do_instrument(remove)
		print(tmp_cnt)


def do_instrument(remove=False):
	global cur_file_path
	global cur_file_instruments
	global instrumented_func_num
	if "cborpretty" in cur_file_path:
		print(cur_file_path)
		print(cur_file_instruments)
	cur_file_instruments.sort(key=takeFirst, reverse=True)
	# print(cur_file_instruments)

	if remove:
		curlines = []
		with open("./" + cur_file_path + ".backup", "r", encoding="utf-8") as backup_file:
			# print(file_path)
			curlines = backup_file.readlines()
			with open("./" + cur_file_path, "w", encoding="utf-8") as cur_file:
				cur_file.writelines(curlines)
		return

	# Instrument function
	# 1. Add include
	# 2. Intrument macro/invocation
	curlines = []
	try:
		with open("./" + cur_file_path, "r", encoding="utf-8") as cur_file:
			# print(file_path)
			curlines = cur_file.readlines()

			# Backup
			with open("./" + cur_file_path + ".backup", "w", encoding="utf-8") as backup_file:
				backup_file.writelines(curlines)

			# print(curlines)
			# print("----->")
			for instru in cur_file_instruments:
				line_base = instru[0] - 1
				# print(instru[0])
				# print(line_base, "---->", curlines[line_base])
				while line_base < len(curlines) - 1 and line_base <= instru[0] + 5:
					if "{" in curlines[line_base]:
						if "}" in curlines[line_base]:
							break
						if MACRO_str not in curlines[line_base + 1]:
							curlines.insert(line_base + 1, MACRO_str)
							instrumented_func_num += 1
						break
					else:
						line_base += 1

			if include_strs[0] not in curlines[0]:
				for i in range(len(include_strs)):
					curlines.insert(0, include_strs[len(include_strs) - 1 - i])

		with open("./" + cur_file_path, "w", encoding="utf-8") as cur_file:
			cur_file.writelines(curlines)
	except Exception as err:
		print(err)


def get_sub_sys():
	files = os.listdir("components")
	ret = []
	for item in files:
		if item.startswith("esp") or item.startswith("xtensa") or item.startswith("free"):
			# continue
			pass
		ret.append("components/" + item)
	print(ret)
	os.exit(0)
	return ret


# get_sub_sys()

print("Start to remove...")
os.system("python3 remove_instrument.py")
print("Remove is Done!")

ins_dirs1 = ["components/lwip", "components/coap", "components/tcp_transport", 'components/wifi_provisioning',
			 'components/wpa_supplicant']  # net
ins_dirs2 = ["components/lwip", "components/coap", "components/tcp_transport", 'components/wifi_provisioning',
			 'components/wpa_supplicant', 'components/app_trace', 'components/app_update', 'components/asio',
			 'components/bt', 'components/cbor', 'components/cmock',
			 'components/coap', 'components/console', 'components/cxx', 'components/driver', 'components/efuse',
			 'components/expat',
			 'components/fatfs', 'components/idf_test', 'components/jsmn',
			 'components/json', 'components/libsodium', 'components/lwip',
			 'components/mdns', 'components/mqtt', 'components/nvs_flash',
			 'components/openssl', 'components/partition_table', 'components/perfmon', 'components/protobuf-c',
			 'components/pthread', 'components/riscv', 'components/sdmmc',
			 'components/spiffs', 'components/tcpip_adapter',
			 'components/tinyusb', 'components/touch_element', 'components/ulp', 'components/unity', 'components/vfs',
			 'components/wear_levelling', 'components/wifi_provisioning']
ins_dirs3 = ["components/lwip", "components/coap", "components/tcp_transport", 'components/wifi_provisioning',
			 'components/wpa_supplicant', 'components/app_trace', 'components/app_update', 'components/asio',
			 'components/bt', 'components/cbor', 'components/cmock',
			 'components/coap', 'components/console', 'components/cxx', 'components/driver', 'components/efuse',
			 'components/expat',
			 'components/fatfs', 'components/idf_test', 'components/jsmn',
			 'components/json', 'components/libsodium', 'components/lwip',
			 'components/mdns', 'components/mqtt', 'components/nvs_flash',
			 'components/openssl', 'components/partition_table', 'components/perfmon', 'components/protobuf-c',
			 'components/pthread', 'components/riscv', 'components/sdmmc',
			 'components/spiffs', 'components/tcpip_adapter',
			 'components/tinyusb', 'components/touch_element', 'components/ulp', 'components/unity', 'components/vfs',
			 'components/wear_levelling', 'components/wifi_provisioning',
			 


'components/esp_https_server', 'components/esp_local_ctrl', 'components/esp_timer',
 
 'components/esp_gdbstub', 'components/esp_ipc', 'components/esp_http_client', 
 'components/esp_pm', 'components/esp_serial_slave_link', 'components/mbedtls', 'components/esptool_py', 'components/esp_netif', 
 'components/nghttp', 'components/esp_hid', 'components/esp-tls', 'components/esp_event', 'components/esp_https_ota', 
  
  
			 ]
"""

warning list:  'components/esp_hw_support',

{'components/esp_https_server', 'components/spi_flash', 'components/esp_local_ctrl', 'components/esp_timer',
 'components/esp_common', 'components/esp_rom', 
 'components/esp_gdbstub', 'components/esp_ipc', 'components/esp_http_client', 
 'components/esp_pm', 'components/esp_serial_slave_link', 'components/mbedtls', 'components/esptool_py', 'components/esp_netif', 
 'components/esp_hw_support', 'components/nghttp', 'components/esp_hid', 'components/esp-tls', 'components/esp_event', 'components/esp_https_ota', 

 'components/esp_ringbuf', 'components/log', 'components/esp_http_server', 'components/esp_wifi', 'components/esp_eth', 'components/esp_system',
 'components/freemodbus', 'components/freertos', 
'components/protocomm', 'components/xtensa', 'components/esp_adc_cal', 'components/hal', 'components/esp_websocket_client', 'components/espcoredump'}
"""

ins_dirs = ins_dirs3

add_instrument("zephyr_test1.txt", ins_dirs,
			   ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"], ret_cons=False,
			   remove=False)
print("\n".join(ret_types))
# add_instrument("zephyr_test1.txt", ["zephyr/subsys/net/lib/coap"], ["int", "u32_t", "u8_t"], remove=True)
print(instrumented_func_num)
# remove_instrument("zephyr_1141_func.txt", ["zephyr/subsys"], ["int", "u32_t", "u32_t"])         
# print(removed_func_num)
