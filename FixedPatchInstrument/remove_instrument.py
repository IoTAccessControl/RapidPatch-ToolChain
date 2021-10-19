import re

# ctags -x --c-kinds=f --_xformat="%N %S" -R --languages=c > result.txt
# ctags -x --c-kinds=f --_xformat="%t %N %S %F" -R --languages=c > zephyr_1141_func.txt
# cscope -d -f db.csc -L -2 '.*' -v
# cscope -b -u -k -f db.csc -R

# include_strs = ['#include "hotpatch/include/fixed_patch_points.h"\n',\
#                     '#include "hotpatch/include/iotpatch.h"\n',\
#                     '#include "hotpatch/include/fixed_patch_point_def.h"\n']

include_strs = ["extern int fixed_patch_point_hanlder();\n",\
                    '#define FIXED_OP_PASS 0x00010000 \n',\
                    '#define PATCH_FUNCTION_ERR_CODE \\ \n',\
                    '\tint _ret_code_ = fixed_patch_point_hanlder();\\ \n',\
                    '\tif (_ret_code_ == FIXED_OP_PASS) {\\ \n',\
                    '\treturn _ret_code_;\\ \n',\
                    '\t} \n',\
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
            #     if con in file_path:
            #         met_path_cons = False
            #         break
            # if not met_path_cons:
            #     continue

            tmp_cnt+=1

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

            for con in ret_type_cons:
                if con in return_type:
                    met_ret_type_cons = True
                    break

            if not ret_cons:
                met_ret_type_cons = True

            if not met_ret_type_cons:
                continue


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
    # print(cur_file_path)
    cur_file_instruments.sort(key=takeFirst, reverse=True)
    # print(cur_file_instruments)
    if "log" in cur_file_path:
        print(cur_file_path)

    if remove:
        try:
            curlines = [] 
            with open("./" + cur_file_path, "r", encoding="utf-8") as cur_file:
                curlines = cur_file.readlines()
                cur_index = len(curlines) - 1
                while cur_index >= 0:
                    if MACRO_str in curlines[cur_index]:
                        del curlines[cur_index]
                    cur_index -= 1
                if len(curlines) > 0 and include_strs[0] in curlines[0]:
                    for i in range(len(include_strs)):
                        curlines.remove(curlines[0])
            with open("./" + cur_file_path, "w", encoding="utf-8") as cur_file:
                cur_file.writelines(curlines)

            with open("./" + cur_file_path + ".backup", "r", encoding="utf-8") as cur_file:
                curlines = cur_file.readlines()
                cur_index = len(curlines) - 1
                while cur_index >= 0:
                    if MACRO_str in curlines[cur_index]:
                        del curlines[cur_index]
                    cur_index -= 1
                if len(curlines) > 0 and include_strs[0] in curlines[0]:
                    for i in range(len(include_strs)):
                        curlines.remove(curlines[0])
            with open("./" + cur_file_path + ".backup", "w", encoding="utf-8") as cur_file:
                cur_file.writelines(curlines)
            return
        except Exception as err:
            # print(err)
            return

    # Instrument function
    # 1. Add include
    # 2. Intrument macro/invocation
    curlines = []
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

ins_dirs1 = ["components/lwip", "components/coap", "components/tcp_transport"]  # net
ins_dirs2 = ['components/app_trace', 'components/app_update', 'components/asio', 'components/bootloader',
			 'components/bootloader_support', 'components/bt', 'components/cbor', 'components/cmock', 'components/coap',
			 'components/console', 'components/cxx', 'components/driver', 'components/efuse', 'components/expat',
			 'components/fatfs', 'components/hal', 'components/heap', 'components/idf_test', 'components/jsmn',
			 'components/json', 'components/libsodium', 'components/log', 'components/lwip', 'components/mbedtls',
			 'components/mdns', 'components/mqtt', 'components/newlib', 'components/nghttp', 'components/nvs_flash',
			 'components/openssl', 'components/partition_table', 'components/perfmon', 'components/protobuf-c',
			 'components/protocomm', 'components/pthread', 'components/riscv', 'components/sdmmc', 'components/soc',
			 'components/spiffs', 'components/spi_flash', 'components/tcpip_adapter', 'components/tcp_transport',
			 'components/tinyusb', 'components/touch_element', 'components/ulp', 'components/unity', 'components/vfs',
			 'components/wear_levelling', 'components/wifi_provisioning', 'components/wpa_supplicant']
ins_dirs3 = ["components/"]  # all

ins_dirs = ins_dirs3

# add_instrument("zephyr_test1.txt", ["zephyr/subsys", "zephyr/kernel", "zephyr/lib", "zephyr/drivers"], ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"], ret_cons=False, remove=True)
# add_instrument("zephyr_test1.txt", ["zephyr/subsys"], ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"], remove=True)

# add_instrument("zephyr_test1.txt", ["zephyr/IoTPatch", "build", "iotpatch"], ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"], ret_cons=False, remove=True)

add_instrument("zephyr_test1.txt", ins_dirs, ["int", "u64_t", "u32_t", "u16_t", "u8_t", "void", "char", "bool", "size_t"], ret_cons=False, remove=True)

# add_instrument("zephyr_test1.txt", ["zephyr/subsys/net/lib/coap"], ["int", "u32_t", "u8_t"], remove=True)
print(instrumented_func_num)       
# remove_instrument("zephyr_1141_func.txt", ["zephyr/subsys"], ["int", "u32_t", "u32_t"])         
# print(removed_func_num) 