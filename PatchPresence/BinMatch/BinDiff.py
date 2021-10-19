import angr, archinfo
import os
import struct
import yaml
import sys
import logging

# Change this when you need to see more info during CFG construction
# DEBUG | INFO | WARNING | ERROR | CRITICAL 
logging.getLogger('angr').setLevel('CRITICAL')

# Usage
# python3 BinDiff.py conf.yaml target_lib target_firmware
# python3 BinDiff.py conf.yaml zephyr.elf zephyr.elf
SYS_ARGV_NUM = 4

FUNCTION_GROUP_NAME = "functions"

def parse_yaml_conf(conf):
	codes = {}
	with open(conf, "r") as stream:
		try:
			groups = yaml.safe_load(stream)
			for gp, fis in groups.items():
				codes[gp] = []
				if not fis:
					continue
				for fi in fis:
					codes[gp].append(fi)
		except yaml.YAMLError as exc:
			print(exc)
	print("all files", codes)
	return codes

if __name__ == "__main__":
    assert (len(sys.argv) == SYS_ARGV_NUM), "Invalid argument num!"

    codes = parse_yaml_conf("conf.yaml")
    functions_to_diff = codes[FUNCTION_GROUP_NAME]

    # Get angr project
    proj_lib = angr.Project(sys.argv[2], load_options={"auto_load_libs":False})
    proj_target = angr.Project(sys.argv[3], load_options={"auto_load_libs":False})

    # Get static CFG
    cfgs_lib = proj_lib.analyses.CFGFast()
    cfgs_target = proj_target.analyses.CFGFast()

    # Get map from function name to addr
    # Assume that the function name is unique
    lib_func_map = {}
    for addr,func in cfgs_lib.kb.functions.items():
        lib_func_map[func.name] = addr
    target_func_map = {}
    for addr,func in cfgs_target.kb.functions.items():
        target_func_map[func.name] = addr
    
    # Function Diffing
    for f in functions_to_diff:
        print(f'------> Diffing function {f}')
        if f not in lib_func_map:
            print(f'{f} not found in lib file!')
            continue
        if f not in target_func_map:
            print(f'{f} not found in target file')
            continue
        addr_lib = lib_func_map[f]
        addr_target = target_func_map[f]
        function_lib = cfgs_lib.kb.functions.function(addr_lib)
        function_target = cfgs_target.kb.functions.function(addr_target)

        function_diffs = angr.analyses.bindiff.FunctionDiff(function_lib, function_target)

        print("Probably identical: ", function_diffs.probably_identical)
        print("Matched Blocks:", function_diffs.block_matches)
        print("Identical Blocks: ", function_diffs.identical_blocks)
        for bb_pair in function_diffs.block_matches:
            print("---->")
            bb0 = proj_lib.factory.block(bb_pair[0].addr)
            bb0.pp()
            print("<----")
            bb1 = proj_target.factory.block(bb_pair[1].addr)
            bb1.pp()

        print("Unmatched Blocks: ", function_diffs.unmatched_blocks)
        print("****>")
        for bb in function_diffs.unmatched_blocks[0]:
            bb0 = proj_lib.factory.block(bb.addr)
            bb0.pp()
        print("<****")
        for bb in function_diffs.unmatched_blocks[1]:
            bb1 = proj_target.factory.block(bb.addr)
            bb1.pp()
        


