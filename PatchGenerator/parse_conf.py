# coding: utf-8
import yaml
import logging
import json
import re

logger = logging.getLogger("PatchGenerator")


class ParsePatchConf:

	def __init__(self, bin_path):
		self.conf = {}
		self.symbol_map = None
		self.symbol_file = None
		self.bin_path = bin_path

	def __parse_patch_options(self, conf_file):
		with open(conf_file, "r") as stream:
			try:
				opts = yaml.safe_load(stream)
				self.__parse_patch_basic_settings(opts)
				self.__parse_patch_running_settings(opts)
				self.__parse_patch_trigger_settings(opts)
				self.__parse_patch_compile_settings(opts)
			except yaml.YAMLError as exc:
				print(exc)
				return False
		return True

	def __parse_patch_basic_settings(self, opts):
		"""  """
		pts = {"filter_patch": 1, "code_replace_patch": 2}
		patch_type = opts.get("patch_type")
		version = opts.get("version", 1)
		if patch_type in pts:
			self.conf["patch_type"] = pts[patch_type]
		self.conf["version"] = version
		self.conf["bin"] = self.bin_path

	def __parse_patch_running_settings(self, opts):
		rts = {"Interpreter": 1, "JIT": 2}
		pri = {"default": 0, "low": 1, "medium": 2, "high": 3}
		run_type = opts.get("run_type")
		self.conf["run_type"] = rts.get(run_type, 1)
		priority = opts.get("priority", "default")
		self.conf["run_priority"] = pri.get(priority, 0)
		self.conf["iterations"] = self.must_be_int(opts, "iteration_threshold", 2048)

	def __parse_patch_trigger_settings(self, opts):
		triggers = {"FIXED": 1, "KPROBE": 2, "FPB": 3}
		trigger_type = opts.get("trigger_type")
		self.conf["trigger_type"] = triggers.get(trigger_type)
		trigger_point = self.must_have(opts, "trigger_point")
		func = trigger_point.get("function_position")
		sym = self.must_have(trigger_point, "symbol_file")
		if sym.endswith(".map"):
			self.symbol_map = sym
		else:
			self.symbol_file = sym
		addr = self.__parse_func_addr(func)
		if not addr:
			raise Exception(f"Failed to locate func ({func}) addr in symbol file ({sym})")
		v = int(addr, 16)
		self.conf["install_addr"] = v
		logger.info(f"Patch install to: {addr} ({v})")

	def __parse_patch_compile_settings(self, opts):
		compile_conf = opts.get("variable_map") or {}
		if "symbol_file" in compile_conf:
			self.symbol_file = compile_conf["symbol_file"]
		pass

	def must_have(self, opts, key):
		if key not in opts:
			raise Exception(f"Patch Deploy Conf should have property: {key}")
		return opts.get(key)

	def must_be_int(self, opts, key, default=0):
		try:
			return int(opts.get(key))
		except:
			if default == -1:
				raise Exception(f"Patch Deploy Conf property ({key}) should be int.")
			return default

	def __parse_func_addr(self, func):
		if not self.symbol_map:
			return None
		with open(self.symbol_map, "r") as fp:
			for li in fp:
				items = li.strip().split()
				if func in items:
					return items[0]

	def parse_compile_entry(self, key, conf):
		if not self.symbol_file:
			return None
		with open(self.symbol_file, "r") as fp:
			for li in fp:
				if conf in li:
					pass

	def gen(self, conf_file, deploy_conf):
		if not self.__parse_patch_options(conf_file):
			logger.error("Failed to gen patch deploy conf.")
			return
		with open(deploy_conf, "w") as fp:
			fp.write(json.dumps(self.conf))


def gen_patch_deploy_conf(bin_file, conf_file):
	deploy_conf = bin_file.replace(".bin", ".json")
	logger.info(f"gen deploy conf to: {deploy_conf}")
	ParsePatchConf(bin_file).gen(conf_file, deploy_conf)
