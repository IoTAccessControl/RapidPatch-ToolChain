# coding: utf-8
__author__ = "fripSide"
import ntpath
from inspect import getframeinfo, stack


def log_print(*args):
	caller = getframeinfo(stack()[1][0])
	fi = ntpath.basename(caller.filename)
	print(fi, caller.lineno, ":", *args)