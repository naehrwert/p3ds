# Example RAM dumper.
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

import sys

from p3ds.util import *
from p3ds.ROP import *

def main(argv):
	r = ROP(0x002B0000)

	# Set file object u64 offset to 0
	r.store_i32(0, 0x279004)
	r.store_i32(0, 0x279008)

	# file_open(0x279000, "YS:/DUMP.BIN", 6)
	r.call(0x1B82AC, [0x279000, Ref("fname"), 6], 5)
	# file_write(0x279000, 0x279020, 0x100000, 0x300000)
	r.call(0x1B3B54, [0x279000, 0x279020, 0x100000, 0x300000], 9)

	# Data.
	r.label("fname")
	r.data("YS:/DUMP.BIN".encode('utf-16le') + "\x00\x00")

	rop = r.gen()
	
	#hexdump(rop, base=0x2B0000)

	with open(arv[0], "wb") as f:
		f.write(rop)

if __name__ == "__main__":
	main(sys.argv[1:])
