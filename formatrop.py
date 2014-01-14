# Hackityhack ROP formatter.
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
import darm # https://github.com/jbremer/darm

# Read RAM dump.
f = open("DUMP.BIN", "rb")
dump = f.read()
f.close()

# Read decrypted launcher.
f = open("Launcher.dat", "rb")
data = f.read()
f.close()

# Format entries.
for i in xrange(len(data)/4):
	v = struct.unpack("<I", data[i*4:i*4+4])[0]
	inst = ""
	if v >= 0x100000 and v <= 0x252000: # This is gonna work just fine.
		if v & 1:
			addr = (v - 0x100000) & 0xFFFFFFFE
			inst = darm.disasm_thumb(struct.unpack("<H", dump[addr:addr+2])[0])
		else:
			addr = v - 0x100000
			inst = darm.disasm_armv7(struct.unpack("<I", dump[addr:addr+4])[0])
		if inst == None:
			print "{0:08X}: {1:08X}".format(i*4, v)
		else:
			print "{0:08X}: {1:08X} - {2}".format(i*4, v, inst)
	else:
		print "{0:08X}: {1:08X}".format(i*4, v)
