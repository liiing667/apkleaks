#!/usr/bin/env python3
import os
import re
import stat
import sys
from apkleaks.colors import color as col

# Files larger than this are skipped so scans stay bounded within the
# disassembler output directory.
MAX_SCAN_FILE_SIZE = 50 * 1024 * 1024

class util:
	@staticmethod
	def write(message, color):
		sys.stdout.write("%s%s%s" % (color, message, col.ENDC))

	@staticmethod
	def writeln(message, color):
		util.write(message + "\n", color)

	@staticmethod
	def finder(pattern, path, max_size=MAX_SCAN_FILE_SIZE):
		matcher = re.compile(pattern)
		found = []
		for fp, dirnames, files in os.walk(path, followlinks=False):
			# Do not descend into symlinked directories, which could point
			# outside the disassembler output directory.
			dirnames[:] = [dn for dn in dirnames if not os.path.islink(os.path.join(fp, dn))]
			for fn in files:
				filepath = os.path.join(fp, fn)
				try:
					filestat = os.lstat(filepath)
					if not stat.S_ISREG(filestat.st_mode):
						continue
					if filestat.st_size > max_size:
						continue
					with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
						for line in handle:
							mo = matcher.search(line)
							if mo:
								found.append(mo.group())
				except OSError:
					continue
		return sorted(list(set(found)))
