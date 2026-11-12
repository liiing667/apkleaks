#!/usr/bin/env python3
import io
import json
import logging.config
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import threading

from contextlib import closing
from shutil import which
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

from pyaxmlparser import APK

from apkleaks.colors import color as col
from apkleaks.utils import util

class APKLeaks:
	def __init__(self, args):
		self.apk = None
		self.file = os.path.realpath(args.file)
		self.json = args.json
		self.disarg = args.args
		self.prefix = "apkleaks-"
		self.tempdir = tempfile.mkdtemp(prefix=self.prefix)
		self.main_dir = os.path.dirname(os.path.realpath(__file__))
		self.output = tempfile.mkstemp(suffix=".%s" % ("json" if self.json else "txt"), prefix=self.prefix)[1] if args.output is None else args.output
		self.fileout = open(self.output, "%s" % ("w" if self.json else "a"))
		self.pattern = os.path.join(str(Path(self.main_dir).parent), "config", "regexes.json") if args.pattern is None else args.pattern
		self.jadx = which("jadx") if which("jadx") is not None else os.path.join(str(Path(self.main_dir).parent), "jadx", "bin", "jadx%s" % (".bat" if os.name == "nt" else "")).replace("\\","/")
		self.out_json = {}
		self.scanned = False
		logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

	def apk_info(self):
		return APK(self.file)

	def dependencies(self):
		exter = "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"
		try:
			with closing(urlopen(exter)) as jadx:
				with ZipFile(io.BytesIO(jadx.read())) as zfile:
					zfile.extractall(os.path.join(str(Path(self.main_dir).parent), "jadx"))
			os.chmod(self.jadx, 33268)
		except Exception as error:
			util.writeln(str(error), col.WARNING)
			sys.exit()

	def integrity(self):
		if os.path.exists(self.jadx) is False:
			util.writeln("Can't find jadx binary.", col.WARNING)
			valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
			while True:
				util.write("Do you want to download jadx? (Y/n) ", col.OKBLUE)
				try:
					choice = input().lower()
					if choice == "":
						choice = valid["y"]
						break
					elif choice in valid:
						choice = valid[choice]
						break
					else:
						util.writeln("\nPlease respond with 'yes' or 'no' (or 'y' or 'n').", col.WARNING)
				except KeyboardInterrupt:
					sys.exit(util.writeln("\n** Interrupted. Aborting.", col.FAIL))
			if choice:
				util.writeln("\n** Downloading jadx...\n", col.OKBLUE)
				self.dependencies()
			else:
				sys.exit(util.writeln("\n** Aborted.", col.FAIL))
		if os.path.isfile(self.file):
			try:
				self.apk = self.apk_info()
			except Exception as error:
				util.writeln(str(error), col.WARNING)
				sys.exit()
			else:
				return self.apk
		else:
			sys.exit(util.writeln("It's not a valid file!", col.WARNING))

	def decompile(self):
		util.writeln("** Decompiling APK...", col.OKBLUE)
		args = [self.jadx, self.file, "-d", self.tempdir]
		# Arguments are parsed into tokens but never handed to a shell, so
		# metacharacters in the APK path or disassembler arguments stay literal.
		try:
			if self.disarg:
				args.extend(shlex.split(self.disarg))
		except ValueError as error:
			sys.exit(util.writeln("** Invalid disassembler arguments: %s" % error, col.FAIL))
		try:
			subprocess.run(args, check=False)
		except OSError as error:
			sys.exit(util.writeln("** Failed to run disassembler: %s" % error, col.FAIL))

	def extract(self, name, matches):
		if len(matches):
			stdout = ("[%s]" % (name))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			for secret in matches:
				if name == "LinkFinder":
					if re.match(r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+", secret) is not None:
						continue
					secret = secret[len("'"):-len("'")]
				stdout = ("- %s" % (secret))
				print(stdout)
				self.fileout.write("%s" % (stdout + "\n" if self.json is False else ""))
			self.fileout.write("%s" % ("\n" if self.json is False else ""))
			self.scanned = True

	def scanning(self):
		if self.apk is None:
			sys.exit(util.writeln("** Undefined package. Exit!", col.FAIL))
		util.writeln("\n** Scanning against '%s'" % (self.apk.package), col.OKBLUE)
		self.out_json["package"] = self.apk.package
		self.out_json["results"] = []
		with open(self.pattern) as regexes:
			regex = json.load(regexes)

		findings = {}
		lock = threading.Lock()
		threads = []

		def collect(rule_name, rule_pattern):
			matches = util.finder(rule_pattern, self.tempdir)
			if matches:
				with lock:
					findings.setdefault(rule_name, set()).update(matches)

		# Worker threads only read files and aggregate matches; they never touch
		# the result structures or the output file, so concurrent scans cannot
		# interleave writes or drop entries.
		for name, pattern in regex.items():
			patterns = pattern if isinstance(pattern, list) else [pattern]
			for rule_pattern in patterns:
				try:
					thread = threading.Thread(target=collect, args=(name, rule_pattern))
					threads.append(thread)
					thread.start()
				except KeyboardInterrupt:
					sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
		try:
			for thread in threads:
				thread.join()
		except KeyboardInterrupt:
			sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

		# Serialize on the main thread in a stable, sorted order.
		for name in sorted(findings):
			matches = sorted(findings[name])
			self.out_json["results"].append({"name": name, "matches": matches})
			self.extract(name, matches)

	def cleanup(self):
		shutil.rmtree(self.tempdir)
		if self.scanned:
			self.fileout.write("%s" % (json.dumps(self.out_json, indent=4) if self.json else ""))
			self.fileout.close()
			print("%s\n** Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output, col.HEADER, col.ENDC))
		else:
			self.fileout.close()
			os.remove(self.output)
			util.writeln("\n** Done with nothing. ¯\\_(ツ)_/¯", col.WARNING)
