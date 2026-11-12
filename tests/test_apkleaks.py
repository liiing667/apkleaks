#!/usr/bin/env python3
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apkleaks.apkleaks import APKLeaks
from apkleaks.utils import util


FAKE_JADX = r'''#!/usr/bin/env python3
import json
import os
import sys

argv_path = os.environ["FAKE_JADX_ARGV"]
with open(argv_path, "w", encoding="utf-8") as handle:
	json.dump(sys.argv[1:], handle)

out_dir = sys.argv[sys.argv.index("-d") + 1]
os.makedirs(os.path.join(out_dir, "sources"), exist_ok=True)
with open(os.path.join(out_dir, "sources", "Strings.java"), "w", encoding="utf-8") as handle:
	handle.write("\n".join([
		'aws = "AKIAIOSFODNN7EXAMPLE"',
		'google = "AIzaSyA1234567890abcdefghijklmnopqrstuv"',
		'endpoint = "https://api.example.com/v1/users"',
		'local = "http://localhost:8080/healthz"',
		'dup = "AKIAIOSFODNN7EXAMPLE"',
	]))
'''


# Shell metacharacters in the APK path and disassembler arguments must remain
# literal data instead of being evaluated by a shell.
PWNED_ARGS_MARKER = "pwned-args"
PWNED_PATH_MARKER = "pwned-path"
INJECTION_ARGS = '--deobf; touch "%s"; `id` --threads-count 4' % PWNED_ARGS_MARKER


class APKLeaksTest(unittest.TestCase):
	def setUp(self):
		self.workdir = tempfile.mkdtemp(prefix="apkleaks-test-")
		self.jadx = os.path.join(self.workdir, "jadx")
		with open(self.jadx, "w", encoding="utf-8") as handle:
			handle.write(FAKE_JADX)
		os.chmod(self.jadx, os.stat(self.jadx).st_mode | stat.S_IXUSR)

		apk_dir = os.path.join(self.workdir, "sub dir")
		os.makedirs(apk_dir)
		self.apk_file = os.path.join(
			apk_dir,
			"evil$(touch %s).apk;reboot & `id`" % PWNED_PATH_MARKER,
		)
		with open(self.apk_file, "w", encoding="utf-8") as handle:
			handle.write("not a real APK, just a placeholder file")

		self.argv_log = os.path.join(self.workdir, "jadx-argv.json")
		self.patterns = os.path.join(os.path.dirname(__file__), "fixtures", "patterns.json")

	def _run_scan(self, as_json):
		output = os.path.join(self.workdir, "results.%s" % ("json" if as_json else "txt"))
		args = SimpleNamespace(
			file=self.apk_file,
			output=output,
			pattern=self.patterns,
			args=INJECTION_ARGS,
			json=as_json,
		)
		scanner = APKLeaks(args)
		scanner.jadx = self.jadx
		os.environ["FAKE_JADX_ARGV"] = self.argv_log

		fake_apk = SimpleNamespace(package="com.example.injected")
		scanner.apk_info = lambda: fake_apk

		try:
			scanner.integrity()
			scanner.decompile()
			scanner.scanning()
		finally:
			scanner.cleanup()
		return output

	def test_injection_is_not_executed(self):
		self._run_scan(as_json=True)

		self.assertFalse(
			os.path.exists(os.path.join(self.workdir, PWNED_PATH_MARKER)),
			"shell metacharacters in the APK path must not execute",
		)
		self.assertFalse(
			os.path.exists(os.path.join(os.getcwd(), PWNED_ARGS_MARKER)),
			"shell metacharacters in disassembler arguments must not execute",
		)

		with open(self.argv_log, encoding="utf-8") as handle:
			jadx_argv = json.load(handle)
		self.assertEqual(jadx_argv[0], os.path.realpath(self.apk_file))
		self.assertIn("--deobf;", jadx_argv)
		self.assertIn("touch", jadx_argv)
		self.assertIn("%s;" % PWNED_ARGS_MARKER, jadx_argv)
		self.assertIn("`id`", jadx_argv)
		self.assertEqual(jadx_argv[jadx_argv.index("--threads-count") + 1], "4")

	def test_json_results_are_complete_and_repeatable(self):
		first = self._run_scan(as_json=True)
		with open(first, encoding="utf-8") as handle:
			first_data = json.load(handle)

		second = self._run_scan(as_json=True)
		with open(second, encoding="utf-8") as handle:
			second_data = json.load(handle)

		self.assertEqual(first_data, second_data)
		self.assertEqual(first_data["package"], "com.example.injected")

		names = [entry["name"] for entry in first_data["results"]]
		self.assertEqual(names, sorted(names))
		self.assertEqual(
			names,
			["AWS_API_Key", "Endpoints", "Google_API_Key"],
		)

		results = {entry["name"]: entry["matches"] for entry in first_data["results"]}
		self.assertEqual(results["AWS_API_Key"], ["AKIAIOSFODNN7EXAMPLE"])
		self.assertEqual(
			results["Google_API_Key"],
			["AIzaSyA1234567890abcdefghijklmnopqrstuv"],
		)
		self.assertEqual(
			results["Endpoints"],
			[
				"http://localhost:8080/healthz",
				"https://api.example.com/v1/users",
			],
		)

		flattened = [match for entry in first_data["results"] for match in entry["matches"]]
		self.assertEqual(len(flattened), len(set(flattened)))

	def test_text_output_contains_every_match(self):
		output = self._run_scan(as_json=False)
		with open(output, encoding="utf-8") as handle:
			text = handle.read()
		for expected in (
			"[AWS_API_Key]",
			"AKIAIOSFODNN7EXAMPLE",
			"[Google_API_Key]",
			"AIzaSyA1234567890abcdefghijklmnopqrstuv",
			"[Endpoints]",
			"https://api.example.com/v1/users",
			"http://localhost:8080/healthz",
		):
			self.assertIn(expected, text)


class FinderBoundaryTest(unittest.TestCase):
	def test_skips_symlinks_oversized_and_unreadable_files(self):
		root = tempfile.mkdtemp(prefix="apkleaks-finder-")
		outside = os.path.join(root, "outside.txt")
		with open(outside, "w", encoding="utf-8") as handle:
			handle.write("AKIAIOSFODNN7EXAMPLE\n")

		inside = os.path.join(root, "inside.txt")
		with open(inside, "w", encoding="utf-8") as handle:
			handle.write("AKIAIOSFODNN7EXAMPLE\n")

		link = os.path.join(root, "link.txt")
		os.symlink(outside, link)

		matches = util.finder("AKIA[0-9A-Z]{16}", root, max_size=4)

		self.assertEqual(matches, [])

	def test_reads_regular_files_within_limit(self):
		root = tempfile.mkdtemp(prefix="apkleaks-finder-")
		with open(os.path.join(root, "small.txt"), "w", encoding="utf-8") as handle:
			handle.write("token AKIAIOSFODNN7EXAMPLE end\n")
		self.assertEqual(util.finder("AKIA[0-9A-Z]{16}", root), ["AKIAIOSFODNN7EXAMPLE"])


if __name__ == "__main__":
	unittest.main()
