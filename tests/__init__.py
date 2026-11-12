# Test package for apkleaks.
#
# The production code imports pyaxmlparser at module load time. Tests never
# parse a real APK, so fall back to a tiny stub when the dependency is missing;
# a real installed package always takes precedence.
try:
	import pyaxmlparser  # noqa: F401
except ImportError:
	import sys
	import types

	stub = types.ModuleType("pyaxmlparser")

	class APK:
		def __init__(self, *args, **kwargs):
			raise RuntimeError("pyaxmlparser stub: real APK parsing is unavailable")

	stub.APK = APK
	sys.modules.setdefault("pyaxmlparser", stub)
