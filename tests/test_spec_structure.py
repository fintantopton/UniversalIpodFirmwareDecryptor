"""Structural regression tests for the PyInstaller specs and build scripts.

These exist because three separate build-breaking bugs were caught only
when the build ran on a real Mac:

  1. CGO_ENABLED=0 on a wInd3x build whose USB layer (gousb) is a cgo
     binding to libusb,
  2. `__file__` used in a spec — undefined in the PyInstaller exec
     namespace on Python 3.13,
  3. `BUNDLE(Analysis)` — removed in PyInstaller 6.x (BUNDLE takes
     COLLECT/EXE).

The checks here run on any platform (no PyInstaller install needed) and
build_macos.sh runs this suite before packaging, so a red spec can never
reach the build again.
"""

import ast
import os
import re
import shutil
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)

MACOS_SPEC = "iPodUniversalDecrypt_b-macos.spec"
WIN_SPEC = "iPodUniversalDecrypt_b.spec"

# Third-party hidden imports that may appear in specs (must be installed
# into the build venv by the build script). Everything else must resolve
# to a local module in the repository root.
_THIRD_PARTY_ALLOWLIST = {
    "Crypto", "Crypto.Cipher", "Crypto.Cipher.AES",
}


def _read(name):
    with open(os.path.join(_REPO, name), encoding="utf-8") as f:
        return f.read()


def _app_version_build():
    src = _read("ipod_universal_decrypt_b.py")
    version = re.search(
        r'^APP_VERSION\s*=\s*"([^"]+)"', src, re.MULTILINE).group(1)
    build = re.search(r"^APP_BUILD\s*=\s*(\d+)", src, re.MULTILINE).group(1)
    return version, build


def _hiddenimports_resolvable(hiddenimports, spec_name):
    problems = []
    for hi in hiddenimports:
        if hi in _THIRD_PARTY_ALLOWLIST:
            continue
        top = hi.split(".")[0]
        if not os.path.isfile(os.path.join(_REPO, top + ".py")) \
                and not os.path.isdir(os.path.join(_REPO, top)):
            problems.append(f"{spec_name}: hidden import '{hi}' is neither "
                            f"local nor in the third-party allowlist")
    return problems


def _make_stubs(calls):
    class StubAnalysis:
        def __init__(self, scripts, **kw):
            self.scripts = scripts
            self.kw = kw
            self.pure = ["_stub_pure"]
            self.binaries = [("_stub.so", "_stub.so", "BINARY")]
            self.datas = list(kw.get("datas", []))
            calls["Analysis"] = self

    class StubPYZ:
        def __init__(self, pure):
            self.pure = pure
            calls["PYZ"] = self

    class StubEXE:
        def __init__(self, *args, **kw):
            self.args = args
            self.kw = kw
            calls["EXE"] = self

    class StubCOLLECT:
        def __init__(self, *args, **kw):
            self.args = args
            self.kw = kw
            calls["COLLECT"] = self

    class StubBUNDLE:
        def __init__(self, *args, **kw):
            self.args = args
            self.kw = kw
            calls["BUNDLE"] = self

    return {"Analysis": StubAnalysis, "PYZ": StubPYZ, "EXE": StubEXE,
            "COLLECT": StubCOLLECT, "BUNDLE": StubBUNDLE}


def _run_spec(spec_name):
    """Exec a spec with stub PyInstaller classes; return (calls, source)."""
    src = _read(spec_name)
    ast.parse(src)  # syntax check

    calls = {}
    classes = _make_stubs(calls)
    ns = dict(classes)
    os.chdir(_REPO)
    exec(compile(src, spec_name, "exec"), ns)
    return calls, src, classes


class TestMacosSpecStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.calls, cls.src, cls.cls = _run_spec(MACOS_SPEC)

    def test_no_file_globally(self):
        # Bug 2: `__file__` is undefined in the spec exec namespace
        # (Python 3.13 + modern PyInstaller). Check actual code nodes —
        # a mention in a comment is fine.
        tree = ast.parse(self.src)
        names = {node.id for node in ast.walk(tree)
                 if isinstance(node, ast.Name)}
        self.assertNotIn("__file__", names)

    def test_bundle_receives_collect_not_analysis(self):
        # Bug 3: PyInstaller 6.x BUNDLE raises
        # "Invalid argument type for BUNDLE" for the Analysis object.
        self.assertIn("BUNDLE", self.calls, "spec must build a BUNDLE")
        bundle = self.calls["BUNDLE"]
        self.assertEqual(len(bundle.args), 1)
        self.assertIs(bundle.args[0], self.calls["COLLECT"],
                      "BUNDLE must receive the COLLECT object")
        self.assertNotIsInstance(bundle.args[0], self.cls["Analysis"])

    def test_stage_order_pyz_exe_collect_bundle(self):
        pyz, exe, collect, bundle = (self.calls["PYZ"], self.calls["EXE"],
                                     self.calls["COLLECT"],
                                     self.calls["BUNDLE"])
        self.assertIs(exe.args[0], pyz)
        self.assertIs(exe.args[1], self.calls["Analysis"].scripts)
        self.assertIs(collect.args[0], exe)
        self.assertIs(bundle.args[0], collect)

    def test_bundle_name_matches_build_script(self):
        bkw = self.calls["BUNDLE"].kw
        app_var = re.search(r'^APP="([^"]+)"', _read("build_macos.sh"),
                            re.MULTILINE)
        self.assertIsNotNone(app_var, "build_macos.sh must set APP=")
        expected = os.path.basename(app_var.group(1))
        self.assertTrue(expected.endswith(".app"))
        self.assertEqual(bkw["name"], expected)

    def test_bundle_version_keys_match_app_source(self):
        bkw = self.calls["BUNDLE"].kw
        plist = bkw["info_plist"]
        version, build = _app_version_build()
        self.assertEqual(plist["CFBundleShortVersionString"], version)
        # Apple expects a plain (dotted) version string here.
        self.assertEqual(plist["CFBundleVersion"], build)
        self.assertRegex(plist["CFBundleVersion"], r"^\d+(\.\d+)*$")
        # The identifier is a BUNDLE kwarg, not an info_plist key
        # (PyInstaller writes CFBundleIdentifier from it).
        self.assertRegex(bkw["bundle_identifier"],
                         r"^[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$")

    def test_exe_is_windowed(self):
        ekw = self.calls["EXE"].kw
        self.assertIs(ekw.get("console"), False)
        self.assertIs(ekw.get("exclude_binaries"), True)

    def test_hiddenimports_resolvable(self):
        self.assertEqual([], _hiddenimports_resolvable(
            self.calls["Analysis"].kw.get("hiddenimports", []), MACOS_SPEC))

    def test_bundle_datas_points_at_vendor_dir(self):
        # Vendor binaries must be shipped from vendor/ (where the build
        # script places them), not from some other location.
        for entry in self.calls["Analysis"].kw.get("datas", []):
            src_path = entry[0]
            self.assertTrue(
                src_path.startswith(os.path.join("vendor", os.sep))
                or src_path.startswith("vendor/"),
                f"datas entry {src_path!r} is not under vendor/")


class TestWindowsSpecStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.calls, cls.src, cls.cls = _run_spec(WIN_SPEC)

    def test_no_file_globally(self):
        tree = ast.parse(self.src)
        names = {node.id for node in ast.walk(tree)
                 if isinstance(node, ast.Name)}
        self.assertNotIn("__file__", names)

    def test_no_bundle_on_windows(self):
        self.assertNotIn("BUNDLE", self.src)

    def test_exe_follows_pyz(self):
        self.assertIn("PYZ", self.calls)
        self.assertIn("EXE", self.calls)
        self.assertIs(self.calls["EXE"].args[0], self.calls["PYZ"])

    def test_hiddenimports_resolvable(self):
        self.assertEqual([], _hiddenimports_resolvable(
            self.calls["Analysis"].kw.get("hiddenimports", []), WIN_SPEC))


class TestBuildScriptGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = _read("build_macos.sh")
        cls.has_bash = shutil.which("bash") is not None

    def test_bash_syntax(self):
        if not self.has_bash:
            self.skipTest("bash not available")
        for name in ("build_macos.sh", "run_macos.sh"):
            proc = subprocess.run(["bash", "-n", os.path.join(_REPO, name)],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             f"bash -n {name}: {proc.stderr}")

    def test_wind3x_built_with_cgo(self):
        # Bug 1: gousb is a cgo binding; CGO_ENABLED=0 cannot compile it.
        self.assertIn("CGO_ENABLED=1", self.script)
        self.assertNotIn("CGO_ENABLED=0", self.script)

    def test_go_version_gate(self):
        self.assertIn("GO_MIN=", self.script)
        self.assertIn("1.23.0", self.script)

    def test_nested_binaries_signed(self):
        # codesign --deep does not necessarily sign Mach-O files that
        # PyInstaller 6 places in Contents/Resources; Apple Silicon
        # refuses to load unsigned Mach-O, so sign them explicitly.
        self.assertIn(
            '"$APP/Contents/Resources"/libusb-1.0.dylib', self.script)
        self.assertIn(
            '"$APP/Contents/Resources"/wInd3x-darwin-*', self.script)
        self.assertRegex(self.script, r'codesign --force --sign - "\$f"')

    def test_wind3x_relinked_to_bundled_libusb(self):
        self.assertIn("install_name_tool -change", self.script)
        self.assertIn("@rpath/libusb-1.0.dylib", self.script)
        self.assertIn("install_name_tool -add_rpath", self.script)

    def test_spec_executed_before_pyinstaller(self):
        # The test suite (including this file) must run before PyInstaller
        # so structural regressions abort the build.
        pyi = self.script.find("PyInstaller --clean")
        suite = self.script.find("unittest")
        self.assertNotEqual(pyi, -1)
        self.assertNotEqual(suite, -1)
        self.assertLess(suite, pyi)


class TestIoregParsing(unittest.TestCase):
    """The macOS USB enumeration parsers must not depend on ioreg's
    unspecified key ordering (which previously shifted product names
    across devices and could mispair vid/pid)."""

    def _platform(self):
        sys.path.insert(0, _REPO)
        try:
            import ipod_platform as plat
        finally:
            sys.path.remove(_REPO)
        return plat

    def test_ioreg_name_after_ids(self):
        # Realistic ordering: idVendor/idProduct before the product name.
        plat = self._platform()
        out = (
            "+-o IOUSBDevice@14100000  "
            "<IOUSBDevice, registered, matched, active, usable> "
            "<dictionary> = {\n"
            '    "IOClass" = "IOUSBDevice"\n'
            '    "idProduct" = 1008\n'
            '    "idVendor" = 1452\n'
            '    "IOProvider" = "IOUSBHostPort@1410"\n'
            '    "USB Product Name" = "iPod"\n'
            '    "IORegistryEntryName" = "iPod"\n'
            "}\n"
        )
        self.assertEqual(plat._parse_ioreg_usb_devices(out),
                         [(0x05AC, 0x03F0, "iPod")])

    def test_ioreg_name_before_ids(self):
        plat = self._platform()
        out = (
            "+-o IOUSBDevice@14100000  <x> <dictionary> = {\n"
            '    "USB Product Name" = "iPod"\n'
            '    "idVendor" = 1452\n'
            '    "idProduct" = 1008\n'
            "}\n"
        )
        self.assertEqual(plat._parse_ioreg_usb_devices(out),
                         [(0x05AC, 0x03F0, "iPod")])

    def test_ioreg_multiple_devices_keep_own_names(self):
        # Regression: every device used to get the previous device's name.
        plat = self._platform()
        out = (
            "+-o IOUSBDevice@14100000  <x> <dictionary> = {\n"
            '    "idVendor" = 1452\n'
            '    "idProduct" = 1008\n'
            '    "USB Product Name" = "iPod"\n'
            "}\n"
            "+-o IOUSBDevice@14200000  <x> <dictionary> = {\n"
            '    "idVendor" = 65535\n'
            '    "idProduct" = 34370\n'
            '    "USB Product Name" = "iBugger"\n'
            "}\n"
            "+-o IOUSBDevice@14300000  <x> <dictionary> = {\n"
            '    "idVendor" = 4969\n'
            '    "idProduct" = 13843\n'
            '    "USB Product Name" = "Unknown"\n'
            "}\n"
        )
        self.assertEqual(plat._parse_ioreg_usb_devices(out), [
            (0x05AC, 0x03F0, "iPod"),
            (0xFFFF, 0x8642, "iBugger"),
            (4969, 13843, "Unknown"),  # decimals: 0x1369 / 0x360B
        ])

    def test_ioreg_dedupes_and_ignores_partial_devices(self):
        plat = self._platform()
        out = (
            "+-o IOUSBDevice@1  <x> <dictionary> = {\n"
            '    "idVendor" = 1452\n'
            '    "idProduct" = 1008\n'
            '    "USB Product Name" = "iPod"\n'
            "}\n"
            "+-o IOUSBDevice@2  <x> <dictionary> = {\n"
            '    "idVendor" = 1452\n'
            '    "idProduct" = 1008\n'
            '    "USB Product Name" = "iPod (dup)"\n'
            "}\n"
            "+-o IOUSBDevice@3  <x> <dictionary> = {\n"
            '    "idVendor" = 7\n'
            '    "USB Product Name" = "NoPids"\n'
            "}\n"
        )
        self.assertEqual(plat._parse_ioreg_usb_devices(out),
                         [(0x05AC, 0x03F0, "iPod")])

    def test_spusb_vendor_id_pairing(self):
        plat = self._platform()
        out = (
            "USB:\n\n"
            "    iPod:\n\n"
            "          Vendor ID: 0x05ac (Apple Inc.)\n"
            "          Version: 1.00\n"
            "          Serial Number: F8XXXXXXXXXXXXX\n"
            "          Speed: 480 MBps\n"
            "          Manufacturer: Apple Inc.\n"
            "          Location ID: 0x01100000 / 2\n"
            "          Current Available (MA): 2000\n"
            "          Maximum Current (MA): 2000\n"
            "          IS Internal: NO\n"
            "          ID: 0x03f0\n\n"
            "    iBugger:\n\n"
            "          Vendor ID: 0xffff\n"
            "          Speed: 12 MBps\n"
            "          ID: 0x8642\n"
        )
        self.assertEqual(plat._parse_spusb(out), [
            (0x05AC, 0x03F0, ""),
            (0xFFFF, 0x8642, ""),
        ])


if __name__ == "__main__":
    unittest.main()
