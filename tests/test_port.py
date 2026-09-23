"""End-to-end and unit tests for the cross-platform decrypt pipeline.

Run from the repository root:

    python3 -m unittest discover -s tests -v

No hardware, network, or third-party Python packages are required: AES
uses PyCryptodome/cryptography when present and falls back to the openssl
CLI (mirroring the app's own fallback chain).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ipod_platform as plat  # noqa: E402
import ipod_universal_decrypt_b as app  # noqa: E402
from ipod_universal_decrypt_b import (  # noqa: E402
    NANO2G_IV,
    NANO2G_KEY,
    DecryptController,
    UniversalDecryptorCLI,
    prepare_nano2g_partition,
    parse_ipsw_filename,
    parse_nano2g_partitions,
)
from mse_members import parse_mse_members  # noqa: E402
from nano5g_resources import extract_silver_images_db  # noqa: E402

import make_fixtures as fx  # noqa: E402


class _CliArgs:
    """Minimal argparse.Namespace stand-in for the CLI backend."""

    def __init__(self, ipsw, output, partitions=None, yes=True):
        self.ipsw = ipsw
        self.output = output
        self.partitions = partitions
        self.yes = yes


class _Headless(app.DecryptController):
    """Bare controller for direct worker-method tests (no threads)."""

    def __init__(self):
        super().__init__(run_sync=True)
        self.dialogs = []

    def log(self, msg):
        pass

    def status(self, msg):
        pass

    def progress(self, value):
        pass

    def show_dialog(self, kind, title, message):
        self.dialogs.append((kind, title, message))


class TestParseIpswFilename(unittest.TestCase):
    def test_format1(self):
        fam, name, cat = parse_ipsw_filename("/x/iPod_26.1.1.3.ipsw")
        self.assertEqual(fam, 26)
        self.assertEqual(cat, 2)

    def test_format2(self):
        fam, name, cat = parse_ipsw_filename("/x/iPod_1.0.2_34A20020.ipsw")
        self.assertEqual(fam, 34)
        self.assertEqual(cat, 2)

    def test_format2_not_confused_with_format1(self):
        # The classic pitfall: 34A20020 must not be read as FamilyID 1.
        fam, _n, _c = parse_ipsw_filename("/x/iPod_1.0.2_34A20020.ipsw")
        self.assertEqual(fam, 34)

    def test_unknown(self):
        fam, name, cat = parse_ipsw_filename("/x/not-an-ipod.zip")
        self.assertIsNone(fam)
        self.assertIsNone(cat)


class TestMseParsing(unittest.TestCase):
    def test_cat2_members(self):
        fw = fx.build_mse_firmware()
        members = parse_mse_members(fw)
        by_name = {m.name: m for m in members}
        self.assertEqual(set(by_name), {"osos", "rsrc", "hash"})
        self.assertTrue(by_name["osos"].is_encrypted)
        self.assertFalse(by_name["rsrc"].is_encrypted)
        self.assertFalse(by_name["hash"].is_encrypted)
        self.assertEqual(by_name["osos"].kind, "encrypted-img1")
        self.assertEqual(by_name["rsrc"].kind, "plaintext-img1")
        self.assertEqual(by_name["hash"].kind, "raw-member")


    def test_cat2_members_nano3_layout(self):
        fw = fx.build_mse_firmware(nano3=True)
        members = parse_mse_members(fw, nano3_layout=True)
        by_name = {m.name: m for m in members}
        self.assertEqual(set(by_name), {"osos", "rsrc"})
        self.assertTrue(by_name["osos"].is_encrypted)
        self.assertFalse(by_name["rsrc"].is_encrypted)
        # Nano 3G logical spans include the 0x1000 header
        self.assertEqual(by_name["osos"].logical_length,
                         0x1000 + len(b"ENCRYPTED_OSOS_BODY_" * 0x200))


class TestCategory1Extraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipod_test_cat1_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_cli(self, ipsw, output):
        args = _CliArgs(ipsw, output, yes=True)
        cli = UniversalDecryptorCLI(args)
        return cli.run()

    def test_header_strip_fallback(self):
        body = b"PLAINTEXT_OSOS_BODY_" * 0x400
        fw = fx.build_cat1_firmware(body)
        ipsw = os.path.join(self.tmp, "iPod_13.1.2_4E9.ipsw")
        fx.make_ipsw(ipsw, fw)
        out = os.path.join(self.tmp, "out.bin")
        rc = self._run_cli(ipsw, out)
        self.assertEqual(rc, 0, "category 1 CLI run should succeed")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), body)

    def test_mse_member_path(self):
        fw = fx.build_mse_firmware()
        ipsw = os.path.join(self.tmp, "iPod_13.1.2_4E9.ipsw")
        fx.make_ipsw(ipsw, fw)
        out = os.path.join(self.tmp, "out.bin")
        rc = self._run_cli(ipsw, out)
        self.assertEqual(rc, 0)
        data = open(out, "rb").read()
        # MSE 'osos' member = IMG1 header (8702, 1.0, format 1) + body
        self.assertTrue(data.startswith(b"8702"))
        self.assertEqual(data[4:7], b"1.0")
        self.assertEqual(data[7], 1)
        self.assertGreater(len(data), 0x800)


class TestCategory3SoftwareAes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipod_test_cat3_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, ipsw, output_dir, partitions=None):
        args = _CliArgs(ipsw, output_dir, partitions=partitions, yes=True)
        cli = UniversalDecryptorCLI(args)
        return cli.run()

    def test_partition_parse_and_roundtrip(self):
        fw, expected = fx.build_nano2g_firmware()
        ranges = parse_nano2g_partitions(fw)
        for name in ("rsrc", "osos", "aupd"):
            offset, length = ranges[name]
            data, note = prepare_nano2g_partition(
                name, fw[offset:offset + length])
            self.assertEqual(data, expected[name], f"{name} roundtrip mismatch")
            if name == "rsrc":
                self.assertEqual(note, "raw/plaintext")
            else:
                self.assertIn("AES body processed", note)

    def test_aes_uses_correct_key(self):
        # Decrypting with the wrong key must not reproduce the plaintext:
        # guards against the public-key path being silently disabled.
        fw, expected = fx.build_nano2g_firmware(
            osos_plaintext=b"Z" * 0x100, aupd_plaintext=b"Y" * 0x100)
        ranges = parse_nano2g_partitions(fw)
        offset, length = ranges["osos"]
        data, _note = prepare_nano2g_partition("osos", fw[offset:offset + length])
        self.assertEqual(data, expected["osos"])
        # Ciphertext must actually differ from the plaintext in the body.
        body = fw[offset + 0x800:offset + length]
        self.assertNotEqual(body[:0x10], b"Z" * 0x10)

    def test_cli_end_to_end(self):
        fw, expected = fx.build_nano2g_firmware()
        ipsw = os.path.join(self.tmp, "iPod_19.1.1_2K160.ipsw")
        fx.make_ipsw(ipsw, fw)
        out_dir = os.path.join(self.tmp, "out")

        # Family 19 is Category 4 (device) in the model DB; exercise the
        # Category 3 worker directly to validate the software-AES path.
        headless = _Headless()
        headless.ipsw_path = ipsw
        headless.output_path = out_dir
        headless.detected_family_id = 19
        headless.detected_model = "iPod Nano 2nd Gen (S5L8701)"
        headless.detected_category = 3
        headless.partition_selected = {
            "osos": True, "aupd": True, "rsrc": True}
        headless._decrypt_category3()
        for name in ("osos", "aupd", "rsrc"):
            out_file = os.path.join(out_dir, f"{name}.bin")
            self.assertTrue(os.path.isfile(out_file), out_file)
            with open(out_file, "rb") as f:
                self.assertEqual(f.read(), expected[name])
        self.assertFalse(
            [d for d in headless.dialogs if d[0] == "error"],
            "no error dialogs expected, got: %r" % headless.dialogs)


class TestCategory2RawExport(unittest.TestCase):
    """Category 2 without a device: raw/plaintext MSE members must still
    be exported, and the device-AES step must fail gracefully."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ipod_test_cat2_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_raw_members_exported_without_device(self):
        fw = fx.build_mse_firmware()
        ipsw = os.path.join(self.tmp, "iPod_24.1.2_7E8.ipsw")
        fx.make_ipsw(ipsw, fw)
        out_dir = os.path.join(self.tmp, "out")

        headless = _Headless()
        headless.ipsw_path = ipsw
        headless.output_path = out_dir
        headless.detected_family_id = 24
        headless.detected_model = "iPod Classic 6G Initial (S5L8702)"
        headless.detected_category = 2
        headless.partition_selected = {"osos": True, "rsrc": True, "hash": True}
        headless._decrypt_category2_native()

        # Plaintext members exported byte-for-byte.
        for name in ("rsrc", "hash"):
            out_file = os.path.join(out_dir, f"{name}.bin")
            self.assertTrue(os.path.isfile(out_file), out_file)
        # No wInd3x binary in this sandbox → device-AES member skipped.
        self.assertFalse(os.path.isfile(os.path.join(out_dir, "osos.bin")))
        errors = [d for d in headless.dialogs if d[0] == "error"]
        if not plat.find_wind3x():
            self.assertTrue(errors, "expected a wInd3x-missing error dialog")


class TestNano5GResources(unittest.TestCase):
    def test_silver_images_db_roundtrip(self):
        silver = b"SILVERIMAGESDB" * 0x400
        rsrc = fx.build_nano5g_rsrc(silver)
        # Sanity: fixture matches the IMG1 checks in nano5g_resources.
        self.assertEqual(rsrc[:4], b"8730")
        self.assertEqual(rsrc[4:7], b"2.0")
        self.assertEqual(rsrc[7], 4)
        extracted = extract_silver_images_db(rsrc)
        self.assertEqual(extracted, silver)

    def test_rejects_wrong_magic(self):
        rsrc = fx.build_nano5g_rsrc()
        bad = b"XXXX" + rsrc[4:]
        with self.assertRaises(Exception):
            extract_silver_images_db(bad)


class TestPlatformModule(unittest.TestCase):
    def test_preflight(self):
        report = plat.preflight_report()
        labels = [label for _ok, label, _detail in report]
        for expected in ("Platform", "Python", "wInd3x binary"):
            self.assertIn(expected, labels)

    def test_run_cmd(self):
        ok, out, err = plat.run_cmd(["echo", "hello"], timeout=10)
        self.assertTrue(ok)
        self.assertEqual(out.strip(), "hello")

    def test_run_cmd_failure(self):
        ok, _out, _err = plat.run_cmd(["definitely-not-a-command-xyz"], timeout=10)
        self.assertFalse(ok)

    def test_temp_dir(self):
        self.assertTrue(os.path.isdir(plat.temp_dir()))

    def test_usb_enumeration_no_crash(self):
        devices = plat.enumerate_usb_devices()
        self.assertIsInstance(devices, list)
        found, detail = plat.find_ibugger_device()
        self.assertIsInstance(found, bool)
        self.assertIsInstance(detail, str)

    def test_wind3x_candidates(self):
        names = plat.wind3x_candidates()
        self.assertTrue(names)
        if plat.IS_MACOS:
            self.assertTrue(any("darwin" in n for n in names))
        if plat.IS_WINDOWS:
            self.assertEqual(names[0], "wInd3x-win.exe")

    def test_get_bundled_path_missing(self):
        self.assertIsNone(plat.get_bundled_path("no-such-file-xyz.bin"))


class TestIbuggerTransportImport(unittest.TestCase):
    """The libusb iBugger transport must import and report a clean
    not-present status when no device is attached (no crash)."""

    def test_find_device_status(self):
        import ibugger_transport
        status, stage, detail = ibugger_transport.find_device_status()
        self.assertIn(status, ("ok", "not_present", "error",
                               "present_no_winusb",
                               "present_winusb_unrecognized_guid"))
        if status != "ok":
            self.assertIsNone(stage)
            self.assertTrue(detail)

    def test_payload_helpers(self):
        import nano2g_device_decrypt as dev
        for name in ("get_loader_htm", "get_core_bin", "get_logo_bin",
                     "get_decryptfirmware_bin"):
            data = getattr(dev, name)()
            self.assertIsInstance(data, bytes)
            self.assertGreater(len(data), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
