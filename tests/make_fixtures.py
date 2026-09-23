"""Synthetic firmware fixture builders for the decryptor test suite.

These builders create structurally valid (but small) stand-ins for real
iPod firmware so the parsing/decryption pipeline can be exercised on any
host without real IPSW files:

- build_cat1_firmware()     plaintext firmware (header + body)
- build_mse_firmware()      Category 2 MSE bundle (S5L8702 IMG1 members)
- build_nano2g_firmware()   Category 3/4 S5L8701 DNAN bundle
- build_nano5g_rsrc()       Nano 5G RSRC: IMG1 8730/2.0/format-4 + FAT16
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipod_universal_decrypt_b import NANO2G_IV, NANO2G_KEY  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-128-CBC using the openssl CLI (no Python deps)."""
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".in") as fin:
        fin.write(plaintext)
        in_path = fin.name
    out_path = in_path + ".out"
    try:
        result = subprocess.run(
            ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(),
             "-iv", iv.hex(), "-nosalt", "-nopad",
             "-in", in_path, "-out", out_path],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"openssl encrypt failed: {result.stderr.decode()}")
        with open(out_path, "rb") as f:
            return f.read()
    finally:
        os.remove(in_path)
        if os.path.exists(out_path):
            os.remove(out_path)


def _fourcc_rev(name: str) -> bytes:
    """MSE stores fourccs byte-reversed (parser does raw[::-1])."""
    return name.encode("ascii")[:4][::-1]


def _img1_header(magic: str, version: str, image_format: int,
                 header_size: int, body_length: int) -> bytes:
    """A minimal structurally-valid IMG1 header padded to header_size."""
    header = bytearray(header_size)
    header[0:4] = magic.encode("ascii")
    header[4:7] = version.encode("ascii")
    header[7] = image_format
    struct.pack_into("<I", header, 12, 0x22000000)      # Entrypoint
    struct.pack_into("<I", header, 16, body_length)      # BodyLength
    struct.pack_into("<I", header, 20, body_length)      # DataLength
    return bytes(header)


def make_ipsw(path: str, firmware: bytes, member_name: str = "Firmware") -> str:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(member_name, firmware)
        z.writestr("Firmware.plist", b"<plist></plist>")
        z.writestr("BuildManifest.plist", b"<plist></plist>")
    return path


# ---------------------------------------------------------------------------
# Category 1: plaintext firmware
# ---------------------------------------------------------------------------

def build_cat1_firmware(body: bytes | None = None) -> bytes:
    """A 0x800-byte IMG-style header followed by plaintext 'OSOS' data."""
    if body is None:
        body = b"PLAINTEXT_OSOS_BODY_" * 0x400  # 24 KiB
    header = bytearray(0x800)
    header[0:4] = b"8900"
    header[4:7] = b"1.0"
    return bytes(header) + body


# ---------------------------------------------------------------------------
# Category 2: MSE bundle (S5L8702, e.g. Classic / Nano 3G)
# ---------------------------------------------------------------------------

def _mse_record(target: str, name: str, physical_offset: int, length: int,
                used: int = 1) -> bytes:
    rec = bytearray(0x28)
    rec[0:4] = _fourcc_rev(target)
    rec[4:8] = _fourcc_rev(name)
    struct.pack_into("<8I", rec, 8, used, physical_offset, length,
                     0, 0, 0, 0, 0)
    return bytes(rec)


def build_mse_firmware(osos_body: bytes | None = None,
                       rsrc_body: bytes | None = None,
                       include_hash: bool = True,
                       nano3: bool = False) -> bytes:
    """Build a minimal but valid MSE container:

    - 0x100 guard with 'Copyright' and a 0xFF check byte
    - ]ih[ volume marker at 0x100, version-3 header
    - zero padding 0x10C..0x5000
    - file records at 0x5000: osos (encrypted IMG1 format 1),
      rsrc (plaintext IMG1 format 4), hash (raw member)

    nano3=True emulates the Nano 3G layout: 0x1000-byte IMG1 headers and
    directory lengths that record only the body (the parser's
    nano3_layout adds the 0x1000 header back).
    """
    if osos_body is None:
        osos_body = b"ENCRYPTED_OSOS_BODY_" * 0x200  # 12 KiB (block aligned)
    if len(osos_body) % 16:
        osos_body += b"\x00" * (16 - len(osos_body) % 16)
    if rsrc_body is None:
        rsrc_body = b"PLAINTEXT_RSRC_BODY_" * 0x100

    header_size = 0x1000 if nano3 else 0x800
    osos = _img1_header("8702", "1.0", 1, header_size, len(osos_body)) + osos_body
    rsrc = _img1_header("8702", "1.0", 4, header_size, len(rsrc_body)) + rsrc_body
    # The raw "hash" member is omitted in nano3 mode: the Nano 3G layout
    # pads raw members with an extra 0x1000 that the parser double-counts,
    # and the smoke tests only need the two IMG1 members there.
    hashb = b"hashdata" * 64  # raw member (no IMG1 magic)
    hash_pad = 0
    osos_dir_len = len(osos_body) if nano3 else len(osos)
    rsrc_dir_len = len(rsrc_body) if nano3 else len(rsrc)
    hash_dir_len = len(hashb)

    # Layout
    osos_off = 0x6000
    rsrc_off = osos_off + len(osos)
    hash_off = rsrc_off + len(rsrc)
    dir_off = 0x5000

    size = hash_off + hash_pad + len(hashb) + 0x100 \
        if (include_hash and not nano3) else rsrc_off + len(rsrc)
    fw = bytearray(size)

    # Guard (0x0..0x100): must contain b"Copyright" and fw[0xFF] == 0
    fw[8:17] = b"Copyright"
    fw[0xFF] = 0

    # Volume header at 0x100
    fw[0x100:0x104] = b"]ih["
    struct.pack_into("<IHH", fw, 0x104, 0x4000, 0x10C, 3)
    # 0x10C..0x5000 already zero

    # File records at 0x5000
    records = [
        _mse_record("NAND", "osos", osos_off, osos_dir_len),
        _mse_record("NAND", "rsrc", rsrc_off, rsrc_dir_len),
    ]
    if include_hash and not nano3:
        records.append(_mse_record("NAND", "hash", hash_off, hash_dir_len))
    for i, rec in enumerate(records):
        fw[dir_off + i * 0x28:dir_off + i * 0x28 + 0x28] = rec
    # remaining records stay zero (terminator)

    fw[osos_off:osos_off + len(osos)] = osos
    fw[rsrc_off:rsrc_off + len(rsrc)] = rsrc
    if include_hash and not nano3:
        fw[hash_off + hash_pad:hash_off + hash_pad + len(hashb)] = hashb
    return bytes(fw)


# ---------------------------------------------------------------------------
# Category 3/4: S5L8701 DNAN bundle (Nano 2G)
# ---------------------------------------------------------------------------

def build_nano2g_firmware(osos_plaintext: bytes | None = None,
                          aupd_plaintext: bytes | None = None,
                          rsrc_data: bytes | None = None,
                          encrypt: bool = True) -> tuple[bytes, dict]:
    """Build a Nano 2G style firmware:

    - ]ih[ marker at 0x100
    - DNAN directory at 0x4800 (crsr/rsrc, soso/osos, dpua/aupd)
    - each partition: 0x800 local header + body
      (osos/aupd bodies AES-128-CBC encrypted with NANO2G_KEY if
       encrypt=True; rsrc is plaintext)

    Returns (firmware_bytes, info) where info maps partition name to the
    expected exported content (header + plaintext body).
    """
    if osos_plaintext is None:
        osos_plaintext = b"NANO2G_OSOS_PLAINTEXT_" * 0x100
    if aupd_plaintext is None:
        aupd_plaintext = b"NANO2G_AUPD_PLAINTEXT_" * 0x80
    if rsrc_data is None:
        rsrc_data = b"NANO2G_RSRC_PLAINTEXT_" * 0x80
    for name, body in (("osos", osos_plaintext), ("aupd", aupd_plaintext)):
        if len(body) % 16:
            raise ValueError(f"{name} plaintext must be 16-byte aligned")

    header = bytearray(0x800)
    header[0:4] = b"8701"
    header[4:7] = b"1.0"
    header = bytes(header)

    bodies = {}
    expected = {}
    if encrypt:
        bodies["osos"] = aes_cbc_encrypt(osos_plaintext, NANO2G_KEY, NANO2G_IV)
        bodies["aupd"] = aes_cbc_encrypt(aupd_plaintext, NANO2G_KEY, NANO2G_IV)
    else:
        bodies["osos"] = osos_plaintext
        bodies["aupd"] = aupd_plaintext
    bodies["rsrc"] = rsrc_data
    expected["osos"] = header + osos_plaintext
    expected["aupd"] = header + aupd_plaintext
    expected["rsrc"] = header + rsrc_data

    # Layout: partitions after the directory (0x4800 + 64*0x28 max)
    order = ["rsrc", "osos", "aupd"]
    offset = 0x8000
    ranges = {}
    for name in order:
        ranges[name] = (offset, 0x800 + len(bodies[name]))
        offset += 0x800 + len(bodies[name])

    fw = bytearray(offset)
    fw[0x100:0x104] = b"]ih["

    raw_names = {b"crsr": "rsrc", b"soso": "osos", b"dpua": "aupd"}
    for i, name in enumerate(order):
        part_offset, part_length = ranges[name]
        raw = [k for k, v in raw_names.items() if v == name][0]
        rec = struct.pack("<4s4s8I", b"DNAN", raw, 0, part_offset,
                          part_length - 0x800, 0, 0, 0, 0, 0)
        fw[0x4800 + i * 0x28:0x4800 + i * 0x28 + 0x28] = rec
        fw[part_offset:part_offset + part_length] = header + bodies[name]

    return bytes(fw), expected


# ---------------------------------------------------------------------------
# Nano 5G RSRC: IMG1 8730/2.0 format 4 + FAT16 with the Silver DB file
# ---------------------------------------------------------------------------

_SILVER_NAME = "SilverImagesDB.LE.bin"


def _lfn_entries(name: str) -> list[bytes]:
    """VFAT long-name entries for ``name``, in directory order."""
    full = name + "\x00"
    parts = [full[i:i + 13] for i in range(0, len(full), 13)]
    offset_map = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
    entries = []
    for seq, part in enumerate(reversed(parts), start=1):
        e = bytearray(32)
        e[0] = seq if seq < 0x40 else seq | 0x40
        e[11] = 0x0F
        for i in range(13):
            ch = part[i] if i < len(part) else None
            value = ord(ch) if ch is not None else 0xFFFF
            e[offset_map[i]:offset_map[i] + 2] = value.to_bytes(2, "little")
        entries.append(bytes(e))
    return entries


def _directory_entry(short_base: str, short_ext: str, attrs: int,
                     first_cluster: int, size: int) -> bytes:
    e = bytearray(32)
    base = short_base.encode("ascii")[:8]
    ext = short_ext.encode("ascii")[:3]
    e[0:8] = base + b" " * (8 - len(base))
    e[8:11] = ext + b" " * (3 - len(ext))
    e[11] = attrs
    struct.pack_into("<H", e, 26, first_cluster)
    struct.pack_into("<I", e, 28, size)
    return bytes(e)


def build_nano5g_rsrc(silver_data: bytes | None = None) -> bytes:
    """IMG1 (8730, v2.0, format 4) header + FAT16 volume containing
    Resources/UI/SilverImagesDB.LE.bin."""
    if silver_data is None:
        silver_data = b"SILVERIMAGESDB" * 0x400  # 0x4000 bytes

    volume_size = 512  # boot sector
    fat_sectors = 2
    fat_size_bytes = fat_sectors * 512
    fat_count = 2
    root_entries = 16
    root_size = (root_entries * 32 + 511) // 512  # 1 sector
    clusters_needed = (len(silver_data) + 511) // 512  # 16
    data_size = clusters_needed * 512

    # Data area holds: cluster 2 (Resources dir), cluster 3 (UI dir),
    # clusters 4.. (file). Size accordingly.
    volume = bytearray(volume_size + fat_count * fat_size_bytes +
                       root_size * 512 + (2 + clusters_needed) * 512)

    # Boot sector BPB
    bs = volume
    bs[0:2] = b"MS"
    struct.pack_into("<H", bs, 11, 512)          # bytes per sector
    bs[13] = 1                                    # sectors per cluster
    struct.pack_into("<H", bs, 14, 1)             # reserved sectors
    bs[16] = fat_count
    struct.pack_into("<H", bs, 17, root_entries)
    bs[21] = 0xF8                                 # media
    struct.pack_into("<H", bs, 22, fat_sectors)   # sectors per FAT
    bs[510:512] = b"\x55\xAA"

    fat_off = 512
    fat1 = bytearray(fat_size_bytes)
    fat1[0:2] = b"\xFF\xFF"
    fat1[2:4] = b"\xFF\xFF"
    # Cluster assignments:
    #   2: Resources dir (single)
    #   3: UI dir (single)
    #   4..4+n-1: file data
    struct.pack_into("<H", fat1, 4, 0xFFF8)
    struct.pack_into("<H", fat1, 6, 0xFFF8)
    for i in range(clusters_needed):
        cluster = 4 + i
        nxt = 4 + i + 1 if i < clusters_needed - 1 else 0xFFF8
        struct.pack_into("<H", fat1, cluster * 2, nxt)
    volume[fat_off:fat_off + fat_size_bytes] = fat1
    volume[fat_off + fat_size_bytes:fat_off + 2 * fat_size_bytes] = fat1

    root_off = fat_off + 2 * fat_size_bytes
    # Root dir: "Resources" -> cluster 2
    entries = []
    entries.extend(_lfn_entries("Resources"))
    entries.append(_directory_entry("RESOURC", "~1", 0x10, 2, 0))
    entries.append(b"\x00" * 32)
    for i, entry in enumerate(entries[:root_entries]):
        volume[root_off + i * 32:root_off + i * 32 + 32] = entry

    data_off = root_off + root_size * 512
    def cluster_addr(cluster):
        return data_off + (cluster - 2) * 512

    # Cluster 2: Resources dir with "UI" -> cluster 3
    res_dir = bytearray(512)
    e = []
    e.extend(_lfn_entries("UI"))
    e.append(_directory_entry("UI", "", 0x10, 3, 0))
    e.append(b"\x00" * 32)
    for i, entry in enumerate(e[:16]):
        res_dir[i * 32:i * 32 + 32] = entry
    volume[cluster_addr(2):cluster_addr(2) + 512] = res_dir

    # Cluster 3: UI dir with SilverImagesDB.LE.bin -> cluster 4
    ui_dir = bytearray(512)
    e = []
    e.extend(_lfn_entries(_SILVER_NAME))
    e.append(_directory_entry("SILVERI", "BIN", 0x20, 4, len(silver_data)))
    e.append(b"\x00" * 32)
    for i, entry in enumerate(e[:16]):
        ui_dir[i * 32:i * 32 + 32] = entry
    volume[cluster_addr(3):cluster_addr(3) + 512] = ui_dir

    # File data starts at cluster 4 (after the two directory clusters).
    file_off = cluster_addr(4)
    volume[file_off:file_off + len(silver_data)] = silver_data

    # Wrap in the 8730 IMG1 format-4 header (0x600)
    header = _img1_header("8730", "2.0", 4, 0x600, len(volume))
    return header + bytes(volume)
