"""Read-only MSE member discovery for the decryptor UI.

The MSE directory is the source of truth for which members a firmware bundle
actually contains. The GUI uses these records to avoid offering a fixed list
of partitions that may not exist in a given IPSW.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct


class MseFormatError(ValueError):
    """The supplied firmware member is not a supported MSE container."""


@dataclass(frozen=True)
class MseMember:
    """One logical MSE member after any 0x1000 prefix wrapper."""

    name: str
    target: str
    used: int
    physical_offset: int
    logical_offset: int
    logical_length: int
    has_prefix: bool
    kind: str  # encrypted-img1, plaintext-img1, or raw-member
    detail: str

    @property
    def is_encrypted(self) -> bool:
        return self.kind == "encrypted-img1"

    @property
    def export_name(self) -> str:
        return f"{self.name}.bin"


def _fourcc(raw: bytes) -> str:
    return raw[::-1].decode("ascii", "replace")


def _is_prefix_header(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 24 > len(data):
        return False
    zero1, unknown, zero2, zero3, zero4, _size = struct.unpack_from(
        "<6I", data, offset
    )
    return zero1 == zero2 == zero3 == zero4 == 0 and unknown in (0, 4)


def _classify(data: bytes, offset: int, length: int) -> tuple[str, str]:
    """Classify a logical member without decrypting or modifying it."""
    if offset < 0 or length <= 0 or offset + min(length, 0x40) > len(data):
        raise MseFormatError("member data range is outside the MSE container")

    magic = data[offset:offset + 4]
    version = data[offset + 4:offset + 7]
    image_format = data[offset + 7]
    known_magic = {b"8702", b"8720", b"8730", b"8723", b"8740"}

    if magic in known_magic and version in (b"1.0", b"2.0"):
        if image_format in (1, 3):
            return "encrypted-img1", (
                f"encrypted IMG1 {magic.decode('ascii')}/{version.decode('ascii')} "
                f"format {image_format}"
            )
        if image_format in (2, 4):
            return "plaintext-img1", (
                f"plaintext IMG1 {magic.decode('ascii')}/{version.decode('ascii')} "
                f"format {image_format}"
            )

    return "raw-member", "raw/plaintext MSE member"


def parse_mse_members(firmware: bytes, *, nano3_layout: bool = False) -> list[MseMember]:
    """Return actual logical members defined by a standard iPod MSE bundle.

    The parser follows the read-only checks used by wInd3x: a 0x100-byte
    guard, a version-3 volume header at 0x100, zero padding through 0x5000,
    then up to sixteen 0x28-byte file records. It deliberately does not
    serialize or modify the MSE.
    """
    directory_start = 0x5000
    record_size = 0x28
    if len(firmware) < directory_start + record_size:
        raise MseFormatError("MSE is too small for the file directory")
    if b"Copyright" not in firmware[:0x100] or firmware[0xFF] != 0:
        raise MseFormatError("MSE guard is missing or invalid")
    if firmware[0x100:0x104] != b"]ih[":
        raise MseFormatError("MSE volume marker ]ih[ is missing")

    directory_offset, extended_offset, version = struct.unpack_from(
        "<IHH", firmware, 0x104
    )
    if directory_offset != 0x4000 or extended_offset != 0x10C or version != 3:
        raise MseFormatError("unsupported MSE volume header")
    if any(firmware[0x10C:directory_start]):
        raise MseFormatError("unexpected data before MSE file directory")

    members: list[MseMember] = []
    names: set[str] = set()
    for index in range(16):
        record_offset = directory_start + index * record_size
        record = firmware[record_offset:record_offset + record_size]
        if record[:4] == b"\0" * 4:
            break

        target = _fourcc(record[:4])
        name = _fourcc(record[4:8])
        if target not in {"NAND", "ATA!"}:
            raise MseFormatError(f"unsupported MSE target {target!r} for {name!r}")
        if not name.isascii() or not name.isprintable() or name in names:
            raise MseFormatError("invalid or duplicate MSE member name")

        used, physical_offset, length, _address, _entry, _checksum, _record_version, _load = (
            struct.unpack_from("<8I", record, 8)
        )
        if length == 0 or physical_offset >= len(firmware):
            raise MseFormatError(f"invalid MSE range for {name}")

        has_prefix = _is_prefix_header(firmware, physical_offset)
        logical_offset = physical_offset + (0x1000 if has_prefix else 0)
        logical_length = length + (0x1000 if nano3_layout else 0)
        if logical_offset + logical_length > len(firmware):
            raise MseFormatError(f"MSE member {name} exceeds firmware bounds")

        kind, detail = _classify(firmware, logical_offset, logical_length)
        members.append(MseMember(
            name=name,
            target=target,
            used=used,
            physical_offset=physical_offset,
            logical_offset=logical_offset,
            logical_length=logical_length,
            has_prefix=has_prefix,
            kind=kind,
            detail=detail,
        ))
        names.add(name)

    if not members:
        raise MseFormatError("MSE has no usable file records")
    return members
