"""Nano 5G resource-partition extraction helpers.

The Nano 5G RSRC MSE member is an IMG1 format-4 image containing a FAT16
volume. SilverImagesDB.LE.bin is a file inside that volume, not a separate
MSE partition and not an AES payload. This module extracts it read-only from
the MSE-extracted RSRC image.
"""

import struct


class Nano5GResourceError(ValueError):
    """The Nano 5G RSRC image is not a readable FAT16 resource image."""


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _decode_lfn(entries):
    """Decode the VFAT long-name entries preceding one short entry."""
    chars = []
    for entry in reversed(entries):
        for start, end in ((1, 11), (14, 26), (28, 32)):
            for offset in range(start, end, 2):
                value = _u16(entry, offset)
                if value in (0, 0xFFFF):
                    continue
                chars.append(chr(value))
    return "".join(chars)


def extract_silver_images_db(rsrc_image):
    """Return ``Resources/UI/SilverImagesDB.LE.bin`` from a Nano 5G RSRC.

    ``rsrc_image`` is the file produced by ``wInd3x mse extract``. It
    includes the 0x600-byte S5L8730 IMG1 header followed by the FAT16
    resource volume. No device or AES operation is required for this file.
    """
    if len(rsrc_image) < 0x600 + 512:
        raise Nano5GResourceError("RSRC image is too small for an IMG1/FAT16 image")
    if rsrc_image[:4] != b"8730" or rsrc_image[4:7] != b"2.0":
        raise Nano5GResourceError("RSRC image is not an S5L8730 IMG1 v2.0 image")
    if rsrc_image[7] != 4:
        raise Nano5GResourceError(
            f"RSRC image format is {rsrc_image[7]}, expected unencrypted format 4"
        )

    volume = 0x600
    if rsrc_image[volume + 510:volume + 512] != b"\x55\xAA":
        raise Nano5GResourceError("RSRC image does not contain a FAT16 boot sector")

    bytes_per_sector = _u16(rsrc_image, volume + 11)
    sectors_per_cluster = rsrc_image[volume + 13]
    reserved_sectors = _u16(rsrc_image, volume + 14)
    fat_count = rsrc_image[volume + 16]
    root_entry_count = _u16(rsrc_image, volume + 17)
    fat_size = _u16(rsrc_image, volume + 22)

    if bytes_per_sector != 512:
        raise Nano5GResourceError(
            f"Unsupported RSRC sector size: {bytes_per_sector}"
        )
    if not sectors_per_cluster or not fat_count or not fat_size:
        raise Nano5GResourceError("Invalid RSRC FAT16 BPB")

    root_directory_sectors = (
        root_entry_count * 32 + bytes_per_sector - 1
    ) // bytes_per_sector
    fat_start = volume + reserved_sectors * bytes_per_sector
    root_start = fat_start + fat_count * fat_size * bytes_per_sector
    data_start = root_start + root_directory_sectors * bytes_per_sector
    cluster_size = sectors_per_cluster * bytes_per_sector
    fat_end = fat_start + fat_size * bytes_per_sector

    if data_start >= len(rsrc_image) or fat_end > len(rsrc_image):
        raise Nano5GResourceError("RSRC FAT16 layout exceeds image bounds")
    fat = rsrc_image[fat_start:fat_end]
    max_cluster = 2 + (len(rsrc_image) - data_start) // cluster_size

    def cluster_chain(first_cluster):
        cluster = first_cluster
        seen = set()
        while 2 <= cluster < 0xFFF8:
            if cluster in seen or cluster >= max_cluster:
                raise Nano5GResourceError("Invalid or looping RSRC FAT16 cluster chain")
            seen.add(cluster)
            yield cluster
            fat_offset = cluster * 2
            if fat_offset + 2 > len(fat):
                raise Nano5GResourceError("RSRC FAT16 cluster index is out of bounds")
            cluster = _u16(fat, fat_offset)

    def directory_entries(first_cluster=None):
        pending_lfn = []
        if first_cluster is None:
            directory_ranges = [
                (root_start + i * bytes_per_sector, bytes_per_sector)
                for i in range(root_directory_sectors)
            ]
        else:
            directory_ranges = [
                (data_start + (cluster - 2) * cluster_size, cluster_size)
                for cluster in cluster_chain(first_cluster)
            ]

        for directory_offset, directory_size in directory_ranges:
            for offset in range(directory_offset, directory_offset + directory_size, 32):
                entry = rsrc_image[offset:offset + 32]
                if len(entry) != 32 or entry[0] == 0:
                    return
                if entry[0] == 0xE5:
                    pending_lfn = []
                    continue
                attributes = entry[11]
                if attributes == 0x0F:
                    pending_lfn.append(entry)
                    continue

                short_base = entry[0:8].decode("ascii", "replace").rstrip()
                short_ext = entry[8:11].decode("ascii", "replace").rstrip()
                short_name = short_base + (("." + short_ext) if short_ext else "")
                name = _decode_lfn(pending_lfn) if pending_lfn else short_name
                pending_lfn = []
                yield {
                    "name": name,
                    "attributes": attributes,
                    "cluster": _u16(entry, 26),
                    "size": _u32(entry, 28),
                }

    def find(directory_cluster, name):
        wanted = name.casefold()
        for entry in directory_entries(directory_cluster):
            if entry["name"].casefold() == wanted:
                return entry
        raise Nano5GResourceError(f"RSRC file or directory not found: {name}")

    resources = find(None, "Resources")
    ui = find(resources["cluster"], "UI")
    target = find(ui["cluster"], "SilverImagesDB.LE.bin")
    if target["attributes"] & 0x10:
        raise Nano5GResourceError("SilverImagesDB.LE.bin is unexpectedly a directory")
    if target["size"] <= 0:
        raise Nano5GResourceError("SilverImagesDB.LE.bin is empty")

    result = bytearray()
    for cluster in cluster_chain(target["cluster"]):
        offset = data_start + (cluster - 2) * cluster_size
        result.extend(rsrc_image[offset:offset + cluster_size])
    if len(result) < target["size"]:
        raise Nano5GResourceError("SilverImagesDB.LE.bin cluster chain is truncated")
    return bytes(result[:target["size"]])
