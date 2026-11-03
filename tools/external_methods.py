#!/usr/bin/env python3
"""Dump IOExternalMethodDispatch tables from a kext.

An IOUserClient's external method surface is a static array of IOExternalMethodDispatch:

    struct { IOExternalMethodAction function;      // 8 bytes, points into __TEXT_EXEC
             uint32_t checkScalarInputCount;
             uint32_t checkStructureInputSize;
             uint32_t checkScalarOutputCount;
             uint32_t checkStructureOutputSize; }  // 24 bytes total

Finding the arrays tells you which selectors exist and the exact input/output sizes they expect,
without calling anything. Usage:

    external_methods.py KEXT
"""

import argparse
import struct
import sys

LC_SEGMENT_64 = 0x19
DISPATCH_SIZE = 24


def read_macho(image):
    header = struct.unpack_from("<IiiIIIII", image, 0)
    if header[0] != 0xFEEDFACF:
        raise SystemExit("not a 64-bit little-endian Mach-O")
    ncmds = header[4]

    segments = []
    sections = []
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", image, offset)
        if cmd == LC_SEGMENT_64:
            segname = image[offset + 8:offset + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", image, offset + 24)
            nsects = struct.unpack_from("<I", image, offset + 64)[0]
            segments.append((segname, vmaddr, vmsize))
            section_offset = offset + 72
            for _ in range(nsects):
                sectname = image[section_offset:section_offset + 16].rstrip(b"\0").decode()
                address, size, section_file_offset = struct.unpack_from("<QQI", image, section_offset + 32)
                sections.append((segname, sectname, address, size, section_file_offset))
                section_offset += 80
        offset += cmdsize
    return segments, sections


def text_range(sections):
    for segment, name, address, size, _ in sections:
        if segment == "__TEXT_EXEC":
            return address, address + size
    return 0, 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kext")
    arguments = parser.parse_args()

    image = open(arguments.kext, "rb").read()
    segments, sections = read_macho(image)
    text_low, text_high = text_range(sections)

    tables = []
    for segment, name, address, size, file_offset in sections:
        if segment not in ("__DATA_CONST", "__DATA") or "const" not in name.lower():
            continue
        body = image[file_offset:file_offset + size]
        for position in range(0, len(body) - DISPATCH_SIZE, 8):
            function, scalar_in, struct_in, scalar_out, struct_out = struct.unpack_from("<QIIII", body, position)
            if not (text_low <= function < text_high):
                continue
            if max(scalar_in, struct_in, scalar_out, struct_out) > 0x40000:
                continue
            if scalar_in > 0x20 or scalar_out > 0x20:
                continue
            tables.append((address + position, function, scalar_in, struct_in, scalar_out, struct_out))

    print("dispatch entries found: {}".format(len(tables)))
    index = 0
    selector = 0
    while index < len(tables):
        address = tables[index][0]
        run = [tables[index]]
        while index + len(run) < len(tables) and tables[index + len(run)][0] == address + len(run) * DISPATCH_SIZE:
            run.append(tables[index + len(run)])
        print("\ntable at 0x{:x}  ({} selectors)".format(address, len(run)))
        for selector, entry in enumerate(run):
            _, function, scalar_in, struct_in, scalar_out, struct_out = entry
            print("  selector {:<3} fn 0x{:x}  in: {} scalar / {} struct bytes   out: {} scalar / {} struct bytes".format(
                selector, function, scalar_in, struct_in, scalar_out, struct_out))
        index += len(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
