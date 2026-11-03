#!/usr/bin/env python3
"""Find the kernel function that references a string in a kext.

Apple's fix for a validation bug usually adds an error string, so the cheapest way to find the
patched code is to walk backwards from the string. Usage:

    find_string_xref.py KEXT "HEVC VPS count is out of range"
"""

import argparse
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

LC_SEGMENT_64 = 0x19


def read_macho(image):
    header = struct.unpack_from("<IiiIIIII", image, 0)
    if header[0] != 0xFEEDFACF:
        raise SystemExit("not a 64-bit little-endian Mach-O")
    ncmds = header[4]

    sections = []
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", image, offset)
        if cmd == LC_SEGMENT_64:
            segname = image[offset + 8:offset + 24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", image, offset + 64)[0]
            section_offset = offset + 72
            for _ in range(nsects):
                sectname = image[section_offset:section_offset + 16].rstrip(b"\0").decode()
                address, size, file_offset = struct.unpack_from("<QQI", image, section_offset + 32)
                sections.append({
                    "segment": segname,
                    "name": sectname,
                    "address": address,
                    "size": size,
                    "offset": file_offset,
                })
                section_offset += 80
        offset += cmdsize
    return sections


def locate_string(image, sections, needle):
    encoded = needle.encode()
    for section in sections:
        body = image[section["offset"]:section["offset"] + section["size"]]
        position = body.find(encoded)
        if position >= 0:
            start = body.rfind(b"\0", 0, position) + 1
            return section["address"] + start, section["name"]
    return None, None


def read_pointer(image, sections, address):
    for section in sections:
        if section["address"] <= address < section["address"] + section["size"]:
            offset = section["offset"] + (address - section["address"])
            return struct.unpack_from("<Q", image, offset)[0]
    return None


def instruction_stream(image, sections):
    for section in sections:
        if section["segment"] == "__TEXT_EXEC" and section["name"] == "__text":
            decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            decoder.detail = True
            decoder.skipdata = True
            code = image[section["offset"]:section["offset"] + section["size"]]
            return list(decoder.disasm(code, section["address"]))
    raise SystemExit("no __TEXT_EXEC.__text")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kext")
    parser.add_argument("needle")
    arguments = parser.parse_args()

    image = open(arguments.kext, "rb").read()
    sections = read_macho(image)
    target, section_name = locate_string(image, sections, arguments.needle)
    if target is None:
        print("string not found")
        return 1
    print("string at 0x{:x} (__{}); {}".format(target, section_name, arguments.needle))

    instructions = instruction_stream(image, sections)
    page_register = {}
    function_start = None
    hits = []
    for instruction in instructions:
        if instruction.mnemonic == "pacibsp":
            function_start = instruction.address
        if instruction.id == 0:
            continue
        if instruction.mnemonic == "adrp":
            destination = instruction.operands[0].reg
            page_register[destination] = instruction.operands[1].imm
            continue
        if instruction.mnemonic == "add" and len(instruction.operands) == 3:
            base = instruction.operands[1]
            if base.type == 1 and base.reg in page_register:
                resolved = page_register[base.reg] + instruction.operands[2].imm
                if resolved == target:
                    hits.append((function_start, instruction.address))
            continue
        if instruction.mnemonic in ("ldr", "ldp") and len(instruction.operands) >= 2:
            memory = instruction.operands[1]
            if memory.type != 3:
                continue
            base_register = memory.mem.base
            if base_register not in page_register:
                continue
            slot = page_register[base_register] + memory.mem.disp
            pointer = read_pointer(image, sections, slot)
            if pointer == target:
                hits.append((function_start, instruction.address))

    for function_start, reference in hits:
        print("  referenced at 0x{:x}, function starts 0x{:x}".format(reference, function_start or 0))
    if not hits:
        print("  no adrp/add reference found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
