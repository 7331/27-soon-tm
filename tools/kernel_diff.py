#!/usr/bin/env python3
"""Function-level diff of the main XNU kernel between two kernelcache extractions.

Scales the kext differ to ~1M instructions by hashing function token streams to 64-bit
values instead of keeping tuples. Exact matches drop out, loose (mnemonic-only) matches
second, similarity pairing last. Usage:

    kernel_diff.py OLD.kernel NEW.kernel --out report.md
"""

import argparse
import difflib
import hashlib
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

LC_SEGMENT_64 = 0x19
BRANCHES = {"bl", "b", "cbz", "cbnz", "tbz", "tbnz", "br", "blr"}
TERMINATORS = {"ret", "retab", "brk"}
MEMORY_ACCESSES = {"ldr", "ldp", "str", "stp", "ldrb", "ldrh", "ldrsw"}
MAX_FUNCTIONS = 400000


def macho_text(image):
    header = struct.unpack_from("<IiiIIIII", image, 0)
    if header[0] != 0xFEEDFACF:
        raise SystemExit("not a 64-bit little-endian Mach-O")
    offset = 32
    for _ in range(header[4]):
        cmd, cmdsize = struct.unpack_from("<II", image, offset)
        if cmd == LC_SEGMENT_64:
            segname = image[offset + 8:offset + 24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", image, offset + 64)[0]
            section_offset = offset + 72
            for _ in range(nsects):
                sectname = image[section_offset:section_offset + 16].rstrip(b"\0").decode()
                address, size, file_offset = struct.unpack_from("<QQI", image, section_offset + 32)
                if segname == "__TEXT_EXEC" and sectname == "__text":
                    return address, image[file_offset:file_offset + size]
                section_offset += 80
        offset += cmdsize
    raise SystemExit("no __TEXT_EXEC.__text")


def decode(base, code, progress_label):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    decoder.skipdata = True
    instructions = list(decoder.disasm(code, base))
    print("decoded {}: {}".format(progress_label, len(instructions)), flush=True)
    return instructions


def register_of(instruction, index):
    if index >= len(instruction.operands):
        return None
    operand = instruction.operands[index]
    if operand.type != ARM64_OP_REG:
        return None
    return instruction.reg_name(operand.reg)


def normalize(instructions):
    address_registers = set()
    tokens = []
    hashes = []
    mnemonic_hashes = []
    for instruction in instructions:
        mnemonic = instruction.mnemonic
        if instruction.id == 0:
            token = "data"
            tokens.append(token)
            continue
        operands = instruction.operands

        if mnemonic in ("adrp", "adr"):
            destination = register_of(instruction, 0)
            if destination:
                address_registers.add(destination)
            token = mnemonic + " #addr"
        elif mnemonic in BRANCHES or mnemonic.startswith("b."):
            token = mnemonic
        elif mnemonic in ("add", "sub") and register_of(instruction, 1) in address_registers:
            token = mnemonic + " #addr-offset"
        else:
            parts = []
            for index, operand in enumerate(operands):
                if operand.type == ARM64_OP_REG:
                    parts.append(instruction.reg_name(operand.reg))
                elif operand.type == ARM64_OP_MEM:
                    if instruction.reg_name(operand.mem.base) in address_registers:
                        parts.append("[" + instruction.reg_name(operand.mem.base) + "+#addr]")
                    else:
                        parts.append("[{}+#{}]".format(instruction.reg_name(operand.mem.base), operand.mem.disp))
                elif operand.type == ARM64_OP_IMM:
                    parts.append("#{}".format(operand.imm))
                else:
                    parts.append("?")
            if mnemonic in MEMORY_ACCESSES:
                destination = register_of(instruction, 0)
                if destination and any(
                    instruction.reg_name(o.mem.base) in address_registers
                    for o in operands if o.type == ARM64_OP_MEM
                ):
                    address_registers.add(destination)
            token = mnemonic + " " + ",".join(parts) if parts else mnemonic
            tokens.append(token)

        hashes.append(int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big"))
        mnemonic_hashes.append(int.from_bytes(hashlib.blake2b(mnemonic.encode(), digest_size=8).digest(), "big"))
    return tokens, hashes, mnemonic_hashes


def split_functions(instructions):
    functions = []
    start = 0
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic in TERMINATORS and index > start:
            functions.append((start, index + 1))
            start = index + 1
    if start < len(instructions):
        functions.append((start, len(instructions)))
    return functions


class Function:
    __slots__ = ("address", "count", "tokens", "hashes", "mnemonic_hashes", "exact", "loose")

    def __init__(self, address, tokens, hashes, mnemonic_hashes):
        self.address = address
        self.count = len(tokens)
        self.tokens = tokens
        self.hashes = hashes
        self.mnemonic_hashes = mnemonic_hashes
        self.exact = hashlib.blake2b(".".join(tokens).encode(), digest_size=16).digest() if tokens else b""
        self.loose = hashlib.blake2b(b",".join(t.split(" ")[0].encode() for t in tokens), digest_size=16).digest() if tokens else b""


def build(instructions, label):
    functions = []
    for start, end in split_functions(instructions):
        chunk = instructions[start:end]
        tokens, hashes, mhashes = normalize(chunk)
        functions.append(Function(chunk[0].address, tokens, hashes, mhashes))
    print("built {}: {} functions".format(label, len(functions)), flush=True)
    return functions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old_kernel")
    parser.add_argument("new_kernel")
    parser.add_argument("--out")
    arguments = parser.parse_args()

    old_address, old_code = macho_text(open(arguments.old_kernel, "rb").read())
    new_address, new_code = macho_text(open(arguments.new_kernel, "rb").read())
    old_functions = build(decode(old_address, old_code, "old"), "old")
    new_functions = build(decode(new_address, new_code, "new"), "new")

    old_exact = {}
    for function in old_functions:
        old_exact.setdefault(function.exact, []).append(function)

    changed_pairs = []
    used_old = set()
    leftovers_new = []

    for function in new_functions:
        group = old_exact.get(function.exact)
        if group:
            old_function = group.pop()
            if not group:
                del old_exact[function.exact]
            used_old.add(id(old_function))
        else:
            leftovers_new.append(function)

    old_loose = {}
    leftovers_old = [f for f in old_functions if id(f) not in used_old]
    for function in leftovers_old:
        old_loose.setdefault(function.loose, []).append(function)

    changed = []
    still_new = []
    for function in leftovers_new:
        group = old_loose.get(function.loose)
        if group:
            old_function = group.pop(0)
            if not group:
                del old_loose[function.loose]
            changed.append((old_function, function))
        else:
            still_new.append(function)

    leftovers_old = [f for f in leftovers_old if id(f) not in {id(o) for o, _ in changed}]

    added = still_new
    removed = leftovers_old

    print("exact-matched: {}".format(len(new_functions) - len(leftovers_new)), flush=True)
    print("loose-changed: {}  added: {}  removed: {}".format(len(changed), len(added), len(removed)), flush=True)

    lines = ["# kernel diff {} vs {}\n".format(arguments.old_kernel, arguments.new_kernel)]
    lines.append("changed: {}  added: {}  removed: {}\n".format(len(changed), len(added), len(removed)))

    ranked = []
    for old_function, new_function in changed:
        matcher = difflib.SequenceMatcher(None, old_function.tokens, new_function.tokens, autojunk=True)
        differing = sum(
            max(new_end - new_start, old_end - old_start)
            for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
            if tag != "equal"
        )
        ranked.append((differing, old_function, new_function))
    ranked.sort(key=lambda item: -item[0])

    lines.append("\n## Top changed functions\n")
    for differing, old_function, new_function in ranked[:60]:
        lines.append("- old 0x{:x} -> new 0x{:x}: {} -> {} insns, {} differing".format(
            old_function.address, new_function.address,
            old_function.count, new_function.count, differing))

    lines.append("\n## Added functions (first 60)\n")
    for function in sorted(added, key=lambda f: -f.count)[:60]:
        lines.append("- new 0x{:x}: {} insns".format(function.address, function.count))

    if arguments.out:
        open(arguments.out, "w").write("\n".join(lines))
        print("wrote", arguments.out, flush=True)


if __name__ == "__main__":
    sys.exit(main())
