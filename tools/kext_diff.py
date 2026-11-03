#!/usr/bin/env python3
"""Function-level diff of a kext between two kernelcache extractions.

Pairwise instruction diffing drowns when a kext gains thousands of instructions between two
releases, so this matches whole functions first and only diffs the ones that do not match
exactly. Usage:

    kext_diff.py OLD.kext NEW.kext            # function level, the useful default
    kext_diff.py OLD.kext NEW.kext --raw      # whole-__text instruction diff
"""

import argparse
import difflib
import json
import struct
import sys
from collections import Counter

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

LC_SEGMENT_64 = 0x19
BRANCHES = {"bl", "b", "cbz", "cbnz", "tbz", "tbnz", "br", "blr"}
TERMINATORS = {"ret", "retab", "brk"}
MEMORY_ACCESSES = {"ldr", "ldp", "str", "stp", "ldrb", "ldrh", "ldrsw"}


def macho_text(image):
    header = struct.unpack_from("<IiiIIIII", image, 0)
    magic, ncmds = header[0], header[4]
    if magic != 0xFEEDFACF:
        raise SystemExit("not a 64-bit little-endian Mach-O")
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", image, offset)
        if cmd == LC_SEGMENT_64:
            segname = image[offset + 8:offset + 24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", image, offset + 64)[0]
            section_offset = offset + 72
            for _ in range(nsects):
                sectname = image[section_offset:section_offset + 16].rstrip(b"\0").decode()
                section_address, section_size, section_file_offset = struct.unpack_from("<QQI", image, section_offset + 32)
                if segname == "__TEXT_EXEC" and sectname == "__text":
                    return section_address, image[section_file_offset:section_file_offset + section_size]
                section_offset += 80
        offset += cmdsize
    raise SystemExit("no __TEXT_EXEC.__text section")


def decode_instructions(base_address, code):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    decoder.skipdata = True
    return list(decoder.disasm(code, base_address))


def register_of(instruction, index):
    if index >= len(instruction.operands):
        return None
    operand = instruction.operands[index]
    if operand.type != ARM64_OP_REG:
        return None
    return instruction.reg_name(operand.reg)


def normalize_stream(instructions):
    address_registers = set()
    signature = []
    for instruction in instructions:
        mnemonic = instruction.mnemonic
        if instruction.id == 0:
            signature.append("data")
            continue
        operands = instruction.operands

        if mnemonic in ("adrp", "adr"):
            destination = register_of(instruction, 0)
            if destination:
                address_registers.add(destination)
            signature.append(mnemonic + " #addr")
            continue

        if mnemonic in ("add", "sub") and register_of(instruction, 1) in address_registers:
            signature.append(mnemonic + " #addr-offset")
            continue

        if mnemonic in BRANCHES or mnemonic.startswith("b."):
            signature.append(mnemonic)
            continue

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
                instruction.reg_name(operand.mem.base) in address_registers
                for operand in operands if operand.type == ARM64_OP_MEM
            ):
                address_registers.add(destination)

        signature.append(mnemonic + " " + ",".join(parts) if parts else mnemonic)
    return signature


def split_functions(instructions):
    starts = []
    previous_terminated = True
    for index, instruction in enumerate(instructions):
        if instruction.id == 0:
            previous_terminated = False
            continue
        if previous_terminated or instruction.mnemonic == "pacibsp":
            if not starts or starts[-1] != index:
                starts.append(index)
        previous_terminated = instruction.mnemonic in TERMINATORS
    functions = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(instructions)
        if end > start:
            functions.append(instructions[start:end])
    return functions


class Function:
    def __init__(self, instructions):
        self.instructions = instructions
        self.address = instructions[0].address
        self.byte_length = instructions[-1].address + instructions[-1].size - self.address
        self.tokens = normalize_stream(instructions)
        self.exact_key = tuple(self.tokens)
        self.loose_key = tuple(token.split(" ")[0] for token in self.tokens)


def index_functions(functions):
    by_exact = {}
    for function in functions:
        by_exact.setdefault(function.exact_key, []).append(function)
    return by_exact


def pair_by_similarity(leftovers_old, leftovers_new, threshold=0.55):
    """A real fix changes the mnemonic sequence, so exact and loose keys both miss it.

    Pair whatever is left by sequence similarity so a patched function reads as one change
    instead of an added plus a removed function.
    """
    scored = []
    for old_function in leftovers_old:
        for new_function in leftovers_new:
            old_length = len(old_function.tokens)
            new_length = len(new_function.tokens)
            if old_length == 0 or new_length == 0:
                continue
            if max(old_length, new_length) > min(old_length, new_length) * 3:
                continue
            ratio = difflib.SequenceMatcher(None, old_function.tokens, new_function.tokens, autojunk=True).quick_ratio()
            if ratio < threshold:
                continue
            ratio = difflib.SequenceMatcher(None, old_function.tokens, new_function.tokens, autojunk=True).ratio()
            if ratio >= threshold:
                scored.append((ratio, old_function, new_function))

    scored.sort(key=lambda item: -item[0])
    paired = []
    used_old, used_new = set(), set()
    for ratio, old_function, new_function in scored:
        if id(old_function) in used_old or id(new_function) in used_new:
            continue
        used_old.add(id(old_function))
        used_new.add(id(new_function))
        paired.append((old_function, new_function))

    remaining_old = [f for f in leftovers_old if id(f) not in used_old]
    remaining_new = [f for f in leftovers_new if id(f) not in used_new]
    return paired, remaining_old, remaining_new


def compare(old_functions, new_functions):
    old_exact = index_functions(old_functions)
    new_exact = index_functions(new_functions)

    matched_old_ids = set()
    matched_new_ids = set()
    for key, new_group in new_exact.items():
        old_group = old_exact.get(key)
        if not old_group:
            continue
        for old_function, new_function in zip(old_group, new_group):
            matched_old_ids.add(id(old_function))
            matched_new_ids.add(id(new_function))

    old_by_loose = {}
    for function in old_functions:
        if id(function) in matched_old_ids:
            continue
        old_by_loose.setdefault(function.loose_key, []).append(function)

    changed = []
    leftovers_new = []
    for function in new_functions:
        if id(function) in matched_new_ids:
            continue
        candidates = old_by_loose.get(function.loose_key)
        if candidates:
            old_function = candidates.pop(0)
            changed.append((old_function, function))
            matched_old_ids.add(id(old_function))
        else:
            leftovers_new.append(function)

    matched_changed_ids = {id(old) for old, _ in changed}
    leftovers_old = [f for f in old_functions
                     if id(f) not in matched_old_ids and id(f) not in matched_changed_ids]

    similar, added, removed = pair_by_similarity(leftovers_old, leftovers_new)
    return changed + similar, added, removed


def report_function_mode(old_functions, new_functions, arguments):
    changed, added, removed = compare(old_functions, new_functions)
    print("functions: {} -> {}".format(len(old_functions), len(new_functions)))
    print("changed: {}  added: {}  removed: {}".format(len(changed), len(added), len(removed)))

    ranked = []
    for old_function, new_function in changed:
        matcher = difflib.SequenceMatcher(None, old_function.tokens, new_function.tokens, autojunk=False)
        differing = sum(
            max(old_end - old_start, new_end - new_start)
            for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
            if tag != "equal"
        )
        ranked.append((differing, old_function, new_function))

    ranked.sort(key=lambda item: -item[0])
    print()
    for differing, old_function, new_function in ranked[:arguments.top]:
        new_check = "check" if "cmp" in " ".join(new_function.tokens) and "cmp" not in " ".join(old_function.tokens) else ""
        print("  0x{:x}  {} -> {} instructions  ({} differing){}{}".format(
            old_function.address,
            len(old_function.instructions), len(new_function.instructions),
            differing,
            "  size {} -> {}".format(old_function.byte_length, new_function.byte_length),
            "  NEW-BOUND-CHECK" if new_check else ""))

    if arguments.json:
        json.dump({
            "changed": [{"old_address": old.address, "new_address": new.address,
                         "old_instructions": len(old.instructions),
                         "new_instructions": len(new.instructions)}
                        for old, new in ranked],
            "added": [{"address": function.address, "instructions": len(function.instructions)} for function in added],
            "removed": [{"address": function.address, "instructions": len(function.instructions)} for function in removed],
        }, open(arguments.json, "w"), indent=2)


def report_raw_mode(old_instructions, new_instructions, arguments):
    old_signature = normalize_stream(old_instructions)
    new_signature = normalize_stream(new_instructions)
    matcher = difflib.SequenceMatcher(None, old_signature, new_signature, autojunk=False)
    hunks = [opcode for opcode in matcher.get_opcodes() if opcode[0] != "equal"]
    print("changed hunks: {}".format(len(hunks)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old_kext")
    parser.add_argument("new_kext")
    parser.add_argument("--json")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--raw", action="store_true")
    arguments = parser.parse_args()

    old_address, old_code = macho_text(open(arguments.old_kext, "rb").read())
    new_address, new_code = macho_text(open(arguments.new_kext, "rb").read())
    old_instructions = decode_instructions(old_address, old_code)
    new_instructions = decode_instructions(new_address, new_code)

    if arguments.raw:
        report_raw_mode(old_instructions, new_instructions, arguments)
        return 0

    old_functions = [Function(slice_) for slice_ in split_functions(old_instructions)]
    new_functions = [Function(slice_) for slice_ in split_functions(new_instructions)]
    report_function_mode(old_functions, new_functions, arguments)
    return 0


if __name__ == "__main__":
    sys.exit(main())
