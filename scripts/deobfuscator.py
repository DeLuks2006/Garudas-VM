#!/usr/bin/env python

import re
import argparse

def find_pattern(target_path:str, pattern:bytes) -> list:
    data = bytearray(open(target_path, "rb").read())
    regex = re.compile(re.escape(pattern))
    matches = list(regex.finditer(data))
    print(f"[i] Found {len(matches)} matches")
    return matches

def add_padding(pattern:bytes, patch:bytes) -> bytes:
    return patch + b"\x90" * (len(pattern) - len(patch))

def patch_file(path:str, offsets:list, patch:bytes) -> None:
    data = bytearray(open(path, "rb").read())
    for off in (o.start() for o in offsets):
        data[off : off + len(patch)] = patch
    open(path, "wb").write(data)

def patch_and_save(path:str, pattern:bytes, patch:bytes) -> None:
    offsets:list = find_pattern(path, pattern)
    print("\t\\__[ offsets ]:", " ".join(f"{o.start():#x}" for o in offsets))
    patch_bytes = add_padding(pattern, patch)
    patch_file(path, offsets, patch_bytes)

def patch_add(filename:str) -> None:
    patterns = [
        # Variant 1
        b"\x41\x8B\xD0\x41\x8B\xC0\x41\x33\xC1\x41\x0B\xD1\x8B\xCA\x2B\xC8"
        b"\x41\x8B\xC0\x41\x23\xC1\x03\xC9\x44\x8B\xC2\x44\x8B\xC9\x44\x2B"
        b"\xC0\x85\xC9\x75\xDB",
        # Variant 2
        b"\x44\x8b\xc0\x8b\xc8\x41\x33\xc9\x45\x0b\xc1\x41\x8b\xd0\x2b\xd1"
        b"\x8b\xc8\x41\x23\xc9\x03\xd2\x41\x8b\xc0\x44\x8b\xca\x2b\xc1\x85"
        b"\xd2\x75\xdd"
    ]
    patch_str = b"\x45\x01\xc8" # add r8d, r9d
    for p in patterns:
        patch_and_save(filename, p, patch_str)

def patch_or(filename:str) -> None:
    patterns = [
        # Variant 1 - MOV rdx, r8; OR rdx, 1
        b"\x33\xc9\x41\x8b\xc0\xd3\xf8\x85\xc0\x7f\x0b\xb8\x01\x00"
        b"\x00\x00\xd3\xf8\x85\xc0\x7e\x21\x41\x8b\xc0\x83\xc8\x01\xd3\xf8"
        b"\x83\xe0\x01\xd3\xe0\x0b\xd0\xff\xc1\xeb\xd9",
        # Variant 2 - MOV rdx, r8; OR rdx, 2
        b"\x33\xc9\x90\x41\x8b\xc0\xd3\xf8\x85\xc0\x7f\x0b\xb8\x02\x00\x00"
        b"\x00\xd3\xf8\x85\xc0\x7e\x21\x41\x8b\xc0\x83\xc8\x02\xd3"
        b"\xf8\x83\xe0\x01\xd3\xe0\x0b\xd0\xff\xc1\xeb\xd9",
        # Variant 3 - MOV r9, r8; OR r9, rdx
        b"\x33\xc9\x66\x0f\x1f\x44\x00\x00\x41\x8b\xc0\xd3\xf8\x85\xc0\x7f"
        b"\x08\x8b\xc2\xd3\xf8\x85\xc0\x7e\x13\x41\x8b\xc0\x0b\xc2\xd3\xf8"
        b"\x83\xe0\x01\xd3\xe0\x44\x0b\xc8\xff\xc1\xeb\xdc"
    ]
    patches = [
        b"\x44\x89\xC2\x83\xCA\x01" + (b"\x90" * 13) + b"\xeb\x21",
        b"\x44\x89\xC2\x83\xCA\x02" + (b"\x90" * 13) + b"\xeb\x21",
        b"\x4D\x89\xC1\x49\x09\xD1"
    ]
    for i in range(len(patches)):
        patch_and_save(filename, patterns[i], patches[i])

def patch_and(filename:str) -> None:
    patterns = [
        b"\x34\x0f\x80\xca\x0f\x2a\xd0",
        b"\x33\xc2\x0b\xca\x2b\xc8",
        b"\x83\xf0\xfe\x83\xca\xfe\x2b\xd0",
        b"\x83\xf0\xfd\x83\xca\xfd\x2b\xd0",
        b"\x34\x0f\x41\x80\xc8\x0f\x44\x2a\xc0",
    ]

    patches = [
        b"\x80\xE2\x0F",
        b"\x21\xD1",
        b"\x44\x89\xC2\x83\xE2\x01",
        b"\x44\x89\xC2\x83\xE2\x02",
        b"\x41\x80\xE0\x0F",
    ]

    for i in range(len(patches)):
        patch_and_save(filename, patterns[i], patches[i])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GarudaVM Deobfuscator")
    parser.add_argument("filename", help="file to process")
    parser.add_argument("-a", "--all", action="store_true", help="run all patches")
    parser.add_argument("--add", dest="add_op", action="store_true", help="deobfuscate the ADD operations")
    parser.add_argument("--or", dest="or_op", action="store_true", help="deobfuscate the OR operations")
    parser.add_argument("--and", dest="and_op", action="store_true", help="deobfuscate the AND operations")
    args = parser.parse_args()

    if args.all:
        patch_add(args.filename)
        patch_or(args.filename)
        patch_and(args.filename)
    if args.add_op:
        patch_add(args.filename)
    if args.or_op:
        patch_or(args.filename)
    if args.and_op:
        patch_and(args.filename)

    print("[+] Finished patching program")

