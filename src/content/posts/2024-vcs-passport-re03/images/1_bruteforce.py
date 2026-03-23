#!/usr/bin/env python3
import hashlib, struct

TARGET = 0x03E70174

for n in range(0x100000000):  # 0 => 0xFFFFFFFF
    digest = hashlib.md5(struct.pack("<I", n)).digest()
    if int.from_bytes(digest[10:14], "little") == TARGET:
        print(f"FOUND 0x{n:08X}")
        break
