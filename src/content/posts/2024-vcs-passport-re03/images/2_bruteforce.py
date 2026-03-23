#!/usr/bin/env python3
# brute_vsn_nested.py

import hashlib
import struct

TARGET_XOR_RESULT = 0xEF8B43  # giá trị sau XOR bạn muốn đạt
CONST_XOR = 0x03088A37  # hằng XOR cố định

for a in range(0x00, 0x100):  # byte thấp nhất
    for b in range(0x00, 0x100):
        for c in range(0x00, 0x100):
            for d in range(0x00, 0x100):  # byte cao nhất
                # Ghép 4 byte little-endian => bytes object
                serial_bytes = bytes([a, b, c, d])

                # Tính MD5
                print(f"[+] Trying Serial : {serial_bytes}")
                md5 = hashlib.md5(serial_bytes).digest()

                # Lấy 4 byte [10:14] => số nguyên little-endian
                val = int.from_bytes(md5[10:14], "little") ^ CONST_XOR

                if val == TARGET_XOR_RESULT:
                    # In ra Serial theo dạng Windows: xxxx-xxxx
                    serial_int = struct.unpack("<I", serial_bytes)[0]
                    hi, lo = (serial_int >> 16) & 0xFFFF, serial_int & 0xFFFF
                    print(f"FOUND  {lo:04X}-{hi:04X}")
                    raise SystemExit
