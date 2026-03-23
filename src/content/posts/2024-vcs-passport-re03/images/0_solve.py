#!/usr/bin/env python3
import hashlib

# Chuỗi byte 4 bytes (little-endian)
# data = bytes([0x04, 0x68, 0x1B, 0xAE])

# 0x95FCE4BA
# data = bytes([0xBA, 0xE4, 0xFC, 0x95])  # Serial cần kiểm tra
# print(data)

# 0xF22B5592
data = bytes([0x92, 0x55, 0x2B, 0xF2])
print(data)

# Tính MD5
md5_hash = hashlib.md5(data).hexdigest()
print(f"MD5: {md5_hash}")

byte_list = [md5_hash[i : i + 2] for i in range(0, len(md5_hash), 2)]
print(byte_list)

print(
    f"Important byte: {byte_list[-3]}, {byte_list[-4]}, {byte_list[-5]}, {byte_list[-6]}"
)

# print(hex(0x0000000003088A37^0xEF8B43)) = 0x3e70174 = 03 e7 01 74 => Edit byte 74 01 e7 03 | Byte đúng điều kiện

# a6 = 0x03088A37

# a7 = 0x2220ADA1917LL
