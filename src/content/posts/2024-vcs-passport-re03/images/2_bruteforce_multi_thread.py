#!/usr/bin/env python3
import hashlib
import struct
import os
import concurrent.futures

TARGET_XOR_RESULT = 0xEF8B43  # giá trị cần đạt sau XOR
CONST_XOR = 0x03088A37  # hằng XOR
CHUNK = 1 << 20  # 1 048 576 serial / thread / lần


# ---------------------------------------------------------------
def check_range(start: int) -> int | None:
    """Dò 1 khối serial [start, start+CHUNK). Khớp ⇒ trả về serial, else None."""
    end = min(start + CHUNK, 1 << 32)
    pack = struct.pack
    for serial in range(start, end):
        md5 = hashlib.md5(pack("<I", serial)).digest()
        if (int.from_bytes(md5[10:14], "little") ^ CONST_XOR) == TARGET_XOR_RESULT:
            return serial
    return None


# ---------------------------------------------------------------
def main() -> None:
    total = 1 << 32  # 4 294 967 296
    workers = os.cpu_count() or 4
    print(f"[+] Threaded brute-force với {workers} thread; chunk = {CHUNK:,}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        # Nạp lần lượt các "công việc" (start offset) vào pool
        futures = {pool.submit(check_range, off): off for off in range(0, total, CHUNK)}

        for fut in concurrent.futures.as_completed(futures):
            serial = fut.result()
            if serial is not None:
                hi = (serial >> 16) & 0xFFFF
                lo = serial & 0xFFFF
                print(f"[=>] FOUND  {lo:04X}-{hi:04X}")
                # Huỷ toàn bộ future còn lại (Python >= 3.9)
                pool.shutdown(cancel_futures=True)
                return

    print("[-] Không tìm thấy serial nào thỏa mãn!")


# ---------------------------------------------------------------
if __name__ == "__main__":
    main()
