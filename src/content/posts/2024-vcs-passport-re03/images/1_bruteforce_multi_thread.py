#!/usr/bin/env python3
import hashlib
import struct
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = 0x03E70174  # hash[10:14] phải khớp
MAX_N = 1 << 32  # 0x100000000
CHUNK = 1 << 20  # 1 048 576 số / task


def scan_range(start: int) -> list[int]:
    """Brute-force n ∈ [start, start+CHUNK). Trả về mọi n thỏa mãn."""
    end = min(start + CHUNK, MAX_N)
    tgt = TARGET
    pack = struct.pack
    hits = []
    for n in range(start, end):
        digest = hashlib.md5(pack("<I", n)).digest()
        if int.from_bytes(digest[10:14], "little") == tgt:
            hits.append(n)
    return hits  # có thể rỗng


def fmt_vs(n: int) -> str:
    hi, lo = (n >> 16) & 0xFFFF, n & 0xFFFF
    return f"{hi:04X}-{lo:04X}"


def main() -> None:
    workers = os.cpu_count() or 4
    print(f"[+] Brute-force 32-bit * {workers} threads * chunk = {CHUNK:,}")

    all_hits: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_range, off): off for off in range(0, MAX_N, CHUNK)}

        for fut in as_completed(futures):
            hits = fut.result()
            if hits:
                for n in hits:  # in ngay
                    print(f"[=>] FOUND 0x{n:08X}  |  VS = {fmt_vs(n)}")
                all_hits.extend(hits)

    print("\n========== SUMMARY ==========")
    if not all_hits:
        print("[-] Không tìm thấy giá trị thoả mãn.")
    else:
        all_hits.sort()
        for idx, n in enumerate(all_hits, 1):
            print(f"{idx:>3}: 0x{n:08X}  |  VS={fmt_vs(n)}")
        print(f"[+] Tổng cộng {len(all_hits)} giá trị khớp.")


if __name__ == "__main__":
    main()


# #!/usr/bin/env python3
# import hashlib
# import struct
# import os
# from concurrent.futures import ThreadPoolExecutor, as_completed

# TARGET = 0x03E70174  # cần trùng với hash[10:14]
# MAX_N = 1 << 32  # 0x100000000
# CHUNK = 1 << 20  # 1 048 576 số / công việc (~1 MiB)


# def scan_range(start: int) -> int | None:
#     """
#     Dò các giá trị trong [start, start+CHUNK).
#     Trả về n đầu tiên thỏa mãn, hoặc None nếu không có.
#     """
#     end = min(start + CHUNK, MAX_N)
#     t = TARGET
#     pack = struct.pack
#     for n in range(start, end):
#         digest = hashlib.md5(pack("<I", n)).digest()
#         if int.from_bytes(digest[10:14], "little") == t:
#             return n
#     return None


# def main() -> None:
#     workers = os.cpu_count() or 4
#     print(f"[+] Brute-force 32-bit với {workers} thread, chunk = {CHUNK:,}")

#     with ThreadPoolExecutor(max_workers=workers) as pool:
#         # Nộp "công việc" — mỗi chunk là một nhiệm vụ độc lập
#         futures = {pool.submit(scan_range, off): off for off in range(0, MAX_N, CHUNK)}

#         for fut in as_completed(futures):
#             n = fut.result()
#             if n is not None:  # Đã tìm thấy!
#                 print(f"[=>] FOUND 0x{n:08X}")
#                 hi = (n >> 16) & 0xFFFF
#                 lo = n & 0xFFFF
#                 print(f"[=>] Volume Serial Number: {lo:04X}-{hi:04X}")
#                 # pool.shutdown(cancel_futures=True)  # Huỷ phần còn lại
#                 return

#     print("[-] Không tìm thấy giá trị thoả mãn.")


# if __name__ == "__main__":
#     main()
