#!/usr/bin/env python3

import argparse
from pathlib import Path


def transform_byte(b: int) -> int:
    # 1) NOT
    b = (~b) & 0xFF
    # 2) XOR với 0x2E
    b ^= 0x2E
    # 3) NEG 8-bit: (0x100 - AL) & 0xFF
    b = (0x100 - b) & 0xFF
    return b


def decode_file(in_path: Path, out_path: Path, chunk_size: int = 1 << 20) -> None:
    """Đọc DumpStack.log, giải mã theo 3 bước, ghi ra data.bin."""
    with in_path.open("rb") as fin, out_path.open("wb") as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            buf = bytearray(chunk)
            for i in range(len(buf)):
                buf[i] = transform_byte(buf[i])
            fout.write(buf)


def main():
    ap = argparse.ArgumentParser(
        description="Decryption DumpStack.log => data.bin (NOT => XOR 0x2E => NEG)"
    )
    ap.add_argument("input", help="Path DumpStack.log (input)")
    ap.add_argument("-o", "--output", default="data.bin", help="Path data.bin (output)")
    ap.add_argument(
        "--chunk", type=int, default=1 << 20, help="Chunk size (default 1MB)"
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.is_file():
        raise SystemExit(f"File not found: {in_path}")

    decode_file(in_path, out_path, args.chunk)
    print(f"[OK] Decrypted: {in_path} -> {out_path}")


if __name__ == "__main__":
    main()

###########################################################
# python decode_dumpstack.py "DumpStack.log" -o data.bin
###########################################################
