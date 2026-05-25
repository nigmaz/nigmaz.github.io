#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined PLX config extractor

Usage:
    python plx_config_extractor.py .\\AVKTray.dat -k 0x63 -o final_payload.bin

Flow:
    AVKTray.dat
      -> XOR decode final_payload from .dat with user supplied XOR key
      -> save decoded payload to output file
      -> read encoded config blob from decoded payload
      -> RC4 first-stage decode
      -> XOR UTF-16LE field decode
      -> print config JSON

Notes about the config field layout:
    The decoded layer-1 blob keeps the original 0x10-byte header:
      +0x00: DWORD rc4_key_len
      +0x04: BYTE[rc4_key_len] rc4_key
      +0x10: decoded config body

    Most wide-string fields use this layout:
      +0x00: DWORD wchar_len
      +0x04: DWORD reserved / unused
      +0x08: WCHAR encrypted_data[wchar_len]

    The decoy document name field is different:
      +0x00: DWORD wchar_len
      +0x04: DWORD reserved / unused
      +0x08: DWORD decoy_docx_size
      +0x0C: DWORD reserved / unused
      +0x10: WCHAR encrypted_data[wchar_len]

    IDA/decompiler pointer note:
      *((WORD *)&field + i + 4) means byte offset +0x08
      *((WORD *)&field + i + 8) means byte offset +0x10
"""

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ====== .dat -> payload decode constants ======

LENGTH_FINAL_PAYLOAD = 0x96800
START_FINAL_PAYLOAD_OFFSET = 0xD
# XOR_KEY_OFFSET = 0x96824


# ====== payload -> config constants ======

PAYLOAD_CONFIG_OFFSET = 0x93418
PAYLOAD_CONFIG_SIZE = 0x8B0

FIRST_STAGE_RC4 = True
CONFIG_HEADER_SIZE = 0x10


# ====== config field offsets, relative to g_tmp_raw_config_blob / layer-1 blob ======
#
# split_blob() returns:
#   blob_decode_layer_1 = original_header_0x10 + rc4_decoded_config_body
#
# Therefore these offsets include the 0x10-byte header. This mirrors the
# global addresses from the pseudocode, for example:
#   g_io_config_blob_1009D62C - g_tmp_raw_config_blob_1009D61C = 0x10

OFFSET_DECOY_DOCUMENT = 0x10      
OFFSET_MUTEX_NAME = 0x218         
OFFSET_PAYLOAD_MARKER = 0x258     
OFFSET_PUBLIC_DIR = 0x298         
OFFSET_DECOY_PATH = 0x4A0         
OFFSET_C2_TABLE = 0x6A8           

FIELD_DATA_WORD_INDEX_COMMON = 4          # decompiler +4 WORDs == +0x08 bytes
FIELD_DATA_WORD_INDEX_DECOY_DOC = 8       # decompiler +8 WORDs == +0x10 bytes
OFFSET_DECOY_DOCX_SIZE = OFFSET_DECOY_DOCUMENT + 0x08


# ----------------------------------------------------------------------
# Basic readers
# ----------------------------------------------------------------------

def parse_int(value: str) -> int:
    """Allow decimal or 0x-prefixed integer CLI values."""
    return int(value, 0)


def u16(buf: bytes, off: int) -> int:
    if off + 2 > len(buf):
        raise ValueError(f"u16 offset 0x{off:X} is beyond buffer size 0x{len(buf):X}")
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    if off + 4 > len(buf):
        raise ValueError(f"u32 offset 0x{off:X} is beyond buffer size 0x{len(buf):X}")
    return struct.unpack_from("<I", buf, off)[0]


# ----------------------------------------------------------------------
# Stage 1: AVKTray.dat -> decoded payload
# ----------------------------------------------------------------------

def decrypt_dat_to_payload_bytes(
    input_path: str,
    xor_key: int,
    start_offset: int = START_FINAL_PAYLOAD_OFFSET,
    length_final_payload: int = LENGTH_FINAL_PAYLOAD,
) -> Tuple[bytes, Dict[str, Any]]:
    """Decode final payload from .dat using the XOR key supplied from CLI."""
    data = Path(input_path).read_bytes()

    if not 0 <= xor_key <= 0xFF:
        raise ValueError(f"XOR key must be one byte: 0x00..0xFF, got 0x{xor_key:X}.")

    if start_offset >= len(data):
        raise ValueError(
            f"Start offset 0x{start_offset:X} is beyond file size 0x{len(data):X}."
        )

    end_offset = start_offset + length_final_payload
    if end_offset > len(data):
        raise ValueError(
            f"Payload end offset 0x{end_offset:X} is beyond file size 0x{len(data):X}."
        )

    enc_blob = data[start_offset:end_offset]
    dec_blob = bytes(b ^ xor_key for b in enc_blob)

    meta = {
        "input": str(input_path),
        "dat_file_size": len(data),
        "payload_start_offset": start_offset,
        "payload_length": length_final_payload,
        "xor_key": xor_key,
        "payload_mz": dec_blob[:2] == b"MZ",
    }

    return dec_blob, meta


# ----------------------------------------------------------------------
# Stage 2: decoded payload -> encoded config blob
# ----------------------------------------------------------------------

def get_config_blob_from_payload(
    payload: bytes,
    config_offset: int = PAYLOAD_CONFIG_OFFSET,
    config_size: int = PAYLOAD_CONFIG_SIZE,
) -> bytes:
    """Read encoded config blob from the decoded payload."""
    if config_offset >= len(payload):
        raise ValueError(
            f"Config offset 0x{config_offset:X} is beyond payload size 0x{len(payload):X}."
        )

    end_offset = config_offset + config_size
    if end_offset > len(payload):
        raise ValueError(
            f"Config end offset 0x{end_offset:X} is beyond payload size 0x{len(payload):X}."
        )

    return payload[config_offset:end_offset]


# ----------------------------------------------------------------------
# Stage 3: config decode helpers
# ----------------------------------------------------------------------

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key is empty.")

    s = list(range(256))
    j = 0
    k = 0

    # KSA: matches fn_rc4_init_sbox_from_key_10080164()
    for i in range(256):
        j = (j + s[i] + key[k]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = (k + 1) % len(key)

    out = bytearray()
    i = 0
    j = 0

    # PRGA: matches fn_rc4_crypt_buffer_100802E2()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]

        ks = s[(s[i] + s[j]) & 0xFF]
        out.append(b ^ ks)

    return bytes(out)


def xor_decode_wide(enc_bytes: bytes, byte_len: int, seed: int) -> bytes:
    """
    Mô phỏng logic fn_xor_decode_wide_buffer_10081750.

    int fn(buf, byte_len, seed)
    {
        v4 = byte_len / 2;
        for j in range(byte_len):
            buf[j] ^= (v4 + seed) ^ 0x18 ^ 0x18;
            seed += v4;
    }

    Vì 0x18 ^ 0x18 == 0, effective XOR key mỗi vòng là:
        (wchar_len + seed) & 0xFF
    """
    if byte_len > len(enc_bytes):
        raise ValueError(
            f"Requested byte_len 0x{byte_len:X}, but field only has 0x{len(enc_bytes):X} bytes."
        )

    data = bytearray(enc_bytes[:byte_len])
    wchar_len = byte_len // 2
    a3 = seed

    for j in range(byte_len):
        xor_key = ((wchar_len + a3) ^ 0x18 ^ 0x18) & 0xFF
        data[j] ^= xor_key
        a3 += wchar_len

    return bytes(data)


def read_xor_wide_field(
    blob_decode_layer_1: bytes,
    field_offset: int,
    key_len: int,
    *,
    data_word_index: Optional[int] = FIELD_DATA_WORD_INDEX_COMMON,
    data_offset: Optional[int] = None,
    field_name: str = "wide field",
) -> str:
    """
    Decode một UTF-16LE config field.

    Có 2 cách truyền điểm bắt đầu encrypted data:

    1) data_word_index:
       Dùng đúng kiểu nhìn từ pseudocode IDA:
         *((WORD *)&field + i + 4)  -> data_word_index=4  -> byte offset +0x08
         *((WORD *)&field + i + 8)  -> data_word_index=8  -> byte offset +0x10

    2) data_offset:
       Dùng byte offset trực tiếp:
         data_offset=0x08 hoặc data_offset=0x10

    Nếu truyền data_offset thì data_offset sẽ được ưu tiên.
    """
    wchar_len = u32(blob_decode_layer_1, field_offset)
    byte_len = wchar_len * 2

    if data_offset is None:
        if data_word_index is None:
            raise ValueError("Either data_word_index or data_offset must be supplied.")
        data_offset = data_word_index * 2

    enc_offset = field_offset + data_offset
    enc_end = enc_offset + byte_len

    if enc_end > len(blob_decode_layer_1):
        raise ValueError(
            f"{field_name} at 0x{field_offset:X} ends at 0x{enc_end:X}, "
            f"beyond config blob size 0x{len(blob_decode_layer_1):X}."
        )

    enc_bytes = blob_decode_layer_1[enc_offset:enc_end]
    seed = key_len + wchar_len
    dec_bytes = xor_decode_wide(enc_bytes, byte_len, seed)

    return dec_bytes.decode("utf-16le", errors="ignore").rstrip("\x00")


def extract_c2_table(
    blob_decode_layer_1: bytes,
    table_offset: int,
    key_len: int,
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    C2 table layout from this sample:

      table_offset +0x00: DWORD c2_entry_count
      table_offset +0x08: first entry

    Entry layout used by the pseudocode:
      +0x00: DWORD v58 = host_len + 5
      +0x08: BYTE flag
      +0x0A: WORD port
      +0x12: WCHAR encrypted_host[host_len]

    Entry stepping:
      n4 starts at 4, entry_offset = table_offset + 2 * n4
      n4 += v58 + 4
    """
    c2_declared_count = u32(blob_decode_layer_1, table_offset)
    c2_list: List[Dict[str, Any]] = []

    n4 = 4
    for entry_index in range(c2_declared_count):
        entry_offset = table_offset + 2 * n4

        if entry_offset + 0x20 > len(blob_decode_layer_1):
            raise ValueError(
                f"C2 entry #{entry_index} at 0x{entry_offset:X} is outside config blob."
            )

        v58 = u32(blob_decode_layer_1, entry_offset)

        # v58 = host_len + 5
        if v58 <= 5 or v58 > 0x100:
            raise ValueError(
                f"Invalid C2 entry #{entry_index} size marker v58=0x{v58:X} "
                f"at 0x{entry_offset:X}."
            )

        host_len = v58 - 5
        byte_len = host_len * 2

        flag = blob_decode_layer_1[entry_offset + 8]
        port = u16(blob_decode_layer_1, entry_offset + 10)

        enc_offset = entry_offset + 18
        enc_end = enc_offset + byte_len
        if enc_end > len(blob_decode_layer_1):
            raise ValueError(
                f"C2 entry #{entry_index} host ends at 0x{enc_end:X}, "
                f"beyond config blob size 0x{len(blob_decode_layer_1):X}."
            )

        enc_host = blob_decode_layer_1[enc_offset:enc_end]

        # seed = v58 + key_len - 5 == key_len + host_len
        seed = v58 + key_len - 5
        dec_host_bytes = xor_decode_wide(enc_host, byte_len, seed)
        host = dec_host_bytes.decode("utf-16le", errors="ignore").rstrip("\x00")

        c2_list.append(
            {
                "index": entry_index,
                "entry_offset": f"0x{entry_offset:X}",
                "host_length": host_len,
                "host": host,
                "port": port,
                "flag": flag,
            }
        )

        # Entry tiếp theo: logic gốc n4 += v58 + 4
        n4 += v58 + 4

    # Return both declared count and actually decrypted count.
    return c2_declared_count, c2_list


def split_blob(blob_encoded: bytes, first_stage_rc4: bool = False) -> Tuple[int, bytes, bytes]:
    """
    Layout blob_encoded:
      +0x00: DWORD key_len
      +0x04: BYTE[key_len] key
      +0x10: config data encoded
    """
    if len(blob_encoded) < CONFIG_HEADER_SIZE:
        raise ValueError(
            f"Config blob too small: 0x{len(blob_encoded):X}, expected at least 0x{CONFIG_HEADER_SIZE:X}."
        )

    key_len = u32(blob_encoded, 0)
    key = blob_encoded[4:4 + key_len]

    if len(key) != key_len:
        raise ValueError(
            f"Invalid RC4 key length 0x{key_len:X}; blob size is only 0x{len(blob_encoded):X}."
        )

    header = blob_encoded[:CONFIG_HEADER_SIZE]
    config_encoded = blob_encoded[CONFIG_HEADER_SIZE:]

    if first_stage_rc4:
        config_decode_layer_1 = rc4_crypt(config_encoded, key)
    else:
        config_decode_layer_1 = config_encoded

    blob_decode_layer_1 = header + config_decode_layer_1
    return key_len, key, blob_decode_layer_1


def extract_config(blob_encoded: bytes, first_stage_rc4: bool = FIRST_STAGE_RC4) -> Dict[str, Any]:
    key_len, key, blob_decode_layer_1 = split_blob(blob_encoded, first_stage_rc4)

    # Dump decoded layer 1 config blob to hex file.
    Path("config_data_dump_layer_1.hex").write_text(
        blob_decode_layer_1.hex(),
        encoding="utf-8",
    )
    print("[+] Decode RC4 encoded_config_blob to 'config_data_dump_layer_1.hex'")

    decoy_doc_name = read_xor_wide_field(
        blob_decode_layer_1,
        OFFSET_DECOY_DOCUMENT,
        key_len,
        data_word_index=FIELD_DATA_WORD_INDEX_DECOY_DOC,  # IDA +8 WORDs == +0x10 bytes
        field_name="decoy document name",
    )

    decoy_docx_size = u32(blob_decode_layer_1, OFFSET_DECOY_DOCX_SIZE)

    # Nếu decoy name rỗng, hoặc decode ra toàn null byte kiểu a ^ a = 0,
    # thì coi như field này không được set.
    decoy_doc_name_is_not_set = not decoy_doc_name or decoy_doc_name.strip("\x00").strip() == ""

    c2_declared_count, c2_entries = extract_c2_table(
        blob_decode_layer_1,
        OFFSET_C2_TABLE,
        key_len,
    )

    result = {
        "rc4_key_len": key_len,
        "rc4_key": key.decode("ascii", errors="ignore"),
        "Decoy Document Name": "<not_set>" if decoy_doc_name_is_not_set else decoy_doc_name,

        # Chỉ chèn dòng này nếu decoy name thật sự có giá trị.
        **(
            {}
            if decoy_doc_name_is_not_set
            else {"Decoy File Size": f"{decoy_docx_size} KB"}
        ),

        "Mutex Name": read_xor_wide_field(
            blob_decode_layer_1,
            OFFSET_MUTEX_NAME,
            key_len,
            data_word_index=FIELD_DATA_WORD_INDEX_COMMON,
            field_name="mutex name",
        ),
        "Payload Marker": read_xor_wide_field(
            blob_decode_layer_1,
            OFFSET_PAYLOAD_MARKER,
            key_len,
            data_word_index=FIELD_DATA_WORD_INDEX_COMMON,
            field_name="payload marker",
        ),
        "Installation PATH": read_xor_wide_field(
            blob_decode_layer_1,
            OFFSET_PUBLIC_DIR,
            key_len,
            data_word_index=FIELD_DATA_WORD_INDEX_COMMON,  # IDA +4 WORDs == +0x08 bytes
            field_name="installation path",
        ),
        "Decoy PATH": read_xor_wide_field(
            blob_decode_layer_1,
            OFFSET_DECOY_PATH,
            key_len,
            data_word_index=FIELD_DATA_WORD_INDEX_COMMON,
            field_name="decoy path",
        ),
        "C2 Entries": {
            "count": len(c2_entries),
            "items": c2_entries,
        },
    }

    return result


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode AVKTray.dat with a supplied XOR key, save decoded payload, and extract PLX config."
    )
    parser.add_argument(
        "dat_path",
        help="Path to AVKTray.dat",
    )
    parser.add_argument(
        "-k",
        "--key",
        type=parse_int,
        required=True,
        help="One-byte XOR key, example: -k 0x63",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output path for decoded payload, example: -o payload_final.bin",
    )
    parser.add_argument(
        "--no-rc4",
        action="store_true",
        help="Skip first-stage RC4. Use only when the config blob is already layer-1 decoded.",
    )

    args = parser.parse_args()

    print("[*] Stage 1: 'AVKTray.dat' -> decoded 'final_payload'")
    payload, meta = decrypt_dat_to_payload_bytes(
        args.dat_path,
        xor_key=args.key,
    )

    Path(args.output).write_bytes(payload)

    print(f"[+] Input .dat                 : {meta['input']}")
    print(f"[+] File size .dat             : 0x{meta['dat_file_size']:X}")
    print(f"[+] Payload start offset       : 0x{meta['payload_start_offset']:X}")
    print(f"[+] Payload length             : 0x{meta['payload_length']:X}")
    print(f"[+] XOR key                    : 0x{meta['xor_key']:02X}")
    print(f"[+] Output payload             : {args.output}")
    print(f"[*] PE file (MZ header)        : {meta['payload_mz']}\n")

    print("[*] Stage 2: 'final_payload' -> extracted config")
    blob_encoded = get_config_blob_from_payload(payload)
    config = extract_config(blob_encoded, first_stage_rc4=not args.no_rc4)

    print(f"[+] Config offset in final_payload  : 0x{PAYLOAD_CONFIG_OFFSET:X}")
    print(f"[+] Config size                     : 0x{PAYLOAD_CONFIG_SIZE:X}\n")
    print(json.dumps(config, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
