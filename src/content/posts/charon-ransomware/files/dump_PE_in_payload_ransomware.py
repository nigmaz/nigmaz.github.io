import struct


def u16_at(data, offset):
    if offset + 2 > len(data):
        raise RuntimeError(f"Không đọc được 2 bytes tại 0x{offset:X}")
    return struct.unpack_from("<H", data, offset)[0]


def u32_at(data, offset):
    if offset + 4 > len(data):
        raise RuntimeError(f"Không đọc được 4 bytes tại 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def dump_pe_by_last_section_from_file(in_path, mz_offset, out_path):
    with open(in_path, "rb") as f:
        f.seek(0, 2)
        file_len = f.tell()
        f.seek(0)
        data = f.read()

    # Kiểm tra 'MZ'
    if data[mz_offset : mz_offset + 2] != b"MZ":
        raise RuntimeError(f"Không thấy 'MZ' tại 0x{mz_offset:X}")

    # addr_e_lfanew = mz_offset + 0x3C
    addr_e_lfanew = mz_offset + 0x3C
    value_e_lfanew = u32_at(data, addr_e_lfanew)

    # addr_PE_header = mz_offset + value_e_lfanew
    addr_PE_header = mz_offset + value_e_lfanew
    sig = data[addr_PE_header : addr_PE_header + 4]
    if sig != b"PE\x00\x00":
        raise RuntimeError(f"Không thấy 'PE\\0\\0' tại 0x{addr_PE_header:X}")

    # addr_number_of_section = addr_PE_header + 4 + 2
    addr_number_of_section = addr_PE_header + 6
    value_number_of_section = u16_at(data, addr_number_of_section)
    if value_number_of_section == 0:
        raise RuntimeError("NumberOfSections = 0 (bất thường)")

    # offset_from_first_section_to_last_section
    offset_from_first_section_to_last_section = 0x28 * (value_number_of_section - 1)

    # addr_first_section = addr_PE_header + 0x108
    addr_first_section = addr_PE_header + 0x108

    # addr_last_section
    addr_last_section = addr_first_section + offset_from_first_section_to_last_section

    # lấy size_of_raw_data / pointer_to_raw_data
    addr_size_of_raw_data = addr_last_section + 0x10
    addr_pointer_to_raw_data = addr_last_section + 0x14

    size_of_raw_data = u32_at(data, addr_size_of_raw_data)
    pointer_to_raw_data = u32_at(data, addr_pointer_to_raw_data)

    file_size = size_of_raw_data + pointer_to_raw_data
    if file_size <= 0:
        raise RuntimeError(f"Kích thước tính ra không hợp lệ: 0x{file_size:X}")

    # dump từ offset MZ đến offset MZ + file_size
    end_off = mz_offset + file_size
    if end_off > len(data):
        raise RuntimeError(
            f"File không đủ dữ liệu: yêu cầu 0x{end_off:X}, có 0x{len(data):X}"
        )

    pe_bytes = data[mz_offset:end_off]

    with open(out_path, "wb") as f:
        f.write(pe_bytes)

    print("[OK] Dumped by last section logic (from file)")
    print(f"    Input file: {in_path}")
    print(f"    MZ @ 0x{mz_offset:X}")
    print(f"    PE @ 0x{addr_PE_header:X}")
    print(f"    NumberOfSections = {value_number_of_section}")
    print(f"    LastSectionHeader @ 0x{addr_last_section:X}")
    print(f"    SizeOfRawData = 0x{size_of_raw_data:X}")
    print(f"    PointerToRawData = 0x{pointer_to_raw_data:X}")
    print(f"    -> file_size = 0x{file_size:X} bytes")
    print(f"    Written: {out_path}")


# ================== CÁCH GỌI ==================
in_path = r".\Charon_Ransomware.exe"
mz_offset = 0x17660
out_path = r".\PE_dump.exe"

dump_pe_by_last_section_from_file(in_path, mz_offset, out_path)
