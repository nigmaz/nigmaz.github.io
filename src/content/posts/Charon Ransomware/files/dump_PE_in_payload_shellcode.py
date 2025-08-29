import struct
import ida_bytes

try:
    import idc  # để đọc RAM khi đang debug
except Exception:
    idc = None


def read_mem(ea, size):
    # RAM (debugger)
    if idc is not None:
        try:
            b = idc.read_dbg_memory(ea, size)
            if b:
                return b
        except Exception:
            pass
    # IDB
    return ida_bytes.get_bytes(ea, size)


def u16_at(ea):
    b = read_mem(ea, 2)
    if not b or len(b) < 2:
        raise RuntimeError(f"Không đọc được 2 bytes tại 0x{ea:X}")
    return struct.unpack_from("<H", b, 0)[0]


def u32_at(ea):
    b = read_mem(ea, 4)
    if not b or len(b) < 4:
        raise RuntimeError(f"Không đọc được 4 bytes tại 0x{ea:X}")
    return struct.unpack_from("<I", b, 0)[0]


def dump_pe_by_last_section(address_MZ, out_path):
    # Kiểm tra 'MZ'
    mz = read_mem(address_MZ, 2)
    if mz != b"MZ":
        raise RuntimeError(f"Không thấy 'MZ' tại 0x{address_MZ:X}")

    # addr_e_lfanew = address_MZ + 0x3C
    addr_e_lfanew = address_MZ + 0x3C
    value_e_lfanew = u32_at(addr_e_lfanew)

    # addr_PE_header = address_MZ + value_e_lfanew
    addr_PE_header = address_MZ + value_e_lfanew
    sig = read_mem(addr_PE_header, 4)
    if sig != b"PE\x00\x00":
        raise RuntimeError(f"Không thấy 'PE\\0\\0' tại 0x{addr_PE_header:X}")

    # addr_number_of_section = addr_PE_header + 4 + 2
    addr_number_of_section = addr_PE_header + 4 + 2
    value_number_of_section = u16_at(addr_number_of_section)
    if value_number_of_section == 0:
        raise RuntimeError("NumberOfSections = 0 (bất thường)")

    # offset_from_first_section_to_last_section = 0x28 * (value_number_of_section - 1)
    offset_from_first_section_to_last_section = 0x28 * (value_number_of_section - 1)

    # addr_first_section = addr_PE_header + 0x108   (theo logic bạn đưa)
    # LƯU Ý: 0x108 = 0x18 (COFF) + 0xF0 (SizeOfOptionalHeader cho PE32+)
    addr_first_section = addr_PE_header + 0x108

    # addr_last_section = addr_first_section + offset_from_first_section_to_last_section
    addr_last_section = addr_first_section + offset_from_first_section_to_last_section

    # addr_size_of_raw_data / addr_pointer_to_raw_data
    addr_size_of_raw_data = addr_last_section + 0x10
    addr_pointer_to_raw_data = addr_last_section + 0x14

    size_of_raw_data = u32_at(addr_size_of_raw_data)
    pointer_to_raw_data = u32_at(addr_pointer_to_raw_data)

    # file_size = size_of_raw_data + pointer_to_raw_data
    file_size = size_of_raw_data + pointer_to_raw_data
    if file_size <= 0:
        raise RuntimeError(f"Kích thước tính ra không hợp lệ: 0x{file_size:X}")

    # Dump bytes từ address_MZ đến address_MZ + file_size
    data = read_mem(address_MZ, file_size)
    if not data or len(data) < file_size:
        # Nếu đọc thiếu (do vùng RAM/segment chưa map), pad 0 phần còn lại
        have = len(data) if data else 0
        data = (data or b"") + b"\x00" * (file_size - have)

    with open(out_path, "wb") as f:
        f.write(data)

    print("[OK] Dumped by last section logic")
    print(f"    MZ @ 0x{address_MZ:X}")
    print(f"    PE @ 0x{addr_PE_header:X}")
    print(f"    NumberOfSections = {value_number_of_section}")
    print(f"    LastSectionHeader @ 0x{addr_last_section:X}")
    print(f"    SizeOfRawData = 0x{size_of_raw_data:X}")
    print(f"    PointerToRawData = 0x{pointer_to_raw_data:X}")
    print(f"    -> file_size = 0x{file_size:X} bytes")
    print(f"    Written: {out_path}")


# ================== CÁCH GỌI ==================
# Đặt địa chỉ MZ thực tế và đường dẫn output ở đây:
address_MZ = 0x000002889BD13098
out_path = r"C:\Users\trant\Desktop\APTxx\malware\CharonRansomware.exe"
dump_pe_by_last_section(address_MZ, out_path)
