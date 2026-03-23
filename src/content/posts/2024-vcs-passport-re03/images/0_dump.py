#!/usr/bin/env python
# gn_unknown_relative_data_2220ADA2F5B

import idaapi
import binascii

start_address = 0x000002220ADA2F5B
gap = 0x3FE3D
end_address = start_address + gap
data = idaapi.get_bytes(start_address, gap)
with open("dumped_data.hex", "wb") as f:
    f.write(data)
    f.close()
    print("Success dump file data!")
