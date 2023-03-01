from struct import pack, unpack

stdout = open("stdout", "r").read()[: 80] + "0000"
stdout_int = [int(stdout[i:i+8], 16) for i in range(0, 88, 8)]
stdout_bytes = b"".join([pack("<I", x) for x in stdout_int])

for i in range(len(stdout_int) - 2):
    i2 = (len(stdout_int) - 3 - i) * 4
    r8 = stdout_bytes[i2 + 4 : i2 + 12]
    r8_num = unpack("<q", r8)[0]
    temp = (r8_num >> 16) & 0xffff0000
    r8_num = (r8_num - temp) & 0xffffffff
    r7_num = r8_num
    r7_num = (r7_num << 16) & 0xffff0000
    r8_num = (r8_num >> 16) & 0x0000ffff
    r7_num += r8_num
    r7 = pack("<I", r7_num & 0xffffffff)
    stdout_bytes = stdout_bytes[: i2 + 4] + r7 + stdout_bytes[i2 + 8 :]
    r6 = (i + 2) % 4
    r6 = ((r6 * -0x21524151) & -1) & 0xffffffff
    r7 = stdout_bytes[i2 : i2 + 8]
    r8 = stdout_bytes[i2 + 4 : i2 + 12]
    r7_num = unpack("<q", r7)[0]
    r8_num = unpack("<q", r8)[0]
    r7_num ^= r8_num
    r7_num ^= r6
    r7 = pack("<I", r7_num & 0xffffffff)
    stdout_bytes = stdout_bytes[: i2] + r7 + stdout_bytes[i2 + 4 :]
    
print(stdout_bytes)