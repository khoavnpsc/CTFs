from struct import unpack

binary = open("./dump", "rb").read()

ins = {
    0x62: f"{'stw':<10} [dst+off], imm",
    0x63: f"{'stxw':<10} [dst+off], src",
    0x85: f"{'call':<10} imm",
    0x7: f"{'add':<10} dst, imm",
    0x27: f"{'mul':<10} dst, imm",
    0x67: f"{'lsh':<10} dst, imm",
    0xc: f"{'add32':<10} dst, src",
    0xaf: f"{'xor':<10} dst, src",
    0x94: f"{'mod32':<10} dst, imm",
    0x55: f"{'jne':<10} dst, imm, +off",
    0x95: f"exit",
    0xb7: f"{'mov':<10} dst, imm",
    0x79: f"{'ldxdw':<10} dst, [src+off]",
    0x57: f"{'and':<10} dst, imm",
    0x77: f"{'rsh':<10} dst, imm",
    0xbf: f"{'mov':<10} dst, src"
}

ins_2 = {
    0x18: f"{'lddw':<10} dst, imm",
}

for i in range(0, len(binary), 8):
    # begin parsing
    opc, dst, off, imm = unpack("<BBhi", binary[i : i + 8])
    src = dst >> 4
    dst &= 0xf
    # end parsing, begin printing
    if(opc in ins):
        print(ins[binary[i]].replace("dst", f"r{dst}").replace("src", f"r{src}").replace("+off", f"+{off}" if(off > 0) else f"{off}" if(off < 0) else "").replace("imm", str(imm) if(imm<10 and imm>-10) else hex(imm)))
    elif(opc in ins_2):
        imm2 = unpack("<i", binary[i + 12 : i + 16])[0]
        imm = imm2 << 32
        print(ins_2[binary[i]].replace("dst", f"r{dst}").replace("src", f"r{src}").replace("+off", f"+{off}" if(off > 0) else f"{off}" if(off < 0) else "").replace("imm", str(imm) if(imm<10 and imm>-10) else hex(imm)))
    # end printing