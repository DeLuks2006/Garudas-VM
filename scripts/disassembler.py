import sys

VM_OPCODES = {
    0x0: "EXIT",
    0x1: "MOV",
    0x2: "IO",
    0x3: "MOV_IMM",
    0x4: "CMP",
    0x5: "JMP",
    0x6: "JZ",
    0x7: "INC",
    0x8: "AND",
    0x9: "ADD",
    0xA: "MOV_MEM",
    0xB: "OR",
    0xC: "SUB",
    0xD: "JNZ",
}

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def disassemble(vm_code):
    pc = 0
    code_len = len(vm_code) - 3
    while pc < code_len:
        opcode_byte = vm_code[pc]
        opcode_low = opcode_byte & 0xF
        opcode_high = opcode_byte >> 4
        mnemonic = VM_OPCODES.get(opcode_low, "UNKNOWN")
        line = f"{pc:04X} > {mnemonic} "

        if opcode_low == 0x0:  # VM_EXIT
            pc_inc = 1
        elif opcode_low == 0x1:  # VM_MOV
            line += f"R{opcode_high}, R{vm_code[pc+1]}"
            pc_inc = 2
        elif opcode_low == 0x2:  # VM_IO
            if (opcode_high == 0x1):
                line += f"INPUT"
            else:
                x = vm_code[pc+1:pc+9]
                y = ""
                for i in x[::-1]:
                    y += f'{i:x}'
                line += f"OUTPUT {"0x"+y}"
            pc_inc = 1 if opcode_high == 1 else 9
        elif opcode_low == 0x3:  # VM_MOV_IMM
            x = vm_code[pc+1:pc+9]
            y = ""
            for i in x[::-1]:
                y += f'{i:x}'
            imm = f"{"0x"+y}"
            line += f"R{opcode_high}, {imm}"
            pc_inc = 9
        elif opcode_low == 0x4:  # VM_CMP
            reg_dest = opcode_high
            reg_src = vm_code[pc+1]
            line += f"R{reg_dest}, R{reg_src}"
            pc_inc = 2
        elif opcode_low == 0x5:  # VM_JMP
            target = vm_code[pc+1]
            line += f"{target:#x}"
            pc_inc = 1
        elif opcode_low == 0x6:  # VM_JZ
            target = vm_code[pc+1]
            line += f"{target:#x}"
            pc_inc = 2# maybe
        elif opcode_low == 0x7:  # VM_INC
            reg = (vm_code[pc+1] | 0xF) - (vm_code[pc+1] ^ 0xF)
            line += f"R{reg}"
            pc_inc = 2
        elif opcode_low == 0x8:  # VM_AND
            reg_dest = opcode_high
            imm = int.from_bytes(vm_code[pc+1:pc+3], "little")
            line += f"R{reg_dest}, {imm:#x}"
            pc_inc = 3
        elif opcode_low == 0x9:  # VM_ADD
            reg_dest = opcode_high
            reg_src = vm_code[pc+1]
            line += f"R{reg_dest}, R{reg_src}"
            pc_inc = 2
        elif opcode_low == 0xA:  # VM_MOV_MEM
            reg_dest = vm_code[pc+1]
            reg_src = opcode_high
            line += f"R{reg_dest}, [R{reg_src}]"
            pc_inc = 2
        elif opcode_low == 0xB:  # VM_OR
            reg_dest = opcode_high
            imm = int.from_bytes(vm_code[pc+1:pc+3], "little")
            line += f"R{reg_dest}, {imm:#x}"
            pc_inc = 3
        elif opcode_low == 0xC:  # VM_SUB
            reg_dest = opcode_high
            reg_src = vm_code[pc+1]
            line += f"R{reg_dest}, R{reg_src}"
            pc_inc = 2
        elif opcode_low == 0xD:  # VM_JNZ
            target = vm_code[pc+1]
            line += f"{target:#x}"
            pc_inc = 1
        else:
            line += "???"
            pc_inc = 1

        print(line)
        pc += pc_inc

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_dump>")
        sys.exit(1)

    path = sys.argv[1]
    vm_code = read_file(path)
    disassemble(vm_code)

