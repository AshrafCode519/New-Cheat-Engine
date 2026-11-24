#include "../../include/debugger/disassembler.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <sstream>
#include <iomanip>
#include <array>
#include <cstring>

namespace nce::debugger {

namespace {

const char* kRegs64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const char* kRegs32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
const char* kRegs16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
const char* kRegs8[]  = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};

} // anonymous namespace

std::string DecodedInstruction::format() const {
    std::ostringstream ss;
    ss << utils::format_address(address) << ":  ";
    
    // Hex bytes (up to 7 bytes shown cleanly)
    for (size_t i = 0; i < 7; ++i) {
        if (i < bytes.size()) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]) << " ";
        } else {
            ss << "   ";
        }
    }

    ss << " " << std::setfill(' ') << std::left << std::setw(8) << mnemonic;
    if (!operands.empty()) {
        ss << " " << operands;
    }
    return ss.str();
}

DecodedInstruction Disassembler::decode(const uint8_t* code, size_t max_len, uintptr_t address) {
    DecodedInstruction inst;
    inst.address = address;
    if (!code || max_len == 0) return inst;

    size_t offset = 0;
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    bool op_size_override = false; // 0x66
    bool rep_prefix = false;        // 0xF3 / 0xF2
    bool is_sse = false;

    // 1. Prefixes
    while (offset < max_len) {
        uint8_t b = code[offset];
        if (b == 0x66) { op_size_override = true; offset++; }
        else if (b == 0xF3 || b == 0xF2) { rep_prefix = true; is_sse = true; offset++; }
        else if (b >= 0x40 && b <= 0x4F) { // REX prefix (x86-64)
            rex_w = (b & 0x08) != 0;
            rex_r = (b & 0x04) != 0;
            rex_x = (b & 0x02) != 0;
            rex_b = (b & 0x01) != 0;
            offset++;
            break; // REX must immediately precede opcode
        }
        else break;
    }

    if (offset >= max_len) {
        inst.length = 1;
        inst.bytes = {code[0]};
        inst.mnemonic = "db";
        inst.operands = "??";
        return inst;
    }

    uint8_t opcode = code[offset++];
    bool two_byte = false;

    if (opcode == 0x0F && offset < max_len) {
        two_byte = true;
        opcode = code[offset++];
    }

    // Determine register naming based on operand size
    auto get_reg = [&](uint8_t reg_idx, bool is_byte = false) -> const char* {
        if (reg_idx > 15) reg_idx = 15;
        if (is_byte) return kRegs8[reg_idx];
        if (rex_w) return kRegs64[reg_idx];
        if (op_size_override) return kRegs16[reg_idx];
        return kRegs32[reg_idx];
    };

    auto decode_modrm_mem = [&](uint8_t mod, uint8_t rm, size_t& cur_offset) -> std::string {
        uint8_t base_reg = rm | (rex_b ? 8 : 0);
        std::ostringstream ss;
        const char* ptr_size = rex_w ? "qword ptr " : (op_size_override ? "word ptr " : "dword ptr ");
        ss << ptr_size << "[";

        if (mod == 0 && rm == 5) { // RIP-relative in 64-bit mode!
            if (cur_offset + 4 <= max_len) {
                int32_t disp = 0;
                std::memcpy(&disp, code + cur_offset, 4);
                cur_offset += 4;
                uintptr_t target_rip = address + cur_offset + disp;
                ss << "rip + 0x" << std::hex << disp << "] ; -> " << utils::format_address(target_rip);
                return ss.str();
            }
        }

        if (rm == 4) { // SIB byte present
            if (cur_offset < max_len) {
                uint8_t sib = code[cur_offset++];
                uint8_t scale = 1 << ((sib >> 6) & 0x03);
                uint8_t index = ((sib >> 3) & 0x07) | (rex_x ? 8 : 0);
                uint8_t base = (sib & 0x07) | (rex_b ? 8 : 0);

                if (base == 5 && mod == 0) {
                    if (cur_offset + 4 <= max_len) {
                        int32_t disp = 0;
                        std::memcpy(&disp, code + cur_offset, 4);
                        cur_offset += 4;
                        ss << "0x" << std::hex << disp;
                    }
                } else {
                    ss << kRegs64[base];
                }

                if (index != 4) { // index 4 (rsp) means no index
                    ss << " + " << kRegs64[index];
                    if (scale > 1) ss << "*" << static_cast<int>(scale);
                }
            }
        } else {
            ss << kRegs64[base_reg];
        }

        if (mod == 1) { // 8-bit displacement
            if (cur_offset < max_len) {
                int8_t disp = static_cast<int8_t>(code[cur_offset++]);
                if (disp >= 0) ss << " + 0x" << std::hex << static_cast<int>(disp);
                else ss << " - 0x" << std::hex << static_cast<int>(-disp);
            }
        } else if (mod == 2) { // 32-bit displacement
            if (cur_offset + 4 <= max_len) {
                int32_t disp = 0;
                std::memcpy(&disp, code + cur_offset, 4);
                cur_offset += 4;
                if (disp >= 0) ss << " + 0x" << std::hex << disp;
                else ss << " - 0x" << std::hex << -disp;
            }
        }

        ss << "]";
        return ss.str();
    };

    // Decode Opcode categories
    if (!two_byte) {
        switch (opcode) {
            case 0x90:
                inst.mnemonic = "nop";
                break;
            case 0xC3:
                inst.mnemonic = "ret";
                break;
            case 0xCC:
                inst.mnemonic = "int3";
                break;

            // MOV r/m, reg or reg, r/m
            case 0x88: case 0x89: case 0x8A: case 0x8B: {
                inst.mnemonic = "mov";
                bool is_byte = (opcode == 0x88 || opcode == 0x8A);
                bool reg_is_dest = (opcode == 0x8A || opcode == 0x8B);

                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);

                    std::string reg_name = get_reg(reg, is_byte);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset);

                    inst.operands = reg_is_dest ? (reg_name + ", " + rm_str) : (rm_str + ", " + reg_name);
                }
                break;
            }

            // SUB, ADD, XOR, CMP, AND, OR (0x00 - 0x3F)
            case 0x00: case 0x01: case 0x02: case 0x03: // ADD
            case 0x28: case 0x29: case 0x2A: case 0x2B: // SUB
            case 0x30: case 0x31: case 0x32: case 0x33: // XOR
            case 0x38: case 0x39: case 0x3A: case 0x3B: // CMP
            case 0x20: case 0x21: case 0x22: case 0x23: // AND
            case 0x08: case 0x09: case 0x0A: case 0x0B: // OR
            {
                uint8_t group = opcode >> 3;
                if (group == 0) inst.mnemonic = "add";
                else if (group == 1) inst.mnemonic = "or";
                else if (group == 4) inst.mnemonic = "and";
                else if (group == 5) inst.mnemonic = "sub";
                else if (group == 6) inst.mnemonic = "xor";
                else if (group == 7) inst.mnemonic = "cmp";

                bool is_byte = (opcode & 1) == 0;
                bool reg_is_dest = (opcode & 2) != 0;

                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);

                    std::string reg_name = get_reg(reg, is_byte);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset);

                    inst.operands = reg_is_dest ? (reg_name + ", " + rm_str) : (rm_str + ", " + reg_name);
                }
                break;
            }

            // Arithmetic immediate: 0x80 - 0x83
            case 0x80: case 0x81: case 0x83: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_sub = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);

                    const char* ops[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
                    inst.mnemonic = ops[op_sub];

                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), opcode == 0x80) : decode_modrm_mem(mod, rm, offset);

                    int64_t imm = 0;
                    if (opcode == 0x80 || opcode == 0x83) {
                        if (offset < max_len) imm = static_cast<int8_t>(code[offset++]);
                    } else if (opcode == 0x81) {
                        if (offset + 4 <= max_len) {
                            int32_t imm32 = 0;
                            std::memcpy(&imm32, code + offset, 4);
                            imm = imm32;
                            offset += 4;
                        }
                    }

                    std::ostringstream ss;
                    ss << rm_str << ", 0x" << std::hex << imm;
                    inst.operands = ss.str();
                }
                break;
            }

            // Group 4/5: inc/dec [mem] (0xFE byte, 0xFF), and FF /2 call, /4 jmp, /6 push (indirect)
            case 0xFE: case 0xFF: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_sub = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);
                    const bool is_byte = (opcode == 0xFE);
                    static const char* g5[] = {"inc", "dec", "call", "callf", "jmp", "jmpf", "push", "?"};
                    inst.mnemonic = g5[op_sub];
                    inst.operands = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset);
                }
                break;
            }

            // LEA reg, [mem]
            case 0x8D: {
                inst.mnemonic = "lea";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    inst.operands = std::string(get_reg(reg)) + ", " + decode_modrm_mem(mod, rm, offset);
                }
                break;
            }

            // CALL / JMP relative (0xE8, 0xE9)
            case 0xE8: case 0xE9: {
                inst.mnemonic = (opcode == 0xE8) ? "call" : "jmp";
                if (offset + 4 <= max_len) {
                    int32_t rel = 0;
                    std::memcpy(&rel, code + offset, 4);
                    offset += 4;
                    uintptr_t target = address + offset + rel;
                    inst.operands = utils::format_address(target);
                }
                break;
            }

            // JMP short (0xEB)
            case 0xEB: {
                inst.mnemonic = "jmp";
                if (offset < max_len) {
                    int8_t rel = static_cast<int8_t>(code[offset++]);
                    uintptr_t target = address + offset + rel;
                    inst.operands = utils::format_address(target);
                }
                break;
            }

            // Conditional Jumps short (0x70 - 0x7F)
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
                const char* jccs[] = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                      "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
                inst.mnemonic = jccs[opcode & 0x0F];
                if (offset < max_len) {
                    int8_t rel = static_cast<int8_t>(code[offset++]);
                    uintptr_t target = address + offset + rel;
                    inst.operands = utils::format_address(target);
                }
                break;
            }

            // PUSH / POP reg (0x50 - 0x5F)
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
                inst.mnemonic = "push";
                inst.operands = kRegs64[(opcode & 0x07) | (rex_b ? 8 : 0)];
                break;
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                inst.mnemonic = "pop";
                inst.operands = kRegs64[(opcode & 0x07) | (rex_b ? 8 : 0)];
                break;

            default:
                inst.mnemonic = "db";
                std::ostringstream ss;
                ss << "0x" << std::hex << static_cast<int>(opcode);
                inst.operands = ss.str();
                break;
        }
    } else {
        // Two-byte opcodes (0x0F xx)
        switch (opcode) {
            case 0x10: case 0x11: {
                inst.mnemonic = rep_prefix ? "movss" : "movups";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = (modrm >> 3) & 0x07;
                    uint8_t rm  = modrm & 0x07;
                    std::string xmm = "xmm" + std::to_string(reg | (rex_r ? 8 : 0));
                    std::string rm_str = (mod == 3) ? ("xmm" + std::to_string(rm | (rex_b ? 8 : 0))) : decode_modrm_mem(mod, rm, offset);
                    inst.operands = (opcode == 0x10) ? (xmm + ", " + rm_str) : (rm_str + ", " + xmm);
                }
                break;
            }
            default:
                inst.mnemonic = "0f";
                std::ostringstream ss;
                ss << "0x" << std::hex << static_cast<int>(opcode);
                inst.operands = ss.str();
                break;
        }
    }

    inst.length = std::max(size_t(1), offset);
    inst.bytes.assign(code, code + inst.length);
    inst.full_text = inst.format();
    return inst;
}

std::vector<DecodedInstruction> Disassembler::disassemble_range(
    const uint8_t* code,
    size_t size,
    uintptr_t base_address,
    size_t max_instructions
) {
    std::vector<DecodedInstruction> instructions;
    size_t offset = 0;

    while (offset < size && instructions.size() < max_instructions) {
        auto inst = decode(code + offset, size - offset, base_address + offset);
        if (inst.length == 0) break;
        instructions.push_back(inst);
        offset += inst.length;
    }

    return instructions;
}

} // namespace nce::debugger
