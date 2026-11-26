#include "../../include/debugger/disassembler.hpp"
#include "../../include/hal/process.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

namespace nce::debugger {

namespace {

const char* kRegs64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const char* kRegs32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
const char* kRegs16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
const char* kRegs8[]  = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
const char* kRegs8High[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
const char* kJccs[] = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                       "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
const char* kCmovs[] = {"cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova",
                        "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg"};
const char* kSets[]  = {"seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta",
                        "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg"};
const char* kShifts[] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"};

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
    if (!resolved_symbol.empty()) {
        ss << " ; " << resolved_symbol;
    }
    return ss.str();
}

DecodedInstruction Disassembler::decode(const uint8_t* code, size_t max_len, uintptr_t address, bool is_64bit) {
    DecodedInstruction inst;
    inst.address = address;
    if (!code || max_len == 0) return inst;

    size_t offset = 0;
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    bool saw_rex = false;
    bool op_size_override = false; // 0x66
    bool has_lock = false;         // 0xF0
    uint8_t sse_rep = 0;            // 0xF2 or 0xF3

    // 1. Prefixes
    while (offset < max_len) {
        uint8_t b = code[offset];
        if (b == 0x66) { op_size_override = true; offset++; }
        else if (b == 0xF3 || b == 0xF2) { sse_rep = b; offset++; }
        else if (b == 0xF0) { has_lock = true; offset++; }
        else if (b == 0x67) { offset++; } // Addr-size prefix
        else if (is_64bit && b >= 0x40 && b <= 0x4F) { // REX prefix (x86-64 only)
            saw_rex = true;
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
        inst.full_text = inst.format();
        return inst;
    }

    auto fmt_hex_imm = [](uint64_t val) {
        std::ostringstream ss;
        ss << "0x" << std::hex << val;
        return ss.str();
    };
    auto fmt_signed_imm = [](int64_t val) {
        std::ostringstream ss;
        ss << "0x" << std::hex << val;
        return ss.str();
    };

    auto get_reg = [&](uint8_t reg_idx, bool is_byte = false) -> const char* {
        if (reg_idx > 15) reg_idx = 15;
        if (!is_64bit && reg_idx >= 8) reg_idx &= 7;
        if (is_byte) {
            if (!saw_rex && reg_idx < 8) return kRegs8High[reg_idx];
            return kRegs8[reg_idx];
        }
        if (is_64bit && rex_w) return kRegs64[reg_idx];
        if (op_size_override) return kRegs16[reg_idx];
        return kRegs32[reg_idx];
    };

    bool has_rip_rel = false;
    int32_t rip_disp = 0;
    bool has_abs32 = false;
    uintptr_t abs32_addr = 0;
    const char* const* addr_regs = is_64bit ? kRegs64 : kRegs32;

    auto decode_modrm_mem = [&](uint8_t mod, uint8_t rm, size_t& cur_offset, int forced_bits = 0) -> std::string {
        uint8_t base_reg = rm | ((is_64bit && rex_b) ? 8 : 0);
        std::ostringstream ss;
        const char* ptr_size = nullptr;
        if (forced_bits == 8) ptr_size = "byte ptr ";
        else if (forced_bits == 16) ptr_size = "word ptr ";
        else if (forced_bits == 32) ptr_size = "dword ptr ";
        else if (forced_bits == 64) ptr_size = "qword ptr ";
        else if (forced_bits == 128) ptr_size = "xmmword ptr ";
        else if (forced_bits == 256) ptr_size = "ymmword ptr ";
        else ptr_size = (is_64bit && rex_w) ? "qword ptr " : (op_size_override ? "word ptr " : "dword ptr ");
        ss << ptr_size << "[";

        if (mod == 0 && rm == 5) {
            if (cur_offset + 4 <= max_len) {
                int32_t disp = 0;
                std::memcpy(&disp, code + cur_offset, 4);
                cur_offset += 4;
                if (is_64bit) {
                    has_rip_rel = true;
                    rip_disp = disp;
                    uintptr_t target_rip = address + cur_offset + disp;
                    ss << "rip + 0x" << std::hex << disp << "] ; -> " << utils::format_address(target_rip);
                } else {
                    has_abs32 = true;
                    abs32_addr = static_cast<uint32_t>(disp);
                    ss << utils::format_address(abs32_addr) << "]";
                }
                return ss.str();
            }
        }

        if (rm == 4) { // SIB byte present
            if (cur_offset < max_len) {
                uint8_t sib = code[cur_offset++];
                uint8_t scale = 1 << ((sib >> 6) & 0x03);
                uint8_t index = ((sib >> 3) & 0x07) | ((is_64bit && rex_x) ? 8 : 0);
                uint8_t base = (sib & 0x07) | ((is_64bit && rex_b) ? 8 : 0);

                if ((base & 7) == 5 && mod == 0) {
                    if (cur_offset + 4 <= max_len) {
                        int32_t disp = 0;
                        std::memcpy(&disp, code + cur_offset, 4);
                        cur_offset += 4;
                        if (!is_64bit) {
                            has_abs32 = true;
                            abs32_addr = static_cast<uint32_t>(disp);
                        }
                        ss << "0x" << std::hex << static_cast<uint32_t>(disp);
                    }
                } else {
                    ss << addr_regs[base];
                }

                if ((index & 7) != 4 || rex_x) {
                    ss << " + ";
                    ss << addr_regs[index];
                    if (scale > 1) ss << "*" << static_cast<int>(scale);
                }
            }
        } else {
            ss << addr_regs[base_reg];
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

    // VEX prefix (AVX / AVX2: 0xC4 3-byte or 0xC5 2-byte)
    if (offset < max_len && (code[offset] == 0xC4 || code[offset] == 0xC5)) {
        const uint8_t p0 = code[offset];
        const bool is_vex3 = (p0 == 0xC4);
        const bool looks_like_vex = is_64bit || (offset + 1 < max_len && (code[offset + 1] & 0xC0) == 0xC0);
        if (looks_like_vex && ((is_vex3 && offset + 3 < max_len) || (!is_vex3 && offset + 2 < max_len))) {
            offset++;
            uint8_t p1 = code[offset++];
            bool v_r = !(p1 & 0x80);
            bool v_x = is_vex3 ? !(p1 & 0x40) : false;
            bool v_b = is_vex3 ? !(p1 & 0x20) : false;
            uint8_t v_map = is_vex3 ? (p1 & 0x1F) : 1;
            uint8_t p2 = is_vex3 ? code[offset++] : p1;
            uint8_t v_vvvv = (~(p2 >> 3)) & 0x0F;
            bool v_l = (p2 & 0x04) != 0;
            uint8_t v_pp = (p2 & 0x03);
            if (!is_64bit) { v_r = v_x = v_b = false; v_vvvv &= 7; }
            rex_r = v_r; rex_x = v_x; rex_b = v_b;
            uint8_t vex_op = code[offset++];
            const char* vpref = v_l ? "ymm" : "xmm";
            const int vbits = v_l ? 256 : 128;

            if (vex_op == 0x77 && v_map == 1) {
                inst.mnemonic = v_l ? "vzeroall" : "vzeroupper";
            } else {
                const char* mn = "vex";
                bool three_op = false;
                bool store_op = false;
                if (v_map == 1) {
                    switch (vex_op) {
                        case 0x10: mn = (v_pp == 2) ? "vmovss" : (v_pp == 3 ? "vmovsd" : (v_pp == 1 ? "vmovupd" : "vmovups")); break;
                        case 0x11: mn = (v_pp == 2) ? "vmovss" : (v_pp == 3 ? "vmovsd" : (v_pp == 1 ? "vmovupd" : "vmovups")); store_op = true; break;
                        case 0x28: mn = (v_pp == 1) ? "vmovapd" : "vmovaps"; break;
                        case 0x29: mn = (v_pp == 1) ? "vmovapd" : "vmovaps"; store_op = true; break;
                        case 0x6F: mn = (v_pp == 2) ? "vmovdqu" : "vmovdqa"; break;
                        case 0x7F: mn = (v_pp == 2) ? "vmovdqu" : "vmovdqa"; store_op = true; break;
                        case 0x57: mn = (v_pp == 1) ? "vxorpd" : "vxorps"; three_op = true; break;
                        case 0xEF: mn = "vpxor"; three_op = true; break;
                        case 0x58: case 0x59: case 0x5C: case 0x5E: {
                            const char* base = (vex_op == 0x58) ? "vadd" : (vex_op == 0x59 ? "vmul" : (vex_op == 0x5C ? "vsub" : "vdiv"));
                            inst.mnemonic = std::string(base) + (v_pp == 2 ? "ss" : (v_pp == 3 ? "sd" : (v_pp == 1 ? "pd" : "ps")));
                            mn = nullptr;
                            three_op = true;
                            break;
                        }
                        default: break;
                    }
                }
                if (mn) inst.mnemonic = mn;
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (v_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string dst = std::string(vpref) + std::to_string(reg);
                    std::string src2 = (mod == 3) ? (std::string(vpref) + std::to_string(rm | (v_b ? 8 : 0)))
                                                  : decode_modrm_mem(mod, rm, offset, vbits);
                    if (three_op) {
                        inst.operands = dst + ", " + vpref + std::to_string(v_vvvv) + ", " + src2;
                    } else if (store_op) {
                        inst.operands = src2 + ", " + dst;
                    } else if (mn && std::string(mn) == "vex") {
                        inst.operands = fmt_hex_imm(vex_op) + " " + dst + ", " + src2;
                    } else {
                        inst.operands = dst + ", " + src2;
                    }
                }
            }
            inst.length = std::max(size_t(1), offset);
            if (has_rip_rel && inst.branch_target == 0) inst.branch_target = address + inst.length + rip_disp;
            else if (has_abs32 && inst.branch_target == 0) inst.branch_target = abs32_addr;
            inst.bytes.assign(code, code + inst.length);
            inst.full_text = inst.format();
            return inst;
        }
    }

    uint8_t opcode = code[offset++];
    bool two_byte = false;

    if (opcode == 0x0F && offset < max_len) {
        two_byte = true;
        opcode = code[offset++];
    }

    // Decode Opcode categories
    if (!two_byte) {
        switch (opcode) {
            case 0x90:
                if (sse_rep == 0xF3) { inst.mnemonic = "pause"; break; }
                if (rex_b) {
                    inst.mnemonic = "xchg";
                    inst.operands = std::string(get_reg(8)) + ", " + get_reg(0);
                    break;
                }
                inst.mnemonic = "nop";
                break;
            case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
                inst.mnemonic = "xchg";
                inst.operands = std::string(get_reg((opcode & 7) | (rex_b ? 8 : 0))) + ", " + get_reg(0);
                break;
            case 0x98:
                inst.mnemonic = rex_w ? "cdqe" : (op_size_override ? "cbw" : "cwde");
                break;
            case 0x99:
                inst.mnemonic = rex_w ? "cqo" : (op_size_override ? "cwd" : "cdq");
                break;
            case 0x9C:
                inst.mnemonic = "pushfq";
                break;
            case 0x9D:
                inst.mnemonic = "popfq";
                break;
            case 0xC3:
                inst.mnemonic = "ret";
                break;
            case 0xC2:
                inst.mnemonic = "ret";
                if (offset + 2 <= max_len) {
                    uint16_t imm16 = 0;
                    std::memcpy(&imm16, code + offset, 2);
                    offset += 2;
                    inst.operands = fmt_hex_imm(imm16);
                }
                break;
            case 0xC9:
                inst.mnemonic = "leave";
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
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);

                    inst.operands = reg_is_dest ? (reg_name + ", " + rm_str) : (rm_str + ", " + reg_name);
                }
                break;
            }

            // MOVSXD reg64, r/m32 (0x63)
            case 0x63: {
                inst.mnemonic = "movsxd";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string dst = get_reg(reg, false);
                    std::string src = (mod == 3) ? kRegs32[(rm | (rex_b ? 8 : 0)) & 15] : decode_modrm_mem(mod, rm, offset, 32);
                    inst.operands = dst + ", " + src;
                }
                break;
            }

            // MOV reg, imm (0xB0 - 0xBF)
            case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
                inst.mnemonic = "mov";
                uint8_t reg = (opcode & 0x07) | (rex_b ? 8 : 0);
                uint8_t imm8 = 0;
                if (offset < max_len) imm8 = code[offset++];
                inst.operands = std::string(get_reg(reg, true)) + ", " + fmt_hex_imm(imm8);
                break;
            }
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
                inst.mnemonic = "mov";
                uint8_t reg = (opcode & 0x07) | (rex_b ? 8 : 0);
                uint64_t imm = 0;
                if (rex_w && offset + 8 <= max_len) {
                    std::memcpy(&imm, code + offset, 8);
                    offset += 8;
                } else if (op_size_override && offset + 2 <= max_len) {
                    uint16_t imm16 = 0;
                    std::memcpy(&imm16, code + offset, 2);
                    offset += 2;
                    imm = imm16;
                } else if (offset + 4 <= max_len) {
                    uint32_t imm32 = 0;
                    std::memcpy(&imm32, code + offset, 4);
                    offset += 4;
                    imm = imm32;
                }
                inst.operands = std::string(get_reg(reg, false)) + ", " + fmt_hex_imm(imm);
                break;
            }

            // MOV r/m, imm (0xC6 / 0xC7)
            case 0xC6: case 0xC7: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t rm  = (modrm & 0x07);
                    bool is_byte = (opcode == 0xC6);
                    inst.mnemonic = "mov";
                    std::string dst = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);
                    int64_t imm = 0;
                    if (is_byte && offset < max_len) {
                        imm = code[offset++];
                    } else if (op_size_override && !rex_w && offset + 2 <= max_len) {
                        uint16_t imm16 = 0;
                        std::memcpy(&imm16, code + offset, 2);
                        offset += 2;
                        imm = imm16;
                    } else if (offset + 4 <= max_len) {
                        int32_t imm32 = 0;
                        std::memcpy(&imm32, code + offset, 4);
                        offset += 4;
                        imm = rex_w ? static_cast<int64_t>(imm32) : static_cast<int64_t>(static_cast<uint32_t>(imm32));
                    }
                    inst.operands = dst + ", " + fmt_signed_imm(imm);
                }
                break;
            }

            // TEST (0x84, 0x85, 0xA8, 0xA9) & XCHG (0x86, 0x87)
            case 0x84: case 0x85: case 0x86: case 0x87: {
                bool is_byte = (opcode == 0x84 || opcode == 0x86);
                inst.mnemonic = (opcode == 0x84 || opcode == 0x85) ? "test" : "xchg";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string reg_name = get_reg(reg, is_byte);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);
                    inst.operands = rm_str + ", " + reg_name;
                }
                break;
            }
            case 0xA8: case 0xA9: {
                inst.mnemonic = "test";
                bool is_byte = (opcode == 0xA8);
                int64_t imm = 0;
                if (is_byte && offset < max_len) {
                    imm = code[offset++];
                } else if (op_size_override && !rex_w && offset + 2 <= max_len) {
                    uint16_t imm16 = 0;
                    std::memcpy(&imm16, code + offset, 2);
                    offset += 2;
                    imm = imm16;
                } else if (offset + 4 <= max_len) {
                    int32_t imm32 = 0;
                    std::memcpy(&imm32, code + offset, 4);
                    offset += 4;
                    imm = imm32;
                }
                inst.operands = std::string(get_reg(0, is_byte)) + ", " + fmt_signed_imm(imm);
                break;
            }

            // ALU AL/EAX, imm (0x04..0x3D)
            case 0x04: case 0x05: case 0x0C: case 0x0D:
            case 0x14: case 0x15: case 0x1C: case 0x1D:
            case 0x24: case 0x25: case 0x2C: case 0x2D:
            case 0x34: case 0x35: case 0x3C: case 0x3D: {
                static const char* kAluNames[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
                inst.mnemonic = kAluNames[(opcode >> 3) & 7];
                const bool is_byte = (opcode & 1) == 0;
                int64_t imm = 0;
                if (is_byte && offset < max_len) {
                    imm = code[offset++];
                } else if (op_size_override && !rex_w && offset + 2 <= max_len) {
                    uint16_t imm16 = 0;
                    std::memcpy(&imm16, code + offset, 2);
                    offset += 2;
                    imm = imm16;
                } else if (offset + 4 <= max_len) {
                    int32_t imm32 = 0;
                    std::memcpy(&imm32, code + offset, 4);
                    offset += 4;
                    imm = imm32;
                }
                inst.operands = std::string(get_reg(0, is_byte)) + ", " + fmt_signed_imm(imm);
                break;
            }

            // SUB, ADD, XOR, CMP, AND, OR, ADC, SBB (0x00 - 0x3B)
            case 0x00: case 0x01: case 0x02: case 0x03: // ADD
            case 0x08: case 0x09: case 0x0A: case 0x0B: // OR
            case 0x10: case 0x11: case 0x12: case 0x13: // ADC
            case 0x18: case 0x19: case 0x1A: case 0x1B: // SBB
            case 0x20: case 0x21: case 0x22: case 0x23: // AND
            case 0x28: case 0x29: case 0x2A: case 0x2B: // SUB
            case 0x30: case 0x31: case 0x32: case 0x33: // XOR
            case 0x38: case 0x39: case 0x3A: case 0x3B: // CMP
            {
                static const char* kAluNames[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
                inst.mnemonic = kAluNames[(opcode >> 3) & 7];

                bool is_byte = (opcode & 1) == 0;
                bool reg_is_dest = (opcode & 2) != 0;

                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);

                    std::string reg_name = get_reg(reg, is_byte);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);

                    inst.operands = reg_is_dest ? (reg_name + ", " + rm_str) : (rm_str + ", " + reg_name);
                }
                break;
            }

            // PUSH imm (0x68, 0x6A) & IMUL 3-op (0x69, 0x6B)
            case 0x68: case 0x6A: {
                inst.mnemonic = "push";
                int64_t imm = 0;
                if (opcode == 0x6A && offset < max_len) imm = static_cast<int8_t>(code[offset++]);
                else if (opcode == 0x68 && offset + 4 <= max_len) {
                    int32_t imm32 = 0;
                    std::memcpy(&imm32, code + offset, 4);
                    offset += 4;
                    imm = imm32;
                }
                inst.operands = fmt_signed_imm(imm);
                break;
            }
            case 0x69: case 0x6B: {
                inst.mnemonic = "imul";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string dst = get_reg(reg, false);
                    std::string src = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                    int64_t imm = 0;
                    if (opcode == 0x6B && offset < max_len) imm = static_cast<int8_t>(code[offset++]);
                    else if (opcode == 0x69 && offset + 4 <= max_len) {
                        int32_t imm32 = 0;
                        std::memcpy(&imm32, code + offset, 4);
                        offset += 4;
                        imm = imm32;
                    }
                    inst.operands = dst + ", " + src + ", " + fmt_signed_imm(imm);
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

                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), opcode == 0x80) : decode_modrm_mem(mod, rm, offset, opcode == 0x80 ? 8 : 0);

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

            // Shifts / Rotates: 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3
            case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_sub = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);
                    const bool is_byte = (opcode & 1) == 0;
                    inst.mnemonic = kShifts[op_sub];
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);
                    if (opcode == 0xD0 || opcode == 0xD1) {
                        inst.operands = rm_str + ", 1";
                    } else if (opcode == 0xD2 || opcode == 0xD3) {
                        inst.operands = rm_str + ", cl";
                    } else {
                        uint8_t cnt = (offset < max_len) ? code[offset++] : 0;
                        inst.operands = rm_str + ", " + fmt_hex_imm(cnt);
                    }
                }
                break;
            }

            // Group 3: 0xF6 / 0xF7 (test, not, neg, mul, imul, div, idiv)
            case 0xF6: case 0xF7: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_sub = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);
                    const bool is_byte = (opcode == 0xF6);
                    static const char* g3[] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
                    inst.mnemonic = g3[op_sub];
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);
                    if (op_sub <= 1) {
                        int64_t imm = 0;
                        if (is_byte && offset < max_len) imm = code[offset++];
                        else if (op_size_override && !rex_w && offset + 2 <= max_len) {
                            uint16_t imm16 = 0;
                            std::memcpy(&imm16, code + offset, 2);
                            offset += 2;
                            imm = imm16;
                        } else if (offset + 4 <= max_len) {
                            int32_t imm32 = 0;
                            std::memcpy(&imm32, code + offset, 4);
                            offset += 4;
                            imm = imm32;
                        }
                        inst.operands = rm_str + ", " + fmt_signed_imm(imm);
                    } else {
                        inst.operands = rm_str;
                    }
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
                    int forced = is_byte ? 8 : ((op_sub == 2 || op_sub == 4 || op_sub == 6) ? 64 : 0);
                    inst.operands = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, forced);
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
                    inst.branch_target = target;
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
                    inst.branch_target = target;
                    inst.operands = utils::format_address(target);
                }
                break;
            }

            // Conditional Jumps short (0x70 - 0x7F)
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
                inst.mnemonic = kJccs[opcode & 0x0F];
                if (offset < max_len) {
                    int8_t rel = static_cast<int8_t>(code[offset++]);
                    uintptr_t target = address + offset + rel;
                    inst.branch_target = target;
                    inst.operands = utils::format_address(target);
                }
                break;
            }

            // 32-bit INC / DEC reg (0x40 - 0x4F, active when !is_64bit)
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
                inst.mnemonic = "inc";
                inst.operands = get_reg(opcode & 7, false);
                break;
            case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                inst.mnemonic = "dec";
                inst.operands = get_reg(opcode & 7, false);
                break;

            // x87 FPU instructions (0xD8 - 0xDF)
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_sub = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);
                    static const char* kFpuArith[] = {"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"};
                    if (opcode == 0xDF && modrm == 0xE0) {
                        inst.mnemonic = "fnstsw";
                        inst.operands = "ax";
                    } else if (mod == 3) {
                        if (opcode == 0xD9 && op_sub == 0) {
                            inst.mnemonic = "fld";
                            inst.operands = "st(" + std::to_string(rm) + ")";
                        } else if (opcode == 0xD9 && op_sub == 1) {
                            inst.mnemonic = "fxch";
                            inst.operands = "st(" + std::to_string(rm) + ")";
                        } else if (opcode == 0xDD && (op_sub == 2 || op_sub == 3)) {
                            inst.mnemonic = (op_sub == 3) ? "fstp" : "fst";
                            inst.operands = "st(" + std::to_string(rm) + ")";
                        } else if (opcode == 0xDE && op_sub == 0) {
                            inst.mnemonic = "faddp";
                            inst.operands = "st(" + std::to_string(rm) + "), st(0)";
                        } else {
                            inst.mnemonic = kFpuArith[op_sub];
                            inst.operands = "st(0), st(" + std::to_string(rm) + ")";
                        }
                    } else {
                        const int fbits = (opcode == 0xDC || opcode == 0xDD) ? 64
                                        : ((opcode == 0xDA || opcode == 0xDE) ? 16 : 32);
                        const bool int_fpu = (opcode == 0xDA || opcode == 0xDB || opcode == 0xDE || opcode == 0xDF);
                        if (opcode == 0xD9 || opcode == 0xDD) {
                            static const char* kLoadStore[] = {"fld", "?", "fst", "fstp", "fldenv", "fldcw", "fnstenv", "fnstcw"};
                            inst.mnemonic = kLoadStore[op_sub];
                        } else if (int_fpu && (op_sub == 0 || op_sub == 2 || op_sub == 3) && (opcode == 0xDB || opcode == 0xDF)) {
                            inst.mnemonic = (op_sub == 0) ? "fild" : (op_sub == 2 ? "fist" : "fistp");
                        } else {
                            inst.mnemonic = std::string(int_fpu ? "fi" : "") + (kFpuArith[op_sub] + (int_fpu ? 1 : 0));
                        }
                        inst.operands = decode_modrm_mem(mod, rm, offset, fbits);
                    }
                }
                break;
            }

            // PUSH / POP reg (0x50 - 0x5F)
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
                inst.mnemonic = "push";
                inst.operands = (is_64bit ? kRegs64 : kRegs32)[(opcode & 0x07) | ((is_64bit && rex_b) ? 8 : 0)];
                break;
            case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                inst.mnemonic = "pop";
                inst.operands = (is_64bit ? kRegs64 : kRegs32)[(opcode & 0x07) | ((is_64bit && rex_b) ? 8 : 0)];
                break;

            // String operations (movs / stos)
            case 0xA4:
                inst.mnemonic = (sse_rep == 0xF3) ? "rep movsb" : "movsb";
                break;
            case 0xA5:
                inst.mnemonic = std::string(sse_rep == 0xF3 ? "rep " : "") + (rex_w ? "movsq" : (op_size_override ? "movsw" : "movsd"));
                break;
            case 0xAA:
                inst.mnemonic = (sse_rep == 0xF3) ? "rep stosb" : "stosb";
                break;
            case 0xAB:
                inst.mnemonic = std::string(sse_rep == 0xF3 ? "rep " : "") + (rex_w ? "stosq" : (op_size_override ? "stosw" : "stosd"));
                break;

            default:
                inst.mnemonic = "db";
                inst.operands = fmt_hex_imm(opcode);
                break;
        }
    } else {
        // Two-byte opcodes (0x0F xx)
        if (opcode >= 0x80 && opcode <= 0x8F) {
            inst.mnemonic = kJccs[opcode & 0x0F];
            if (offset + 4 <= max_len) {
                int32_t rel = 0;
                std::memcpy(&rel, code + offset, 4);
                offset += 4;
                uintptr_t target = address + offset + rel;
                inst.branch_target = target;
                inst.operands = utils::format_address(target);
            }
        } else if (opcode >= 0x40 && opcode <= 0x4F) {
            inst.mnemonic = kCmovs[opcode & 0x0F];
            if (offset < max_len) {
                uint8_t modrm = code[offset++];
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                uint8_t rm  = (modrm & 0x07);
                std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                inst.operands = std::string(get_reg(reg, false)) + ", " + rm_str;
            }
        } else if (opcode >= 0x90 && opcode <= 0x9F) {
            inst.mnemonic = kSets[opcode & 0x0F];
            if (offset < max_len) {
                uint8_t modrm = code[offset++];
                uint8_t mod = (modrm >> 6) & 0x03;
                uint8_t rm  = (modrm & 0x07);
                inst.operands = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), true) : decode_modrm_mem(mod, rm, offset, 8);
            }
        } else switch (opcode) {
            case 0x0B:
                inst.mnemonic = "ud2";
                break;
            case 0x31:
                inst.mnemonic = "rdtsc";
                break;
            case 0xA2:
                inst.mnemonic = "cpuid";
                break;
            case 0x1F:
                inst.mnemonic = "nop";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t rm  = (modrm & 0x07);
                    inst.operands = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                }
                break;
            case 0xAF:
                inst.mnemonic = "imul";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                    inst.operands = std::string(get_reg(reg, false)) + ", " + rm_str;
                }
                break;
            case 0xB6: case 0xB7: case 0xBE: case 0xBF: {
                const bool is_zx = (opcode == 0xB6 || opcode == 0xB7);
                const bool src_byte = (opcode == 0xB6 || opcode == 0xBE);
                inst.mnemonic = is_zx ? "movzx" : "movsx";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string rm_str;
                    if (mod == 3) {
                        uint8_t rm_idx = (rm | (rex_b ? 8 : 0)) & 15;
                        rm_str = src_byte ? get_reg(rm_idx, true) : kRegs16[rm_idx];
                    } else {
                        rm_str = decode_modrm_mem(mod, rm, offset, src_byte ? 8 : 16);
                    }
                    inst.operands = std::string(get_reg(reg, false)) + ", " + rm_str;
                }
                break;
            }
            case 0x10: case 0x11: case 0x28: case 0x29:
            case 0x51: case 0x54: case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x2E: case 0x2F: case 0x6F: case 0x7F: case 0xEF: {
                if (opcode == 0x10 || opcode == 0x11) {
                    inst.mnemonic = (sse_rep == 0xF3) ? "movss" : (sse_rep == 0xF2 ? "movsd" : (op_size_override ? "movupd" : "movups"));
                } else if (opcode == 0x28 || opcode == 0x29) {
                    inst.mnemonic = op_size_override ? "movapd" : "movaps";
                } else if (opcode == 0x6F || opcode == 0x7F) {
                    inst.mnemonic = (sse_rep == 0xF3) ? "movdqu" : "movdqa";
                } else if (opcode == 0x51) {
                    inst.mnemonic = (sse_rep == 0xF3) ? "sqrtss" : (sse_rep == 0xF2 ? "sqrtsd" : (op_size_override ? "sqrtpd" : "sqrtps"));
                } else if (opcode == 0x54) {
                    inst.mnemonic = op_size_override ? "andpd" : "andps";
                } else if (opcode == 0x56) {
                    inst.mnemonic = op_size_override ? "orpd" : "orps";
                } else if (opcode == 0x57) {
                    inst.mnemonic = op_size_override ? "xorpd" : "xorps";
                } else if (opcode == 0x5A) {
                    inst.mnemonic = (sse_rep == 0xF3) ? "cvtss2sd" : (sse_rep == 0xF2 ? "cvtsd2ss" : (op_size_override ? "cvtpd2ps" : "cvtps2pd"));
                } else if (opcode == 0xEF) {
                    inst.mnemonic = "pxor";
                } else if (opcode == 0x2E) {
                    inst.mnemonic = op_size_override ? "ucomisd" : "ucomiss";
                } else if (opcode == 0x2F) {
                    inst.mnemonic = op_size_override ? "comisd" : "comiss";
                } else {
                    const char* base = (opcode == 0x58) ? "add"
                                     : (opcode == 0x5C) ? "sub"
                                     : (opcode == 0x59) ? "mul"
                                     : (opcode == 0x5D) ? "min"
                                     : (opcode == 0x5F) ? "max" : "div";
                    inst.mnemonic = std::string(base) + (sse_rep == 0xF3 ? "ss" : (sse_rep == 0xF2 ? "sd" : (op_size_override ? "pd" : "ps")));
                }
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = (modrm >> 3) & 0x07;
                    uint8_t rm  = modrm & 0x07;
                    std::string xmm = "xmm" + std::to_string(reg | (rex_r ? 8 : 0));
                    int mem_bits = (sse_rep == 0xF3) ? 32 : ((sse_rep == 0xF2) ? 64 : 128);
                    std::string rm_str = (mod == 3) ? ("xmm" + std::to_string(rm | (rex_b ? 8 : 0))) : decode_modrm_mem(mod, rm, offset, mem_bits);
                    const bool store_op = (opcode == 0x11 || opcode == 0x29 || opcode == 0x7F);
                    inst.operands = store_op ? (rm_str + ", " + xmm) : (xmm + ", " + rm_str);
                }
                break;
            }
            case 0x6E: case 0x7E: case 0xD6: {
                if (opcode == 0x7E && sse_rep == 0xF3) {
                    inst.mnemonic = "movq";
                    if (offset < max_len) {
                        uint8_t modrm = code[offset++];
                        uint8_t mod = (modrm >> 6) & 0x03;
                        uint8_t reg = (modrm >> 3) & 0x07;
                        uint8_t rm  = modrm & 0x07;
                        std::string xmm = "xmm" + std::to_string(reg | (rex_r ? 8 : 0));
                        std::string rm_str = (mod == 3) ? ("xmm" + std::to_string(rm | (rex_b ? 8 : 0))) : decode_modrm_mem(mod, rm, offset, 64);
                        inst.operands = xmm + ", " + rm_str;
                    }
                } else if (opcode == 0xD6) {
                    inst.mnemonic = "movq";
                    if (offset < max_len) {
                        uint8_t modrm = code[offset++];
                        uint8_t mod = (modrm >> 6) & 0x03;
                        uint8_t reg = (modrm >> 3) & 0x07;
                        uint8_t rm  = modrm & 0x07;
                        std::string xmm = "xmm" + std::to_string(reg | (rex_r ? 8 : 0));
                        std::string rm_str = (mod == 3) ? ("xmm" + std::to_string(rm | (rex_b ? 8 : 0))) : decode_modrm_mem(mod, rm, offset, 64);
                        inst.operands = rm_str + ", " + xmm;
                    }
                } else {
                    inst.mnemonic = rex_w ? "movq" : "movd";
                    if (offset < max_len) {
                        uint8_t modrm = code[offset++];
                        uint8_t mod = (modrm >> 6) & 0x03;
                        uint8_t reg = (modrm >> 3) & 0x07;
                        uint8_t rm  = modrm & 0x07;
                        std::string xmm = "xmm" + std::to_string(reg | (rex_r ? 8 : 0));
                        const int bits = rex_w ? 64 : 32;
                        std::string rm_str;
                        if (mod == 3) {
                            const uint8_t idx = (rm | (rex_b ? 8 : 0)) & 15;
                            rm_str = rex_w ? kRegs64[idx] : kRegs32[idx];
                        } else {
                            rm_str = decode_modrm_mem(mod, rm, offset, bits);
                        }
                        inst.operands = (opcode == 0x6E) ? (xmm + ", " + rm_str) : (rm_str + ", " + xmm);
                    }
                }
                break;
            }
            case 0xB0: case 0xB1: case 0xC0: case 0xC1: {
                const bool is_byte = (opcode == 0xB0 || opcode == 0xC0);
                inst.mnemonic = (opcode == 0xB0 || opcode == 0xB1) ? "cmpxchg" : "xadd";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = modrm & 0x07;
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), is_byte) : decode_modrm_mem(mod, rm, offset, is_byte ? 8 : 0);
                    inst.operands = rm_str + ", " + get_reg(reg, is_byte);
                }
                break;
            }
            case 0xA3: case 0xAB: case 0xB3: case 0xBB: {
                inst.mnemonic = (opcode == 0xA3) ? "bt" : (opcode == 0xAB) ? "bts" : (opcode == 0xB3) ? "btr" : "btc";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                    inst.operands = rm_str + ", " + get_reg(reg, false);
                }
                break;
            }
            case 0xBA: {
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t op_ext = (modrm >> 3) & 0x07;
                    uint8_t rm  = (modrm & 0x07);
                    inst.mnemonic = (op_ext == 4) ? "bt" : (op_ext == 5) ? "bts" : (op_ext == 6) ? "btr" : (op_ext == 7) ? "btc" : "bt?";
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                    uint8_t bit_imm = (offset < max_len) ? code[offset++] : 0;
                    inst.operands = rm_str + ", " + std::to_string(bit_imm);
                }
                break;
            }
            case 0xBC: case 0xBD: {
                inst.mnemonic = (opcode == 0xBC) ? "bsf" : "bsr";
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string rm_str = (mod == 3) ? get_reg(rm | (rex_b ? 8 : 0), false) : decode_modrm_mem(mod, rm, offset);
                    inst.operands = std::string(get_reg(reg, false)) + ", " + rm_str;
                }
                break;
            }
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
                inst.mnemonic = "bswap";
                inst.operands = get_reg((opcode & 7) | (rex_b ? 8 : 0), false);
                break;
            }
            case 0x2A: case 0x2C: {
                const bool to_int = (opcode == 0x2C);
                inst.mnemonic = to_int ? ((sse_rep == 0xF2) ? "cvttsd2si" : "cvttss2si")
                                       : ((sse_rep == 0xF2) ? "cvtsi2sd"  : "cvtsi2ss");
                if (offset < max_len) {
                    uint8_t modrm = code[offset++];
                    uint8_t mod = (modrm >> 6) & 0x03;
                    uint8_t reg = ((modrm >> 3) & 0x07) | (rex_r ? 8 : 0);
                    uint8_t rm  = (modrm & 0x07);
                    std::string r_op = to_int ? get_reg(reg, false) : ("xmm" + std::to_string(reg));
                    std::string rm_op;
                    if (mod == 3) {
                        uint8_t idx = (rm | (rex_b ? 8 : 0)) & 15;
                        rm_op = to_int ? ("xmm" + std::to_string(idx)) : get_reg(idx, false);
                    } else {
                        rm_op = decode_modrm_mem(mod, rm, offset, to_int ? (sse_rep == 0xF2 ? 64 : 32) : (rex_w ? 64 : 32));
                    }
                    inst.operands = r_op + ", " + rm_op;
                }
                break;
            }
            default:
                inst.mnemonic = "0f";
                inst.operands = fmt_hex_imm(opcode);
                break;
        }
    }

    inst.length = std::max(size_t(1), offset);
    if (has_rip_rel && inst.branch_target == 0) {
        inst.branch_target = address + inst.length + rip_disp;
    } else if (has_abs32 && inst.branch_target == 0) {
        inst.branch_target = abs32_addr;
    }
    if (has_lock && !inst.mnemonic.empty() && inst.mnemonic != "db") {
        inst.mnemonic = "lock " + inst.mnemonic;
    }
    inst.bytes.assign(code, code + inst.length);
    inst.full_text = inst.format();
    return inst;
}

std::vector<DecodedInstruction> Disassembler::disassemble_range(
    const uint8_t* code,
    size_t size,
    uintptr_t base_address,
    size_t max_instructions,
    bool is_64bit
) {
    std::vector<DecodedInstruction> instructions;
    size_t offset = 0;

    while (offset < size && instructions.size() < max_instructions) {
        auto inst = decode(code + offset, size - offset, base_address + offset, is_64bit);
        if (inst.length == 0) break;
        instructions.push_back(inst);
        offset += inst.length;
    }

    return instructions;
}

namespace {

bool is_uncond_jmp(const std::string& m) { return m == "jmp"; }
bool is_ret_insn(const std::string& m) { return m == "ret" || m == "retn" || m == "retf" || m == "int3"; }
bool is_cond_jmp(const std::string& m) {
    if (m.empty() || m[0] != 'j') return false;
    return m != "jmp";
}

using CodeReaderFn = std::function<bool(uintptr_t addr, size_t len, std::vector<uint8_t>& out)>;

ControlFlowGraph build_cfg_core(
    const CodeReaderFn& reader,
    uintptr_t entry_address,
    size_t max_instructions,
    size_t max_blocks,
    bool is_64bit)
{
    ControlFlowGraph cfg;
    cfg.entry_address = entry_address;
    if (entry_address == 0 || max_instructions == 0 || max_blocks == 0) return cfg;

    const uintptr_t window_lo = (entry_address > 0x10000) ? (entry_address - 0x10000) : 0;
    const uintptr_t window_hi = entry_address + 0x10000;

    std::set<uintptr_t> leaders{entry_address};
    std::deque<uintptr_t> worklist{entry_address};
    std::set<uintptr_t> visited_starts;
    std::map<uintptr_t, DecodedInstruction> decoded_map;

    size_t total_decoded = 0;
    while (!worklist.empty() && visited_starts.size() < max_blocks * 2 && total_decoded < max_instructions) {
        const uintptr_t start = worklist.front();
        worklist.pop_front();
        if (!visited_starts.insert(start).second) continue;

        std::vector<uint8_t> buf;
        if (!reader(start, 256, buf) || buf.empty()) continue;

        size_t off = 0;
        while (off < buf.size() && total_decoded < max_instructions) {
            const uintptr_t cur_addr = start + off;
            if (decoded_map.count(cur_addr)) break;

            auto insn = Disassembler::decode(buf.data() + off, buf.size() - off, cur_addr, is_64bit);
            if (insn.length == 0) break;
            decoded_map[cur_addr] = insn;
            ++total_decoded;
            off += insn.length;

            const uintptr_t next_addr = cur_addr + insn.length;
            if (is_ret_insn(insn.mnemonic)) {
                break;
            }
            if (is_uncond_jmp(insn.mnemonic)) {
                if (insn.branch_target >= window_lo && insn.branch_target < window_hi) {
                    leaders.insert(insn.branch_target);
                    worklist.push_back(insn.branch_target);
                }
                break;
            }
            if (is_cond_jmp(insn.mnemonic)) {
                if (insn.branch_target >= window_lo && insn.branch_target < window_hi) {
                    leaders.insert(insn.branch_target);
                    worklist.push_back(insn.branch_target);
                }
                leaders.insert(next_addr);
                worklist.push_back(next_addr);
                break;
            }
        }
    }

    if (decoded_map.empty()) return cfg;

    // Partition decoded instructions cleanly at every leader address
    std::unordered_map<uintptr_t, size_t> start_to_block;
    for (uintptr_t ldr : leaders) {
        auto it = decoded_map.find(ldr);
        if (it == decoded_map.end()) continue;
        if (cfg.blocks.size() >= max_blocks) break;

        BasicBlock blk;
        blk.id = cfg.blocks.size();
        blk.start_address = ldr;
        uintptr_t cur = ldr;
        while (it != decoded_map.end()) {
            const auto& insn = it->second;
            blk.instructions.push_back(insn);
            cur = insn.address + insn.length;
            if (is_ret_insn(insn.mnemonic) || is_uncond_jmp(insn.mnemonic) || is_cond_jmp(insn.mnemonic)) {
                break;
            }
            if (leaders.count(cur)) break;
            it = decoded_map.find(cur);
        }
        blk.end_address = cur;
        start_to_block[blk.start_address] = blk.id;
        cfg.blocks.push_back(std::move(blk));
    }

    // Wire edges between basic blocks
    for (const auto& blk : cfg.blocks) {
        if (blk.instructions.empty()) continue;
        const auto& last = blk.instructions.back();
        const uintptr_t fall = last.address + last.length;
        if (is_ret_insn(last.mnemonic)) continue;
        if (is_uncond_jmp(last.mnemonic)) {
            auto it = start_to_block.find(last.branch_target);
            if (it != start_to_block.end()) {
                cfg.edges.push_back({blk.id, it->second, CFGEdge::Kind::Unconditional});
            }
        } else if (is_cond_jmp(last.mnemonic)) {
            auto it_t = start_to_block.find(last.branch_target);
            if (it_t != start_to_block.end()) {
                cfg.edges.push_back({blk.id, it_t->second, CFGEdge::Kind::TrueBranch});
            }
            auto it_f = start_to_block.find(fall);
            if (it_f != start_to_block.end()) {
                cfg.edges.push_back({blk.id, it_f->second, CFGEdge::Kind::FalseBranch});
            }
        } else {
            auto it_f = start_to_block.find(fall);
            if (it_f != start_to_block.end()) {
                cfg.edges.push_back({blk.id, it_f->second, CFGEdge::Kind::Unconditional});
            }
        }
    }

    // BFS level & lane assignment for clean visual graph layout
    std::vector<std::vector<size_t>> adj(cfg.blocks.size());
    for (const auto& e : cfg.edges) {
        if (e.from_block < adj.size()) adj[e.from_block].push_back(e.to_block);
    }
    std::vector<bool> seen(cfg.blocks.size(), false);
    std::deque<size_t> q;
    auto entry_it = start_to_block.find(entry_address);
    if (entry_it != start_to_block.end()) {
        seen[entry_it->second] = true;
        cfg.blocks[entry_it->second].level = 0;
        q.push_back(entry_it->second);
    }
    while (!q.empty()) {
        size_t u = q.front();
        q.pop_front();
        for (size_t v : adj[u]) {
            if (!seen[v]) {
                seen[v] = true;
                cfg.blocks[v].level = cfg.blocks[u].level + 1;
                q.push_back(v);
            }
        }
    }
    std::unordered_map<int, int> level_lanes;
    for (auto& blk : cfg.blocks) {
        blk.lane = level_lanes[blk.level]++;
    }

    return cfg;
}

} // namespace

ControlFlowGraph Disassembler::build_cfg(
    const hal::IProcess& proc, uintptr_t entry_address, size_t max_instructions, size_t max_blocks)
{
    if (!proc.is_attached() || entry_address == 0) {
        ControlFlowGraph empty;
        empty.entry_address = entry_address;
        return empty;
    }
    CodeReaderFn reader = [&](uintptr_t addr, size_t len, std::vector<uint8_t>& out) -> bool {
        out.resize(len);
        size_t ok_bytes = 0;
        for (size_t chunk = len; chunk >= 16; chunk /= 2) {
            if (proc.read_raw(addr, out.data(), chunk)) {
                ok_bytes = chunk;
                break;
            }
        }
        if (ok_bytes == 0) {
            out.clear();
            return false;
        }
        out.resize(ok_bytes);
        return true;
    };
    return build_cfg_core(reader, entry_address, max_instructions, max_blocks, proc.pointer_size() != 4);
}

ControlFlowGraph Disassembler::build_cfg_from_bytes(
    const uint8_t* code, size_t size, uintptr_t entry_address, uintptr_t base_address,
    size_t max_instructions, size_t max_blocks, bool is_64bit)
{
    const uintptr_t base = (base_address != 0) ? base_address : entry_address;
    if (!code || size == 0 || entry_address < base) return {};
    CodeReaderFn reader = [&](uintptr_t addr, size_t len, std::vector<uint8_t>& out) -> bool {
        if (addr < base || addr >= base + size) return false;
        const size_t off = static_cast<size_t>(addr - base);
        const size_t avail = std::min(len, size - off);
        out.assign(code + off, code + off + avail);
        return !out.empty();
    };
    return build_cfg_core(reader, entry_address, max_instructions, max_blocks, is_64bit);
}

std::vector<CrossReference> Disassembler::find_references(
    const hal::IProcess& proc,
    uintptr_t target_address,
    uintptr_t module_base,
    size_t max_results)
{
    std::vector<CrossReference> refs;
    if (!proc.is_attached() || target_address == 0 || max_results == 0) return refs;

    const bool is_64 = (proc.pointer_size() != 4);
    const auto mods = proc.get_modules();

    uintptr_t filter_lo = 0, filter_hi = 0;
    if (module_base != 0) {
        for (const auto& m : mods) {
            if (m.base_address == module_base) {
                filter_lo = m.base_address;
                filter_hi = m.base_address + m.size;
                break;
            }
        }
        if (filter_lo == 0) {
            filter_lo = module_base;
            filter_hi = module_base + 0x20000000ULL;
        }
    }

    auto find_mod_name = [&](uintptr_t addr) -> std::string {
        for (const auto& m : mods) {
            if (addr >= m.base_address && addr < m.base_address + m.size) return m.name;
        }
        return {};
    };

    constexpr uint32_t kExecMask = hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess |
                                   hal::FilterFlags::ExcludeGuardPages | hal::FilterFlags::ExecutableOnly;
    constexpr size_t kChunk = 1024 * 1024;
    std::vector<uint8_t> buf;

    for (const auto& reg : proc.query_regions(kExecMask)) {
        if (reg.size == 0 || reg.size > 64 * 1024 * 1024) continue;
        if (filter_lo != 0 && (reg.end_address() <= filter_lo || reg.base_address >= filter_hi)) continue;

        for (size_t off = 0; off < reg.size && refs.size() < max_results; off += kChunk) {
            const size_t n = std::min(kChunk, reg.size - off);
            buf.resize(n);
            if (!proc.read_raw(reg.base_address + off, buf.data(), n)) continue;

            size_t pos = 0;
            while (pos < n && refs.size() < max_results) {
                const uintptr_t cur_addr = reg.base_address + off + pos;
                if (filter_lo != 0 && (cur_addr < filter_lo || cur_addr >= filter_hi)) {
                    ++pos;
                    continue;
                }
                auto inst = decode(buf.data() + pos, n - pos, cur_addr, is_64);
                if (inst.length == 0) { ++pos; continue; }
                if (inst.branch_target == target_address) {
                    CrossReference xref;
                    xref.from_address = inst.address;
                    xref.module_name  = find_mod_name(inst.address);
                    if (inst.mnemonic == "call") xref.kind = "call";
                    else if (inst.mnemonic == "jmp") xref.kind = "jmp";
                    else if (!inst.mnemonic.empty() && inst.mnemonic[0] == 'j') xref.kind = "jcc";
                    else xref.kind = is_64 ? "rip-mem" : "abs-mem";
                    xref.instruction = inst.mnemonic + (inst.operands.empty() ? "" : (" " + inst.operands));
                    refs.push_back(std::move(xref));
                }
                pos += inst.length;
            }
        }
    }

    return refs;
}

} // namespace nce::debugger
