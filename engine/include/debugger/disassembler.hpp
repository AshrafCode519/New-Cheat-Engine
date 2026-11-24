#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace nce::debugger {

struct DecodedInstruction {
    uintptr_t address{0};
    size_t length{1};
    std::string mnemonic{"unknown"};
    std::string operands;
    std::string full_text;
    std::vector<uint8_t> bytes;

    [[nodiscard]] std::string format() const;
};

class Disassembler {
public:
    static DecodedInstruction decode(const uint8_t* code, size_t max_len, uintptr_t address);
    static std::vector<DecodedInstruction> disassemble_range(const uint8_t* code, size_t size, uintptr_t base_address, size_t max_instructions = 16);
};

} // namespace nce::debugger
