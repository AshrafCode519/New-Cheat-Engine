#pragma once

#include "access_watcher.hpp"
#include "../hal/process.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace nce::debugger {

// Evaluates C/debugger-style condition expressions for conditional breakpoints and tracepoints.
// Examples:
//   "rax == 0x100"
//   "eax != 0 && rcx > 10"
//   "dword[rcx + 0x10] == 100 || hit >= 5"
//   "(r8 & 0xFF) == 0x1A"
class ConditionEvaluator {
public:
    struct Result {
        bool ok{false};
        bool matched{false};
        uint64_t value{0};
        std::string error;
    };

    // Validates syntax without dereferencing live target memory. Returns nullopt if valid, else error message.
    static std::optional<std::string> validate(const std::string& expression);

    // Evaluates expression against live registers, optional process memory, and breakpoint hit count.
    static Result evaluate(
        const std::string& expression,
        const Registers& regs,
        const hal::IProcess* process = nullptr,
        size_t hit_count = 0
    );
};

} // namespace nce::debugger
