#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "assembler/auto_assembler.hpp"
#include "assembler/x86_assembler.hpp"
#include <memory>

using namespace nce;
using test::FakeProcess;
using assembler::AutoAssembler;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

std::vector<uint8_t> read(FakeProcess& p, uintptr_t addr, size_t n) {
    std::vector<uint8_t> out(n);
    p.read_raw(addr, out.data(), n);
    return out;
}

std::string hex(const std::vector<uint8_t>& bytes) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : bytes) { s += d[b >> 4]; s += d[b & 0xF]; }
    return s;
}

} // anonymous namespace

TEST_CASE("the encoder is wired for the target's bitness via AutoAssembler::resolve") {
    auto process = std::make_shared<FakeProcess>(0x4000);
    process->add_module("game.exe", 0x0, 0x2000);
    AutoAssembler aa(process);

    CHECK(aa.resolve("\"game.exe\"+0x1A4") == kBase + 0x1A4);
    CHECK(aa.resolve("game.exe+0x10") == kBase + 0x10);
    CHECK(aa.resolve("0x1234") == 0x1234);
    CHECK(aa.resolve("4096") == 4096);
    aa.set_symbol("health", kBase + 0x500);
    CHECK(aa.resolve("health+0x8") == kBase + 0x508);
    CHECK_FALSE(aa.resolve("nope.dll+0x10"));
}

TEST_CASE("a simple patch writes bytes and the disable restores the originals") {
    auto process = std::make_shared<FakeProcess>(0x4000);
    process->add_module("game.exe", 0x0, 0x2000);
    // at game.exe+0x1000: sub dword ptr [rax], 1  (29 ... ) -> we'll nop it out
    process->put<uint8_t>(0x1000, 0x83);
    process->put<uint8_t>(0x1001, 0x28); // sub dword ptr [rax], imm8
    process->put<uint8_t>(0x1002, 0x01);

    AutoAssembler aa(process);
    const std::string script =
        "[ENABLE]\n"
        "\"game.exe\"+0x1000:\n"
        "  nop\n"
        "  nop\n"
        "  nop\n"
        "[DISABLE]\n"
        "\"game.exe\"+0x1000:\n"
        "  db 83 28 01\n";

    const auto on = aa.enable(script);
    REQUIRE(on.ok);
    CHECK(hex(read(*process, kBase + 0x1000, 3)) == "909090");
    CHECK(on.effect.patches.size() == 1);
    CHECK(hex(on.effect.patches[0].original) == "832801");

    const auto off = aa.disable(script, on.effect);
    CHECK(off.ok);
    CHECK(hex(read(*process, kBase + 0x1000, 3)) == "832801"); // original instruction back
}

TEST_CASE("a full hook: aobscanmodule, a cave, jmp in and back, registersymbol") {
    auto process = std::make_shared<FakeProcess>(0x4000);
    process->add_module("game.exe", 0x0, 0x2000);
    // the code to hook: a 5-byte sequence 89 01 90 90 90 (mov [rcx], eax ; nop nop nop) at +0x1000
    const uint8_t code[] = {0x89, 0x01, 0x90, 0x90, 0x90};
    for (size_t i = 0; i < sizeof(code); ++i) process->put<uint8_t>(0x1000 + i, code[i]);

    AutoAssembler aa(process);
    const std::string script =
        "[ENABLE]\n"
        "aobscanmodule(hook, game.exe, 89 01 90 90 90)\n"
        "alloc(cave, 256)\n"
        "label(return)\n"
        "registersymbol(hook)\n"
        "\n"
        "cave:\n"
        "  mov dword ptr [rcx], 0x3E7\n"  // force the value to 999
        "  jmp return\n"
        "\n"
        "hook:\n"
        "  jmp cave\n"
        "return:\n"
        "\n"
        "[DISABLE]\n"
        "hook:\n"
        "  db 89 01 90 90 90\n"
        "unregistersymbol(hook)\n"
        "dealloc(cave)\n";

    const auto on = aa.enable(script);
    REQUIRE_MESSAGE(on.ok, on.message);
    REQUIRE(on.effect.allocations.size() == 1);
    const uintptr_t cave = on.effect.allocations[0].address;

    // hook now begins with E9 (jmp rel32) that lands on the cave
    const auto hook_bytes = read(*process, kBase + 0x1000, 5);
    CHECK(hook_bytes[0] == 0xE9);
    const int32_t rel = static_cast<int32_t>(hook_bytes[1] | (hook_bytes[2] << 8) | (hook_bytes[3] << 16) |
                                             (uint32_t(hook_bytes[4]) << 24));
    CHECK(kBase + 0x1000 + 5 + rel == cave);

    // the cave holds: mov dword ptr [rcx], 0x3E7  then  jmp back to hook+5
    const auto cave_bytes = read(*process, cave, 11);
    CHECK(hex(std::vector<uint8_t>(cave_bytes.begin(), cave_bytes.begin() + 6)) == "c701e7030000");
    CHECK(cave_bytes[6] == 0xE9);
    const int32_t back = static_cast<int32_t>(cave_bytes[7] | (cave_bytes[8] << 8) | (cave_bytes[9] << 16) |
                                              (uint32_t(cave_bytes[10]) << 24));
    CHECK(cave + 6 + 5 + back == kBase + 0x1005); // returns just past the 5 overwritten bytes

    CHECK(aa.symbol("hook") == kBase + 0x1000); // registersymbol made it global

    const auto off = aa.disable(script, on.effect);
    CHECK(off.ok);
    CHECK(hex(read(*process, kBase + 0x1000, 5)) == "8901909090"); // original code restored
    CHECK_FALSE(aa.symbol("hook"));                                // unregistered
    CHECK_FALSE(process->free_memory(cave));                       // the cave was already freed on disable
}

TEST_CASE("a script with no [DISABLE] rolls itself back from the recorded effect") {
    auto process = std::make_shared<FakeProcess>(0x4000);
    process->add_module("game.exe", 0x0, 0x2000);
    process->put<uint8_t>(0x1000, 0xAB);
    process->put<uint8_t>(0x1001, 0xCD);

    AutoAssembler aa(process);
    const std::string script = "game.exe+0x1000:\n  db 90 90\n"; // no [ENABLE]/[DISABLE] markers

    const auto on = aa.enable(script);
    REQUIRE(on.ok);
    CHECK(hex(read(*process, kBase + 0x1000, 2)) == "9090");

    const auto off = aa.disable(script, on.effect); // no [DISABLE] -> restore from effect
    CHECK(off.ok);
    CHECK(hex(read(*process, kBase + 0x1000, 2)) == "abcd");
}

TEST_CASE("a failure part-way through leaves the target untouched") {
    auto process = std::make_shared<FakeProcess>(0x4000);
    process->add_module("game.exe", 0x0, 0x2000);
    process->put<uint8_t>(0x1000, 0x11);
    process->put<uint8_t>(0x1001, 0x22);

    AutoAssembler aa(process);
    // the first line patches, the second is a nonsense instruction: the whole thing must roll back
    const auto bad = aa.enable("game.exe+0x1000:\n  nop\n  frobnicate rax, rbx\n");
    CHECK_FALSE(bad.ok);
    CHECK(bad.message.find("frobnicate") != std::string::npos);
    CHECK(hex(read(*process, kBase + 0x1000, 2)) == "1122"); // the nop was undone

    // not attached: a clear message, nothing written
    process->detach();
    const auto detached = aa.enable("game.exe+0x1000:\n  nop\n");
    CHECK_FALSE(detached.ok);
    CHECK(detached.message.find("Attach") != std::string::npos);
}

TEST_CASE("split_sections separates [ENABLE] and [DISABLE]") {
    const auto s = AutoAssembler::split_sections("[ENABLE]\nnop\n[DISABLE]\nret\n");
    CHECK(s.had_markers);
    CHECK(s.enable.find("nop") != std::string::npos);
    CHECK(s.enable.find("ret") == std::string::npos);
    CHECK(s.disable.find("ret") != std::string::npos);

    const auto none = AutoAssembler::split_sections("nop\nret\n");
    CHECK_FALSE(none.had_markers);
    CHECK(none.enable.find("nop") != std::string::npos); // no markers: all of it is enable
    CHECK(none.disable.empty());
}
