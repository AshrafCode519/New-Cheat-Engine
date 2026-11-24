#include <doctest/doctest.h>
#include "debugger/disassembler.hpp"
#include "debugger/access_watcher.hpp"
#include <string>

using namespace nce;
using debugger::Disassembler;

namespace {

std::string text(std::initializer_list<uint8_t> bytes) {
    std::vector<uint8_t> v(bytes);
    const auto d = Disassembler::decode(v.data(), v.size(), 0x1000);
    return d.mnemonic + (d.operands.empty() ? "" : " " + d.operands);
}

size_t len(std::initializer_list<uint8_t> bytes) {
    std::vector<uint8_t> v(bytes);
    return Disassembler::decode(v.data(), v.size(), 0x1000).length;
}

} // anonymous namespace

TEST_CASE("the disassembler decodes the common instructions a write watchpoint catches") {
    CHECK(text({0x89, 0x41, 0x10}) == "mov dword ptr [rcx + 0x10], eax");
    CHECK(len({0x89, 0x41, 0x10}) == 3);
    CHECK(text({0x48, 0x89, 0x01}) == "mov qword ptr [rcx], rax");
    CHECK(text({0x8b, 0x45, 0xf8}) == "mov eax, dword ptr [rbp - 0x8]");
    CHECK(text({0x01, 0xd8}) == "add eax, ebx");
    CHECK(text({0x83, 0x28, 0x01}) == "sub dword ptr [rax], 0x1");
    CHECK(text({0xff, 0x00}) == "inc dword ptr [rax]");      // ammo-- style write
    CHECK(text({0xff, 0x08}) == "dec dword ptr [rax]");
    CHECK(text({0x48, 0xff, 0xc0}) == "inc rax");
    CHECK(text({0xc3}) == "ret");
    CHECK(text({0x8d, 0x4c, 0x24, 0x08}) == "lea ecx, dword ptr [rsp + 0x8]");

    // a rel32 jmp resolves its absolute target (here from base 0x1000)
    CHECK(text({0xe9, 0x00, 0x01, 0x00, 0x00}).find("jmp") == 0);
    CHECK(len({0xe9, 0x00, 0x01, 0x00, 0x00}) == 5);

    // unknown bytes come back as db, length 1, so a caller can skip forward
    CHECK(len({0x0f, 0x0b}) >= 1);
}

TEST_CASE("a hit's register-by-name reads the right register, 32-bit names included") {
    debugger::Registers r;
    r.rax = 0x1111; r.rcx = 0x2222; r.rbp = 0x3333; r.r12 = 0x4444;
    CHECK(r.by_name("rax") == 0x1111);
    CHECK(r.by_name("eax") == 0x1111); // 32-bit name maps to the 64-bit register
    CHECK(r.by_name("rcx") == 0x2222);
    CHECK(r.by_name("rbp") == 0x3333);
    CHECK(r.by_name("r12") == 0x4444);
    CHECK(r.by_name("rdx") == 0);
    CHECK(r.by_name("") == 0);

    debugger::AccessHit hit;
    hit.registers = r;
    hit.base_register = "rax";
    hit.base_offset = 0x10;
    CHECK(hit.base_pointer() == 0x1111);           // the base register's value
    CHECK(hit.base_pointer() + hit.base_offset == 0x1121);
    hit.base_register.clear();
    CHECK(hit.base_pointer() == 0);                 // no [reg+disp] operand -> no base
}
