#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "view/memory_diff.hpp"
#include "debugger/pe_analyzer.hpp"
#include <cstring>

using namespace nce;
using test::FakeProcess;

TEST_CASE("MemoryDiff compares static memory buffers") {
    uintptr_t base_addr = 0x7FF700001000;
    std::vector<uint8_t> buf_a = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    std::vector<uint8_t> buf_b = { 0x10, 0x99, 0x30, 0x40, 0x50, 0xFF, 0x70, 0x80 };

    auto summary = view::MemoryDiff::compare_buffers(base_addr, buf_a.data(), buf_b.data(), buf_a.size());

    CHECK(summary.address == base_addr);
    CHECK(summary.total_bytes == 8);
    CHECK(summary.changed_bytes == 2);
    CHECK(summary.changed_percentage == 25.0);
    REQUIRE(summary.diffs.size() == 2);

    CHECK(summary.diffs[0].address == base_addr + 1);
    CHECK(summary.diffs[0].old_val == 0x20);
    CHECK(summary.diffs[0].new_val == 0x99);

    CHECK(summary.diffs[1].address == base_addr + 5);
    CHECK(summary.diffs[1].old_val == 0x60);
    CHECK(summary.diffs[1].new_val == 0xFF);
}

TEST_CASE("MemoryDiff takes snapshots from process memory and detects changes") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    uintptr_t target_addr = FakeProcess::kBase + 0x200;

    // Fill initial values (e.g. 100 HP)
    process->put<int32_t>(0x200, 100);
    process->put<int32_t>(0x204, 500);

    view::MemoryDiff diff;
    CHECK_FALSE(diff.has_snapshot_a());
    CHECK_FALSE(diff.has_snapshot_b());

    REQUIRE(diff.take_snapshot_a(*process, target_addr, 8));
    CHECK(diff.has_snapshot_a());
    CHECK_FALSE(diff.has_snapshot_b());
    CHECK(diff.address() == target_addr);
    CHECK(diff.size() == 8);

    // No changes yet: taking snapshot B now yields 0 diffs
    REQUIRE(diff.take_snapshot_b(*process));
    CHECK(diff.has_snapshot_b());
    auto initial_diff = diff.compare();
    CHECK(initial_diff.changed_bytes == 0);
    CHECK(initial_diff.diffs.empty());

    // Modify memory (damage taken: 100 -> 75)
    process->put<int32_t>(0x200, 75);

    REQUIRE(diff.take_snapshot_b(*process));
    auto final_diff = diff.compare();
    CHECK(final_diff.changed_bytes == 1); // 100 is 0x64, 75 is 0x4B (1st byte changed)
    REQUIRE(final_diff.diffs.size() == 1);
    CHECK(final_diff.diffs[0].address == target_addr);
    CHECK(final_diff.diffs[0].old_val == 0x64);
    CHECK(final_diff.diffs[0].new_val == 0x4B);

    diff.clear();
    CHECK_FALSE(diff.has_snapshot_a());
    CHECK_FALSE(diff.has_snapshot_b());
}

TEST_CASE("PEAnalyzer parses raw PE headers correctly") {
    // Construct a synthetic 64-bit PE binary header in memory
    std::vector<uint8_t> pe(1024, 0);

    // 1. DOS Header
    pe[0] = 'M';
    pe[1] = 'Z';
    int32_t lfanew = 0x80;
    std::memcpy(&pe[0x3C], &lfanew, 4);

    // 2. PE Signature
    pe[0x80] = 'P';
    pe[0x81] = 'E';
    pe[0x82] = 0;
    pe[0x83] = 0;

    // 3. File Header (at +4 from sig = 0x84)
    uint16_t machine = 0x8664; // AMD64
    uint16_t num_sections = 2;
    uint16_t opt_hdr_size = 240;
    std::memcpy(&pe[0x84], &machine, 2);
    std::memcpy(&pe[0x86], &num_sections, 2);
    std::memcpy(&pe[0x94], &opt_hdr_size, 2);

    // 4. Optional Header (at 0x98)
    uint16_t opt_magic = 0x020B; // PE32+ (64-bit)
    uint32_t entry_rva = 0x1000;
    uint64_t image_base = 0x140000000ULL;
    uint32_t image_size = 0x8000;
    uint16_t subsystem = 3; // Console

    std::memcpy(&pe[0x98], &opt_magic, 2);
    std::memcpy(&pe[0x98 + 16], &entry_rva, 4);
    std::memcpy(&pe[0x98 + 24], &image_base, 8);
    std::memcpy(&pe[0x98 + 56], &image_size, 4);
    std::memcpy(&pe[0x98 + 68], &subsystem, 2);

    // 5. Sections (at 0x98 + 240 = 0x188)
    size_t sec1_off = 0x188;
    std::memcpy(&pe[sec1_off], ".text\0\0\0", 8);
    uint32_t sec1_vsize = 0x2000;
    uint32_t sec1_rva = 0x1000;
    uint32_t sec1_flags = 0x60000020; // Code | Executable | Readable
    std::memcpy(&pe[sec1_off + 8], &sec1_vsize, 4);
    std::memcpy(&pe[sec1_off + 12], &sec1_rva, 4);
    std::memcpy(&pe[sec1_off + 36], &sec1_flags, 4);

    size_t sec2_off = sec1_off + 40;
    std::memcpy(&pe[sec2_off], ".data\0\0\0", 8);
    uint32_t sec2_vsize = 0x1000;
    uint32_t sec2_rva = 0x3000;
    uint32_t sec2_flags = 0xC0000040; // InitData | Readable | Writable
    std::memcpy(&pe[sec2_off + 8], &sec2_vsize, 4);
    std::memcpy(&pe[sec2_off + 12], &sec2_rva, 4);
    std::memcpy(&pe[sec2_off + 36], &sec2_flags, 4);

    // Analyze synthetic PE
    auto info = debugger::PEAnalyzer::analyze_bytes(pe);
    REQUIRE(info.has_value());
    CHECK(info->is_valid);
    CHECK(info->is_64bit);
    CHECK(info->image_base == image_base);
    CHECK(info->sections.size() == 2);

    CHECK(info->sections[0].name == ".text");
    CHECK(info->sections[0].is_executable);
    CHECK(info->sections[0].is_readable);
    CHECK_FALSE(info->sections[0].is_writable);

    CHECK(info->sections[1].name == ".data");
    CHECK_FALSE(info->sections[1].is_executable);
    CHECK(info->sections[1].is_readable);
    CHECK(info->sections[1].is_writable);

    // Test find_section helper
    auto text_sec = debugger::PEAnalyzer::find_section(*info, 0x140001500ULL);
    REQUIRE(text_sec != nullptr);
    CHECK(text_sec->name == ".text");

    auto data_sec = debugger::PEAnalyzer::find_section(*info, 0x140003200ULL);
    REQUIRE(data_sec != nullptr);
    CHECK(data_sec->name == ".data");

    CHECK(debugger::PEAnalyzer::find_section(*info, 0x140009999ULL) == nullptr);
}

#ifdef _WIN32
#include <windows.h>

TEST_CASE("PEAnalyzer analyzes current live process module") {
    std::shared_ptr<hal::IProcess> proc = hal::IProcess::create();
    REQUIRE(proc->attach(GetCurrentProcessId()));

    auto self_module = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    REQUIRE(self_module != 0);

    auto info = debugger::PEAnalyzer::analyze(*proc, self_module);
    REQUIRE(info.has_value());
    CHECK(info->is_valid);
    CHECK(info->is_64bit);
    CHECK(info->sections.size() >= 2);

    // In any standard Win32 binary, .text section exists
    auto sec = debugger::PEAnalyzer::find_section(*info, info->entry_point);
    REQUIRE(sec != nullptr);
    CHECK(sec->is_executable);

    proc->detach();
}
#endif
