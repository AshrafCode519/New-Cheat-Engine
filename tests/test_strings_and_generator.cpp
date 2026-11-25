#include "doctest/doctest.h"
#include "scanner/strings_scanner.hpp"
#include "table/standalone_generator.hpp"
#include "test_helpers.hpp"

using namespace nce;
using namespace nce::scanner;
using namespace nce::table;

TEST_CASE("standalone trainer generator creates valid C++ source code") {
    CheatTable table;
    table.process_name = "test_game.exe";

    TableEntry e1;
    e1.description = "Infinite Ammo";
    e1.type = DataType::Int32;
    e1.location.module_name = "game.dll";
    e1.location.base_offset = 0x12345;
    e1.location.offsets = {0x18, 0x20};
    table.entries.push_back(e1);

    TableEntry e2;
    e2.description = "Speed Multiplier";
    e2.type = DataType::Float;
    e2.location.base_offset = 0x7FF1000;
    table.entries.push_back(e2);

    std::string cpp = generate_standalone_trainer_cpp(table, "custom_game.exe");

    CHECK(cpp.find("kTargetProcess = \"custom_game.exe\"") != std::string::npos);
    CHECK(cpp.find("FindProcessId") != std::string::npos);
    CHECK(cpp.find("ResolveAddress") != std::string::npos);
    CHECK(cpp.find("Infinite Ammo") != std::string::npos);
    CHECK(cpp.find("game.dll") != std::string::npos);
    CHECK(cpp.find("0x12345") != std::string::npos);
    CHECK(cpp.find("0x18, 0x20") != std::string::npos);
    CHECK(cpp.find("Speed Multiplier") != std::string::npos);
    CHECK(cpp.find("WriteProcessMemory") != std::string::npos);
    CHECK(cpp.find("GetAsyncKeyState") != std::string::npos);
}

TEST_CASE("standalone trainer generator creates valid Native Win32 GUI source code") {
    CheatTable table;
    table.process_name = "test_game.exe";

    TableEntry e1;
    e1.description = "Infinite Health";
    e1.type = DataType::Int32;
    e1.location.module_name = "game.dll";
    e1.location.base_offset = 0x54321;
    e1.location.offsets = {0x10, 0x30};
    table.entries.push_back(e1);

    std::string cpp = generate_standalone_trainer_cpp(table, "gui_game.exe", TrainerKind::GUI);

    CHECK(cpp.find("WinMain") != std::string::npos);
    CHECK(cpp.find("NCETrainerGUI") != std::string::npos);
    CHECK(cpp.find("CreateWindowExW") != std::string::npos);
    CHECK(cpp.find("WM_COMMAND") != std::string::npos);
    CHECK(cpp.find("WM_CTLCOLORSTATIC") != std::string::npos);
    CHECK(cpp.find("WM_UPDATE_CHECKBOX") != std::string::npos);
    CHECK(cpp.find("Infinite Health") != std::string::npos);
    CHECK(cpp.find("gui_game.exe") != std::string::npos);
    CHECK(cpp.find("0x54321") != std::string::npos);

    // Special characters in description/module/process must be escaped as valid C++ string literals
    TableEntry e_esc;
    e_esc.description = "God \"Mode\" \\ Shield";
    e_esc.type = DataType::Int32;
    e_esc.location.module_name = "sub\\mod.dll";
    table.entries.push_back(e_esc);
    const std::string escaped_cpp = generate_standalone_trainer_cpp(table, "my\"game.exe", TrainerKind::Console);
    CHECK(escaped_cpp.find("God \\\"Mode\\\" \\\\ Shield") != std::string::npos);
    CHECK(escaped_cpp.find("sub\\\\mod.dll") != std::string::npos);
    CHECK(escaped_cpp.find("kTargetProcess = \"my\\\"game.exe\"") != std::string::npos);
}

TEST_CASE("strings scanner extracts ASCII and UTF-16 strings with filter") {
    auto proc = std::make_shared<test::FakeProcess>(4096);
    proc->attach(1);

    // Prepare ASCII text
    std::string s1 = "Hello World!";
    proc->write_raw(test::FakeProcess::kBase + 0x10, s1.data(), s1.size() + 1);

    // Prepare UTF-16 string "PlayerOne"
    std::u16string s2 = u"PlayerOne";
    std::vector<uint8_t> utf16_bytes;
    for (char16_t c : s2) {
        utf16_bytes.push_back(static_cast<uint8_t>(c & 0xFF));
        utf16_bytes.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    utf16_bytes.push_back(0);
    utf16_bytes.push_back(0);
    proc->write_raw(test::FakeProcess::kBase + 0x50, utf16_bytes.data(), utf16_bytes.size());

    StringsScanner scanner(proc);

    // 1. Scan without filter
    auto all_strings = scanner.scan(4);
    CHECK(all_strings.size() >= 2);

    // 2. Scan with filter "world"
    auto world_match = scanner.scan(4, "world");
    REQUIRE(world_match.size() == 1);
    CHECK(world_match[0].text == "Hello World!");
    CHECK(world_match[0].encoding == StringEncoding::ASCII);

    // 3. Scan with filter "player" (case-insensitive for UTF-16)
    auto player_match = scanner.scan(4, "player");
    REQUIRE(player_match.size() == 1);
    CHECK(player_match[0].text == "PlayerOne");
    CHECK(player_match[0].encoding == StringEncoding::UTF16);
}
