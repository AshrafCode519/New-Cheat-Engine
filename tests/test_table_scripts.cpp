#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "session/session.hpp"
#include <filesystem>
#include <memory>

using namespace nce;
using test::FakeProcess;
namespace fs = std::filesystem;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

std::vector<uint8_t> read(FakeProcess& p, uintptr_t a, size_t n) {
    std::vector<uint8_t> out(n);
    p.read_raw(a, out.data(), n);
    return out;
}

std::string hex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) { s += d[x >> 4]; s += d[x & 0xF]; }
    return s;
}

// A process whose module holds the 3-byte instruction `83 28 01` (sub dword [rax], 1) at +0x1000
std::shared_ptr<FakeProcess> make_target() {
    auto p = std::make_shared<FakeProcess>(0x4000);
    p->add_module("game.exe", 0x0, 0x2000);
    p->set_name("game.exe");
    p->put<uint8_t>(0x1000, 0x83);
    p->put<uint8_t>(0x1001, 0x28);
    p->put<uint8_t>(0x1002, 0x01);
    return p;
}

const std::string kScript =
    "[ENABLE]\n"
    "\"game.exe\"+0x1000:\n"
    "  db 90 90 90\n"   // nop out the sub (no health drain)
    "[DISABLE]\n"
    "\"game.exe\"+0x1000:\n"
    "  db 83 28 01\n";

} // anonymous namespace

TEST_CASE("a table script turns on, patches the game, and turns off again") {
    auto p = make_target();
    session::Session s(p, nullptr);
    REQUIRE(s.attach(1).ok);

    REQUIRE(s.table().add_script("No health drain", kScript).ok);
    CHECK(s.table().script_count() == 1);
    CHECK_FALSE(s.table().script(0)->enabled);

    const auto on = s.table().set_script_enabled(0, true);
    REQUIRE(on.ok);
    CHECK(s.table().script(0)->enabled);
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "909090");

    const auto off = s.table().set_script_enabled(0, false);
    REQUIRE(off.ok);
    CHECK_FALSE(s.table().script(0)->enabled);
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "832801"); // original instruction restored
}

TEST_CASE("scripts need a unique name and refuse bad assembly") {
    auto p = make_target();
    session::Session s(p, nullptr);
    REQUIRE(s.attach(1).ok);

    REQUIRE(s.table().add_script("x", kScript).ok);
    CHECK(s.table().add_script("x", kScript).message.find("already exists") != std::string::npos);

    REQUIRE(s.table().add_script("broken", "\"game.exe\"+0x1000:\n  frobnicate rax\n").ok);
    const auto bad = s.table().set_script_enabled(1, true);
    CHECK_FALSE(bad.ok);
    CHECK_FALSE(s.table().script(1)->enabled);
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "832801"); // nothing applied
}

TEST_CASE("scripts save and load with the table and re-apply on attach") {
    const auto file = (fs::temp_directory_path() / "nce_scripts_table.json").string();
    {
        auto p = make_target();
        session::Session s(p, nullptr);
        REQUIRE(s.attach(1).ok);
        REQUIRE(s.table().add_script("No health drain", kScript).ok);
        REQUIRE(s.table().set_script_enabled(0, true).ok);
        REQUIRE(s.table().save(file).ok);
    }

    // A fresh session + process: loading restores the script, and (being saved on) re-applies it on attach
    auto p = make_target();
    session::Session s(p, nullptr);
    const auto report = s.attach(1);
    REQUIRE(report.ok);
    std::vector<session::TableKeeper::ReconcileLine> ignore;
    const auto loaded = s.table().load(file, &ignore);
    fs::remove(file);
    REQUIRE(loaded.ok);
    CHECK(loaded.message.find("1 scripts") != std::string::npos);
    REQUIRE(s.table().script_count() == 1);
    CHECK(s.table().script(0)->enabled);                 // came back on
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "909090"); // and was re-applied
    CHECK(loaded.message.find("Re-applied 1 script") != std::string::npos);
}

TEST_CASE("detaching undoes a running script so the target is left clean") {
    auto p = make_target();
    session::Session s(p, nullptr);
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.table().add_script("x", kScript).ok);
    REQUIRE(s.table().set_script_enabled(0, true).ok);
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "909090");

    s.detach();
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "832801"); // restored on detach

    // editing a script's body while it's on undoes the old patch first
    REQUIRE(s.attach(1).ok); // re-applies (it's still marked enabled)
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "909090");
    REQUIRE(s.table().set_script_body(0, "\"game.exe\"+0x1000:\n  db 11 22 33\n").ok);
    CHECK(hex(read(*p, kBase + 0x1000, 3)) == "832801"); // old patch undone, new one not yet on
    CHECK_FALSE(s.table().script(0)->enabled);
    REQUIRE(s.table().remove_script(0).ok);
    CHECK(s.table().script_count() == 0);
}
