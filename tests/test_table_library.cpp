#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "session/session.hpp"
#include <chrono>
#include <filesystem>
#include <thread>

using namespace nce;
using scanner::DataType;
using test::FakeProcess;
namespace fs = std::filesystem;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// A fresh library folder for one test, removed afterwards
struct LibraryFixture {
    fs::path folder = fs::temp_directory_path() / "nce_library_test";
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);

    LibraryFixture() {
        fs::remove_all(folder);
        process->add_module("game.exe", 0x0, 0x1000);
        process->set_name("game.exe");
    }
    ~LibraryFixture() { fs::remove_all(folder); }

    std::unique_ptr<session::Session> session() {
        auto s = std::make_unique<session::Session>(process, nullptr);
        s->table().set_library(folder);
        return s;
    }
};

template <typename Pred>
bool eventually(Pred pred, int seconds = 4) {
    for (int i = 0; i < seconds * 20; ++i) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

} // anonymous namespace

TEST_CASE("the table library keeps each program's table and opens it on attach") {
    LibraryFixture f;
    {
        auto s = f.session();
        const auto first = s->attach(1);
        CHECK(first.table_note.empty()); // nothing in the library yet: the (empty) table becomes game.exe's
        REQUIRE(s->table().add_address(kBase + 0x200, DataType::Int32, "Gold").ok);
        CHECK(s->table().library_file() == f.folder / "game.exe.json");

        // Saved by itself within 2 s
        CHECK(eventually([&] { return fs::exists(f.folder / "game.exe.json"); }));

        // Another program: this table goes to the library and a new one starts
        f.process->set_name("Other.exe");
        const auto other = s->attach(2);
        CHECK(other.table_note == "Kept the table of game.exe (1 entry) in the library. New table for Other.exe.");
        CHECK(s->table().size() == 0);
        REQUIRE(s->table().add_address(kBase + 0x300, DataType::Float, "Speed").ok);
        CHECK(s->table().library_file() == f.folder / "other.exe.json");

        // Back: game.exe's table comes out of the library, other.exe's goes in
        f.process->set_name("game.exe");
        const auto back = s->attach(3);
        CHECK(back.table_note ==
              "Kept the table of Other.exe (1 entry) in the library. Opened the table of game.exe from the library: 1 entry.");
        REQUIRE(s->table().size() == 1);
        CHECK(s->table().entry(0)->description == "Gold");

        // The same program again (a restart) keeps the table as it is, unsaved changes included
        REQUIRE(s->table().add_address(kBase + 0x204, DataType::Int32, "Silver").ok);
        const auto restart = s->attach(4);
        CHECK(restart.table_note.empty());
        CHECK(s->table().size() == 2);
    } // going away saves the last changes

    // The next time: both tables are there
    auto s = f.session();
    const auto opened = s->attach(5);
    CHECK(opened.table_note == "Opened the table of game.exe from the library: 2 entries.");
    CHECK(s->table().entry(1)->description == "Silver");
    f.process->set_name("other.exe");
    CHECK(s->attach(6).table_note.find("Opened the table of other.exe from the library: 1 entry.") != std::string::npos);
    CHECK(s->table().entry(0)->type == DataType::Float);
}

TEST_CASE("the table library leaves nothing behind for programs with an empty table") {
    LibraryFixture f;
    auto s = f.session();
    f.process->set_name("tool.exe");
    REQUIRE(s->attach(1).ok);
    CHECK(s->table().save_to_library().message == "The table is empty.");
    f.process->set_name("game.exe");
    CHECK(s->attach(2).table_note == "New table for game.exe.");
    CHECK_FALSE(fs::exists(f.folder / "tool.exe.json"));

    // Freezes, hotkeys and permanent paths travel with the table
    REQUIRE(s->table().add_address(kBase + 0x200, DataType::Int32, "Gold").ok);
    REQUIRE(s->table().freeze(0, "5").ok);
    REQUIRE(s->table().add_hotkey(0, "F13", table::Hotkey::Action::Add, "10").ok);
    const auto saved = s->table().save_to_library();
    CHECK(saved.ok);
    CHECK(saved.message == "Saved the table to " + (f.folder / "game.exe.json").string() + ".");
    f.process->set_name("tool.exe");
    s->attach(3);
    f.process->set_name("game.exe");
    const auto back = s->attach(4);
    CHECK(back.table_note.find("Opened the table of game.exe from the library: 1 entry, 1 frozen, 1 hotkey.") !=
          std::string::npos);
    CHECK(s->table().entry(0)->frozen_value == "5");
}

TEST_CASE("a table made before attaching is adopted, and without a library the table stays") {
    LibraryFixture f;
    {
        // Loaded from a file that names no program: it becomes the attached program's
        auto s = f.session();
        table::CheatTable t;
        t.entries.push_back(table::make_entry(kBase + 0x200, DataType::Int32, {}, "Gold"));
        const auto file = (fs::temp_directory_path() / "nce_library_adopt.json").string();
        REQUIRE(table::save_table(file, t));
        REQUIRE(s->table().load(file).ok);
        fs::remove(file);
        CHECK(s->attach(1).table_note.empty());
        CHECK(s->table().size() == 1);
        CHECK(s->table().library_file() == f.folder / "game.exe.json");
        CHECK(s->table().save_to_library().ok);
    }

    // The library off: attaching to another program keeps the table (and saves nothing)
    session::Session s(f.process, nullptr);
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.table().add_address(kBase + 0x200, DataType::Int32, "Gold").ok);
    f.process->set_name("other.exe");
    CHECK(s.attach(2).table_note.empty());
    CHECK(s.table().size() == 1);
    CHECK(s.table().library_file().empty());
    CHECK(s.table().save_to_library().message == "The table library is off.");

    CHECK_FALSE(session::default_library_folder().empty());
    CHECK(session::default_library_folder().filename() == "tables");
}
