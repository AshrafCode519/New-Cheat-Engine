#include <cstdint>
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

TEST_CASE("review: a table from elsewhere never silently replaces the library's table") {
    LibraryFixture f;
    {
        auto s = f.session();
        REQUIRE(s->attach(1).ok);
        REQUIRE(s->table().add_address(kBase + 0x200, DataType::Int32, "Saved").ok);
        REQUIRE(s->table().save_to_library().ok);
    }

    // A table naming no program, loaded before attaching, is adopted: the library's one is kept as .bak
    table::CheatTable shared;
    shared.entries.push_back(table::make_entry(kBase + 0x300, DataType::Int32, {}, "Shared"));
    const auto file = (fs::temp_directory_path() / "nce_library_shared.json").string();
    REQUIRE(table::save_table(file, shared));
    {
        auto s = f.session();
        f.process->detach(); // not attached yet
        REQUIRE(s->table().load(file).ok);
        const auto attached = s->attach(1);
        CHECK(attached.table_note == "This table is game.exe's now; the library's earlier table of it will be kept as "
                                     "game.exe.json.bak.");
        REQUIRE(s->table().save_to_library().ok);
        const auto kept = table::load_table((f.folder / "game.exe.json.bak").string());
        REQUIRE(kept);
        CHECK(kept->entries.at(0).description == "Saved");

        // tload while attached: the open table's latest changes are saved first, and kept as .bak
        REQUIRE(s->table().add_address(kBase + 0x204, DataType::Int32, "Unsaved").ok);
        REQUIRE(s->table().load(file).ok);
        CHECK(s->table().library_file() == f.folder / "game.exe.json"); // the loaded table is the attached program's
        const auto second = s->table().save_to_library();
        INFO(second.message);
        REQUIRE(second.ok);
        const auto before = table::load_table((f.folder / "game.exe.json.bak").string());
        REQUIRE(before);
        REQUIRE(before->entries.size() == 2);
        CHECK(before->entries[1].description == "Unsaved");
    }
    fs::remove(file);
}

TEST_CASE("review: a frozen permanent entry is found before the freeze thread writes it") {
    // [game.exe + 0x100] -> A, [A + 8] -> B, value at B + 0x10 between 0x1111 and 0x2222
    LibraryFixture f;
    uintptr_t b = kBase + 0x6000;
    auto write_struct = [&](uintptr_t at) {
        f.process->put<uint32_t>(at - kBase + 0x0C, 0x1111);
        f.process->put<int32_t>(at - kBase + 0x10, 1337);
        f.process->put<uint32_t>(at - kBase + 0x14, 0x2222);
    };
    f.process->put_pointer(0x100, kBase + 0x4000);
    f.process->put_pointer(0x180, kBase + 0x4000);
    f.process->put_pointer(0x4008, b);
    write_struct(b);
    {
        auto s = f.session();
        REQUIRE(s->attach(1).ok);
        REQUIRE(s->table().add_address(b + 0x10, DataType::Int32, "Score").ok);
        const auto entry = s->table().entry(0);
        REQUIRE(s->table().make_permanent(0, *entry, s->find_permanent_paths(*entry)).ok);
        REQUIRE(s->table().freeze(0, "4242").ok);
        s->detach(); // the game exits; the table goes to the library when the session ends
    }

    // The next run: the object moved, and its old place holds something else that last run's path still reaches
    const uintptr_t old = b;
    b += 0x2000;
    f.process->put_pointer(0x4008, b);
    write_struct(b);
    f.process->put<int32_t>(old - kBase + 0x10, 2228282);
    f.process->put_pointer(0x100, old - 0x8); // the first-ranked path now leads to the old place

    auto s = f.session();
    const auto attached = s->attach(2);
    REQUIRE(attached.reconciled.size() == 1);
    CHECK(attached.reconciled[0].result.address == b + 0x10);
    CHECK(eventually([&] {
        return s->table().with([&](const auto&, const auto&) {
            int32_t v = 0;
            f.process->read_raw(b + 0x10, &v, sizeof v);
            return v == 4242;
        });
    }));
    const int32_t at_old_place = s->table().with([&](const auto&, const auto&) {
        int32_t v = 0;
        f.process->read_raw(old + 0x10, &v, sizeof v);
        return v;
    });
    CHECK(at_old_place == 2228282); // never written
}
