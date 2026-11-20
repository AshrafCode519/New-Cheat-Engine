#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "table/cheat_table.hpp"
#include <filesystem>
#include <memory>

using namespace nce;
using scanner::DataType;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// game.exe covers the first 0x1000 bytes; [game.exe + 0x100] -> object at +0x4000, value at object + 0x10
struct TableFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    std::vector<hal::ModuleInfo> modules;

    TableFixture() {
        process->add_module("game.exe", 0x0, 0x1000);
        process->put_pointer(0x100, kBase + 0x4000);
        process->put<int32_t>(0x4010, 1337);
        process->put<float>(0x200, 25.5f);
        modules = process->get_modules();
    }
};

table::TableEntry pointer_entry() {
    scanner::PointerPath path;
    path.module_name = "game.exe";
    path.base_offset = 0x100;
    path.offsets = {0x10};
    return table::make_entry(path, DataType::Int32, "Health");
}

} // anonymous namespace

TEST_CASE("make_entry stores module-relative locations when it can") {
    TableFixture f;

    auto in_module = table::make_entry(kBase + 0x200, DataType::Float, f.modules, "Mana");
    CHECK(in_module.location.module_name == "game.exe");
    CHECK(in_module.location.base_offset == 0x200);
    CHECK(in_module.location_string() == "game.exe+0x200");
    CHECK(in_module.address(*f.process, f.modules) == kBase + 0x200);

    auto on_heap = table::make_entry(kBase + 0x4010, DataType::Int32, f.modules);
    CHECK(on_heap.is_absolute());
    CHECK(on_heap.address(*f.process, f.modules) == kBase + 0x4010);

    auto chained = pointer_entry();
    CHECK(chained.location_string() == "game.exe+0x100 -> 0x10");
    CHECK(chained.address(*f.process, f.modules) == kBase + 0x4010);
}

TEST_CASE("pointer entries follow the value when the object moves") {
    TableFixture f;
    auto entry = pointer_entry();

    f.process->put<int32_t>(0x8010, 999);
    f.process->put_pointer(0x100, kBase + 0x8000); // "restart": object reallocated elsewhere

    CHECK(entry.address(*f.process, f.modules) == kBase + 0x8010);
    auto value = table::read_entry(entry, *f.process, f.modules);
    REQUIRE(value.has_value());
    CHECK(std::get<int32_t>(value->value) == 999);
}

TEST_CASE("read_entry and write_entry handle numbers and text") {
    TableFixture f;

    auto health = pointer_entry();
    REQUIRE(table::write_entry(health, "4242", *f.process, f.modules));
    CHECK(std::get<int32_t>(table::read_entry(health, *f.process, f.modules)->value) == 4242);
    CHECK_FALSE(table::write_entry(health, "abc", *f.process, f.modules));
    CHECK_FALSE(table::write_entry(health, "3000000000", *f.process, f.modules));

    const std::string name = "CyberWarrior";
    for (size_t i = 0; i < name.size(); ++i) f.process->put<char>(0x300 + i, name[i]);
    auto text = table::make_entry(kBase + 0x300, DataType::String, f.modules, "Name", 16);
    CHECK(table::read_entry(text, *f.process, f.modules)->to_string() == "\"CyberWarrior\"");

    REQUIRE(table::write_entry(text, "Neo", *f.process, f.modules));
    CHECK(table::read_entry(text, *f.process, f.modules)->to_string() == "\"Neo\""); // terminated, old tail ignored
    CHECK_FALSE(table::write_entry(text, "a name that is far too long", *f.process, f.modules));

    auto wide = table::make_entry(kBase + 0x400, DataType::String16, f.modules, "Wide", 16);
    REQUIRE(table::write_entry(wide, "Hi", *f.process, f.modules));
    CHECK(table::read_entry(wide, *f.process, f.modules)->to_string() == "\"Hi\"");

    auto aob = table::make_entry(kBase + 0x500, DataType::AOB, f.modules, "Code", 4);
    CHECK_FALSE(table::write_entry(aob, "90 90", *f.process, f.modules)); // aob entries are read-only
}

TEST_CASE("tables round-trip through JSON") {
    TableFixture f;
    table::CheatTable t;
    t.process_name = "game.exe";
    t.entries.push_back(pointer_entry());
    t.entries.back().frozen_value = "999";
    t.entries.push_back(table::make_entry(kBase + 0x200, DataType::Float, f.modules, "Mana"));
    t.entries.push_back(table::make_entry(kBase + 0x4010, DataType::Int32, f.modules, "Heap value"));
    t.entries.push_back(table::make_entry(kBase + 0x300, DataType::String16, f.modules, "Name", 24));

    const std::string text = table::to_json(t);
    CHECK(text.find("\"offset\": \"0x100\"") != std::string::npos); // hex stays readable
    CHECK(text.find("\"pointer\": [\n        \"0x10\"\n      ]") != std::string::npos);

    auto loaded = table::from_json(text);
    REQUIRE(loaded.has_value());
    CHECK(loaded->process_name == "game.exe");
    REQUIRE(loaded->entries.size() == t.entries.size());
    for (size_t i = 0; i < t.entries.size(); ++i) {
        const auto& a = t.entries[i];
        const auto& b = loaded->entries[i];
        CHECK(a.description == b.description);
        CHECK(a.type == b.type);
        CHECK(a.location.module_name == b.location.module_name);
        CHECK(a.location.base_offset == b.location.base_offset);
        CHECK(a.location.offsets == b.location.offsets);
        CHECK(a.length == b.length);
        CHECK(a.frozen_value == b.frozen_value);
    }

    const auto file = (std::filesystem::temp_directory_path() / "nce_table_roundtrip.json").string();
    REQUIRE(table::save_table(file, t));
    auto from_file = table::load_table(file);
    std::filesystem::remove(file);
    REQUIRE(from_file.has_value());
    CHECK(from_file->entries.size() == t.entries.size());
}

namespace {

// A heap value reachable from several statics: [game.exe + 0x100/0x180/0x1C0] -> A, [A + 8] -> B,
// value at B + 0x10 inside a struct with constant neighbours (0x1111 before, 0x2222 after it).
// Decoys [other.dll + 0x200 + 8k] -> B + 8 reach it only by coincidence.
struct PermanentFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    std::vector<hal::ModuleInfo> modules;
    uintptr_t b = kBase + 0x6000;

    explicit PermanentFixture(int statics = 3, int decoys = 1) {
        process->add_module("game.exe", 0x0, 0x1000);
        process->add_module("other.dll", 0x1000, 0x1000);
        const size_t static_slots[] = {0x100, 0x180, 0x1C0};
        for (int i = 0; i < statics; ++i) process->put_pointer(static_slots[i], kBase + 0x4000);
        for (int i = 0; i < decoys; ++i) process->put_pointer(0x1200 + 8 * static_cast<size_t>(i), b + 0x8);
        process->put_pointer(0x4008, b);
        write_struct(b);
        modules = process->get_modules();
    }

    void write_struct(uintptr_t at) {
        process->put<uint32_t>(at - kBase + 0x0C, 0x1111);
        process->put<int32_t>(at - kBase + 0x10, 1337);
        process->put<uint32_t>(at - kBase + 0x14, 0x2222);
    }

    // A restart: the object is allocated elsewhere, and its old place is reused by something else that
    // the coincidental decoys still point into
    void restart() {
        const uintptr_t old = b;
        b += 0x2000;
        process->put_pointer(0x4008, b);
        write_struct(b);
        process->put<uint32_t>(old - kBase + 0x0C, 0x7777);
        process->put<int32_t>(old - kBase + 0x10, 2228282);
        process->put<uint32_t>(old - kBase + 0x14, 0);
    }
};

table::TableEntry permanent_entry(PermanentFixture& f) {
    auto entry = table::make_entry(f.b + 0x10, DataType::Int32, f.modules, "Score");
    REQUIRE(table::make_permanent(entry, table::find_permanent_paths(entry, f.process, f.modules), *f.process, f.modules));
    return entry;
}

} // anonymous namespace

TEST_CASE("a permanent entry finds its value again after a restart") {
    PermanentFixture f;
    auto entry = table::make_entry(f.b + 0x10, DataType::Int32, f.modules, "Score");
    REQUIRE(entry.is_absolute());

    const auto paths = table::find_permanent_paths(entry, f.process, f.modules);
    REQUIRE(paths.size() == 4); // three real chains and the decoy
    REQUIRE(table::make_permanent(entry, paths, *f.process, f.modules));
    CHECK_FALSE(entry.is_absolute());
    CHECK(entry.alternatives.size() == 3);
    CHECK(entry.location.module_name == "game.exe"); // main module ranks first
    CHECK(entry.context.size() == 2 * table::TableEntry::CONTEXT_RADIUS + 4);

    f.restart();
    const auto result = table::reconcile(entry, *f.process, f.modules);
    CHECK(result.paths == 4);
    CHECK(result.resolved == 4);
    CHECK(result.agreeing == 3);
    CHECK(result.address == f.b + 0x10);
    CHECK(result.context_words == 2); // 0x1111 and 0x2222 (zero words don't count)
    CHECK(result.context_matches == 2);
    CHECK(result.value_matches);
    CHECK_FALSE(result.ambiguous);
    CHECK(result.changed);
    CHECK(entry.alternatives.size() == 2); // the decoy is gone
    CHECK(std::get<int32_t>(table::read_entry(entry, *f.process, f.modules)->value) == 1337);

    // The next restart has nothing left to drop
    f.restart();
    CHECK_FALSE(table::reconcile(entry, *f.process, f.modules).changed);
}

TEST_CASE("the remembered surroundings beat a majority of paths that move together") {
    // Seen on target_dummy: hundreds of paths through the same heap structures outvoted the real chain
    PermanentFixture f(3, 5);
    auto entry = permanent_entry(f);
    REQUIRE(entry.alternatives.size() == 7);

    f.restart(); // the 5 decoys now lead to the old place, the 3 real chains to the new one
    const auto result = table::reconcile(entry, *f.process, f.modules);
    CHECK(result.address == f.b + 0x10);
    CHECK(result.agreeing == 3);
    CHECK(result.by_context);
    CHECK_FALSE(result.ambiguous);
    CHECK(std::get<int32_t>(table::read_entry(entry, *f.process, f.modules)->value) == 1337);

    // Without the context the vote alone picks the old place
    PermanentFixture g(3, 5);
    auto blind = permanent_entry(g);
    blind.context.clear();
    const uintptr_t old_place = g.b + 0x10;
    g.restart();
    CHECK(table::reconcile(blind, *g.process, g.modules).address == old_place);
}

TEST_CASE("the value's direct neighbours count more than far words any heap block has") {
    // Seen on target_dummy: heap block headers 6-9 words before the value matched at an unrelated block
    // that most paths led to, while the real value kept only its two struct neighbours and its value.
    // Counting every word alike chose the unrelated block (4 far words beat 2 near ones and the value).
    PermanentFixture f(3, 5);
    const size_t value = f.b - kBase + 0x10;
    for (size_t k = 0; k < 4; ++k) f.process->put<uint32_t>(value - 0x24 + 4 * k, 0xABC00000 + static_cast<uint32_t>(k));
    auto entry = permanent_entry(f);

    f.restart(); // the headers stay at the old place, where the 5 decoys still lead
    const auto result = table::reconcile(entry, *f.process, f.modules);
    CHECK(result.address == f.b + 0x10);
    CHECK(result.agreeing == 3);
    CHECK(result.by_context);
    CHECK(result.value_matches);
    CHECK(result.context_words == 6);
    CHECK(result.context_matches == 2);
}

TEST_CASE("reconcile changes nothing on a close vote or when nothing resolves") {
    PermanentFixture f(1); // one real chain against the decoy: 1 vote each after the restart
    auto entry = permanent_entry(f);
    entry.context.clear(); // a table made before contexts existed: only the vote is left
    const auto before = entry.alternatives.size();

    f.restart();
    const auto close = table::reconcile(entry, *f.process, f.modules);
    CHECK(close.ambiguous);
    CHECK_FALSE(close.changed);
    CHECK(entry.alternatives.size() == before);

    // Another program: no module of the paths is loaded
    const auto none = table::reconcile(entry, *f.process, {});
    CHECK(none.resolved == 0);
    CHECK_FALSE(none.changed);
    CHECK(entry.alternatives.size() == before);
}

TEST_CASE("pointer alternatives and the context survive a JSON round trip") {
    PermanentFixture f;
    auto entry = permanent_entry(f);

    table::CheatTable t;
    t.entries.push_back(entry);
    auto loaded = table::from_json(table::to_json(t));
    REQUIRE(loaded.has_value());
    const auto& e = loaded->entries.front();
    CHECK(e.context == entry.context);
    REQUIRE(e.alternatives.size() == entry.alternatives.size());
    for (size_t i = 0; i < e.alternatives.size(); ++i) {
        CHECK(e.alternatives[i].module_name == entry.alternatives[i].module_name);
        CHECK(e.alternatives[i].base_offset == entry.alternatives[i].base_offset);
        CHECK(e.alternatives[i].offsets == entry.alternatives[i].offsets);
    }

    // An alternative must be a pointer path (with a module); the context must be hex
    CHECK_FALSE(table::from_json(R"({"format": "nce-table", "version": 1, "entries": [)"
                                 R"({"type": "i32", "offset": "0x10", "alternatives": [{"offset": "0x20"}]}]})").has_value());
    CHECK_FALSE(table::from_json(R"({"format": "nce-table", "version": 1, "entries": [)"
                                 R"({"type": "i32", "offset": "0x10", "context": "XYZ"}]})").has_value());
}

TEST_CASE("from_json rejects malformed tables") {
    CHECK_FALSE(table::from_json("not json").has_value());
    CHECK_FALSE(table::from_json(R"({"format": "something-else", "version": 1, "entries": []})").has_value());
    CHECK_FALSE(table::from_json(R"({"format": "nce-table", "version": 2, "entries": []})").has_value());
    CHECK_FALSE(table::from_json(R"({"format": "nce-table", "version": 1})").has_value());

    const char* bad_entries[] = {
        R"([{"type": "nope", "offset": "0x10"}])",                     // unknown type
        R"([{"type": "i32", "offset": "zz"}])",                         // bad hex
        R"([{"type": "i32", "offset": "0x10", "pointer": ["0xZZ"]}])",  // bad pointer offset
        R"([{"type": "str", "offset": "0x10"}])",                       // text without a length
        R"([{"type": "i32", "offset": "0x10", "freeze": 5}])",          // freeze value must be text
    };
    for (const char* entries : bad_entries) {
        CAPTURE(entries);
        const std::string doc = std::string(R"({"format": "nce-table", "version": 1, "entries": )") + entries + "}";
        CHECK_FALSE(table::from_json(doc).has_value());
    }

    CHECK(table::from_json(R"({"format": "nce-table", "version": 1, "entries": []})").has_value());
}
