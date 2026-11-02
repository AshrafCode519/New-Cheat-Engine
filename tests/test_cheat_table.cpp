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
