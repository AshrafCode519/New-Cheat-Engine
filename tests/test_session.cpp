#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "session/session.hpp"
#include "utils/hex_utils.hpp"
#include <chrono>
#include <filesystem>
#include <thread>

using namespace nce;
using scanner::DataType;
using scanner::FloatMatchMode;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

std::optional<size_t> index_of(const scanner::ScanResults& results, uintptr_t address) {
    for (size_t i = 0; i < results.count(); ++i) {
        if (results.address(i) == address) return i;
    }
    return std::nullopt;
}

// The freeze thread writes into the fake memory, so the test touches it under the table lock too
int32_t value_at(session::Session& s, FakeProcess& p, size_t offset) {
    return s.table().with([&](const auto&, const auto&) {
        int32_t v = 0;
        p.read_raw(kBase + offset, &v, sizeof v);
        return v;
    });
}

void put_locked(session::Session& s, FakeProcess& p, size_t offset, int32_t value) {
    s.table().with([&](const auto&, const auto&) { p.put<int32_t>(offset, value); });
}

template <typename Pred>
bool eventually(Pred pred) {
    for (int i = 0; i < 40; ++i) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

} // anonymous namespace

TEST_CASE("a scan session narrows a value down and undoes") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->put<int32_t>(0x100, 777);
    process->put<int32_t>(0x2000, 777);

    session::ScanSession scans;
    CHECK(scans.first_scan("i32", "777", FloatMatchMode::Rounded).message == "Attach to a process first.");
    scans.set_scanner(std::make_shared<scanner::MemoryScanner>(process), process);
    CHECK(scans.empty());
    CHECK_FALSE(scans.next_scan("inc", "", "", FloatMatchMode::Rounded).ok);

    REQUIRE(scans.first_scan("i32", "777", FloatMatchMode::Rounded).ok);
    CHECK(scans.state().results.count() == 2);
    CHECK(scans.describe() == "2 matches");

    process->put<int32_t>(0x100, 778);
    REQUIRE(scans.next_scan("inc", "", "", FloatMatchMode::Rounded).ok);
    REQUIRE(scans.state().results.count() == 1);
    CHECK(scans.state().results.address(0) == kBase + 0x100);

    REQUIRE(scans.undo());
    CHECK(scans.state().results.count() == 2);
    REQUIRE(scans.next_scan("exact", "778", "", FloatMatchMode::Rounded).ok);
    CHECK(scans.state().results.count() == 1);

    // The history keeps the last MAX_UNDO_STEPS states
    for (size_t i = 0; i < session::ScanSession::MAX_UNDO_STEPS + 3; ++i) {
        REQUIRE(scans.next_scan("unchanged", "", "", FloatMatchMode::Rounded).ok);
    }
    size_t undos = 0;
    while (scans.undo()) ++undos;
    CHECK(undos == session::ScanSession::MAX_UNDO_STEPS);

    // The target exited: scanning it would only empty the results
    const size_t before = scans.state().results.count();
    process->detach();
    CHECK(scans.next_scan("unchanged", "", "", FloatMatchMode::Rounded).message ==
          "The target is no longer running; attach again.");
    CHECK(scans.state().results.count() == before);
}

TEST_CASE("a scan session explains what it can't do") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    session::ScanSession scans;
    scans.set_scanner(std::make_shared<scanner::MemoryScanner>(process), process);

    CHECK(scans.first_scan("i33", "1", FloatMatchMode::Rounded).message.find("Unknown type") == 0);
    CHECK(scans.first_scan("i32", "abc", FloatMatchMode::Rounded).message ==
          "'abc' is not a valid i32 value (not a number, or out of range).");
    CHECK(scans.first_scan("u8", "300", FloatMatchMode::Rounded).message.find("not a valid u8") != std::string::npos);
    CHECK(scans.first_scan("aob", "48 ZZ", FloatMatchMode::Rounded).message == "Invalid AOB pattern. Example: 48 8B ? ? 89");
    CHECK_FALSE(scans.first_scan("str", "", FloatMatchMode::Rounded).ok);
    CHECK(scans.empty()); // nothing failed into the history
    CHECK_FALSE(scans.can_undo());

    process->put<char>(0x300, 'h');
    process->put<char>(0x301, 'p');
    REQUIRE(scans.first_scan("str", "hp", FloatMatchMode::Rounded).ok);
    CHECK(scans.state().results.count() == 1);
    CHECK(scans.next_scan("inc", "", "", FloatMatchMode::Rounded).message == "Text and AOB results only support changed and unchanged.");
    CHECK(scans.next_scan("sideways", "", "", FloatMatchMode::Rounded).message.find("Unknown condition") == 0);
    CHECK(scans.next_scan("unchanged", "", "", FloatMatchMode::Rounded).ok);

    // A float typed as shown in the game matches the range it was rounded from
    process->put<float>(0x400, 25.53f);
    const auto floats = scans.first_scan("f32", "25.5", FloatMatchMode::Rounded);
    REQUIRE(floats.ok);
    CHECK(floats.message.find("matching f32 values in [") == 0);
    CHECK(test::contains_address(scans.state().results, kBase + 0x400));
}

TEST_CASE("an unknown-value search stays a snapshot until a results list is smaller") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    session::ScanSession scans;
    scans.set_scanner(std::make_shared<scanner::MemoryScanner>(process), process);

    REQUIRE(scans.first_scan("i32", "?", FloatMatchMode::Rounded).ok);
    REQUIRE(scans.state().snapshot);
    CHECK(scans.state().snapshot->candidate_count() == 0x10000 / 4);
    CHECK(scans.describe().find("candidates, snapshot") != std::string::npos);

    REQUIRE(scans.next_scan("unchanged", "", "", FloatMatchMode::Rounded).ok);
    CHECK(scans.state().snapshot); // still every address

    process->put<int32_t>(0x800, 42);
    REQUIRE(scans.next_scan("changed", "", "", FloatMatchMode::Rounded).ok);
    CHECK_FALSE(scans.state().snapshot);
    REQUIRE(scans.state().results.count() == 1);
    CHECK(scans.state().results.address(0) == kBase + 0x800);

    // Undo brings the snapshot back
    REQUIRE(scans.undo());
    CHECK(scans.state().snapshot);
}

TEST_CASE("a session keeps frozen table entries at their values") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x0, 0x1000);
    process->put<int32_t>(0x200, 100);

    session::Session s(process);
    const auto report = s.attach(1);
    REQUIRE(report.ok);
    CHECK_FALSE(report.read_only);
    CHECK(report.reconciled.empty());

    REQUIRE(s.scans().first_scan("i32", "100", FloatMatchMode::Rounded).ok);
    const auto index = index_of(s.scans().state().results, kBase + 0x200);
    REQUIRE(index);
    const auto added = s.table().add_result(s.scans().state().results, *index, "Gold");
    REQUIRE(added.ok);
    CHECK(added.message == "Added #0: game.exe+0x200");
    CHECK_FALSE(s.table().add_result(s.scans().state().results, 99, "").ok);

    REQUIRE(s.table().freeze(0, std::nullopt).ok); // at its current value, 100
    CHECK(s.table().entry(0)->frozen_value == "100");
    put_locked(s, *process, 0x200, 5);
    CHECK(eventually([&] { return value_at(s, *process, 0x200) == 100; }));

    // Setting a frozen entry moves the freeze to the new value
    REQUIRE(s.table().set_value(0, "250").ok);
    CHECK(s.table().entry(0)->frozen_value == "250");
    put_locked(s, *process, 0x200, 5);
    CHECK(eventually([&] { return value_at(s, *process, 0x200) == 250; }));

    REQUIRE(s.table().unfreeze(0).ok);
    put_locked(s, *process, 0x200, 7);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK(value_at(s, *process, 0x200) == 7);

    CHECK_FALSE(s.table().set_value(0, "abc").ok);
    CHECK(s.table().freeze(3, "1").message == "No table entry #3 (there are 1).");
    CHECK_FALSE(s.table().remove(3).ok);
    REQUIRE(s.table().remove(0).ok);
    CHECK(s.table().size() == 0);
}

TEST_CASE("attaching again unfreezes heap entries and starts a new search") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x0, 0x1000);
    session::Session s(process);
    REQUIRE(s.attach(1).ok);

    REQUIRE(s.table().add_address(kBase + 0x200, DataType::Int32, "in the module").ok);
    const auto heap = s.table().add_address(kBase + 0x5000, DataType::Int32, "on the heap");
    CHECK(heap.message.find("only valid until the target restarts") != std::string::npos);
    REQUIRE(s.table().freeze(0, "1").ok);
    REQUIRE(s.table().freeze(1, "1").ok);

    REQUIRE(s.scans().first_scan("i32", "0", FloatMatchMode::Rounded).ok);
    s.set_noise(std::make_shared<scanner::NoiseMap>());
    CHECK(s.noise());
    CHECK(s.describe_noise() == "none known");

    const auto report = s.attach(1);
    REQUIRE(report.ok);
    CHECK(report.unfrozen == 1);
    CHECK(s.table().entry(0)->frozen_value);
    CHECK_FALSE(s.table().entry(1)->frozen_value);
    CHECK(s.scans().empty());
    CHECK_FALSE(s.scans().can_undo());
    CHECK_FALSE(s.noise());
    CHECK(s.table().unfreeze_all() == 1);

    s.detach();
    CHECK_FALSE(s.attached());
    CHECK(s.table().modules().empty());
    CHECK(s.scans().first_scan("i32", "0", FloatMatchMode::Rounded).message == "Attach to a process first.");
}

TEST_CASE("a session makes an entry permanent and finds it again after a restart") {
    // [game.exe + 0x100/0x180] -> A, [A + 8] -> B, value at B + 0x10 between two constants
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x0, 0x1000);
    uintptr_t b = kBase + 0x6000;
    auto write_struct = [&](uintptr_t at) {
        process->put<uint32_t>(at - kBase + 0x0C, 0x1111);
        process->put<int32_t>(at - kBase + 0x10, 1337);
        process->put<uint32_t>(at - kBase + 0x14, 0x2222);
    };
    process->put_pointer(0x100, kBase + 0x4000);
    process->put_pointer(0x180, kBase + 0x4000);
    process->put_pointer(0x4008, b);
    write_struct(b);

    session::Session s(process);
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.table().add_address(b + 0x10, DataType::Int32, "Score").ok);

    const auto scanned = s.table().entry(0);
    REQUIRE(scanned);
    const auto paths = s.find_permanent_paths(*scanned);
    REQUIRE(paths.size() == 2);

    // The table changed during the (slow) search: nothing is applied
    REQUIRE(s.table().add_address(kBase + 0x200, DataType::Int32, "other").ok);
    REQUIRE(s.table().remove(0).ok);
    CHECK_FALSE(s.table().make_permanent(0, *scanned, paths).ok);
    REQUIRE(s.table().remove(0).ok);
    REQUIRE(s.table().add_address(b + 0x10, DataType::Int32, "Score").ok);

    CHECK_FALSE(s.table().make_permanent(0, *scanned, {}).ok);
    const auto made = s.table().make_permanent(0, *scanned, paths);
    REQUIRE(made.ok);
    CHECK(made.message.find("#0 is permanent: game.exe+0x") == 0);
    CHECK_FALSE(s.table().entry(0)->is_absolute());

    // A restart moves the object; the new attach finds it
    const uintptr_t old = b;
    b += 0x2000;
    process->put_pointer(0x4008, b);
    write_struct(b);
    process->put<int32_t>(old - kBase + 0x10, 99);

    const auto report = s.attach(1);
    REQUIRE(report.reconciled.size() == 1);
    CHECK(report.reconciled[0].description == "Score");
    CHECK(report.reconciled[0].result.address == b + 0x10);
    CHECK(report.reconciled[0].result.value_matches);
    CHECK(session::describe_reconcile(report.reconciled[0].result).find("found at " + utils::format_address(b + 0x10)) == 0);
}

TEST_CASE("a session's table survives a save and a load") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x0, 0x1000);
    const auto file = (std::filesystem::temp_directory_path() / "nce_session_table.json").string();
    {
        session::Session s(process);
        REQUIRE(s.attach(1).ok);
        REQUIRE(s.table().add_address(kBase + 0x200, DataType::Int32, "Gold").ok);
        REQUIRE(s.table().add_address(kBase + 0x204, DataType::Float, "Speed").ok);
        REQUIRE(s.table().freeze(0, "9").ok);
        REQUIRE(s.table().save(file).ok);
    }

    session::Session s(process);
    CHECK_FALSE(s.table().load(file + ".missing").ok);
    const auto loaded = s.table().load(file);
    std::filesystem::remove(file);
    REQUIRE(loaded.ok);
    CHECK(loaded.message == "Loaded 2 entries for 'game.exe' (1 frozen).");
    CHECK(s.table().entry(1)->description == "Speed");
    CHECK_FALSE(s.find_restart()); // the fake process has no name
}
