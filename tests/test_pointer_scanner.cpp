#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "scanner/pointer_scanner.hpp"
#include <filesystem>
#include <memory>

using namespace nce;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// game.exe (main module) at +0x0000, other.dll at +0x1000, heap after that.
//   real:  [game.exe + 0x100] -> A;  [A + 0x8] -> B;  target = B + 0x10
//   decoy: [other.dll + 0x200] -> B + 0x8          (one level, but only by coincidence)
struct PointerFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    uintptr_t a = kBase + 0x4000;
    uintptr_t b = kBase + 0x6000;

    explicit PointerFixture(size_t pointer_size = sizeof(uintptr_t)) {
        process->add_module("game.exe", 0x0, 0x1000);
        process->add_module("other.dll", 0x1000, 0x1000);
        process->set_pointer_size(pointer_size);
        process->put_pointer(0x100, a);
        process->put_pointer(a + 0x8 - kBase, b);
        process->put_pointer(0x1200, b + 0x8);
    }

    [[nodiscard]] uintptr_t target() const { return b + 0x10; }

    // Simulates a restart: the object moves, the static pointer chain is rebuilt, the decoy is stale
    void move_object() {
        b = kBase + 0x8000;
        process->put_pointer(a + 0x8 - kBase, b);
    }
};

bool has_path(const std::vector<scanner::PointerPath>& paths, const std::string& module, uintptr_t base_offset,
              const std::vector<int64_t>& offsets) {
    for (const auto& p : paths) {
        if (p.module_name == module && p.base_offset == base_offset && p.offsets == offsets) return true;
    }
    return false;
}

} // anonymous namespace

TEST_CASE("pointer scan finds the real chain and ranks the main module first") {
    PointerFixture f;
    scanner::PointerScanner ps(f.process);

    auto result = ps.scan(f.target());
    REQUIRE(result.paths.size() == 2);
    CHECK_FALSE(result.truncated);

    // The longer game.exe path ranks above the shorter other.dll one
    CHECK(result.paths[0].module_name == "game.exe");
    CHECK(result.paths[0].base_offset == 0x100);
    CHECK(result.paths[0].offsets == std::vector<int64_t>{0x8, 0x10});
    CHECK(result.paths[0].to_string() == "[game.exe + 0x100] -> [0x8] -> [0x10]");
    CHECK(has_path(result.paths, "other.dll", 0x200, {0x8}));

    const auto modules = f.process->get_modules();
    for (const auto& p : result.paths) {
        CHECK(p.resolve(*f.process, modules) == f.target());
    }
}

TEST_CASE("rescan after a restart keeps only the path that still leads to the value") {
    PointerFixture f;
    scanner::PointerScanner ps(f.process);
    auto paths = ps.scan(f.target()).paths;
    REQUIRE(paths.size() == 2);

    f.move_object();
    auto survivors = scanner::PointerScanner::verify_paths(*f.process, paths, f.target());
    REQUIRE(survivors.size() == 1);
    CHECK(survivors[0].module_name == "game.exe");
    CHECK(survivors[0].offsets == std::vector<int64_t>{0x8, 0x10});
}

TEST_CASE("pointer scan works on 32-bit targets (4-byte pointers)") {
    PointerFixture f(4);
    scanner::PointerScanner ps(f.process);

    auto result = ps.scan(f.target());
    CHECK(has_path(result.paths, "game.exe", 0x100, {0x8, 0x10}));
    CHECK(result.paths.front().resolve(*f.process, f.process->get_modules()) == f.target());

    // 8-byte reads would combine two 4-byte slots and miss this; resolve must read 4 bytes too
    f.move_object();
    CHECK(scanner::PointerScanner::verify_paths(*f.process, result.paths, f.target()).size() == 1);
}

TEST_CASE("a static address resolves to itself, not to the value stored there") {
    PointerFixture f;
    f.process->put<int32_t>(0x300, 1337);

    scanner::PointerPath static_path;
    static_path.module_name = "GAME.EXE"; // module names compare case-insensitively
    static_path.base_offset = 0x300;
    CHECK(static_path.resolve(*f.process, f.process->get_modules()) == kBase + 0x300); // used to return 1337

    scanner::PointerScanner ps(f.process);
    auto result = ps.scan(kBase + 0x300);
    REQUIRE_FALSE(result.paths.empty());
    CHECK(result.paths[0].offsets.empty());
    CHECK(result.paths[0].base_offset == 0x300);
}

TEST_CASE("base_module and max_results limit the search") {
    PointerFixture f;
    scanner::PointerScanner ps(f.process);

    scanner::PointerScanOptions only_other;
    only_other.base_module = "OTHER.DLL";
    auto filtered = ps.scan(f.target(), only_other);
    REQUIRE(filtered.paths.size() == 1);
    CHECK(filtered.paths[0].module_name == "other.dll");

    scanner::PointerScanOptions one_result;
    one_result.max_results = 1;
    auto capped = ps.scan(f.target(), one_result);
    CHECK(capped.paths.size() == 1);
    CHECK(capped.truncated);

    scanner::PointerScanOptions shallow;
    shallow.max_depth = 1;
    auto depth_one = ps.scan(f.target(), shallow);
    REQUIRE(depth_one.paths.size() == 1);
    CHECK(depth_one.paths[0].module_name == "other.dll");
}

TEST_CASE("pointer paths survive a save / load round trip") {
    PointerFixture f;
    scanner::PointerScanner ps(f.process);
    auto paths = ps.scan(f.target()).paths;
    scanner::PointerPath static_path;
    static_path.module_name = "game.exe";
    static_path.base_offset = 0x300;
    paths.push_back(static_path);

    const auto file = (std::filesystem::temp_directory_path() / "nce_pointers_roundtrip.txt").string();
    REQUIRE(scanner::save_pointer_paths(file, paths));
    auto loaded = scanner::load_pointer_paths(file);
    std::filesystem::remove(file);

    REQUIRE(loaded.has_value());
    REQUIRE(loaded->size() == paths.size());
    for (size_t i = 0; i < paths.size(); ++i) {
        CHECK((*loaded)[i].module_name == paths[i].module_name);
        CHECK((*loaded)[i].base_offset == paths[i].base_offset);
        CHECK((*loaded)[i].offsets == paths[i].offsets);
    }
}
