#include <doctest/doctest.h>
#include "../engine/include/view/vector_detector.hpp"
#include "../engine/include/utils/sig_generator.hpp"
#include "../engine/include/utils/hex_utils.hpp"
#include "test_helpers.hpp"
#include <vector>
#include <cmath>
#include <cstring>

using namespace nce::view;
using namespace nce::utils;
using nce::test::FakeProcess;

TEST_CASE("Vector3: Distance and Validity") {
    Vector3 a{0.0f, 0.0f, 0.0f};
    Vector3 b{3.0f, 4.0f, 0.0f};
    CHECK(doctest::Approx(a.distance_to(b)) == 5.0f);

    Vector3 valid{100.0f, 200.0f, 300.0f};
    CHECK(valid.is_valid());

    Vector3 nan_vec{NAN, 0.0f, 0.0f};
    CHECK_FALSE(nan_vec.is_valid());

    Vector3 zero_vec{0.0f, 0.0f, 0.0f};
    CHECK_FALSE(zero_vec.is_valid()); // ignored as uninitialized candidate
}

TEST_CASE("VectorDetector: Snapshot, Motion Detection and Nudge") {
    auto proc = std::make_shared<FakeProcess>(1024 * 1024);
    proc->attach(1);

    Vector3 initial_pos{100.0f, 50.0f, 25.0f};
    uintptr_t target_offset = 0x2000;
    proc->put<Vector3>(target_offset, initial_pos);

    VectorDetector detector;
    size_t count = detector.take_snapshot(*proc);
    CHECK(count >= 1);

    SUBCASE("No movement detected when memory unchanged") {
        auto hits = detector.detect_motion(*proc, 1.0f, 100.0f);
        CHECK(hits.empty());
    }

    SUBCASE("Detect movement when player moves") {
        // Move player by +3.0 in X and +4.0 in Y (distance = 5.0)
        Vector3 moved_pos{103.0f, 54.0f, 25.0f};
        proc->put<Vector3>(target_offset, moved_pos);

        auto hits = detector.detect_motion(*proc, 1.0f, 100.0f);
        REQUIRE_FALSE(hits.empty());
        auto it = std::find_if(hits.begin(), hits.end(), [&](const auto& h) {
            return h.address == FakeProcess::kBase + target_offset;
        });
        REQUIRE(it != hits.end());
        CHECK(doctest::Approx(it->delta_dist) == 5.0f);
        CHECK(doctest::Approx(it->current.x) == 103.0f);
        CHECK(doctest::Approx(it->current.y) == 54.0f);
    }

    SUBCASE("Direct Read, Write and Nudge") {
        uintptr_t addr = FakeProcess::kBase + target_offset;
        auto read_val = VectorDetector::read_vector(*proc, addr);
        REQUIRE(read_val.has_value());
        CHECK(read_val->x == 100.0f);

        // Nudge +10 Z
        bool ok = VectorDetector::nudge(*proc, addr, 0.0f, 0.0f, 10.0f);
        CHECK(ok);

        auto nudged_val = VectorDetector::read_vector(*proc, addr);
        REQUIRE(nudged_val.has_value());
        CHECK(nudged_val->z == 35.0f);
    }

    SUBCASE("Waypoints and Teleport") {
        uintptr_t addr = FakeProcess::kBase + target_offset;
        detector.add_waypoint("BaseCamp", {500.0f, 600.0f, 700.0f});
        REQUIRE(detector.waypoints().size() == 1);
        CHECK(detector.waypoints()[0].name == "BaseCamp");

        // Teleport to waypoint
        bool ok = VectorDetector::write_vector(*proc, addr, detector.waypoints()[0].position);
        CHECK(ok);

        auto pos = VectorDetector::read_vector(*proc, addr);
        REQUIRE(pos.has_value());
        CHECK(pos->x == 500.0f);
        CHECK(pos->y == 600.0f);
        CHECK(pos->z == 700.0f);

        detector.remove_waypoint(0);
        CHECK(detector.waypoints().empty());
    }
}

TEST_CASE("VectorDetector: UE5 Double3, Chunk Boundary Overlap, Iterative Narrowing, and Batch Coalescing") {
    class CountingFakeProcess final : public FakeProcess {
    public:
        using FakeProcess::FakeProcess;
        mutable size_t read_calls{0};
        bool read_raw(uintptr_t address, void* buffer, size_t size) const override {
            ++read_calls;
            return FakeProcess::read_raw(address, buffer, size);
        }
    };

    SUBCASE("Double3 (UE5 LWC) snapshot, detect, read/write/nudge") {
        auto proc = std::make_shared<CountingFakeProcess>(64 * 1024);
        proc->attach(1);

        const size_t pos_off = 0x2000;
        const uintptr_t pos_va = FakeProcess::kBase + pos_off;
        proc->put<Vector3d>(pos_off, Vector3d{1000.25, -450.75, 80.5});

        VectorDetector det;
        CHECK(det.take_snapshot(*proc, nce::hal::FilterFlags::DefaultScanFilter, VectorFormat::Double3) >= 1);

        proc->put<Vector3d>(pos_off, Vector3d{1005.25, -450.75, 80.5});
        auto hits = det.detect_motion(*proc, 1.0f, 50.0f);
        REQUIRE_FALSE(hits.empty());
        auto it = std::find_if(hits.begin(), hits.end(), [&](const VectorCandidate& c) {
            return c.address == pos_va;
        });
        REQUIRE(it != hits.end());
        CHECK(it->format == VectorFormat::Double3);
        CHECK(it->delta_dist_d == doctest::Approx(5.0));

        CHECK(VectorDetector::nudge_d(*proc, pos_va, 0.0, 10.0, -0.5));
        auto cur = VectorDetector::read_vector_d(*proc, pos_va);
        REQUIRE(cur.has_value());
        CHECK(cur->y == doctest::Approx(-440.75));
        CHECK(cur->z == doctest::Approx(80.0));
    }

    SUBCASE("Chunk boundary straddling at 512 KB and batch coalescing") {
        // 600 KB memory ensures two 512 KB chunks; place a Vector3 straddling the exact 512 KB seam
        auto proc = std::make_shared<CountingFakeProcess>(600 * 1024);
        proc->attach(1);

        const size_t boundary_off = 512 * 1024 - 4; // starts at 512K - 4, ends at 512K + 8
        proc->put<Vector3>(boundary_off, Vector3{77.0f, 88.0f, 99.0f});

        // Also place 80 closely-spaced valid vectors to prove batch read coalescing
        for (size_t i = 0; i < 80; ++i) {
            proc->put<Vector3>(0x1000 + i * 32, Vector3{10.0f + i, 20.0f, 30.0f});
        }

        VectorDetector det;
        CHECK(det.take_snapshot(*proc) >= 81);

        proc->put<Vector3>(boundary_off, Vector3{80.0f, 92.0f, 99.0f}); // moved distance = 5.0 across boundary!
        proc->read_calls = 0;
        auto hits = det.detect_motion(*proc, 1.0f, 50.0f);
        CHECK(proc->read_calls <= 5); // Coalesced instead of >= 81 individual syscalls!

        auto it = std::find_if(hits.begin(), hits.end(), [&](const VectorCandidate& c) {
            return c.address == FakeProcess::kBase + boundary_off;
        });
        REQUIRE(it != hits.end());
        CHECK(it->delta_dist_d == doctest::Approx(5.0));
    }

    SUBCASE("Iterative filter_stationary and filter_moved narrowing") {
        auto proc = std::make_shared<CountingFakeProcess>(64 * 1024);
        proc->attach(1);

        const size_t player_off = 0x1000;
        const size_t npc_off    = 0x2000;
        proc->put<Vector3>(player_off, Vector3{10.0f, 20.0f, 30.0f});
        proc->put<Vector3>(npc_off,    Vector3{50.0f, 60.0f, 70.0f});

        VectorDetector det;
        det.take_snapshot(*proc);

        // Player stands still, NPC patrols continuously -> filter_stationary removes NPC!
        proc->put<Vector3>(npc_off, Vector3{55.0f, 60.0f, 70.0f});
        det.filter_stationary(*proc, 0.05);

        // Player now moves -> filter_moved isolates player coordinates and proves NPC was eliminated!
        proc->put<Vector3>(player_off, Vector3{15.0f, 20.0f, 30.0f});
        proc->put<Vector3>(npc_off,    Vector3{60.0f, 60.0f, 70.0f});
        auto moved = det.filter_moved(*proc, 1.0, 50.0);
        REQUIRE_FALSE(moved.empty());
        const bool has_player = std::any_of(moved.begin(), moved.end(), [&](const VectorCandidate& c) {
            return c.address == FakeProcess::kBase + player_off;
        });
        const bool has_npc = std::any_of(moved.begin(), moved.end(), [&](const VectorCandidate& c) {
            return c.address == FakeProcess::kBase + npc_off;
        });
        CHECK(has_player);
        CHECK_FALSE(has_npc);
    }
}

TEST_CASE("SignatureGenerator: Pattern Generation with Wildcards") {
    auto proc = std::make_shared<FakeProcess>(64 * 1024);
    proc->attach(1);

    // Mock function code:
    // push rbp                  (55)
    // mov rbp, rsp              (48 89 E5)
    // call rel32                (E8 12 34 56 78 -> wildcards: E8 ?? ?? ?? ??)
    // mov eax, [rbp - 4]        (8B 45 FC)
    // ret                       (C3)
    std::vector<uint8_t> code = {
        0x55,
        0x48, 0x89, 0xE5,
        0xE8, 0x12, 0x34, 0x56, 0x78,
        0x8B, 0x45, 0xFC,
        0xC3
    };

    uintptr_t func_offset = 0x1000;
    for (size_t i = 0; i < code.size(); ++i) {
        proc->put<uint8_t>(func_offset + i, code[i]);
    }

    // Put duplicate prologues elsewhere in the module so 55 48 89 E5 is not unique by itself
    uintptr_t other_func = 0x2000;
    std::vector<uint8_t> prologue = {0x55, 0x48, 0x89, 0xE5};
    for (size_t i = 0; i < prologue.size(); ++i) {
        proc->put<uint8_t>(other_func + i, prologue[i]);
    }

    // Add module encompassing this region
    proc->add_module("game.exe", 0, 64 * 1024);

    uintptr_t addr = FakeProcess::kBase + func_offset;
    auto sig = SignatureGenerator::generate(*proc, addr, 32);

    REQUIRE(sig.has_value());
    CHECK(sig->length >= 9);
    CHECK(sig->is_unique);
    // The pattern must contain wildcards '?' for the call rel32 displacement
    CHECK(sig->wildcard_count >= 4);
    CHECK(sig->pattern.find("?") != std::string::npos);
    CHECK(sig->pattern.find("55") != std::string::npos);
}
