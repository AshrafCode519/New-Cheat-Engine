#include <doctest/doctest.h>
#include "../engine/include/scanner/simd_scanner.hpp"
#include "../engine/include/scanner/memory_scanner.hpp"
#include "../engine/include/utils/hex_utils.hpp"
#include "test_helpers.hpp"
#include <vector>
#include <cstdint>
#include <cstring>

using namespace nce::scanner;
using namespace nce::utils;

TEST_CASE("SIMD: CPU Feature Detection") {
    // Should return without crashing or throwing
    bool has_avx2 = simd::cpu_supports_avx2();
    MESSAGE("CPU AVX2 Support: ", has_avx2 ? "Yes" : "No");
    // Most modern x86_64 CPUs have AVX2
    CHECK((has_avx2 == true || has_avx2 == false));
}

TEST_CASE("SIMD: AVX2 Exact Value Integer & Float Scans") {
    if (!simd::cpu_supports_avx2()) {
        MESSAGE("Skipping AVX2 test on non-AVX2 CPU");
        return;
    }

    // Prepare a 4 KB buffer filled with background data (0xAA)
    std::vector<uint8_t> buffer(4096, 0xAA);
    uintptr_t base = 0x10000;

    SUBCASE("int32_t exact value scan") {
        int32_t target = 133742;
        // Place targets at offset 0, 32, 128, 4000 (tail)
        std::vector<size_t> target_offsets = {0, 32, 128, 512, 4000};
        for (size_t off : target_offsets) {
            std::memcpy(buffer.data() + off, &target, sizeof(target));
        }

        ScanResults out(DataType::Int32, sizeof(int32_t));
        bool ok = simd::scan_chunk_exact_i32_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, target, 4, out
        );

        CHECK(ok);
        CHECK(out.count() == target_offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + target_offsets[i]);
        }
    }

    SUBCASE("float exact value scan with epsilon") {
        float target = 3.14159f;
        std::vector<size_t> target_offsets = {4, 64, 256, 3900};
        for (size_t off : target_offsets) {
            std::memcpy(buffer.data() + off, &target, sizeof(target));
        }

        ScanResults out(DataType::Float, sizeof(float));
        bool ok = simd::scan_chunk_exact_float_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, target, 4, out
        );

        CHECK(ok);
        CHECK(out.count() == target_offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + target_offsets[i]);
        }
    }

    SUBCASE("int64_t exact value scan") {
        int64_t target = 0x0123456789ABCDEFull;
        std::vector<size_t> target_offsets = {0, 64, 512, 2048, 4080};
        for (size_t off : target_offsets) {
            std::memcpy(buffer.data() + off, &target, sizeof(target));
        }

        ScanResults out(DataType::Int64, sizeof(int64_t));
        bool ok = simd::scan_chunk_exact_i64_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, target, 8, out
        );

        CHECK(ok);
        CHECK(out.count() == target_offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + target_offsets[i]);
        }
    }

    SUBCASE("double exact value scan") {
        double target = 2.718281828459;
        std::vector<size_t> target_offsets = {8, 128, 1024, 4000};
        for (size_t off : target_offsets) {
            std::memcpy(buffer.data() + off, &target, sizeof(target));
        }

        ScanResults out(DataType::Double, sizeof(double));
        bool ok = simd::scan_chunk_exact_double_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, target, 8, out
        );

        CHECK(ok);
        CHECK(out.count() == target_offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + target_offsets[i]);
        }
    }

    SUBCASE("int16_t exact value scan") {
        int16_t target = 12345;
        std::vector<size_t> target_offsets = {0, 2, 34, 128, 4090};
        for (size_t off : target_offsets) {
            std::memcpy(buffer.data() + off, &target, sizeof(target));
        }

        ScanResults out(DataType::Int16, sizeof(int16_t));
        bool ok = simd::scan_chunk_exact_i16_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, target, 2, out
        );

        CHECK(ok);
        CHECK(out.count() == target_offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + target_offsets[i]);
        }
    }
}

TEST_CASE("SIMD: AVX2 AOB Pattern Matching") {
    if (!simd::cpu_supports_avx2()) return;

    std::vector<uint8_t> buffer(8192, 0xCC);
    uintptr_t base = 0x20000;

    // Pattern: 48 8B 05 ? ? ? ? 48 85 C0
    auto opt_pattern = parse_aob_pattern("48 8B 05 ? ? ? ? 48 85 C0");
    REQUIRE(opt_pattern.has_value());
    const auto& pattern = *opt_pattern;

    std::vector<uint8_t> match_bytes = {0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48, 0x85, 0xC0};
    std::vector<size_t> offsets = {0, 17, 100, 256, 1024, 7501};

    for (size_t off : offsets) {
        std::memcpy(buffer.data() + off, match_bytes.data(), match_bytes.size());
    }

    SUBCASE("AOB scan with alignment = 1") {
        ScanResults out;
        bool ok = simd::scan_chunk_aob_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, pattern, 1, out
        );

        CHECK(ok);
        CHECK(out.count() == offsets.size());
        for (size_t i = 0; i < out.count(); ++i) {
            CHECK(out.address(i) == base + offsets[i]);
        }
    }

    SUBCASE("AOB scan with alignment = 4") {
        // Only offsets that are multiples of 4 should match: 0, 100, 256, 1024 (17 and 7501 are not)
        ScanResults out;
        bool ok = simd::scan_chunk_aob_avx2(
            buffer.data(), buffer.size(), buffer.size(), base, pattern, 4, out
        );

        CHECK(ok);
        CHECK(out.count() == 4);
        CHECK(out.address(0) == base + 0);
        CHECK(out.address(1) == base + 100);
        CHECK(out.address(2) == base + 256);
        CHECK(out.address(3) == base + 1024);
    }
}

TEST_CASE("SIMD & Work-Stealing: End-to-End MemoryScanner Integration") {
    // Create a 4 MB fake memory process (4 chunks of 1 MB each)
    auto proc = std::make_shared<nce::test::FakeProcess>(4 * 1024 * 1024);
    proc->attach(1);

    int32_t val = 999999;
    proc->put<int32_t>(100, val);                     // chunk 0
    proc->put<int32_t>(1024 * 1024 + 52, val);         // chunk 1
    proc->put<int32_t>(2 * 1024 * 1024 + 200, val);     // chunk 2
    proc->put<int32_t>(3 * 1024 * 1024 + 4000, val);    // chunk 3

    MemoryScanner scanner(proc);
    scanner.set_thread_count(4);

    ScanValue target_val;
    target_val.type = DataType::Int32;
    target_val.value = val;

    ScanResults res = scanner.first_scan(
        DataType::Int32, ScanCondition::ExactValue,
        target_val, {}, 4
    );

    uintptr_t base = nce::test::FakeProcess::kBase;
    CHECK(res.count() == 4);
    CHECK(res.address(0) == base + 100);
    CHECK(res.address(1) == base + 1024 * 1024 + 52);
    CHECK(res.address(2) == base + 2 * 1024 * 1024 + 200);
    CHECK(res.address(3) == base + 3 * 1024 * 1024 + 4000);
}
