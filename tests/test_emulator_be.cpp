#include "doctest/doctest.h"
#include "scanner/memory_scanner.hpp"
#include "scanner/scan_results.hpp"
#include "scanner/scan_types.hpp"
#include "utils/hex_utils.hpp"
#include "table/ce_table_format.hpp"
#include "test_helpers.hpp"

using namespace nce;
using namespace nce::scanner;

TEST_CASE("Emulator BE: byte swapping routines") {
    // 16-bit
    CHECK(swap_bytes(static_cast<uint16_t>(0x1234)) == 0x3412);
    CHECK(swap_bytes(static_cast<int16_t>(0x1234)) == static_cast<int16_t>(0x3412));

    // 32-bit
    CHECK(swap_bytes(static_cast<uint32_t>(0x12345678)) == 0x78563412);
    CHECK(swap_bytes(static_cast<int32_t>(1000)) == static_cast<int32_t>(0xE8030000)); // 1000 = 0x000003E8 -> swapped = 0xE8030000

    // 64-bit
    CHECK(swap_bytes(static_cast<uint64_t>(0x0102030405060708ULL)) == 0x0807060504030201ULL);

    // Float: 100.0f = 0x42C80000 -> swapped = 0x0000C842
    float f = 100.0f;
    float f_swapped = swap_bytes(f);
    uint32_t f_raw = 0;
    std::memcpy(&f_raw, &f_swapped, sizeof(float));
    CHECK(f_raw == 0x0000C842);
    CHECK(swap_bytes(f_swapped) == f);
}

TEST_CASE("Emulator BE: value_to_bytes and value_from_bytes") {
    // Int32BE
    ScanValue sv = ScanValue::of(DataType::Int32BE, static_cast<int32_t>(1000)); // 0x000003E8
    auto bytes = value_to_bytes(sv);
    REQUIRE(bytes.size() == 4);
    CHECK(bytes[0] == 0x00);
    CHECK(bytes[1] == 0x00);
    CHECK(bytes[2] == 0x03);
    CHECK(bytes[3] == 0xE8);

    auto decoded = value_from_bytes(DataType::Int32BE, bytes.data(), bytes.size());
    REQUIRE(decoded.has_value());
    CHECK(decoded->type == DataType::Int32BE);
    CHECK(std::get<int32_t>(decoded->value) == 1000);
    CHECK(decoded->to_string() == "1000");

    // FloatBE
    ScanValue sv_f = ScanValue::of(DataType::FloatBE, 100.0f); // 0x42C80000
    auto bytes_f = value_to_bytes(sv_f);
    REQUIRE(bytes_f.size() == 4);
    CHECK(bytes_f[0] == 0x42);
    CHECK(bytes_f[1] == 0xC8);
    CHECK(bytes_f[2] == 0x00);
    CHECK(bytes_f[3] == 0x00);

    auto decoded_f = value_from_bytes(DataType::FloatBE, bytes_f.data(), bytes_f.size());
    REQUIRE(decoded_f.has_value());
    CHECK(std::get<float>(decoded_f->value) == doctest::Approx(100.0f));
}

TEST_CASE("Emulator BE: MemoryScanner scans Big-Endian values with SIMD acceleration") {
    auto proc = std::make_shared<test::FakeProcess>(8192);
    proc->attach(1);

    // Write Big-Endian 1000 (0x00 00 03 E8) at offset 0x100
    uint8_t be_1000[] = {0x00, 0x00, 0x03, 0xE8};
    proc->write_raw(test::FakeProcess::kBase + 0x100, be_1000, 4);

    // Write Big-Endian 1000 at offset 0x200
    proc->write_raw(test::FakeProcess::kBase + 0x200, be_1000, 4);

    // Write Big-Endian 2500 (0x00 00 09 C4) at offset 0x300
    uint8_t be_2500[] = {0x00, 0x00, 0x09, 0xC4};
    proc->write_raw(test::FakeProcess::kBase + 0x300, be_2500, 4);

    MemoryScanner scanner(proc);

    // 1. First scan exact value 1000 as Int32BE
    ScanValue target = ScanValue::of(DataType::Int32BE, static_cast<int32_t>(1000));
    auto res = scanner.first_scan(DataType::Int32BE, ScanCondition::ExactValue, target);
    CHECK(res.count() == 2);
    CHECK(res.address(0) == test::FakeProcess::kBase + 0x100);
    CHECK(res.address(1) == test::FakeProcess::kBase + 0x200);

    // 2. Next scan: increase value at 0x100 to 1500 (0x00 00 05 DC)
    uint8_t be_1500[] = {0x00, 0x00, 0x05, 0xDC};
    proc->write_raw(test::FakeProcess::kBase + 0x100, be_1500, 4);

    auto next_res = scanner.next_scan(res, ScanCondition::Increased);
    CHECK(next_res.count() == 1);
    CHECK(next_res.address(0) == test::FakeProcess::kBase + 0x100);

    // 3. Scan GreaterThan on Int32BE
    ScanValue gt_target = ScanValue::of(DataType::Int32BE, static_cast<int32_t>(2000));
    auto gt_res = scanner.first_scan(DataType::Int32BE, ScanCondition::GreaterThan, gt_target);
    CHECK(gt_res.count() == 1);
    CHECK(gt_res.address(0) == test::FakeProcess::kBase + 0x300); // 2500 > 2000
}

TEST_CASE("Emulator BE: Cheat Table XML (.CT) VariableType roundtrip") {
    CHECK(table::ce_variable_type_str(DataType::Int16BE) == std::string("2 Bytes (Big Endian)"));
    CHECK(table::ce_variable_type_str(DataType::Int32BE) == std::string("4 Bytes (Big Endian)"));
    CHECK(table::ce_variable_type_str(DataType::Int64BE) == std::string("8 Bytes (Big Endian)"));
    CHECK(table::ce_variable_type_str(DataType::FloatBE) == std::string("Float (Big Endian)"));
    CHECK(table::ce_variable_type_str(DataType::DoubleBE) == std::string("Double (Big Endian)"));

    CHECK(table::parse_ce_variable_type("2 Bytes (Big Endian)") == DataType::Int16BE);
    CHECK(table::parse_ce_variable_type("4 Bytes (Big Endian)") == DataType::Int32BE);
    CHECK(table::parse_ce_variable_type("8 Bytes (Big Endian)") == DataType::Int64BE);
    CHECK(table::parse_ce_variable_type("Float (Big Endian)") == DataType::FloatBE);
    CHECK(table::parse_ce_variable_type("Double (Big Endian)") == DataType::DoubleBE);
}
