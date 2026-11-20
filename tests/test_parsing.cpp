#include <doctest/doctest.h>
#include "utils/hex_utils.hpp"

using namespace nce;
using scanner::DataType;

TEST_CASE("parse_data_type accepts known type names only") {
    CHECK(utils::parse_data_type("i32") == DataType::Int32);
    CHECK(utils::parse_data_type("int") == DataType::Int32);
    CHECK(utils::parse_data_type("u32") == DataType::UInt32);
    CHECK(utils::parse_data_type("u64") == DataType::UInt64);
    CHECK(utils::parse_data_type("f32") == DataType::Float);
    CHECK(utils::parse_data_type("double") == DataType::Double);
    CHECK(utils::parse_data_type("aob") == DataType::AOB);
    CHECK(utils::parse_data_type("str") == DataType::String);
    CHECK(utils::parse_data_type("wstr") == DataType::String16);

    // Used to fall back to Int32 silently
    CHECK_FALSE(utils::parse_data_type("text").has_value());
    CHECK_FALSE(utils::parse_data_type("I32").has_value());
    CHECK_FALSE(utils::parse_data_type("").has_value());
}

TEST_CASE("format_data_type is the inverse of parse_data_type") {
    for (auto type : {DataType::Int8, DataType::Int16, DataType::Int32, DataType::Int64,
                      DataType::UInt8, DataType::UInt16, DataType::UInt32, DataType::UInt64,
                      DataType::Float, DataType::Double, DataType::String, DataType::String16, DataType::AOB}) {
        CHECK(utils::parse_data_type(utils::format_data_type(type)) == type);
    }
}

TEST_CASE("float_match_range follows the decimals the user typed") {
    using scanner::FloatMatchMode;

    auto rounded = utils::float_match_range("25.5", FloatMatchMode::Rounded);
    REQUIRE(rounded.has_value());
    CHECK(rounded->first == doctest::Approx(25.45));
    CHECK(rounded->second == doctest::Approx(25.55));
    CHECK(rounded->second < 25.55); // open upper edge

    auto whole = utils::float_match_range("250", FloatMatchMode::Rounded);
    REQUIRE(whole.has_value());
    CHECK(whole->first == doctest::Approx(249.5));
    CHECK(whole->second == doctest::Approx(250.5));

    auto truncated = utils::float_match_range("25.5", FloatMatchMode::Truncated);
    REQUIRE(truncated.has_value());
    CHECK(truncated->first == 25.5);
    CHECK(truncated->second == doctest::Approx(25.6));
    CHECK(truncated->second < 25.6);

    // Truncation goes toward zero: -25.57 truncates to -25.5
    auto negative = utils::float_match_range("-25.5", FloatMatchMode::Truncated);
    REQUIRE(negative.has_value());
    CHECK(negative->first == doctest::Approx(-25.6));
    CHECK(negative->first > -25.6);
    CHECK(negative->second == -25.5);

    CHECK_FALSE(utils::float_match_range("25.5", FloatMatchMode::Exact).has_value());
    CHECK_FALSE(utils::float_match_range("1e3", FloatMatchMode::Rounded).has_value());
    CHECK_FALSE(utils::float_match_range("abc", FloatMatchMode::Rounded).has_value());
}

TEST_CASE("parse_scan_value stores the variant alternative that matches the type") {
    auto f = utils::parse_scan_value(DataType::Float, "25.5");
    REQUIRE(f.has_value());
    CHECK(f->type == DataType::Float);
    CHECK(std::get<float>(f->value) == doctest::Approx(25.5f));

    auto i8 = utils::parse_scan_value(DataType::Int8, "-128");
    REQUIRE(i8.has_value());
    CHECK(std::get<int8_t>(i8->value) == -128);

    auto u32 = utils::parse_scan_value(DataType::UInt32, "3000000000");
    REQUIRE(u32.has_value());
    CHECK(std::get<uint32_t>(u32->value) == 3000000000u);

    auto i64 = utils::parse_scan_value(DataType::Int64, "5000000000");
    REQUIRE(i64.has_value());
    CHECK(std::get<int64_t>(i64->value) == 5000000000LL);
}

TEST_CASE("parse_scan_value rejects bad input instead of turning it into 0") {
    CHECK_FALSE(utils::parse_scan_value(DataType::Float, "abc").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::Int32, "3000000000").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::Int8, "300").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::UInt32, "-1").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::Int32, "12abc").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::Int32, "").has_value());
    CHECK_FALSE(utils::parse_scan_value(DataType::AOB, "90").has_value());
}

TEST_CASE("parse_address takes hex with or without 0x, and nothing else") {
    CHECK(utils::parse_address("0x7FF63E80A078") == 0x7FF63E80A078);
    CHECK(utils::parse_address("7ff63e80a078") == 0x7FF63E80A078);
    CHECK(utils::parse_address("0X1A") == 0x1A);
    CHECK(utils::parse_address("12zz") == 0); // used to read as 0x12
    CHECK(utils::parse_address("0x") == 0);
    CHECK(utils::parse_address("") == 0);
    CHECK(utils::parse_address("-1") == 0);
}

TEST_CASE("parse_aob_pattern marks wildcards as don't-care") {
    auto pattern = utils::parse_aob_pattern("48 8B ? ?? 89");
    REQUIRE(pattern.has_value());
    REQUIRE(pattern->bytes.size() == 5);
    CHECK(pattern->bytes[0] == 0x48);
    CHECK(pattern->bytes[4] == 0x89);
    CHECK(pattern->mask == std::vector<bool>{true, true, false, false, true});

    CHECK_FALSE(utils::parse_aob_pattern("").has_value());
    CHECK_FALSE(utils::parse_aob_pattern("zz").has_value());
}
