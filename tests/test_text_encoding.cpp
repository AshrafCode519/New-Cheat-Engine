#include <doctest/doctest.h>
#include "utils/text_encoding.hpp"

using namespace nce;

TEST_CASE("utf8_to_utf16le encodes ASCII, BMP and astral characters") {
    auto ascii = utils::utf8_to_utf16le("Hi");
    REQUIRE(ascii.has_value());
    CHECK(*ascii == std::vector<uint8_t>{'H', 0, 'i', 0});

    // U+0645 ARABIC LETTER MEEM
    auto arabic = utils::utf8_to_utf16le("\xD9\x85");
    REQUIRE(arabic.has_value());
    CHECK(*arabic == std::vector<uint8_t>{0x45, 0x06});

    // U+1F600 needs a surrogate pair: D83D DE00
    auto emoji = utils::utf8_to_utf16le("\xF0\x9F\x98\x80");
    REQUIRE(emoji.has_value());
    CHECK(*emoji == std::vector<uint8_t>{0x3D, 0xD8, 0x00, 0xDE});
}

TEST_CASE("utf8_to_utf16le rejects invalid UTF-8") {
    CHECK_FALSE(utils::utf8_to_utf16le("\xFF").has_value());          // invalid lead byte
    CHECK_FALSE(utils::utf8_to_utf16le("\xD9").has_value());          // truncated sequence
    CHECK_FALSE(utils::utf8_to_utf16le("\xC0\xAF").has_value());      // overlong '/'
    CHECK_FALSE(utils::utf8_to_utf16le("\xED\xA0\x80").has_value());  // encoded surrogate
}

TEST_CASE("utf16le_to_utf8 round-trips and replaces broken surrogates") {
    const std::string text = "Player \xD9\x85 \xF0\x9F\x98\x80";
    auto encoded = utils::utf8_to_utf16le(text);
    REQUIRE(encoded.has_value());
    CHECK(utils::utf16le_to_utf8(encoded->data(), encoded->size()) == text);

    const std::vector<uint8_t> lone_high{0x3D, 0xD8, 'A', 0};
    CHECK(utils::utf16le_to_utf8(lone_high.data(), lone_high.size()) == "\xEF\xBF\xBD" "A");
}
