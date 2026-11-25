#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "script/lua_engine.hpp"
#include "session/session.hpp"

using namespace nce;
using test::FakeProcess;

TEST_CASE("LuaEngine: basic math and print redirection") {
    script::LuaEngine lua;

    auto res = lua.execute_string("print('Answer:', 10 + 32)");
    CHECK(res.success);
    CHECK(res.error.empty());
    CHECK(res.output.find("Answer:\t42\n") != std::string::npos);
}

TEST_CASE("LuaEngine: syntax and runtime error reporting") {
    script::LuaEngine lua;

    auto syntax_err = lua.execute_string("this is totally invalid lua code !!!");
    CHECK_FALSE(syntax_err.success);
    CHECK_FALSE(syntax_err.error.empty());

    auto runtime_err = lua.execute_string("error('custom explosion')");
    CHECK_FALSE(runtime_err.success);
    CHECK(runtime_err.error.find("custom explosion") != std::string::npos);
}

TEST_CASE("LuaEngine: hexadecimal utility functions") {
    script::LuaEngine lua;

    auto res1 = lua.execute_string("print(toHex(255))");
    CHECK(res1.success);
    CHECK(res1.output.find("0xFF") != std::string::npos);

    auto res2 = lua.execute_string("local val = fromHex('0x100'); print(val)");
    CHECK(res2.success);
    CHECK(res2.output.find("256") != std::string::npos);
}

TEST_CASE("LuaEngine: memory read and write integration with Process") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    session::Session session(process);

    uintptr_t addr_hp = FakeProcess::kBase + 0x200;
    uintptr_t addr_float = FakeProcess::kBase + 0x300;
    uintptr_t addr_str = FakeProcess::kBase + 0x400;
    uintptr_t addr_bytes = FakeProcess::kBase + 0x500;

    // Initial values
    process->put<int32_t>(0x200, 100);
    process->put<float>(0x300, 123.5f);
    process->write_raw(addr_str, "Initial", 8);

    auto* lua = session.lua_engine();
    REQUIRE(lua != nullptr);

    SUBCASE("readInteger and writeInteger") {
        std::string script = "local hp = readInteger(" + std::to_string(addr_hp) + "); "
                             "print('Read HP:', hp); "
                             "writeInteger(" + std::to_string(addr_hp) + ", hp + 900);";
        auto res = lua->execute_string(script);
        CHECK(res.success);
        CHECK(res.output.find("Read HP:\t100") != std::string::npos);

        int32_t new_hp = 0;
        process->read(addr_hp, new_hp);
        CHECK(new_hp == 1000);
    }

    SUBCASE("readFloat and writeFloat") {
        std::string script = "local f = readFloat(" + std::to_string(addr_float) + "); "
                             "writeFloat(" + std::to_string(addr_float) + ", f * 2);";
        auto res = lua->execute_string(script);
        CHECK(res.success);

        float new_f = 0.0f;
        process->read(addr_float, new_f);
        CHECK(new_f == doctest::Approx(247.0f));
    }

    SUBCASE("readString and writeString") {
        std::string script = "local s = readString(" + std::to_string(addr_str) + ", 20); "
                             "print('Read String:', s); "
                             "writeString(" + std::to_string(addr_str) + ", 'CheatEngine');";
        auto res = lua->execute_string(script);
        CHECK(res.success);
        CHECK(res.output.find("Read String:\tInitial") != std::string::npos);

        char buf[16]{};
        process->read_raw(addr_str, buf, 12);
        CHECK(std::string(buf) == "CheatEngine");
    }

    SUBCASE("writeBytes with hex string and readBytes") {
        std::string script = "writeBytes(" + std::to_string(addr_bytes) + ", '90 90 90 CC'); "
                             "local b = readBytes(" + std::to_string(addr_bytes) + ", 4); "
                             "print('Byte 4:', toHex(b[4]));";
        auto res = lua->execute_string(script);
        CHECK(res.success);
        CHECK(res.output.find("0xCC") != std::string::npos);

        uint8_t raw[4]{};
        process->read_raw(addr_bytes, raw, 4);
        CHECK(raw[0] == 0x90);
        CHECK(raw[1] == 0x90);
        CHECK(raw[2] == 0x90);
        CHECK(raw[3] == 0xCC);
    }
}

TEST_CASE("LuaEngine: Module address and symbol resolution") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x1000, 0x5000);
    session::Session session(process);

    auto* lua = session.lua_engine();
    REQUIRE(lua != nullptr);

    std::string script = "local base = getAddress('game.exe+0x200'); "
                         "print('Resolved:', toHex(base));";
    auto res = lua->execute_string(script);
    CHECK(res.success);

    uintptr_t expected = FakeProcess::kBase + 0x1000 + 0x200;
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << expected;
    CHECK(res.output.find(ss.str()) != std::string::npos);
}

TEST_CASE("LuaEngine: Reset state clears variables") {
    script::LuaEngine lua;
    lua.execute_string("global_var = 12345");

    auto res1 = lua.execute_string("print(global_var)");
    CHECK(res1.output.find("12345") != std::string::npos);

    lua.reset();
    auto res2 = lua.execute_string("print(global_var)");
    CHECK(res2.output.find("nil") != std::string::npos);
}
