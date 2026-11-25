#include "script/lua_engine.hpp"
#include "session/session.hpp"
#include "hal/process.hpp"
#include "hal/hotkeys.hpp"
#include "debugger/debug_coordinator.hpp"
#include "debugger/hook_engine.hpp"
#include "debugger/pe_analyzer.hpp"
#include "debugger/elf_analyzer.hpp"
#include "debugger/disassembler.hpp"
#include "view/engine_inspector.hpp"
#include "assembler/auto_assembler.hpp"
#include "utils/hex_utils.hpp"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <iostream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <vector>

namespace nce::script {

namespace {

LuaEngine* get_engine(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "NCE_LUA_ENGINE");
    auto* eng = static_cast<LuaEngine*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return eng;
}

session::Session* get_session_from_lua(lua_State* L) {
    auto* eng = get_engine(L);
    return eng ? eng->get_session() : nullptr;
}

hal::IProcess* get_process_from_lua(lua_State* L) {
    auto* s = get_session_from_lua(L);
    return s ? &s->process() : nullptr;
}

bool iequals(const std::string& a, const std::string& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](unsigned char ca, unsigned char cb) {
        return std::tolower(ca) == std::tolower(cb);
    });
}

uintptr_t parse_address(lua_State* L, int idx, hal::IProcess* proc) {
    if (lua_isinteger(L, idx)) {
        return static_cast<uintptr_t>(lua_tointeger(L, idx));
    }
    if (lua_isnumber(L, idx)) {
        return static_cast<uintptr_t>(lua_tonumber(L, idx));
    }
    if (lua_isstring(L, idx)) {
        std::string s = lua_tostring(L, idx);
        auto plus_pos = s.find('+');
        if (plus_pos != std::string::npos && proc) {
            std::string mod_name = s.substr(0, plus_pos);
            std::string off_str = s.substr(plus_pos + 1);
            uintptr_t base = 0;
            for (const auto& mod : proc->get_modules()) {
                if (iequals(mod.name, mod_name)) {
                    base = mod.base_address;
                    break;
                }
            }
            uintptr_t offset = 0;
            try {
                offset = std::stoull(off_str, nullptr, 0);
            } catch (...) {}
            return base + offset;
        }
        try {
            return std::stoull(s, nullptr, 0);
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

// print(...)
int l_print(lua_State* L) {
    auto* eng = get_engine(L);
    int n = lua_gettop(L);
    std::ostringstream ss;
    for (int i = 1; i <= n; ++i) {
        if (i > 1) ss << "\t";
        if (lua_isstring(L, i)) {
            ss << lua_tostring(L, i);
        } else if (lua_isnil(L, i)) {
            ss << "nil";
        } else if (lua_isboolean(L, i)) {
            ss << (lua_toboolean(L, i) ? "true" : "false");
        } else {
            const char* s = luaL_tolstring(L, i, nullptr);
            ss << (s ? s : "");
            lua_pop(L, 1);
        }
    }
    ss << "\n";
    std::string line = ss.str();
    if (eng) {
        eng->append_output(line);
    }
    return 0;
}

// readInteger(address)
int l_readInteger(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    int32_t val = 0;
    if (proc->read(addr, val)) {
        lua_pushinteger(L, val);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readQword(address) or readPointer(address)
int l_readQword(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    uint64_t val = 0;
    if (proc->read(addr, val)) {
        lua_pushinteger(L, static_cast<lua_Integer>(val));
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readSmallInteger(address)
int l_readSmallInteger(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    int16_t val = 0;
    if (proc->read(addr, val)) {
        lua_pushinteger(L, val);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readByte(address)
int l_readByte(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    uint8_t val = 0;
    if (proc->read(addr, val)) {
        lua_pushinteger(L, val);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readFloat(address)
int l_readFloat(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    float val = 0.0f;
    if (proc->read(addr, val)) {
        lua_pushnumber(L, val);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readDouble(address)
int l_readDouble(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    double val = 0.0;
    if (proc->read(addr, val)) {
        lua_pushnumber(L, val);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// readString(address, [max_length=50])
int l_readString(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    size_t max_len = lua_isinteger(L, 2) ? static_cast<size_t>(lua_tointeger(L, 2)) : 50;

    std::string result;
    result.reserve(max_len);
    for (size_t i = 0; i < max_len; ++i) {
        char c = 0;
        if (!proc->read(addr + i, c) || c == '\0') break;
        result.push_back(c);
    }
    lua_pushlstring(L, result.data(), result.size());
    return 1;
}

// readBytes(address, count) -> { [1]=b0, [2]=b1, ... }
int l_readBytes(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    size_t count = lua_isinteger(L, 2) ? static_cast<size_t>(lua_tointeger(L, 2)) : 0;
    if (count == 0) {
        lua_newtable(L);
        return 1;
    }

    std::vector<uint8_t> buf(count);
    if (!proc->read_raw(addr, buf.data(), count)) {
        lua_pushnil(L);
        return 1;
    }

    lua_createtable(L, static_cast<int>(count), 0);
    for (size_t i = 0; i < count; ++i) {
        lua_pushinteger(L, buf[i]);
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

// writeInteger(address, value)
int l_writeInteger(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    int32_t val = static_cast<int32_t>(lua_tointeger(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeQword(address, value)
int l_writeQword(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    uint64_t val = static_cast<uint64_t>(lua_tointeger(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeSmallInteger(address, value)
int l_writeSmallInteger(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    int16_t val = static_cast<int16_t>(lua_tointeger(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeByte(address, value)
int l_writeByte(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    uint8_t val = static_cast<uint8_t>(lua_tointeger(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeFloat(address, value)
int l_writeFloat(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    float val = static_cast<float>(lua_tonumber(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeDouble(address, value)
int l_writeDouble(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    double val = static_cast<double>(lua_tonumber(L, 2));
    bool ok = proc->write(addr, val);
    lua_pushboolean(L, ok);
    return 1;
}

// writeString(address, text)
int l_writeString(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    size_t len = 0;
    const char* str = lua_tolstring(L, 2, &len);
    if (!str) { lua_pushboolean(L, false); return 1; }
    bool ok = proc->write_raw(addr, str, len + 1);
    lua_pushboolean(L, ok);
    return 1;
}

// writeBytes(address, table_or_hex_string)
int l_writeBytes(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);

    std::vector<uint8_t> bytes;
    if (lua_istable(L, 2)) {
        size_t len = lua_rawlen(L, 2);
        bytes.reserve(len);
        for (size_t i = 1; i <= len; ++i) {
            lua_rawgeti(L, 2, static_cast<lua_Integer>(i));
            bytes.push_back(static_cast<uint8_t>(lua_tointeger(L, -1)));
            lua_pop(L, 1);
        }
    } else if (lua_isstring(L, 2)) {
        std::string hex_str = lua_tostring(L, 2);
        std::string clean;
        for (char c : hex_str) {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') clean += c;
        }
        for (size_t i = 0; i + 1 < clean.size(); i += 2) {
            try {
                auto b = static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16));
                bytes.push_back(b);
            } catch (...) {}
        }
    } else {
        lua_pushboolean(L, false);
        return 1;
    }

    if (bytes.empty()) {
        lua_pushboolean(L, true);
        return 1;
    }

    bool ok = proc->write_raw(addr, bytes.data(), bytes.size());
    lua_pushboolean(L, ok);
    return 1;
}

// getAddress(expr_or_string)
int l_getAddress(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    uintptr_t addr = parse_address(L, 1, proc);
    lua_pushinteger(L, static_cast<lua_Integer>(addr));
    return 1;
}

// getModuleAddress(module_name)
int l_getModuleAddress(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc || !lua_isstring(L, 1)) { lua_pushnil(L); return 1; }
    std::string mod_name = lua_tostring(L, 1);
    for (const auto& mod : proc->get_modules()) {
        if (iequals(mod.name, mod_name)) {
            lua_pushinteger(L, static_cast<lua_Integer>(mod.base_address));
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

// allocateMemory(size)
int l_allocateMemory(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushinteger(L, 0); return 1; }
    size_t size = lua_isinteger(L, 1) ? static_cast<size_t>(lua_tointeger(L, 1)) : 4096;
    uintptr_t res = proc->allocate_memory(size);
    lua_pushinteger(L, static_cast<lua_Integer>(res));
    return 1;
}

// deallocateMemory(address)
int l_deallocateMemory(lua_State* L) {
    auto* proc = get_process_from_lua(L);
    if (!proc) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, proc);
    bool ok = proc->free_memory(addr);
    lua_pushboolean(L, ok);
    return 1;
}

// autoAssemble(script_text)
int l_autoAssemble(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    if (!lua_isstring(L, 1)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "Invalid script text argument");
        return 2;
    }
    std::string script_text = lua_tostring(L, 1);
    assembler::AutoAssembler aa(s->process_ptr());
    if (auto* eng = get_engine(L)) {
        aa.set_lua_runner([eng](const std::string& lua_code, std::string& out_msg) -> bool {
            auto r = eng->execute_string(lua_code);
            out_msg = r.success ? r.output : r.error;
            return r.success;
        });
    }
    auto res = aa.enable(script_text);
    if (!res.ok) {
        lua_pushboolean(L, false);
        lua_pushstring(L, res.message.c_str());
        return 2;
    }

    lua_pushboolean(L, true);
    return 1;
}

// toHex(number)
int l_toHex(lua_State* L) {
    uint64_t val = 0;
    if (lua_isinteger(L, 1)) {
        val = static_cast<uint64_t>(lua_tointeger(L, 1));
    } else if (lua_isnumber(L, 1)) {
        val = static_cast<uint64_t>(lua_tonumber(L, 1));
    }
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << val;
    lua_pushstring(L, ss.str().c_str());
    return 1;
}

// fromHex(string)
int l_fromHex(lua_State* L) {
    if (!lua_isstring(L, 1)) { lua_pushinteger(L, 0); return 1; }
    std::string s = lua_tostring(L, 1);
    uint64_t val = 0;
    try {
        val = std::stoull(s, nullptr, 16);
    } catch (...) {}
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

// sleep(ms)
int l_sleep(lua_State* L) {
    int ms = lua_isinteger(L, 1) ? static_cast<int>(lua_tointeger(L, 1)) : 100;
    if (ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
    return 0;
}

std::string to_lower_copy(std::string s) {
    for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return s;
}

uintptr_t resolve_lua_address(lua_State* L, int idx, session::Session* s) {
    if (lua_isinteger(L, idx)) return static_cast<uintptr_t>(lua_tointeger(L, idx));
    if (lua_isnumber(L, idx)) return static_cast<uintptr_t>(lua_tonumber(L, idx));
    if (!lua_isstring(L, idx)) return 0;

    std::string text = lua_tostring(L, idx);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    if (text.empty()) return 0;

    const size_t plus = text.find('+');
    if (plus != std::string::npos && s && s->attached()) {
        std::string mod_name = text.substr(0, plus);
        while (!mod_name.empty() && (mod_name.front() == '"' || std::isspace(static_cast<unsigned char>(mod_name.front())))) mod_name.erase(mod_name.begin());
        while (!mod_name.empty() && (mod_name.back() == '"' || std::isspace(static_cast<unsigned char>(mod_name.back())))) mod_name.pop_back();
        std::string off_str = text.substr(plus + 1);
        while (!off_str.empty() && std::isspace(static_cast<unsigned char>(off_str.front()))) off_str.erase(off_str.begin());
        if (!off_str.empty() && off_str.front() == '$') off_str.erase(off_str.begin());
        const uintptr_t off = utils::parse_address(off_str);
        const std::string want_low = to_lower_copy(mod_name);
        for (const auto& m : s->process().get_modules()) {
            if (to_lower_copy(m.name) == want_low) {
                return m.base_address + off;
            }
        }
    }

    if (!text.empty() && text.front() == '$') text.erase(text.begin());
    return utils::parse_address(text);
}

bool parse_lua_bytes_arg(lua_State* L, int idx, std::vector<uint8_t>& out_bytes, std::string& err_out) {
    out_bytes.clear();
    if (lua_istable(L, idx)) {
        const lua_Integer len = static_cast<lua_Integer>(lua_rawlen(L, idx));
        if (len <= 0) {
            err_out = "Byte table cannot be empty";
            return false;
        }
        out_bytes.reserve(static_cast<size_t>(len));
        for (lua_Integer i = 1; i <= len; ++i) {
            lua_rawgeti(L, idx, i);
            if (!lua_isinteger(L, -1) && !lua_isnumber(L, -1)) {
                lua_pop(L, 1);
                err_out = "Byte table must contain numbers";
                return false;
            }
            out_bytes.push_back(static_cast<uint8_t>(lua_tointeger(L, -1) & 0xFF));
            lua_pop(L, 1);
        }
        return true;
    }

    if (lua_isstring(L, idx)) {
        const char* s = lua_tostring(L, idx);
        std::string hex;
        for (const char* p = s; p && *p; ++p) {
            const unsigned char c = static_cast<unsigned char>(*p);
            if (std::isspace(c) || c == ',' || c == ';') continue;
            if ((c == '0' && (p[1] == 'x' || p[1] == 'X')) || (c == '\\' && (p[1] == 'x' || p[1] == 'X'))) {
                ++p;
                continue;
            }
            if (!std::isxdigit(c)) {
                err_out = std::string("Invalid hex character in byte string: '") + *p + "'";
                return false;
            }
            hex.push_back(static_cast<char>(c));
        }
        if (hex.empty() || (hex.size() % 2) != 0) {
            err_out = "Hex byte string must contain pairs of hex digits";
            return false;
        }
        for (size_t i = 0; i < hex.size(); i += 2) {
            const int v = std::stoi(hex.substr(i, 2), nullptr, 16);
            out_bytes.push_back(static_cast<uint8_t>(v));
        }
        return true;
    }

    err_out = "Expected destination address, hex byte string, or byte table";
    return false;
}

bool aob_scan_process(const hal::IProcess& proc,
                      const std::string& pattern_str,
                      const std::optional<std::string>& module_filter,
                      size_t max_results,
                      std::vector<uintptr_t>& out_addrs,
                      std::string& err_out) {
    out_addrs.clear();
    const auto pat_opt = utils::parse_aob_pattern(pattern_str);
    if (!pat_opt || pat_opt->bytes.empty()) {
        err_out = "Invalid AOB pattern";
        return false;
    }
    const auto& pat = *pat_opt;
    const size_t pat_len = pat.bytes.size();

    constexpr uint32_t kScanFlags =
        hal::FilterFlags::OnlyCommitted | hal::FilterFlags::ExcludeNoAccess | hal::FilterFlags::ExcludeGuardPages;
    const auto regions = proc.query_regions(kScanFlags);

    struct Interval { uintptr_t start; uintptr_t end; };
    std::vector<Interval> mod_ranges;
    std::string mod_low;
    if (module_filter && !module_filter->empty()) {
        mod_low = to_lower_copy(*module_filter);
        const auto mods = proc.get_modules();
        for (const auto& m : mods) {
            if (to_lower_copy(m.name) == mod_low) {
                mod_ranges.push_back({m.base_address, m.base_address + m.size});
            }
        }
        if (mod_ranges.empty()) {
            for (const auto& m : mods) {
                if (to_lower_copy(m.name).find(mod_low) != std::string::npos) {
                    mod_ranges.push_back({m.base_address, m.base_address + m.size});
                }
            }
        }
    }

    constexpr size_t kChunkSize = 4 * 1024 * 1024;
    std::vector<uint8_t> buf;

    auto scan_range = [&](uintptr_t range_start, uintptr_t range_end) -> bool {
        if (range_end <= range_start || range_end - range_start < pat_len) return false;
        uintptr_t cursor = range_start;
        while (cursor < range_end) {
            const size_t rem = static_cast<size_t>(range_end - cursor);
            if (rem < pat_len) break;
            const size_t to_read = std::min(kChunkSize, rem);
            buf.resize(to_read);
            if (!proc.read_raw(cursor, buf.data(), to_read)) break;

            for (size_t i = 0; i + pat_len <= to_read; ++i) {
                bool match = true;
                for (size_t j = 0; j < pat_len; ++j) {
                    if (pat.mask[j] && buf[i + j] != pat.bytes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    const uintptr_t found = cursor + i;
                    if (out_addrs.empty() || out_addrs.back() != found) {
                        out_addrs.push_back(found);
                        if (max_results > 0 && out_addrs.size() >= max_results) return true;
                    }
                }
            }
            const size_t step = (to_read > pat_len - 1 && cursor + to_read < range_end)
                ? (to_read - (pat_len - 1))
                : to_read;
            cursor += std::max<size_t>(1, step);
        }
        return false;
    };

    for (const auto& reg : regions) {
        if (!reg.is_committed || !reg.is_readable || reg.is_guard || reg.size < pat_len) continue;
        const uintptr_t reg_start = reg.base_address;
        const uintptr_t reg_end = reg.end_address();

        if (module_filter && !module_filter->empty()) {
            bool matched_interval = false;
            for (const auto& iv : mod_ranges) {
                const uintptr_t s = std::max(reg_start, iv.start);
                const uintptr_t e = std::min(reg_end, iv.end);
                if (e > s) {
                    matched_interval = true;
                    if (scan_range(s, e)) return true;
                }
            }
            if (!matched_interval && mod_ranges.empty() && !reg.module_name.empty() &&
                to_lower_copy(reg.module_name).find(mod_low) != std::string::npos) {
                if (scan_range(reg_start, reg_end)) return true;
            }
        } else {
            if (scan_range(reg_start, reg_end)) return true;
        }
    }
    return true;
}

std::string map_scan_type_name(std::string t) {
    t = to_lower_copy(std::move(t));
    if (t == "byte" || t == "sbyte") return "i8";
    if (t == "ubyte") return "u8";
    if (t == "short" || t == "int16" || t == "2bytes") return "i16";
    if (t == "ushort" || t == "uint16" || t == "word") return "u16";
    if (t == "int" || t == "int32" || t == "4bytes" || t == "long") return "i32";
    if (t == "uint" || t == "uint32" || t == "dword") return "u32";
    if (t == "int64" || t == "8bytes" || t == "longlong") return "i64";
    if (t == "uint64" || t == "qword") return "u64";
    if (t == "float" || t == "single") return "f32";
    if (t == "double") return "f64";
    if (t == "string" || t == "ascii" || t == "utf8") return "str";
    if (t == "wstring" || t == "utf16" || t == "unicode") return "wstr";
    if (t == "bytes") return "aob";
    return t;
}

std::string map_next_condition_name(std::string c) {
    c = to_lower_copy(std::move(c));
    if (c == "=" || c == "==") return "exact";
    if (c == "!=") return "changed";
    if (c == "increased" || c == "+") return "inc";
    if (c == "decreased" || c == "-") return "dec";
    if (c == "greater" || c == "greaterthan" || c == ">") return "gt";
    if (c == "less" || c == "lessthan" || c == "<") return "lt";
    if (c == "increasedby") return "incby";
    if (c == "decreasedby") return "decby";
    return c;
}

scanner::FloatMatchMode parse_float_mode_arg(lua_State* L, int idx) {
    if (idx > lua_gettop(L) || !lua_isstring(L, idx)) return scanner::FloatMatchMode::Rounded;
    const std::string m = to_lower_copy(lua_tostring(L, idx));
    if (m == "exact") return scanner::FloatMatchMode::Exact;
    if (m == "truncated" || m == "trunc") return scanner::FloatMatchMode::Truncated;
    return scanner::FloatMatchMode::Rounded;
}

std::string lua_arg_text(lua_State* L, int idx) {
    if (idx > lua_gettop(L) || lua_isnil(L, idx)) return {};
    if (lua_isinteger(L, idx)) return std::to_string(lua_tointeger(L, idx));
    if (lua_isnumber(L, idx)) {
        std::ostringstream ss;
        ss << std::setprecision(15) << lua_tonumber(L, idx);
        return ss.str();
    }
    if (lua_isstring(L, idx)) return lua_tostring(L, idx);
    return {};
}

// AOBScan(pattern) -> { addr1, addr2, ... } or nil, err
int l_AOBScan(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushnil(L);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const char* pat = luaL_checkstring(L, 1);
    std::vector<uintptr_t> addrs;
    std::string err;
    if (!aob_scan_process(s->process(), pat, std::nullopt, 10000, addrs, err)) {
        lua_pushnil(L);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_createtable(L, static_cast<int>(addrs.size()), 0);
    for (size_t i = 0; i < addrs.size(); ++i) {
        lua_pushinteger(L, static_cast<lua_Integer>(addrs[i]));
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

// AOBScanFirst(pattern) -> addr or nil
int l_AOBScanFirst(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushnil(L);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const char* pat = luaL_checkstring(L, 1);
    std::vector<uintptr_t> addrs;
    std::string err;
    if (!aob_scan_process(s->process(), pat, std::nullopt, 1, addrs, err) || addrs.empty()) {
        lua_pushnil(L);
        if (!err.empty()) {
            lua_pushstring(L, err.c_str());
            return 2;
        }
        return 1;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(addrs[0]));
    return 1;
}

// AOBScanModule(moduleName, pattern) -> firstAddr, {allAddrs...} or nil
int l_AOBScanModule(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushnil(L);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    std::string mod = luaL_checkstring(L, 1);
    std::string pat = luaL_checkstring(L, 2);
    std::vector<uintptr_t> addrs;
    std::string err;
    if (!aob_scan_process(s->process(), pat, mod, 10000, addrs, err)) {
        lua_pushnil(L);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    if (addrs.empty()) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(addrs[0]));
    lua_createtable(L, static_cast<int>(addrs.size()), 0);
    for (size_t i = 0; i < addrs.size(); ++i) {
        lua_pushinteger(L, static_cast<lua_Integer>(addrs[i]));
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 2;
}

// injectDLL(path) -> true | false, err
int l_injectDLL(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const char* path = luaL_checkstring(L, 1);
    std::string err;
    if (!s->inject_dll(path, err)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    return 1;
}

// getThreads() -> { {tid=..., ownerPid=..., priority=...}, ... }
int l_getThreads(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto threads = s->list_threads();
    lua_createtable(L, static_cast<int>(threads.size()), 0);
    for (size_t i = 0; i < threads.size(); ++i) {
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(threads[i].tid));
        lua_setfield(L, -2, "tid");
        lua_pushinteger(L, static_cast<lua_Integer>(threads[i].owner_pid));
        lua_setfield(L, -2, "ownerPid");
        lua_pushinteger(L, static_cast<lua_Integer>(threads[i].base_priority));
        lua_setfield(L, -2, "priority");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

// installHook(targetAddr, payloadBytesOrHexOrDestAddr) -> HookInfo table or nil, err
int l_installHook(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached() || !s->hook_engine()) {
        lua_pushnil(L);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const uintptr_t target = resolve_lua_address(L, 1, s);
    if (target == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid target address");
        return 2;
    }

    std::optional<debugger::HookInfo> info;
    if (lua_isinteger(L, 2) || lua_isnumber(L, 2)) {
        const uintptr_t dest = static_cast<uintptr_t>(lua_isinteger(L, 2) ? lua_tointeger(L, 2) : lua_tonumber(L, 2));
        if (dest == 0) {
            lua_pushnil(L);
            lua_pushstring(L, "Invalid detour destination address");
            return 2;
        }
        info = s->hook_detour(target, dest);
    } else {
        std::vector<uint8_t> bytes;
        std::string err;
        if (!parse_lua_bytes_arg(L, 2, bytes, err)) {
            lua_pushnil(L);
            lua_pushstring(L, err.c_str());
            return 2;
        }
        info = s->hook_payload(target, bytes);
    }

    if (!info) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to install hook at target address");
        return 2;
    }

    lua_createtable(L, 0, 5);
    lua_pushinteger(L, static_cast<lua_Integer>(info->target_address));
    lua_setfield(L, -2, "target");
    lua_pushinteger(L, static_cast<lua_Integer>(info->destination_address));
    lua_setfield(L, -2, "destination");
    lua_pushinteger(L, static_cast<lua_Integer>(info->cave_address));
    lua_setfield(L, -2, "cave");
    lua_pushinteger(L, static_cast<lua_Integer>(info->trampoline_address));
    lua_setfield(L, -2, "trampoline");
    lua_pushinteger(L, static_cast<lua_Integer>(info->stolen_bytes_count));
    lua_setfield(L, -2, "stolen");
    return 1;
}

// removeHook(targetAddr) -> bool
int l_removeHook(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->hook_engine()) {
        lua_pushboolean(L, false);
        return 1;
    }
    const uintptr_t target = resolve_lua_address(L, 1, s);
    lua_pushboolean(L, target != 0 && s->unhook(target));
    return 1;
}

// getHooks() -> { {target=..., destination=..., cave=..., trampoline=..., stolen=..., active=...}, ... }
int l_getHooks(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto hooks = s->active_hooks();
    lua_createtable(L, static_cast<int>(hooks.size()), 0);
    for (size_t i = 0; i < hooks.size(); ++i) {
        lua_createtable(L, 0, 6);
        lua_pushinteger(L, static_cast<lua_Integer>(hooks[i].target_address));
        lua_setfield(L, -2, "target");
        lua_pushinteger(L, static_cast<lua_Integer>(hooks[i].destination_address));
        lua_setfield(L, -2, "destination");
        lua_pushinteger(L, static_cast<lua_Integer>(hooks[i].cave_address));
        lua_setfield(L, -2, "cave");
        lua_pushinteger(L, static_cast<lua_Integer>(hooks[i].trampoline_address));
        lua_setfield(L, -2, "trampoline");
        lua_pushinteger(L, static_cast<lua_Integer>(hooks[i].stolen_bytes_count));
        lua_setfield(L, -2, "stolen");
        lua_pushboolean(L, hooks[i].is_active);
        lua_setfield(L, -2, "active");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

// firstScan(type, valueOrQuestion, [floatMode]) -> bool, countOrErr
int l_firstScan(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const std::string type_name = map_scan_type_name(luaL_checkstring(L, 1));
    const std::string input = lua_arg_text(L, 2);
    const auto float_mode = parse_float_mode_arg(L, 3);
    const auto out = s->scans().first_scan(type_name, input, float_mode);
    if (!out.ok) {
        lua_pushboolean(L, false);
        lua_pushstring(L, out.message.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    lua_pushinteger(L, static_cast<lua_Integer>(s->scans().state().results.count()));
    return 2;
}

// nextScan(condition, [val1], [val2], [floatMode]) -> bool, countOrErr
int l_nextScan(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "No process attached");
        return 2;
    }
    const std::string cond = map_next_condition_name(luaL_checkstring(L, 1));
    const std::string val1 = lua_arg_text(L, 2);
    const std::string val2 = lua_arg_text(L, 3);
    const auto float_mode = parse_float_mode_arg(L, 4);
    const auto out = s->scans().next_scan(cond, val1, val2, float_mode);
    if (!out.ok) {
        lua_pushboolean(L, false);
        lua_pushstring(L, out.message.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    lua_pushinteger(L, static_cast<lua_Integer>(s->scans().state().results.count()));
    return 2;
}

// getScanCount() -> int
int l_getScanCount(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) {
        lua_pushinteger(L, 0);
        return 1;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(s->scans().state().results.count()));
    return 1;
}

// getScanResults([maxCount]) -> { {address=..., value=..., previous=...}, ... }
int l_getScanResults(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const size_t max_count = (lua_gettop(L) >= 1 && lua_isinteger(L, 1))
        ? static_cast<size_t>(std::max<lua_Integer>(0, lua_tointeger(L, 1)))
        : size_t{1000};
    const auto& results = s->scans().state().results;
    const size_t n = std::min(max_count, results.count());
    lua_createtable(L, static_cast<int>(n), 0);
    for (size_t i = 0; i < n; ++i) {
        const auto m = results[i];
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(m.address));
        lua_setfield(L, -2, "address");
        lua_pushstring(L, session::value_text(m.current_value).c_str());
        lua_setfield(L, -2, "value");
        lua_pushstring(L, session::value_text(m.previous_value).c_str());
        lua_setfield(L, -2, "previous");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

} // namespace (temporarily close anonymous namespace below for friend LuaApi)

struct LuaApi {
    static int createTimer(lua_State* L);
    static int destroyTimer(lua_State* L);
    static int clearTimersLua(lua_State* L);
    static int createHotkey(lua_State* L);
    static int destroyHotkey(lua_State* L);
    static int triggerHotkeyLua(lua_State* L);
};

int LuaApi::createTimer(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    const int interval_ms = std::max<int>(5, static_cast<int>(luaL_checkinteger(L, 1)));
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 2);
    const int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    auto entry = std::make_shared<LuaEngine::TimerEntry>();
    entry->lua_ref = ref;
    {
        std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
        entry->id = eng->m_next_timer_id++;
        eng->m_timers[entry->id] = entry;
    }

    entry->worker = std::thread([eng, entry, interval_ms]() {
        while (!entry->stop.load()) {
            int rem = interval_ms;
            while (rem > 0 && !entry->stop.load()) {
                const int step = std::min(20, rem);
                std::this_thread::sleep_for(std::chrono::milliseconds(step));
                rem -= step;
            }
            if (entry->stop.load()) break;

            std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
            if (entry->stop.load() || !eng->m_L || entry->lua_ref == LUA_NOREF) break;

            lua_rawgeti(eng->m_L, LUA_REGISTRYINDEX, entry->lua_ref);
            if (lua_isfunction(eng->m_L, -1)) {
                lua_pushinteger(eng->m_L, static_cast<lua_Integer>(entry->id));
                if (lua_pcall(eng->m_L, 1, 0, 0) != LUA_OK) {
                    const char* err = lua_tostring(eng->m_L, -1);
                    eng->append_output(std::string("[Timer ") + std::to_string(entry->id) + " error] " + (err ? err : "unknown") + "\n");
                    lua_pop(eng->m_L, 1);
                }
            } else {
                lua_pop(eng->m_L, 1);
            }
        }
    });

    lua_pushinteger(L, static_cast<lua_Integer>(entry->id));
    return 1;
}

int LuaApi::destroyTimer(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) {
        lua_pushboolean(L, false);
        return 1;
    }
    const uint64_t id = static_cast<uint64_t>(luaL_checkinteger(L, 1));
    std::shared_ptr<LuaEngine::TimerEntry> target;
    {
        std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
        auto it = eng->m_timers.find(id);
        if (it == eng->m_timers.end()) {
            lua_pushboolean(L, false);
            return 1;
        }
        target = std::move(it->second);
        eng->m_timers.erase(it);
        target->stop.store(true);
        if (eng->m_L && target->lua_ref != LUA_NOREF) {
            luaL_unref(eng->m_L, LUA_REGISTRYINDEX, target->lua_ref);
            target->lua_ref = LUA_NOREF;
        }
    }
    if (target->worker.joinable()) {
        if (target->worker.get_id() == std::this_thread::get_id()) {
            std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
            eng->m_retired_timers.push_back(std::move(target));
        } else {
            target->worker.join();
        }
    }
    lua_pushboolean(L, true);
    return 1;
}

int LuaApi::clearTimersLua(lua_State* L) {
    if (auto* eng = get_engine(L)) eng->clear_timers();
    return 0;
}

int LuaApi::createHotkey(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) return 0;
    std::string raw_keys = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    const std::string norm = hal::normalize_hotkey(raw_keys);
    const std::string key_id = norm.empty() ? raw_keys : norm;
    if (key_id.empty()) {
        lua_pushnil(L);
        lua_pushstring(L, "Empty hotkey string");
        return 2;
    }

    lua_pushvalue(L, 2);
    const int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    std::vector<std::string> os_combos;
    {
        std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
        auto it = eng->m_hotkey_refs.find(key_id);
        if (it != eng->m_hotkey_refs.end() && it->second != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, it->second);
        }
        eng->m_hotkey_refs[key_id] = ref;
        for (const auto& [k, _] : eng->m_hotkey_refs) {
            if (!hal::normalize_hotkey(k).empty()) os_combos.push_back(k);
        }
    }
    eng->sync_os_hotkeys_outside_lock(os_combos);

    lua_pushstring(L, key_id.c_str());
    return 1;
}

int LuaApi::destroyHotkey(lua_State* L) {
    auto* eng = get_engine(L);
    if (!eng) {
        lua_pushboolean(L, false);
        return 1;
    }
    std::string raw_keys = luaL_checkstring(L, 1);
    const std::string norm = hal::normalize_hotkey(raw_keys);
    const std::string key_id = norm.empty() ? raw_keys : norm;

    bool erased = false;
    std::vector<std::string> os_combos;
    {
        std::lock_guard<std::recursive_mutex> lock(eng->m_mutex);
        auto it = eng->m_hotkey_refs.find(key_id);
        if (it != eng->m_hotkey_refs.end()) {
            if (eng->m_L && it->second != LUA_NOREF) {
                luaL_unref(eng->m_L, LUA_REGISTRYINDEX, it->second);
            }
            eng->m_hotkey_refs.erase(it);
            erased = true;
            for (const auto& [k, _] : eng->m_hotkey_refs) {
                if (!hal::normalize_hotkey(k).empty()) os_combos.push_back(k);
            }
        }
    }
    if (erased) eng->sync_os_hotkeys_outside_lock(os_combos);
    lua_pushboolean(L, erased);
    return 1;
}

int LuaApi::triggerHotkeyLua(lua_State* L) {
    auto* eng = get_engine(L);
    const char* keys = luaL_checkstring(L, 1);
    lua_pushboolean(L, eng && eng->trigger_hotkey(keys));
    return 1;
}

namespace { // reopen anonymous namespace before closing brace in file

// Speedhack: setSpeed(factor), getSpeed()
int l_setSpeed(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) { lua_pushboolean(L, false); return 1; }
    double factor = lua_tonumber(L, 1);
    bool ok = s->set_speed(factor);
    lua_pushboolean(L, ok);
    return 1;
}

int l_getSpeed(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) { lua_pushnumber(L, 1.0); return 1; }
    lua_pushnumber(L, s->speedhack_speed());
    return 1;
}

// Step Debugger: setBreakpoint(addr), removeBreakpoint(addr), pause(), resume(), stepInto(), stepOver()
int l_setBreakpoint(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, &s->process());
    bool ok = s->dbg_set_bp(addr);
    lua_pushboolean(L, ok);
    return 1;
}

int l_removeBreakpoint(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s) { lua_pushboolean(L, false); return 1; }
    uintptr_t addr = parse_address(L, 1, &s->process());
    bool ok = s->dbg_remove_bp(addr);
    lua_pushboolean(L, ok);
    return 1;
}

int l_pause(lua_State* L) {
    auto* s = get_session_from_lua(L);
    bool ok = s && s->dbg_pause();
    lua_pushboolean(L, ok);
    return 1;
}

int l_resume(lua_State* L) {
    auto* s = get_session_from_lua(L);
    bool ok = s && s->dbg_resume();
    lua_pushboolean(L, ok);
    return 1;
}

int l_stepInto(lua_State* L) {
    auto* s = get_session_from_lua(L);
    bool ok = s && s->dbg_step_into();
    lua_pushboolean(L, ok);
    return 1;
}

int l_stepOver(lua_State* L) {
    auto* s = get_session_from_lua(L);
    bool ok = s && s->dbg_step_over();
    lua_pushboolean(L, ok);
    return 1;
}

// Phase 4 & 5 Bindings: PE/ELF, Unity/Unreal Inspector, Disasm CFG
int l_analyzePE(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    std::optional<debugger::PEInfo> info;
    if (lua_type(L, 1) == LUA_TSTRING) {
        std::string arg = lua_tostring(L, 1);
        uintptr_t addr = utils::parse_address(arg);
        info = addr ? s->analyze_pe(addr) : s->analyze_module(arg);
    } else {
        info = s->analyze_pe(parse_address(L, 1, &s->process()));
    }
    if (!info || !info->is_valid) { lua_pushnil(L); return 1; }

    lua_newtable(L);
    lua_pushboolean(L, info->is_64bit); lua_setfield(L, -2, "is64");
    lua_pushinteger(L, static_cast<lua_Integer>(info->image_base)); lua_setfield(L, -2, "base");
    lua_pushinteger(L, static_cast<lua_Integer>(info->entry_point)); lua_setfield(L, -2, "entry");
    lua_pushinteger(L, static_cast<lua_Integer>(info->image_size)); lua_setfield(L, -2, "size");

    lua_newtable(L);
    for (const auto& exp : info->exports) {
        if (!exp.name.empty()) {
            lua_pushinteger(L, static_cast<lua_Integer>(exp.va));
            lua_setfield(L, -2, exp.name.c_str());
        }
    }
    lua_setfield(L, -2, "exports");
    return 1;
}

int l_analyzeELF(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    std::optional<debugger::ELFInfo> info;
    if (lua_type(L, 1) == LUA_TSTRING) {
        std::string arg = lua_tostring(L, 1);
        uintptr_t addr = utils::parse_address(arg);
        info = addr ? s->analyze_elf(addr) : s->analyze_module_elf(arg);
    } else {
        info = s->analyze_elf(parse_address(L, 1, &s->process()));
    }
    if (!info || !info->is_valid) { lua_pushnil(L); return 1; }

    lua_newtable(L);
    lua_pushboolean(L, info->is_64bit); lua_setfield(L, -2, "is64");
    lua_pushinteger(L, static_cast<lua_Integer>(info->image_base)); lua_setfield(L, -2, "base");
    lua_pushinteger(L, static_cast<lua_Integer>(info->entry_point)); lua_setfield(L, -2, "entry");
    lua_pushinteger(L, static_cast<lua_Integer>(info->image_size)); lua_setfield(L, -2, "size");
    lua_pushstring(L, info->type_name.c_str()); lua_setfield(L, -2, "type");
    lua_pushstring(L, info->machine_name.c_str()); lua_setfield(L, -2, "machine");

    lua_newtable(L);
    for (const auto& sym : info->symbols) {
        if (!sym.name.empty()) {
            lua_pushinteger(L, static_cast<lua_Integer>(sym.va));
            lua_setfield(L, -2, sym.name.c_str());
        }
    }
    lua_setfield(L, -2, "symbols");
    return 1;
}

int l_detectEngine(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    auto det = s->detect_game_engine();
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(det.kind)); lua_setfield(L, -2, "kind");
    lua_pushstring(L, det.engine_name.c_str()); lua_setfield(L, -2, "name");
    lua_pushstring(L, det.runtime_module.c_str()); lua_setfield(L, -2, "module");
    lua_pushinteger(L, static_cast<lua_Integer>(det.runtime_base)); lua_setfield(L, -2, "base");
    lua_pushinteger(L, static_cast<lua_Integer>(det.gnames_hint)); lua_setfield(L, -2, "gnames");
    lua_pushinteger(L, static_cast<lua_Integer>(det.gobjects_hint)); lua_setfield(L, -2, "gobjects");
    lua_pushstring(L, det.details.c_str()); lua_setfield(L, -2, "details");
    return 1;
}

int l_findUnrealGlobals(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    uintptr_t mod_base = (lua_gettop(L) >= 1) ? parse_address(L, 1, &s->process()) : 0;
    auto res = s->find_unreal_globals(mod_base);
    lua_newtable(L);
    lua_pushboolean(L, res.found_names); lua_setfield(L, -2, "found_names");
    lua_pushboolean(L, res.found_objects); lua_setfield(L, -2, "found_objects");
    lua_pushboolean(L, res.found_world); lua_setfield(L, -2, "found_world");
    lua_pushinteger(L, static_cast<lua_Integer>(res.fname_pool_va)); lua_setfield(L, -2, "gnames");
    lua_pushinteger(L, static_cast<lua_Integer>(res.guobject_array_va)); lua_setfield(L, -2, "gobjects");
    lua_pushinteger(L, static_cast<lua_Integer>(res.gworld_va)); lua_setfield(L, -2, "gworld");
    lua_pushstring(L, res.source_module.c_str()); lua_setfield(L, -2, "module");
    return 1;
}

int l_readUnrealName(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushstring(L, ""); return 1; }
    uintptr_t gnames = parse_address(L, 1, &s->process());
    uint32_t idx = static_cast<uint32_t>(luaL_checkinteger(L, 2));
    std::string out = view::EngineInspector::read_unreal_fname(s->process(), gnames, idx);
    lua_pushstring(L, out.c_str());
    return 1;
}

int l_dumpUnrealObjects(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_newtable(L); return 1; }
    uintptr_t gobj   = parse_address(L, 1, &s->process());
    uintptr_t gnames = parse_address(L, 2, &s->process());
    std::string filter = (lua_gettop(L) >= 3 && lua_isstring(L, 3)) ? lua_tostring(L, 3) : "";
    size_t max_objs = (lua_gettop(L) >= 4 && lua_isinteger(L, 4)) ? static_cast<size_t>(lua_tointeger(L, 4)) : 256;
    auto objs = s->dump_unreal_objects(gobj, gnames, {}, filter, max_objs);
    lua_createtable(L, static_cast<int>(objs.size()), 0);
    for (size_t i = 0; i < objs.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(objs[i].index)); lua_setfield(L, -2, "index");
        lua_pushinteger(L, static_cast<lua_Integer>(objs[i].address)); lua_setfield(L, -2, "address");
        lua_pushstring(L, objs[i].name.c_str()); lua_setfield(L, -2, "name");
        lua_pushstring(L, objs[i].class_name.c_str()); lua_setfield(L, -2, "class_name");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

int l_dumpUnrealActors(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_newtable(L); return 1; }
    uintptr_t uworld = parse_address(L, 1, &s->process());
    uintptr_t gnames = parse_address(L, 2, &s->process());
    size_t max_act = (lua_gettop(L) >= 3 && lua_isinteger(L, 3)) ? static_cast<size_t>(lua_tointeger(L, 3)) : 256;
    auto actors = s->dump_unreal_actors(uworld, gnames, {}, max_act);
    lua_createtable(L, static_cast<int>(actors.size()), 0);
    for (size_t i = 0; i < actors.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(actors[i].index)); lua_setfield(L, -2, "index");
        lua_pushinteger(L, static_cast<lua_Integer>(actors[i].address)); lua_setfield(L, -2, "address");
        lua_pushstring(L, actors[i].name.c_str()); lua_setfield(L, -2, "name");
        lua_pushstring(L, actors[i].class_name.c_str()); lua_setfield(L, -2, "class_name");
        lua_pushboolean(L, actors[i].has_location); lua_setfield(L, -2, "has_location");
        lua_pushnumber(L, actors[i].x); lua_setfield(L, -2, "x");
        lua_pushnumber(L, actors[i].y); lua_setfield(L, -2, "y");
        lua_pushnumber(L, actors[i].z); lua_setfield(L, -2, "z");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

int l_inspectUnityMemory(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    std::string filter = (lua_gettop(L) >= 1 && lua_isstring(L, 1)) ? lua_tostring(L, 1) : "";
    auto rep = s->inspect_unity_metadata_memory(0, filter, 128);
    if (!rep.valid) { lua_pushnil(L); return 1; }
    lua_newtable(L);
    lua_pushinteger(L, rep.version); lua_setfield(L, -2, "version");
    lua_pushinteger(L, static_cast<lua_Integer>(rep.total_types)); lua_setfield(L, -2, "total_types");
    lua_createtable(L, static_cast<int>(rep.types.size()), 0);
    for (size_t i = 0; i < rep.types.size(); ++i) {
        lua_newtable(L);
        lua_pushstring(L, rep.types[i].name.c_str()); lua_setfield(L, -2, "name");
        lua_pushstring(L, rep.types[i].namespaze.c_str()); lua_setfield(L, -2, "namespace");
        lua_createtable(L, static_cast<int>(rep.types[i].fields.size()), 0);
        for (size_t f = 0; f < rep.types[i].fields.size(); ++f) {
            lua_pushstring(L, rep.types[i].fields[f].name.c_str());
            lua_rawseti(L, -2, static_cast<lua_Integer>(f + 1));
        }
        lua_setfield(L, -2, "fields");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "types");
    return 1;
}

int l_dissectUnityObject(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    uintptr_t obj = parse_address(L, 1, &s->process());
    auto lay = s->dissect_unity_object(obj);
    lua_newtable(L);
    lua_pushstring(L, lay.class_name.c_str()); lua_setfield(L, -2, "class_name");
    lua_createtable(L, static_cast<int>(lay.fields.size()), 0);
    for (size_t i = 0; i < lay.fields.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(lay.fields[i].offset)); lua_setfield(L, -2, "offset");
        lua_pushstring(L, lay.fields[i].name.c_str()); lua_setfield(L, -2, "name");
        lua_pushstring(L, lay.fields[i].value.c_str()); lua_setfield(L, -2, "value");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "fields");
    return 1;
}

int l_buildCFG(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    uintptr_t entry = parse_address(L, 1, &s->process());
    size_t max_i = (lua_gettop(L) >= 2 && lua_isinteger(L, 2)) ? static_cast<size_t>(lua_tointeger(L, 2)) : 128;
    auto cfg = s->build_cfg(entry, max_i, 32);
    lua_newtable(L);
    lua_pushinteger(L, static_cast<lua_Integer>(cfg.entry_address)); lua_setfield(L, -2, "entry");
    lua_createtable(L, static_cast<int>(cfg.blocks.size()), 0);
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.blocks[i].id)); lua_setfield(L, -2, "id");
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.blocks[i].start_address)); lua_setfield(L, -2, "start");
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.blocks[i].end_address)); lua_setfield(L, -2, "end_addr");
        lua_pushinteger(L, cfg.blocks[i].level); lua_setfield(L, -2, "level");
        lua_pushinteger(L, cfg.blocks[i].lane); lua_setfield(L, -2, "lane");
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.blocks[i].instructions.size())); lua_setfield(L, -2, "insn_count");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "blocks");
    lua_createtable(L, static_cast<int>(cfg.edges.size()), 0);
    for (size_t i = 0; i < cfg.edges.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.edges[i].from_block)); lua_setfield(L, -2, "from");
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.edges[i].to_block)); lua_setfield(L, -2, "to");
        lua_pushinteger(L, static_cast<lua_Integer>(cfg.edges[i].kind)); lua_setfield(L, -2, "kind");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "edges");
    return 1;
}

int l_generateAOBScript(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    uintptr_t addr = parse_address(L, 1, &s->process());
    if (!addr) { lua_pushnil(L); return 1; }
    std::string label = (lua_gettop(L) >= 2 && lua_isstring(L, 2)) ? lua_tostring(L, 2) : "INJECT";
    size_t min_bytes = (lua_gettop(L) >= 3 && lua_isinteger(L, 3)) ? static_cast<size_t>(lua_tointeger(L, 3)) : 5;
    std::string script = s->generate_aob_hook_script(addr, label, min_bytes);
    if (script.empty()) { lua_pushnil(L); return 1; }
    lua_pushlstring(L, script.data(), script.size());
    return 1;
}

int l_findXRefs(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_newtable(L); return 1; }
    uintptr_t target = parse_address(L, 1, &s->process());
    uintptr_t mod_base = (lua_gettop(L) >= 2) ? parse_address(L, 2, &s->process()) : 0;
    size_t max_res = (lua_gettop(L) >= 3 && lua_isinteger(L, 3)) ? static_cast<size_t>(lua_tointeger(L, 3)) : 256;
    auto refs = s->find_references(target, mod_base, max_res);
    lua_createtable(L, static_cast<int>(refs.size()), 0);
    for (size_t i = 0; i < refs.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, static_cast<lua_Integer>(refs[i].from_address)); lua_setfield(L, -2, "from");
        lua_pushstring(L, refs[i].module_name.c_str()); lua_setfield(L, -2, "module");
        lua_pushstring(L, refs[i].kind.c_str()); lua_setfield(L, -2, "kind");
        lua_pushstring(L, refs[i].instruction.c_str()); lua_setfield(L, -2, "instruction");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

int l_calibrateUnrealOffsets(lua_State* L) {
    auto* s = get_session_from_lua(L);
    if (!s || !s->attached()) { lua_pushnil(L); return 1; }
    uintptr_t obj = parse_address(L, 1, &s->process());
    uintptr_t gnames = parse_address(L, 2, &s->process());
    auto cal = s->calibrate_unreal_offsets(obj, gnames);
    lua_newtable(L);
    lua_pushboolean(L, cal.ok); lua_setfield(L, -2, "ok");
    lua_pushinteger(L, static_cast<lua_Integer>(cal.offsets.uworld_level_offset)); lua_setfield(L, -2, "uworld_level");
    lua_pushinteger(L, static_cast<lua_Integer>(cal.offsets.ulevel_actors_offset)); lua_setfield(L, -2, "ulevel_actors");
    lua_pushinteger(L, static_cast<lua_Integer>(cal.offsets.actor_root_comp_offset)); lua_setfield(L, -2, "root_comp");
    lua_pushinteger(L, static_cast<lua_Integer>(cal.offsets.scene_comp_location_offset)); lua_setfield(L, -2, "rel_location");
    lua_pushboolean(L, cal.offsets.lwc_double_coords); lua_setfield(L, -2, "lwc_double");
    return 1;
}

} // namespace

LuaEngine::LuaEngine(session::Session* session)
    : m_session(session) {
    init_state();
}

LuaEngine::~LuaEngine() {
    clear_timers();
    clear_hotkeys();
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_L) {
        lua_close(m_L);
        m_L = nullptr;
    }
}

void LuaEngine::set_print_callback(PrintCallback cb) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_print_cb = std::move(cb);
}

void LuaEngine::set_session(session::Session* session) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_session = session;
}

void LuaEngine::reset() {
    clear_timers();
    clear_hotkeys();
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_L) {
        lua_close(m_L);
        m_L = nullptr;
    }
    m_output_buffer.str("");
    m_output_buffer.clear();
    m_eval_depth = 0;
    init_state();
}

ScriptResult LuaEngine::execute_string(const std::string& code) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_L) {
        return ScriptResult{ false, "", "Lua state is not initialized" };
    }

    size_t start_pos = 0;
    if (m_eval_depth == 0) {
        m_output_buffer.str("");
        m_output_buffer.clear();
    } else {
        start_pos = m_output_buffer.str().size();
    }
    struct DepthGuard {
        int& d;
        explicit DepthGuard(int& v) : d(v) { ++d; }
        ~DepthGuard() { --d; }
    } depth_guard(m_eval_depth);

    auto slice_output = [&]() {
        const std::string full = m_output_buffer.str();
        return (start_pos <= full.size()) ? full.substr(start_pos) : full;
    };

    int load_res = luaL_loadbuffer(m_L, code.c_str(), code.size(), "nce_chunk");
    if (load_res != LUA_OK) {
        std::string err = lua_tostring(m_L, -1);
        lua_pop(m_L, 1);
        return ScriptResult{ false, slice_output(), err };
    }

    int run_res = lua_pcall(m_L, 0, LUA_MULTRET, 0);
    if (run_res != LUA_OK) {
        std::string err = lua_tostring(m_L, -1);
        lua_pop(m_L, 1);
        return ScriptResult{ false, slice_output(), err };
    }

    return ScriptResult{ true, slice_output(), "" };
}

ScriptResult LuaEngine::execute_file(const std::string& filepath) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_L) {
        return ScriptResult{ false, "", "Lua state is not initialized" };
    }

    size_t start_pos = 0;
    if (m_eval_depth == 0) {
        m_output_buffer.str("");
        m_output_buffer.clear();
    } else {
        start_pos = m_output_buffer.str().size();
    }
    struct DepthGuard {
        int& d;
        explicit DepthGuard(int& v) : d(v) { ++d; }
        ~DepthGuard() { --d; }
    } depth_guard(m_eval_depth);

    auto slice_output = [&]() {
        const std::string full = m_output_buffer.str();
        return (start_pos <= full.size()) ? full.substr(start_pos) : full;
    };

    int load_res = luaL_loadfile(m_L, filepath.c_str());
    if (load_res != LUA_OK) {
        std::string err = lua_tostring(m_L, -1);
        lua_pop(m_L, 1);
        return ScriptResult{ false, slice_output(), err };
    }

    int run_res = lua_pcall(m_L, 0, LUA_MULTRET, 0);
    if (run_res != LUA_OK) {
        std::string err = lua_tostring(m_L, -1);
        lua_pop(m_L, 1);
        return ScriptResult{ false, slice_output(), err };
    }

    return ScriptResult{ true, slice_output(), "" };
}

bool LuaEngine::on_breakpoint_hit(uint32_t thread_id, uintptr_t rip, debugger::Registers& regs) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_L) return false;

    lua_getglobal(m_L, "debugger_onBreakpoint");
    if (!lua_isfunction(m_L, -1)) {
        lua_pop(m_L, 1);
        return false;
    }

    auto set_reg = [&](const char* name, uint64_t val) {
        lua_pushinteger(m_L, static_cast<lua_Integer>(val));
        lua_setglobal(m_L, name);
    };
    set_reg("RAX", regs.rax); set_reg("RBX", regs.rbx); set_reg("RCX", regs.rcx); set_reg("RDX", regs.rdx);
    set_reg("RSI", regs.rsi); set_reg("RDI", regs.rdi); set_reg("RBP", regs.rbp); set_reg("RSP", regs.rsp);
    set_reg("RIP", rip);
    set_reg("R8",  regs.r8);  set_reg("R9",  regs.r9);  set_reg("R10", regs.r10); set_reg("R11", regs.r11);
    set_reg("R12", regs.r12); set_reg("R13", regs.r13); set_reg("R14", regs.r14); set_reg("R15", regs.r15);
    set_reg("EFLAGS", regs.eflags);
    set_reg("THREADID", thread_id);

    if (lua_pcall(m_L, 0, 1, 0) != LUA_OK) {
        const char* err = lua_tostring(m_L, -1);
        append_output(std::string("[debugger_onBreakpoint error] ") + (err ? err : "unknown") + "\n");
        lua_pop(m_L, 1);
        return false;
    }

    bool auto_continue = false;
    if (lua_isinteger(m_L, -1) || lua_isnumber(m_L, -1)) {
        auto_continue = (lua_tointeger(m_L, -1) != 0);
    } else if (lua_isboolean(m_L, -1)) {
        auto_continue = (lua_toboolean(m_L, -1) != 0);
    }
    lua_pop(m_L, 1);

    auto read_reg = [&](const char* name, uint64_t& dst) {
        lua_getglobal(m_L, name);
        if (lua_isinteger(m_L, -1)) dst = static_cast<uint64_t>(lua_tointeger(m_L, -1));
        else if (lua_isnumber(m_L, -1)) dst = static_cast<uint64_t>(lua_tonumber(m_L, -1));
        lua_pop(m_L, 1);
    };
    read_reg("RAX", regs.rax); read_reg("RBX", regs.rbx); read_reg("RCX", regs.rcx); read_reg("RDX", regs.rdx);
    read_reg("RSI", regs.rsi); read_reg("RDI", regs.rdi); read_reg("RBP", regs.rbp); read_reg("RSP", regs.rsp);
    read_reg("RIP", regs.rip);
    read_reg("R8",  regs.r8);  read_reg("R9",  regs.r9);  read_reg("R10", regs.r10); read_reg("R11", regs.r11);
    read_reg("R12", regs.r12); read_reg("R13", regs.r13); read_reg("R14", regs.r14); read_reg("R15", regs.r15);
    read_reg("EFLAGS", regs.eflags);

    return auto_continue;
}

bool LuaEngine::trigger_hotkey(const std::string& keys) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_L) return false;

    const std::string norm = hal::normalize_hotkey(keys);
    const std::string key_id = norm.empty() ? keys : norm;
    auto it = m_hotkey_refs.find(key_id);
    if (it == m_hotkey_refs.end() || it->second == LUA_NOREF) return false;

    lua_rawgeti(m_L, LUA_REGISTRYINDEX, it->second);
    if (!lua_isfunction(m_L, -1)) {
        lua_pop(m_L, 1);
        return false;
    }
    lua_pushstring(m_L, key_id.c_str());
    if (lua_pcall(m_L, 1, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(m_L, -1);
        append_output(std::string("[Hotkey error] ") + (err ? err : "unknown") + "\n");
        lua_pop(m_L, 1);
        return false;
    }
    return true;
}

void LuaEngine::sync_os_hotkeys_outside_lock(const std::vector<std::string>& combos) {
    std::unique_ptr<hal::IHotkeys> created;
    hal::IHotkeys* hk_ptr = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (!m_hotkeys && !combos.empty()) {
            m_hotkeys = hal::IHotkeys::create();
            if (m_hotkeys) {
                m_hotkeys->on_press([this](const std::string& combo) {
                    trigger_hotkey(combo);
                });
            }
        }
        hk_ptr = m_hotkeys.get();
    }
    if (hk_ptr) hk_ptr->set(combos);
}

void LuaEngine::clear_timers() {
    std::vector<std::shared_ptr<TimerEntry>> to_join;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        for (auto& [id, t] : m_timers) {
            t->stop.store(true);
            if (m_L && t->lua_ref != LUA_NOREF) {
                luaL_unref(m_L, LUA_REGISTRYINDEX, t->lua_ref);
                t->lua_ref = LUA_NOREF;
            }
            to_join.push_back(std::move(t));
        }
        m_timers.clear();
        for (auto& t : m_retired_timers) {
            t->stop.store(true);
            to_join.push_back(std::move(t));
        }
        m_retired_timers.clear();
    }
    const auto self_id = std::this_thread::get_id();
    std::vector<std::shared_ptr<TimerEntry>> self_refs;
    for (auto& t : to_join) {
        if (t->worker.joinable()) {
            if (t->worker.get_id() == self_id) {
                self_refs.push_back(std::move(t));
            } else {
                t->worker.join();
            }
        }
    }
    if (!self_refs.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        for (auto& t : self_refs) m_retired_timers.push_back(std::move(t));
    }
}

void LuaEngine::clear_hotkeys() {
    std::unique_ptr<hal::IHotkeys> hk_to_clear;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_L) {
            for (const auto& [k, ref] : m_hotkey_refs) {
                if (ref != LUA_NOREF) luaL_unref(m_L, LUA_REGISTRYINDEX, ref);
            }
        }
        m_hotkey_refs.clear();
        hk_to_clear = std::move(m_hotkeys);
    }
    if (hk_to_clear) {
        hk_to_clear->set({});
        hk_to_clear.reset();
    }
}

size_t LuaEngine::active_timer_count() const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_timers.size();
}

size_t LuaEngine::active_hotkey_count() const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_hotkey_refs.size();
}

void LuaEngine::append_output(const std::string& text) {
    m_output_buffer << text;
    if (m_print_cb) {
        m_print_cb(text);
    }
}

void LuaEngine::init_state() {
    m_L = luaL_newstate();
    if (!m_L) return;

    luaL_openlibs(m_L);

    lua_pushlightuserdata(m_L, this);
    lua_setfield(m_L, LUA_REGISTRYINDEX, "NCE_LUA_ENGINE");

    register_nce_api();
}

void LuaEngine::register_nce_api() {
    if (!m_L) return;

    // Override global print
    lua_pushcfunction(m_L, l_print);
    lua_setglobal(m_L, "print");

    // Memory reading
    lua_pushcfunction(m_L, l_readInteger);
    lua_setglobal(m_L, "readInteger");
    lua_pushcfunction(m_L, l_readQword);
    lua_setglobal(m_L, "readQword");
    lua_pushcfunction(m_L, l_readQword);
    lua_setglobal(m_L, "readPointer");
    lua_pushcfunction(m_L, l_readSmallInteger);
    lua_setglobal(m_L, "readSmallInteger");
    lua_pushcfunction(m_L, l_readByte);
    lua_setglobal(m_L, "readByte");
    lua_pushcfunction(m_L, l_readFloat);
    lua_setglobal(m_L, "readFloat");
    lua_pushcfunction(m_L, l_readDouble);
    lua_setglobal(m_L, "readDouble");
    lua_pushcfunction(m_L, l_readString);
    lua_setglobal(m_L, "readString");
    lua_pushcfunction(m_L, l_readBytes);
    lua_setglobal(m_L, "readBytes");

    // Memory writing
    lua_pushcfunction(m_L, l_writeInteger);
    lua_setglobal(m_L, "writeInteger");
    lua_pushcfunction(m_L, l_writeQword);
    lua_setglobal(m_L, "writeQword");
    lua_pushcfunction(m_L, l_writeSmallInteger);
    lua_setglobal(m_L, "writeSmallInteger");
    lua_pushcfunction(m_L, l_writeByte);
    lua_setglobal(m_L, "writeByte");
    lua_pushcfunction(m_L, l_writeFloat);
    lua_setglobal(m_L, "writeFloat");
    lua_pushcfunction(m_L, l_writeDouble);
    lua_setglobal(m_L, "writeDouble");
    lua_pushcfunction(m_L, l_writeString);
    lua_setglobal(m_L, "writeString");
    lua_pushcfunction(m_L, l_writeBytes);
    lua_setglobal(m_L, "writeBytes");

    // Addresses & Modules
    lua_pushcfunction(m_L, l_getAddress);
    lua_setglobal(m_L, "getAddress");
    lua_pushcfunction(m_L, l_getModuleAddress);
    lua_setglobal(m_L, "getModuleAddress");

    // Memory allocation & Caves
    lua_pushcfunction(m_L, l_allocateMemory);
    lua_setglobal(m_L, "allocateMemory");
    lua_pushcfunction(m_L, l_deallocateMemory);
    lua_setglobal(m_L, "deallocateMemory");

    // Auto-Assembler
    lua_pushcfunction(m_L, l_autoAssemble);
    lua_setglobal(m_L, "autoAssemble");

    // Speedhack
    lua_pushcfunction(m_L, l_setSpeed);
    lua_setglobal(m_L, "setSpeed");
    lua_pushcfunction(m_L, l_getSpeed);
    lua_setglobal(m_L, "getSpeed");

    // Step Debugger
    lua_pushcfunction(m_L, l_setBreakpoint);
    lua_setglobal(m_L, "setBreakpoint");
    lua_pushcfunction(m_L, l_removeBreakpoint);
    lua_setglobal(m_L, "removeBreakpoint");
    lua_pushcfunction(m_L, l_pause);
    lua_setglobal(m_L, "pause");
    lua_pushcfunction(m_L, l_resume);
    lua_setglobal(m_L, "resume");
    lua_pushcfunction(m_L, l_stepInto);
    lua_setglobal(m_L, "stepInto");
    lua_pushcfunction(m_L, l_stepOver);
    lua_setglobal(m_L, "stepOver");

    // Utilities
    lua_pushcfunction(m_L, l_toHex);
    lua_setglobal(m_L, "toHex");
    lua_pushcfunction(m_L, l_fromHex);
    lua_setglobal(m_L, "fromHex");
    lua_pushcfunction(m_L, l_sleep);
    lua_setglobal(m_L, "sleep");

    // AOB Scanning
    lua_pushcfunction(m_L, l_AOBScan);
    lua_setglobal(m_L, "AOBScan");
    lua_pushcfunction(m_L, l_AOBScanFirst);
    lua_setglobal(m_L, "AOBScanFirst");
    lua_pushcfunction(m_L, l_AOBScanModule);
    lua_setglobal(m_L, "AOBScanModule");

    // DLL Injection & Thread Enumeration
    lua_pushcfunction(m_L, l_injectDLL);
    lua_setglobal(m_L, "injectDLL");
    lua_pushcfunction(m_L, l_getThreads);
    lua_setglobal(m_L, "getThreads");

    // HookEngine (Code Caves, Detours & Inline Payloads)
    lua_pushcfunction(m_L, l_installHook);
    lua_setglobal(m_L, "installHook");
    lua_pushcfunction(m_L, l_removeHook);
    lua_setglobal(m_L, "removeHook");
    lua_pushcfunction(m_L, l_getHooks);
    lua_setglobal(m_L, "getHooks");

    // Scanner Automation
    lua_pushcfunction(m_L, l_firstScan);
    lua_setglobal(m_L, "firstScan");
    lua_pushcfunction(m_L, l_nextScan);
    lua_setglobal(m_L, "nextScan");
    lua_pushcfunction(m_L, l_getScanCount);
    lua_setglobal(m_L, "getScanCount");
    lua_pushcfunction(m_L, l_getScanResults);
    lua_setglobal(m_L, "getScanResults");

    // Timers & Hotkeys
    lua_pushcfunction(m_L, LuaApi::createTimer);
    lua_setglobal(m_L, "createTimer");
    lua_pushcfunction(m_L, LuaApi::destroyTimer);
    lua_setglobal(m_L, "destroyTimer");
    lua_pushcfunction(m_L, LuaApi::clearTimersLua);
    lua_setglobal(m_L, "clearTimers");
    lua_pushcfunction(m_L, LuaApi::createHotkey);
    lua_setglobal(m_L, "createHotkey");
    lua_pushcfunction(m_L, LuaApi::destroyHotkey);
    lua_setglobal(m_L, "destroyHotkey");
    lua_pushcfunction(m_L, LuaApi::triggerHotkeyLua);
    lua_setglobal(m_L, "triggerHotkey");

    // Phase 4 & 5: Binary Inspection, Unity/Unreal & Control-Flow Graph
    lua_pushcfunction(m_L, l_analyzePE);
    lua_setglobal(m_L, "analyzePE");
    lua_pushcfunction(m_L, l_analyzeELF);
    lua_setglobal(m_L, "analyzeELF");
    lua_pushcfunction(m_L, l_detectEngine);
    lua_setglobal(m_L, "detectEngine");
    lua_pushcfunction(m_L, l_findUnrealGlobals);
    lua_setglobal(m_L, "findUnrealGlobals");
    lua_pushcfunction(m_L, l_readUnrealName);
    lua_setglobal(m_L, "readUnrealName");
    lua_pushcfunction(m_L, l_dumpUnrealObjects);
    lua_setglobal(m_L, "dumpUnrealObjects");
    lua_pushcfunction(m_L, l_dumpUnrealActors);
    lua_setglobal(m_L, "dumpUnrealActors");
    lua_pushcfunction(m_L, l_inspectUnityMemory);
    lua_setglobal(m_L, "inspectUnityMemory");
    lua_pushcfunction(m_L, l_dissectUnityObject);
    lua_setglobal(m_L, "dissectUnityObject");
    lua_pushcfunction(m_L, l_buildCFG);
    lua_setglobal(m_L, "buildCFG");
    lua_pushcfunction(m_L, l_generateAOBScript);
    lua_setglobal(m_L, "generateAOBScript");
    lua_pushcfunction(m_L, l_findXRefs);
    lua_setglobal(m_L, "findXRefs");
    lua_pushcfunction(m_L, l_calibrateUnrealOffsets);
    lua_setglobal(m_L, "calibrateUnrealOffsets");
}

} // namespace nce::script
