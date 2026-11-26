#include "doctest/doctest.h"
#include "hal/remote_process.hpp"
#include "debugger/pdb_reader.hpp"
#include "view/engine_inspector.hpp"
#include "session/session.hpp"
#include "utils/updater.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <vector>

using namespace nce;

namespace {

class RemoteV3MockProcess final : public hal::IProcess {
public:
    std::vector<uint8_t> ram = std::vector<uint8_t>(4096, 0x2A);
    std::vector<hal::ModuleInfo> mods = {
        {"libgodot.so", "/tmp/libgodot.so", 0x400000, 0x4000},
        {"game.exe", "game.exe", 0x500000, 0x2000}
    };
    uint32_t pid{0};

    bool attach(uint32_t p) override { pid = p; return p == 4242; }
    void detach() override { pid = 0; }
    bool is_attached() const noexcept override { return pid != 0; }
    uint32_t get_pid() const noexcept override { return pid; }

    bool read_raw(uintptr_t addr, void* buf, size_t sz) const override {
        if (addr >= 0x600000 && addr + sz <= 0x600000 + ram.size()) {
            std::memcpy(buf, ram.data() + (addr - 0x600000), sz);
            return true;
        }
        return false;
    }
    bool write_raw(uintptr_t addr, const void* buf, size_t sz, bool) const override {
        if (addr >= 0x600000 && addr + sz <= 0x600000 + ram.size()) {
            auto* self = const_cast<RemoteV3MockProcess*>(this);
            std::memcpy(self->ram.data() + (addr - 0x600000), buf, sz);
            return true;
        }
        return false;
    }
    std::vector<hal::MemoryRegion> query_regions(uint32_t) const override {
        return {{0x600000, ram.size(), 0x04, 0x1000, 0x20000, true, true, false, false, true, hal::MemoryType::Private, ""}};
    }
    std::vector<hal::ModuleInfo> get_modules() const override { return mods; }
    uintptr_t allocate_memory(size_t, uint32_t, uintptr_t) override { return 0x700000; }
    bool free_memory(uintptr_t, size_t) override { return true; }
    size_t pointer_size() const noexcept override { return 8; }
    bool can_write() const noexcept override { return true; }
    std::string name() const override { return "mock_v3"; }
    bool suspend() override { return true; }
    bool resume() override { return true; }
};

void append_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
}
void append_u32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
}

// Builds a synthetic valid MSF 7.00 .PDB binary with:
// Stream 1..N mapping + DBI (Stream 3) pointing to SymRecs (Stream 4) and SectionHeaders (Stream 5)
std::vector<uint8_t> build_synthetic_msf7_pdb() {
    constexpr uint32_t kBlkSz = 4096;
    // Block 0: SuperBlock
    // Block 1: FPM1
    // Block 2: FPM2
    // Block 3: Directory Map block -> [Block 4]
    // Block 4: Stream Directory
    // Block 5: Stream 0 (root/old)
    // Block 6: Stream 1 (PDB header)
    // Block 7: Stream 2 (TPI)
    // Block 8: Stream 3 (DBI)
    // Block 9: Stream 4 (Public/Global Symbol Records)
    // Block 10: Stream 5 (Section Headers)
    constexpr uint32_t kNumBlocks = 11;
    std::vector<uint8_t> pdb(kNumBlocks * kBlkSz, 0);

    // Build Stream 4: S_PUB32 (0x110E) and S_GPROC32 (0x1110)
    std::vector<uint8_t> syms;
    auto push_spub32 = [&](uint32_t flags, uint32_t off, uint16_t seg, const std::string& name) {
        std::vector<uint8_t> rec;
        append_u32(rec, flags);
        append_u32(rec, off);
        append_u16(rec, seg);
        rec.insert(rec.end(), name.begin(), name.end());
        rec.push_back(0);
        const uint16_t reclen = static_cast<uint16_t>(2 + rec.size());
        append_u16(syms, reclen);
        append_u16(syms, 0x110Eu);
        syms.insert(syms.end(), rec.begin(), rec.end());
    };
    push_spub32(2, 0x120, 1, "Player::TakeDamage");
    push_spub32(2, 0x350, 1, "World::Tick");
    std::memcpy(pdb.data() + 9 * kBlkSz, syms.data(), syms.size());

    // Build Stream 5: 1 IMAGE_SECTION_HEADER (40 bytes), Section #1 VA=0x1000
    std::vector<uint8_t> secs(40, 0);
    std::memcpy(secs.data(), ".text\0\0\0", 8);
    uint32_t rva = 0x1000;
    std::memcpy(secs.data() + 12, &rva, 4);
    std::memcpy(pdb.data() + 10 * kBlkSz, secs.data(), secs.size());

    // Build Stream 3: DBI header (64 bytes + optionalDbgHeader[6]=secHdrStream after sub-streams)
    std::vector<uint8_t> dbi(64 + 12 * 2, 0);
    auto put32 = [&](size_t off, int32_t val) { std::memcpy(dbi.data() + off, &val, 4); };
    auto putu16 = [&](size_t off, uint16_t val) { std::memcpy(dbi.data() + off, &val, 2); };
    put32(0, -1); // verSignature
    put32(4, 19990903);
    putu16(20, 4); // symRecordStreamIndex = 4
    put32(48, 24); // OptionalDbgHeaderSize = 12 * u16 (substream sizes are 0)
    putu16(64 + 5 * 2, 5); // dbgHdr[5] (SECTION_HDR) = stream 5
    std::memcpy(pdb.data() + 8 * kBlkSz, dbi.data(), dbi.size());

    // Build Stream Directory in Block 4 (6 streams: 0..5)
    std::vector<uint8_t> dir;
    append_u32(dir, 6);
    append_u32(dir, 0); // stream 0 size
    append_u32(dir, 0); // stream 1 size
    append_u32(dir, 0); // stream 2 size
    append_u32(dir, static_cast<uint32_t>(dbi.size()));  // stream 3
    append_u32(dir, static_cast<uint32_t>(syms.size())); // stream 4
    append_u32(dir, static_cast<uint32_t>(secs.size())); // stream 5
    append_u32(dir, 8);  // block of stream 3
    append_u32(dir, 9);  // block of stream 4
    append_u32(dir, 10); // block of stream 5
    std::memcpy(pdb.data() + 4 * kBlkSz, dir.data(), dir.size());

    // Block 3: directory map -> Block 4
    uint32_t map_blk = 4;
    std::memcpy(pdb.data() + 3 * kBlkSz, &map_blk, 4);

    // Block 0: SuperBlock
    static constexpr const char kMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
    std::memcpy(pdb.data(), kMagic, 32);
    auto sb_u32 = [&](size_t off, uint32_t val) { std::memcpy(pdb.data() + off, &val, 4); };
    sb_u32(32, kBlkSz);
    sb_u32(36, 1);
    sb_u32(40, kNumBlocks);
    sb_u32(44, static_cast<uint32_t>(dir.size()));
    sb_u32(48, 0);
    sb_u32(52, 3); // directoryMapBlock = 3
    return pdb;
}

} // namespace

TEST_CASE("NCE3 encrypted loopback (SHA256-CTR + HMAC) and remote debug/watch state RPCs") {
    hal::RemoteServer srv(
        [] { return std::make_unique<RemoteV3MockProcess>(); },
        [] { return std::vector<hal::ProcessInfo>{{4242, "mock_v3"}}; }
    );
    REQUIRE(srv.start("127.0.0.1", 0, "top-secret-v3"));
    const uint16_t port = srv.bound_port();
    REQUIRE(port > 0);

    // Wrong token must still fail
    {
        hal::RemoteProcess bad;
        CHECK(!bad.connect("127.0.0.1", port, "wrong-token"));
    }

    // Matching token activates transparent NCE3 session encryption
    auto cli = std::make_shared<hal::RemoteProcess>();
    REQUIRE(cli->connect("127.0.0.1", port, "top-secret-v3"));
    CHECK(cli->is_encrypted());
    CHECK(cli->protocol_version() == 3);
    REQUIRE(cli->attach(4242));

    uint32_t v = 0;
    REQUIRE(cli->read_raw(0x600000, &v, sizeof(v)));
    CHECK(v == 0x2A2A2A2Au);

    const uint32_t nv = 0xCAFEBABEu;
    REQUIRE(cli->write_raw(0x600010, &nv, sizeof(nv)));
    uint32_t back = 0;
    REQUIRE(cli->read_raw(0x600010, &back, sizeof(back)));
    CHECK(back == 0xCAFEBABEu);

    // Remote state / watch poll over encrypted channel
    bool active = true;
    std::vector<hal::RemoteWatchHit> whits;
    CHECK(cli->remote_watch_poll(active, whits));
    CHECK(!active);

    hal::RemoteDebugState st;
    CHECK(cli->remote_dbg_state(st));
    CHECK(!st.attached);

    cli->disconnect();
    srv.stop();
}

TEST_CASE("MSF 7.00 PDBReader parses local synthetic PDB and resolves RVA and names") {
    const auto bytes = build_synthetic_msf7_pdb();
    debugger::PDBReader rdr;
    REQUIRE(rdr.load_bytes(bytes));
    CHECK(rdr.symbols().size() == 2);

    auto sym = rdr.find_by_rva(0x1120 + 0x10); // Section .text (0x1000) + 0x120 + 0x10
    REQUIRE(sym.has_value());
    CHECK(sym->first.name == "Player::TakeDamage");
    CHECK(sym->second == 0x10);

    const auto matches = rdr.find_by_name("tick");
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].name == "World::Tick");
    CHECK(matches[0].rva == 0x1350);
}

TEST_CASE("EngineInspector v3 detects Godot and generates C++20 SDK.hpp and .CT XML") {
    RemoteV3MockProcess proc;
    proc.attach(4242);
    const auto det = view::EngineInspector::detect(proc);
    CHECK(det.kind == view::GameEngineKind::Godot);

    std::vector<view::SdkClassDef> defs;
    view::SdkClassDef player;
    player.namespaze = "Game";
    player.name = "APlayer";
    player.size = 0x40;
    player.fields = {
        {0x18, 4, "int32_t", "Health", "100", "", 0},
        {0x20, 4, "float", "Stamina", "55.5", "", 0},
    };
    defs.push_back(player);

    const std::string hdr = view::EngineInspector::generate_sdk_header(defs);
    CHECK(hdr.find("struct Game_APlayer") != std::string::npos);
    CHECK(hdr.find("_pad_0_0[0x18]") != std::string::npos);
    CHECK(hdr.find("int32_t Health; // +0x18") != std::string::npos);
    CHECK(hdr.find("float Stamina; // +0x20") != std::string::npos);

    const std::string xml = view::EngineInspector::generate_sdk_cheat_table_xml(defs, 0x500000);
    CHECK(xml.find("APlayer::Health") != std::string::npos);
    CHECK(xml.find("500018") != std::string::npos);
    CHECK(xml.find("<VariableType>Float</VariableType>") != std::string::npos);
}

TEST_CASE("PluginManager discovers, enables, dispatches hooks, and invokes custom Lua commands") {
    namespace fs = std::filesystem;
    const fs::path pdir = fs::temp_directory_path() / "nce_v3_plugin_test";
    std::error_code ec;
    fs::remove_all(pdir, ec);
    fs::create_directories(pdir, ec);

    {
        std::ofstream f(pdir / "demo_ext.lua", std::ios::binary | std::ios::trunc);
        f << "-- PLUGIN_NAME: Demo V3 Plugin\n"
          << "-- PLUGIN_VERSION: 3.1\n"
          << "g_attach_seen = 0\n"
          << "function onAttach() g_attach_seen = g_attach_seen + 1 end\n"
          << "function onCustomPing(arg) print('PONG:' .. arg) end\n"
          << "registerPluginCommand('pingv3', 'Test ping', 'onCustomPing', 'demo_ext')\n";
    }

    session::Session ses(std::make_shared<RemoteV3MockProcess>(), nullptr);
    auto& pm = ses.plugins();
    pm.clear_search_dirs();
    pm.add_search_dir(pdir);
    REQUIRE(pm.scan_plugins() == 1);
    REQUIRE(pm.enable_plugin("demo_ext"));

    pm.dispatch_hook("onAttach");
    std::string out;
    REQUIRE(pm.invoke_command("pingv3", "hello", out));
    CHECK(out.find("PONG:hello") != std::string::npos);

    const auto ev = ses.eval_lua_expression("g_attach_seen");
    CHECK(ev.success);
    CHECK(ev.output == "1");

    CHECK(pm.disable_plugin("demo_ext"));
    fs::remove_all(pdir, ec);
}

TEST_CASE("Updater compares SemVer tags cleanly and parses GitHub Release JSON") {
    CHECK(utils::Updater::is_newer_version("v3.0.1", "3.0.0"));
    CHECK(utils::Updater::is_newer_version("v3.1.0", "v3.0.9"));
    CHECK(utils::Updater::is_newer_version("v4.0.0", "3.9.9"));
    CHECK(!utils::Updater::is_newer_version("v3.0.0", "3.0.0"));
    CHECK(!utils::Updater::is_newer_version("v2.9.9", "3.0.0"));
    CHECK(!utils::Updater::is_newer_version("v3.0.0-rc1", "3.0.0"));
    CHECK(utils::Updater::is_newer_version("v3.0.0", "3.0.0-rc1"));

    const char* sample_json = R"({
        "tag_name": "v3.1.0",
        "html_url": "https://github.com/AshrafCode519/New-Cheat-Engine/releases/tag/v3.1.0",
        "body": "Performance & v3.1 fixes",
        "assets": [
            { "name": "NCE-v3.1.0-linux-x64.tar.gz", "size": 123456, "browser_download_url": "https://example.com/linux.tar.gz" },
            { "name": "NCE-v3.1.0-windows-x64.zip", "size": 234567, "browser_download_url": "https://example.com/win.zip" }
        ]
    })";

    const auto win_info = utils::Updater::parse_github_release_json(sample_json, "3.0.0", true);
    CHECK(win_info.ok);
    CHECK(win_info.update_available);
    CHECK(win_info.latest_version == "3.1.0");
    CHECK(win_info.asset_name == "NCE-v3.1.0-windows-x64.zip");
    CHECK(win_info.asset_url == "https://example.com/win.zip");

    const auto lin_info = utils::Updater::parse_github_release_json(sample_json, "3.0.0", false);
    CHECK(lin_info.ok);
    CHECK(lin_info.asset_name == "NCE-v3.1.0-linux-x64.tar.gz");

    const auto up_to_date = utils::Updater::parse_github_release_json(sample_json, "3.1.0", true);
    CHECK(up_to_date.ok);
    CHECK(!up_to_date.update_available);

    const auto bad = utils::Updater::parse_github_release_json("not json", "3.0.0", true);
    CHECK(!bad.ok);
}
