#include <doctest/doctest.h>
#include "hal/process_linux.hpp"

using namespace nce;
using namespace nce::hal;
using namespace nce::hal::linux_utils;

TEST_CASE("Linux HAL: parse_maps_line on x86_64 ELF and Proton paths") {
    SUBCASE("Standard Linux executable mapping") {
        std::string line = "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/mygame";
        auto parsed = parse_maps_line(line);
        REQUIRE(parsed.has_value());
        CHECK(parsed->start_addr == 0x00400000);
        CHECK(parsed->end_addr == 0x00452000);
        CHECK(parsed->readable == true);
        CHECK(parsed->writable == false);
        CHECK(parsed->executable == true);
        CHECK(parsed->is_private == true);
        CHECK(parsed->offset == 0);
        CHECK(parsed->pathname == "/usr/bin/mygame");
    }

    SUBCASE("Writable data mapping with COW") {
        std::string line = "00652000-00655000 rw-p 00052000 08:02 173521 /usr/bin/mygame";
        auto parsed = parse_maps_line(line);
        REQUIRE(parsed.has_value());
        CHECK(parsed->start_addr == 0x00652000);
        CHECK(parsed->end_addr == 0x00655000);
        CHECK(parsed->readable == true);
        CHECK(parsed->writable == true);
        CHECK(parsed->executable == false);
        CHECK(parsed->is_private == true);
        CHECK(parsed->offset == 0x52000);
    }

    SUBCASE("Anonymous memory (heap/alloc)") {
        std::string line = "01a2b000-01c00000 rw-p 00000000 00:00 0 [heap]";
        auto parsed = parse_maps_line(line);
        REQUIRE(parsed.has_value());
        CHECK(parsed->start_addr == 0x01a2b000);
        CHECK(parsed->end_addr == 0x01c00000);
        CHECK(parsed->pathname == "[heap]");
    }

    SUBCASE("Proton Windows PE module path on Steam Deck") {
        std::string line = "140000000-140500000 r-xp 00000000 00:35 5283921 /home/deck/.local/share/Steam/steamapps/compatdata/123/drive_c/game/EldenRing.exe";
        auto parsed = parse_maps_line(line);
        REQUIRE(parsed.has_value());
        CHECK(parsed->start_addr == 0x140000000ULL);
        CHECK(parsed->end_addr == 0x140500000ULL);
        CHECK(parsed->executable == true);
        CHECK(parsed->pathname.find("EldenRing.exe") != std::string::npos);
    }
}

TEST_CASE("Linux HAL: permissions_to_protect conversion") {
    CHECK(permissions_to_protect(true, true, true) == 0x40);  // PAGE_EXECUTE_READWRITE
    CHECK(permissions_to_protect(true, false, true) == 0x20); // PAGE_EXECUTE_READ
    CHECK(permissions_to_protect(false, false, true) == 0x10); // PAGE_EXECUTE
    CHECK(permissions_to_protect(true, true, false) == 0x04); // PAGE_READWRITE
    CHECK(permissions_to_protect(true, false, false) == 0x02); // PAGE_READONLY
    CHECK(permissions_to_protect(false, false, false) == 0x01); // PAGE_NOACCESS
}

TEST_CASE("Linux HAL: parse_maps_to_regions with filters") {
    std::string sample_maps =
        "00400000-00420000 r-xp 00000000 08:01 123 /bin/game\n"
        "00620000-00622000 r--p 00020000 08:01 123 /bin/game\n"
        "00622000-00625000 rw-p 00022000 08:01 123 /bin/game\n"
        "01000000-01050000 rw-p 00000000 00:00 0   [heap]\n"
        "7fff0000-7fff1000 ---p 00000000 00:00 0   \n";

    SUBCASE("All valid committed regions") {
        auto regions = parse_maps_to_regions(sample_maps, 0);
        CHECK(regions.size() == 5);
        CHECK(regions[0].base_address == 0x00400000);
        CHECK(regions[0].raw_protection == 0x20); // RX
        CHECK(regions[2].raw_protection == 0x04); // RW
    }

    SUBCASE("WritableOnly filter") {
        auto regions = parse_maps_to_regions(sample_maps, FilterFlags::WritableOnly);
        CHECK(regions.size() == 2); // data + heap
        CHECK(regions[0].base_address == 0x00622000);
        CHECK(regions[1].base_address == 0x01000000);
    }

    SUBCASE("ExecutableOnly filter") {
        auto regions = parse_maps_to_regions(sample_maps, FilterFlags::ExecutableOnly);
        CHECK(regions.size() == 1); // code
        CHECK(regions[0].base_address == 0x00400000);
    }

    SUBCASE("ExcludeNoAccess filter") {
        auto regions = parse_maps_to_regions(sample_maps, FilterFlags::ExcludeNoAccess);
        CHECK(regions.size() == 4); // excludes ---p
    }
}

TEST_CASE("Linux HAL: parse_maps_to_modules aggregation") {
    std::string sample_maps =
        "00400000-00420000 r-xp 00000000 08:01 123 /bin/game\n"
        "00620000-00622000 r--p 00020000 08:01 123 /bin/game\n"
        "00622000-00625000 rw-p 00022000 08:01 123 /bin/game\n"
        "7f000000-7f050000 r-xp 00000000 08:01 456 /lib/libc.so.6\n"
        "7f050000-7f060000 rw-p 00050000 08:01 456 /lib/libc.so.6\n";

    auto modules = parse_maps_to_modules(sample_maps);
    REQUIRE(modules.size() == 2);

    CHECK(modules[0].name == "game");
    CHECK(modules[0].base_address == 0x00400000);
    CHECK(modules[0].size == (0x00625000 - 0x00400000));

    CHECK(modules[1].name == "libc.so.6");
    CHECK(modules[1].base_address == 0x7f000000);
    CHECK(modules[1].size == (0x7f060000 - 0x7f000000));
}

TEST_CASE("Linux HAL: Proton and Wine detection and Game name extraction") {
    SUBCASE("Proton command lines") {
        std::string cmd1 = "proton waitforexitandrun /home/deck/.steam/steamapps/common/Cyberpunk 2077/bin/x64/Cyberpunk2077.exe";
        CHECK(is_proton_or_wine(cmd1));
        CHECK(extract_game_name_from_cmdline(cmd1) == "Cyberpunk2077.exe");

        std::string cmd2 = "/usr/bin/wine64-preloader C:\\Program Files\\Game\\EldenRing.exe";
        CHECK(is_proton_or_wine(cmd2));
        CHECK(extract_game_name_from_cmdline(cmd2) == "EldenRing.exe");
    }

    SUBCASE("Native Linux process") {
        std::string cmd = "/usr/bin/htop -d 10";
        CHECK_FALSE(is_proton_or_wine(cmd));
    }
}

#ifndef _WIN32
#include "debugger/debug_coordinator.hpp"
#include "debugger/elf_analyzer.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fstream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

volatile int32_t g_linux_live_marker = 0x13572468;

int read_yama_ptrace_scope() {
    std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
    int scope = 0;
    if (f.is_open() && (f >> scope)) return scope;
    return 0;
}

} // namespace

TEST_CASE("Linux HAL live: LinuxProcess self-attach, maps, read/write, and ELFAnalyzer") {
    auto proc = hal::IProcess::create();
    const uint32_t self_pid = static_cast<uint32_t>(getpid());
    REQUIRE(proc->attach(self_pid));
    CHECK(proc->is_attached());
    CHECK(proc->get_pid() == self_pid);
    CHECK_FALSE(proc->name().empty());

    const auto all_procs = hal::IProcess::list_processes();
    CHECK_FALSE(all_procs.empty());

    const auto regions = proc->query_regions();
    CHECK_FALSE(regions.empty());

    const auto mods = proc->get_modules();
    REQUIRE_FALSE(mods.empty());

    const uintptr_t addr = reinterpret_cast<uintptr_t>(&g_linux_live_marker);
    int32_t val = 0;
    REQUIRE(proc->read(addr, val));
    CHECK(val == 0x13572468);

    // Find module containing this binary and run live ELFAnalyzer against process RAM
    uintptr_t self_base = 0;
    for (const auto& m : mods) {
        if (addr >= m.base_address && addr < m.base_address + m.size) {
            self_base = m.base_address;
            break;
        }
    }
    if (self_base != 0 && debugger::ELFAnalyzer::is_elf_magic(*proc, self_base)) {
        auto elf = debugger::ELFAnalyzer::analyze(*proc, self_base);
        REQUIRE(elf.has_value());
        CHECK(elf->is_valid);
        CHECK(elf->is_64bit);
        CHECK_FALSE(elf->segments.empty());
    }

    proc->detach();
    CHECK_FALSE(proc->is_attached());
}

TEST_CASE("Linux HAL live: child process attach, remote mmap, and DebugCoordinator ptrace") {
    if (read_yama_ptrace_scope() >= 2) {
        MESSAGE("Skipping child ptrace test because /proc/sys/kernel/yama/ptrace_scope >= 2");
        return;
    }

    int pipe_fd[2]{-1, -1};
    REQUIRE(pipe(pipe_fd) == 0);

    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        close(pipe_fd[1]);
        char buf = 0;
        // Block waiting for parent to close pipe or finish testing (retry on EINTR during ptrace)
        for (;;) {
            const ssize_t r = read(pipe_fd[0], &buf, 1);
            if (r == 0 || (r < 0 && errno != EINTR)) break;
        }
        close(pipe_fd[0]);
        _exit(0);
    }

    close(pipe_fd[0]);
    // Give child a moment to enter blocking read()
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    auto proc = hal::IProcess::create();
    REQUIRE(proc->attach(static_cast<uint32_t>(child)));

    int32_t marker = 0;
    const uintptr_t marker_addr = reinterpret_cast<uintptr_t>(&g_linux_live_marker);
    REQUIRE(proc->read(marker_addr, marker));
    CHECK(marker == 0x13572468);

    REQUIRE(proc->write(marker_addr, int32_t{0x2468ACE0}));
    int32_t updated = 0;
    REQUIRE(proc->read(marker_addr, updated));
    CHECK(updated == 0x2468ACE0);

    const uintptr_t cave = proc->allocate_memory(4096, 0x40);
    REQUIRE(cave != 0);
    const uint8_t nop_ret[4] = {0x90, 0x90, 0x90, 0xC3};
    REQUIRE(proc->write_raw(cave, nop_ret, sizeof(nop_ret), true));
    uint8_t rb[4]{};
    REQUIRE(proc->read_raw(cave, rb, sizeof(rb)));
    CHECK(rb[0] == 0x90);
    CHECK(rb[3] == 0xC3);
    CHECK(proc->free_memory(cave, 4096));

    // Attach DebugCoordinator using Linux ptrace backend, pause, read registers, and detach
    debugger::DebugCoordinator dbg(proc);
    REQUIRE(dbg.attach());
    CHECK(dbg.is_attached());
    CHECK(dbg.pause());
    for (int i = 0; i < 40 && !dbg.is_paused(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (dbg.is_paused()) {
        CHECK(dbg.registers().rip != 0);
        CHECK(dbg.resume());
    }
    dbg.detach();
    CHECK_FALSE(dbg.is_attached());

    proc->detach();
    close(pipe_fd[1]);
    int st = 0;
    waitpid(child, &st, 0);
}
#endif
