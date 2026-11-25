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
