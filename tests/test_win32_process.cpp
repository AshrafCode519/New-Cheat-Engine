#ifdef _WIN32

#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "hal/process.hpp"
#include "scanner/memory_scanner.hpp"
#include <windows.h>
#include <memory>

using namespace nce;
using scanner::DataType;
using scanner::ScanCondition;

namespace {
// Distinctive value in .data so the scan has a known address to find
volatile int64_t g_marker = 0x5EED1234ABCD0042LL;
}

TEST_CASE("Win32Process scans, reads and writes a live process (itself)") {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(GetCurrentProcessId()));

    const auto address = reinterpret_cast<uintptr_t>(&g_marker);
    scanner::MemoryScanner ms(process);

    scanner::ScanValue target;
    target.type = DataType::Int64;
    target.value = int64_t{0x5EED1234ABCD0042LL};

    auto results = ms.first_scan(DataType::Int64, ScanCondition::ExactValue, target, {}, 8);
    REQUIRE(test::contains_address(results, address));

    REQUIRE(process->write(address, int64_t{0x5EED1234ABCD0043LL}));
    CHECK(g_marker == 0x5EED1234ABCD0043LL);

    scanner::ScanValue one;
    one.type = DataType::Int64;
    one.value = int64_t{1};
    auto increased = ms.next_scan(results, ScanCondition::IncreasedBy, one);
    CHECK(test::contains_address(increased, address));

    int64_t read_back = 0;
    REQUIRE(process->read(address, read_back));
    CHECK(read_back == 0x5EED1234ABCD0043LL);

    process->detach();
    CHECK_FALSE(process->is_attached());
}

#endif
