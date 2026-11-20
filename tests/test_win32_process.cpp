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

namespace {

DWORD protection_of(const void* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(address, &mbi, sizeof(mbi));
    return mbi.Protect;
}

} // anonymous namespace

TEST_CASE("Win32Process reports its name and write access") {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(GetCurrentProcessId()));
    CHECK(process->name() == "engine_tests.exe");
    CHECK(process->can_write());
}

TEST_CASE("writes leave page protection as it was") {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(GetCurrentProcessId()));

    // A normal writable page stays writable, not RWX (the old write_raw set RWX on every write)
    const auto address = reinterpret_cast<uintptr_t>(&g_marker);
    const DWORD before = protection_of(const_cast<int64_t*>(&g_marker));
    REQUIRE(process->write(address, int64_t{42}));
    CHECK(protection_of(const_cast<int64_t*>(&g_marker)) == before);

    // A read-only page can still be written, and is read-only again afterwards
    auto* page = static_cast<int32_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(page != nullptr);
    DWORD old = 0;
    REQUIRE(VirtualProtect(page, 4096, PAGE_READONLY, &old));
    REQUIRE(process->write(reinterpret_cast<uintptr_t>(page), int32_t{1337}));
    CHECK(*page == 1337);
    CHECK(protection_of(page) == PAGE_READONLY);
    VirtualFree(page, 0, MEM_RELEASE);
}

TEST_CASE("is_attached turns false when the target exits") {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t command[] = L"cmd.exe /c exit 0";
    REQUIRE(CreateProcessW(nullptr, command, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));

    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(pi.dwProcessId)); // our handle keeps the process object around even if it already exited
    REQUIRE(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0);
    CHECK_FALSE(process->is_attached());

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

#endif
