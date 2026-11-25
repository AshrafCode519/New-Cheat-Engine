#ifdef _WIN32

#include <doctest/doctest.h>
#include "hal/process.hpp"
#include "debugger/hook_engine.hpp"
#include "debugger/disassembler.hpp"
#include "speedhack/speedhack.hpp"
#include <windows.h>
#include <thread>
#include <chrono>

using namespace nce;

TEST_CASE("HookEngine installs detour and restores original function") {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(GetCurrentProcessId()));

    // Allocate an executable buffer in this process
    uintptr_t code_addr = process->allocate_memory(256, PAGE_EXECUTE_READWRITE);
    REQUIRE(code_addr != 0);

    // Write a function in x86-64 machine code:
    // int test_func(int a, int b) { return a + b; }
    // Windows x64 ABI: a in ECX, b in EDX, return in EAX
    // 8D 04 11             lea eax, [rcx + rdx]
    // 90 90 90 90 90 90 90 NOPs padding up to 16 bytes
    // C3                   ret
    std::vector<uint8_t> func_bytes = {
        0x8D, 0x04, 0x11,                         // lea eax, [rcx + rdx]
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 7 NOPs
        0x90, 0x90, 0x90, 0x90, 0x90,             // 5 NOPs (total 15 bytes)
        0xC3                                      // ret (16th byte)
    };

    REQUIRE(process->write_raw(code_addr, func_bytes.data(), func_bytes.size(), true));

    using TestFunc_t = int (*)(int, int);
    auto test_func = reinterpret_cast<TestFunc_t>(code_addr);

    // Initial test: 20 + 30 = 50
    CHECK(test_func(20, 30) == 50);

    // Create a target destination function:
    // int hook_dest(int a, int b) { return 9999; }
    // B8 0F 27 00 00       mov eax, 9999
    // C3                   ret
    uintptr_t dest_addr = process->allocate_memory(64, PAGE_EXECUTE_READWRITE);
    REQUIRE(dest_addr != 0);
    std::vector<uint8_t> dest_bytes = {
        0xB8, 0x0F, 0x27, 0x00, 0x00, // mov eax, 9999 (0x270F)
        0xC3                          // ret
    };
    REQUIRE(process->write_raw(dest_addr, dest_bytes.data(), dest_bytes.size(), true));

    // Install hook using HookEngine
    debugger::HookEngine hook_engine(process);
    uintptr_t tramp = 0;
    REQUIRE(hook_engine.install_detour(code_addr, dest_addr, &tramp));
    CHECK(hook_engine.is_hooked(code_addr));
    CHECK(tramp != 0);

    // Call test_func now: it should jump to dest_addr and return 9999!
    CHECK(test_func(20, 30) == 9999);

    // Call trampoline directly: it executes stolen instructions and returns 50!
    auto tramp_func = reinterpret_cast<TestFunc_t>(tramp);
    CHECK(tramp_func(20, 30) == 50);

    // Remove hook
    REQUIRE(hook_engine.remove_hook(code_addr));
    CHECK_FALSE(hook_engine.is_hooked(code_addr));

    // Call test_func: should be restored back to original return 50!
    CHECK(test_func(20, 30) == 50);

    process->free_memory(code_addr);
    process->free_memory(dest_addr);
    process->detach();
}

TEST_CASE("Speedhack modifies virtual time progression") {
    std::shared_ptr<hal::IProcess> process = hal::IProcess::create();
    REQUIRE(process->attach(GetCurrentProcessId()));

    speedhack::Speedhack sh(process);
    REQUIRE(sh.attach());
    CHECK(sh.is_installed());

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    // Measure time with 1.0x (normal)
    sh.set_speed(1.0);
    sh.enable();
    CHECK(sh.is_enabled());

    LARGE_INTEGER t1, t2;
    QueryPerformanceCounter(&t1);
    ::Sleep(30);
    QueryPerformanceCounter(&t2);
    double elapsed_1x_ms = static_cast<double>(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
    CHECK(elapsed_1x_ms >= 20.0);
    CHECK(elapsed_1x_ms <= 80.0);

    // Measure time with 4.0x speed
    sh.set_speed(4.0);
    QueryPerformanceCounter(&t1);
    ::Sleep(30);
    QueryPerformanceCounter(&t2);
    double elapsed_4x_ms = static_cast<double>(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
    INFO("elapsed_1x_ms: ", elapsed_1x_ms, " elapsed_4x_ms: ", elapsed_4x_ms);
    CHECK(elapsed_4x_ms > 85.0);

    // Measure time with 0.25x speed
    sh.set_speed(0.25);
    QueryPerformanceCounter(&t1);
    ::Sleep(40);
    QueryPerformanceCounter(&t2);
    double elapsed_slow_ms = static_cast<double>(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
    INFO("elapsed_slow_ms: ", elapsed_slow_ms, " t1: ", t1.QuadPart, " t2: ", t2.QuadPart);
    CHECK(elapsed_slow_ms < 25.0);

    // Disable speedhack
    sh.disable();
    CHECK_FALSE(sh.is_enabled());
    QueryPerformanceCounter(&t1);
    ::Sleep(30);
    QueryPerformanceCounter(&t2);
    double elapsed_disabled_ms = static_cast<double>(t2.QuadPart - t1.QuadPart) * 1000.0 / freq.QuadPart;
    CHECK(elapsed_disabled_ms >= 20.0);
    CHECK(elapsed_disabled_ms <= 80.0);

    // Detach and verify cleanup
    sh.detach();
    CHECK_FALSE(sh.is_installed());

    process->detach();
}

#endif
