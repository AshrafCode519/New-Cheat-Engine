# Contributing to New-Cheat-Engine (NCE)

Thank you for your interest in contributing to **New-Cheat-Engine**!

## Development Prerequisites
- **Windows:** MinGW-w64 (GCC 13+ / MSYS2 MINGW64) or MSVC 2022, CMake 3.20+
- **Linux:** `g++` (GCC 13+ with C++20 support), CMake 3.20+, optional `libx11` runtime for global hotkeys

## Building & Testing Locally

```powershell
# Windows (MinGW)
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j 4
./build/bin/engine_tests.exe
```

```bash
# Linux (GCC)
cmake -S . -B build
cmake --build build -j 4
./build/bin/engine_tests
```

## Guidelines
1. **Cross-Platform Hygiene:** Code under `engine/`, `cli/`, `target_dummy/`, and `tests/` must build cleanly under `-std=c++20 -Wall -Wextra -Wpedantic` on both Windows (MinGW) and Linux (GCC). Guard Windows-specific headers (`<windows.h>`, Win32/VEH APIs) behind `#ifdef _WIN32`.
2. **Tests:** Add or update unit tests in `tests/` (`doctest`) for new features or bug fixes. Verify `engine_tests` passes completely before opening a Pull Request.
3. **Scope:** This repository is strictly for educational reverse engineering, security research, and offline/single-player analysis. PRs targeting online anti-cheat bypasses will be rejected.
