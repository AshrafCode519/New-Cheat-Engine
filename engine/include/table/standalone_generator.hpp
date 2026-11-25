#pragma once

#include "cheat_table.hpp"
#include <string>

namespace nce::table {

enum class TrainerKind {
    Console,      // Command-line interactive Win32 trainer (-mconsole)
    GUI,          // Pure Win32 graphical window trainer (-mwindows)
    LinuxConsole  // Standalone Linux / Steam Deck console trainer (process_vm_writev)
};

// Generates a standalone, dependency-free Win32 C++ source file that can be compiled
// into an independent trainer executable (Console or Native GUI Window).
[[nodiscard]] std::string generate_standalone_trainer_cpp(
    const CheatTable& table,
    const std::string& target_process_name = "",
    TrainerKind kind = TrainerKind::Console
);

// Convenience helper to write the generated C++ code directly to a file
bool export_standalone_trainer_file(
    const std::string& output_file_path,
    const CheatTable& table,
    const std::string& target_process_name,
    std::string& error_msg,
    TrainerKind kind = TrainerKind::Console
);

} // namespace nce::table
