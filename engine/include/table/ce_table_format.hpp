#pragma once

#include "cheat_table.hpp"
#include <string>

namespace nce::table {

// Type serialization helpers
scanner::DataType parse_ce_variable_type(const std::string& type_str);
const char* ce_variable_type_str(scanner::DataType type);

// Parses a Cheat Engine .CT XML table file into an NCE CheatTable structure.
// Supports regular entries (integers, floats, strings, pointers) and Auto Assembler Scripts.
bool parse_ce_table(const std::string& xml_content, CheatTable& out_table, std::string& error_msg);

// Serializes an NCE CheatTable structure into standard Cheat Engine 7.x compatible XML.
[[nodiscard]] std::string serialize_ce_table(const CheatTable& table);

// Convenience file IO helpers
bool load_ce_table_file(const std::string& file_path, CheatTable& out_table, std::string& error_msg);
bool save_ce_table_file(const std::string& file_path, const CheatTable& table, std::string& error_msg);

} // namespace nce::table
