#include "doctest/doctest.h"
#include "table/ce_table_format.hpp"

using namespace nce;
using namespace nce::table;

TEST_CASE("parse_ce_table parses standard Cheat Engine .CT XML tables") {
    const std::string ce_xml = R"(<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="42">
  <CheatEntries>
    <CheatEntry>
      <ID>0</ID>
      <Description>"Player Health"</Description>
      <VariableType>4 Bytes</VariableType>
      <Address>"game.exe"+1000</Address>
    </CheatEntry>
    <CheatEntry>
      <ID>1</ID>
      <Description>"Ammo Pointer"</Description>
      <VariableType>Float</VariableType>
      <Address>"game.exe"+2000</Address>
      <Offsets>
        <Offset>18</Offset>
        <Offset>20</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>2</ID>
      <Description>"God Mode Script"</Description>
      <VariableType>Auto Assembler Script</VariableType>
      <AssemblerScript><![CDATA[[ENABLE]
// God mode injection
alloc(newmem, 1024)
[DISABLE]
dealloc(newmem)
]]></AssemblerScript>
    </CheatEntry>
  </CheatEntries>
</CheatTable>
)";

    CheatTable table;
    std::string err;
    bool ok = parse_ce_table(ce_xml, table, err);

    CHECK(ok);
    CHECK(err.empty());
    REQUIRE(table.entries.size() == 2);
    REQUIRE(table.scripts.size() == 1);

    // Entry 0: Player Health
    CHECK(table.entries[0].description == "Player Health");
    CHECK(table.entries[0].type == scanner::DataType::Int32);
    CHECK(table.entries[0].location.module_name == "game.exe");
    CHECK(table.entries[0].location.base_offset == 0x1000);
    CHECK(table.entries[0].location.offsets.empty());

    // Entry 1: Ammo Pointer (Note reverse order: CE XML has <Offset>18</Offset> then <Offset>20</Offset>)
    // NCE pointer path should be: root 0x20 -> leaf 0x18
    CHECK(table.entries[1].description == "Ammo Pointer");
    CHECK(table.entries[1].type == scanner::DataType::Float);
    CHECK(table.entries[1].location.module_name == "game.exe");
    CHECK(table.entries[1].location.base_offset == 0x2000);
    REQUIRE(table.entries[1].location.offsets.size() == 2);
    CHECK(table.entries[1].location.offsets[0] == 0x20);
    CHECK(table.entries[1].location.offsets[1] == 0x18);

    // Script 0: God Mode Script
    CHECK(table.scripts[0].name == "God Mode Script");
    CHECK(table.scripts[0].body.find("[ENABLE]") != std::string::npos);
    CHECK(table.scripts[0].body.find("alloc(newmem, 1024)") != std::string::npos);
    CHECK(table.scripts[0].body.find("[DISABLE]") != std::string::npos);
}

TEST_CASE("serialize_ce_table roundtrips with parse_ce_table") {
    CheatTable orig;
    
    TableEntry e1;
    e1.description = "Score";
    e1.type = scanner::DataType::Int32;
    e1.location.base_offset = 0x140001000;
    orig.entries.push_back(e1);

    TableEntry e2;
    e2.description = "Speed";
    e2.type = scanner::DataType::Double;
    e2.location.module_name = "physics.dll";
    e2.location.base_offset = 0x500;
    e2.location.offsets = {0x10, 0x28};
    orig.entries.push_back(e2);

    TableScript s1;
    s1.name = "Infinite Stamina";
    s1.body = "[ENABLE]\n// code\n[DISABLE]\n// undo";
    orig.scripts.push_back(s1);

    std::string xml = serialize_ce_table(orig);
    CHECK(xml.find("<CheatTable") != std::string::npos);
    CHECK(xml.find("Score") != std::string::npos);
    CHECK(xml.find("physics.dll") != std::string::npos);
    CHECK(xml.find("Infinite Stamina") != std::string::npos);

    CheatTable parsed;
    std::string err;
    bool ok = parse_ce_table(xml, parsed, err);

    CHECK(ok);
    REQUIRE(parsed.entries.size() == 2);
    REQUIRE(parsed.scripts.size() == 1);

    CHECK(parsed.entries[0].description == "Score");
    CHECK(parsed.entries[0].type == scanner::DataType::Int32);
    CHECK(parsed.entries[0].location.base_offset == 0x140001000);

    CHECK(parsed.entries[1].description == "Speed");
    CHECK(parsed.entries[1].type == scanner::DataType::Double);
    CHECK(parsed.entries[1].location.module_name == "physics.dll");
    CHECK(parsed.entries[1].location.base_offset == 0x500);
    REQUIRE(parsed.entries[1].location.offsets.size() == 2);
    CHECK(parsed.entries[1].location.offsets[0] == 0x10);
    CHECK(parsed.entries[1].location.offsets[1] == 0x28);

    CHECK(parsed.scripts[0].name == "Infinite Stamina");
    CHECK(parsed.scripts[0].body == s1.body);
}
