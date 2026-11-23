#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "view/structure_dissector.hpp"
#include <cstring>
#include <memory>

using namespace nce;
using test::FakeProcess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// Builds a 64-bit MSVC RTTI chain for class "Player" in the fake process:
//   object -> vtable; [vtable-8] -> COL; COL.pSelf/pTypeDescriptor are RVAs; TypeDescriptor.name is mangled.
// Offsets are module-relative (module base = kBase). Returns the object's address.
struct RttiFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    std::vector<hal::ModuleInfo> modules;

    static constexpr size_t kObject = 0x2000;
    static constexpr size_t kVtable = 0x3000;
    static constexpr size_t kCol = 0x4000;
    static constexpr size_t kTypeDesc = 0x5000;

    RttiFixture() {
        process->add_module("game.exe", 0x0, 0x8000);

        // vtable: three function pointers into the module, then a non-pointer to end the count
        process->put_pointer(kVtable + 0x00, kBase + 0x100);
        process->put_pointer(kVtable + 0x08, kBase + 0x108);
        process->put_pointer(kVtable + 0x10, kBase + 0x110);
        process->put<uint64_t>(kVtable + 0x18, 0); // not a code pointer -> stops at 3

        // the CompleteObjectLocator pointer sits one slot before the vtable
        process->put_pointer(kVtable - 0x08, kBase + kCol);
        process->put<uint32_t>(kCol + 0x14, kCol);      // pSelf RVA -> module base = COL - pSelf = kBase
        process->put<uint32_t>(kCol + 0x0C, kTypeDesc); // pTypeDescriptor RVA

        const char* mangled = ".?AVPlayer@@";
        process->write_raw(kBase + kTypeDesc + 0x10, mangled, std::strlen(mangled) + 1);

        // the object itself
        process->put_pointer(kObject + 0x00, kBase + kVtable); // vtable
        process->put<float>(kObject + 0x08, 100.0f);           // health
        process->put<int32_t>(kObject + 0x0C, 42);             // level
        process->put<int64_t>(kObject + 0x10, 5'000'000'000LL);
        modules = process->get_modules();
    }
};

} // anonymous namespace

TEST_CASE("the MSVC and Itanium name manglings are decoded") {
    CHECK(view::demangle_msvc(".?AVPlayer@@") == "Player");
    CHECK(view::demangle_msvc(".?AUStats@@") == "Stats");               // a struct
    CHECK(view::demangle_msvc(".?AVWeapon@game@@") == "game::Weapon");  // a namespace
    CHECK(view::demangle_msvc(".?AVInner@Outer@space@@") == "space::Outer::Inner");
    CHECK(view::demangle_msvc("not a name").empty());

    CHECK(view::demangle_itanium("7MyClass") == "MyClass");
    CHECK(view::demangle_itanium("N4game6WeaponE") == "game::Weapon");
    CHECK(view::demangle_itanium("Player") == "Player"); // not length-prefixed: unchanged
}

TEST_CASE("the dissector recovers the class name and vtable from MSVC RTTI") {
    RttiFixture f;
    view::StructureDissector d(f.process);

    const auto cls = d.class_from_vtable(kBase + RttiFixture::kVtable, f.modules);
    REQUIRE(cls.has_value());
    CHECK(*cls == "Player");
    CHECK(d.vtable_function_count(kBase + RttiFixture::kVtable, f.modules) == 3);

    // a pointer that isn't a vtable gives nothing
    CHECK_FALSE(d.class_from_vtable(kBase + 0x2000, f.modules));
    CHECK(d.vtable_function_count(kBase + 0x7000, f.modules) == 0);
}

TEST_CASE("the dissector lays out an object's fields and exports a C++ struct") {
    RttiFixture f;
    view::StructureDissector d(f.process);
    const auto layout = d.dissect(kBase + RttiFixture::kObject, 0x18, f.modules);

    CHECK(layout.class_name == "Player");
    CHECK(layout.vtable_functions == 3);
    REQUIRE(layout.fields.size() >= 4);

    CHECK(layout.fields[0].offset == 0);
    CHECK(layout.fields[0].name == "vtable");
    CHECK(layout.fields[0].note.find("vtable of Player") != std::string::npos);

    CHECK(layout.fields[1].offset == 8);
    CHECK(layout.fields[1].type == "float");
    CHECK(layout.fields[1].value == "100");

    CHECK(layout.fields[2].offset == 0xC);
    CHECK(layout.fields[2].type == "int32_t");
    CHECK(layout.fields[2].value == "42");

    CHECK(layout.fields[3].offset == 0x10);
    CHECK(layout.fields[3].type == "int64_t");

    const std::string cpp = layout.to_cpp();
    CHECK(cpp.find("struct Player {") != std::string::npos);
    CHECK(cpp.find("void** vtable;") != std::string::npos);
    CHECK(cpp.find("float field_8;") != std::string::npos);
    CHECK(cpp.find("RTTI class Player") != std::string::npos);
}

TEST_CASE("the dissector reads char* and pointers to other RTTI objects") {
    RttiFixture f;
    // a char* at object+0x20 pointing to a string, and a Player* at object+0x28
    const char* text = "CyberWarrior";
    f.process->write_raw(kBase + 0x7000, text, std::strlen(text) + 1);
    f.process->put_pointer(RttiFixture::kObject + 0x20, kBase + 0x7000);

    // another object at 0x6000 whose vtable is the Player vtable
    f.process->put_pointer(0x6000, kBase + RttiFixture::kVtable);
    f.process->put_pointer(RttiFixture::kObject + 0x28, kBase + 0x6000);

    view::StructureDissector d(f.process);
    const auto layout = d.dissect(kBase + RttiFixture::kObject, 0x30, f.modules);

    const view::StructField* str = nullptr;
    const view::StructField* obj = nullptr;
    for (const auto& field : layout.fields) {
        if (field.offset == 0x20) str = &field;
        if (field.offset == 0x28) obj = &field;
    }
    REQUIRE(str);
    CHECK(str->type == "char*");
    CHECK(str->note.find("CyberWarrior") != std::string::npos);
    REQUIRE(obj);
    CHECK(obj->type == "Player*");
    CHECK(obj->note.find("points to a Player") != std::string::npos);
}

TEST_CASE("the dissector copes with unreadable memory") {
    RttiFixture f;
    f.process->make_unreadable(RttiFixture::kObject + 0x100, 0x40);
    view::StructureDissector d(f.process);
    const auto layout = d.dissect(kBase + RttiFixture::kObject, 0x140, f.modules);
    bool saw_unreadable = false;
    for (const auto& field : layout.fields) {
        if (field.note == "unreadable") saw_unreadable = true;
    }
    CHECK(saw_unreadable);
    CHECK(layout.class_name == "Player"); // the readable head still dissects
}
