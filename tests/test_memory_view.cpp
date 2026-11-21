#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "session/session.hpp"
#include "utils/hex_utils.hpp"
#include "view/memory_view.hpp"
#include <memory>

using namespace nce;
using test::FakeProcess;
using view::Guess;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// A struct on the "heap" at +0x2000 with one value of each kind; game.exe covers the first 0x1000 bytes
struct ViewFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    std::vector<hal::ModuleInfo> modules;

    ViewFixture() {
        process->add_module("game.exe", 0x0, 0x1000);
        process->put<int32_t>(0x2000, 100);
        process->put<float>(0x2004, 25.5f);
        process->put<uint64_t>(0x2008, kBase + 0x100);  // into game.exe
        process->put<uint64_t>(0x2010, kBase + 0x5000); // into other readable memory
        process->put<double>(0x2018, 12.3456);
        process->put<int64_t>(0x2020, 5'000'000'000LL);
        process->put<uint32_t>(0x2028, 0x65627943);     // "Cybe"
        process->put<uint32_t>(0x2030, 0x8000F00D);
        process->put<int32_t>(0x2034, -1);
        process->put<uint64_t>(0x2038, 0x00007FF600000000ULL); // looks like a pointer, but nothing is there
        modules = process->get_modules();
    }
};

} // anonymous namespace

TEST_CASE("the memory view reads each slot as what it most likely is") {
    ViewFixture f;
    view::MemoryView v;
    v.set_address(kBase + 0x2008, 2, 14);
    REQUIRE(v.slots().size() == 16);
    CHECK(v.focus() == 2);
    CHECK(v.slots()[0].address == kBase + 0x2000);
    CHECK(v.slots()[0].offset == -8);

    v.refresh(*f.process, f.modules);
    const auto& s = v.slots();
    auto at = [&](size_t offset) -> const view::Slot& { return s[(offset - 0x2000) / 4]; };

    CHECK(at(0x2000).guess == Guess::Int);
    CHECK(at(0x2000).value_text() == "100");
    CHECK(at(0x2000).bytes_text() == "64 00 00 00");
    CHECK(view::format_offset(at(0x2000).offset) == "-0x8");
    CHECK(view::format_offset(at(0x2028).offset) == "+0x20");
    CHECK(at(0x2004).guess == Guess::Float);
    CHECK(at(0x2004).value_text() == "25.5");
    CHECK(at(0x2004).data_type() == scanner::DataType::Float);

    CHECK(at(0x2008).guess == Guess::Pointer);
    CHECK(at(0x2008).value_text() == "-> game.exe+0x100");
    CHECK(at(0x200C).guess == Guess::Continued);
    CHECK(at(0x2010).guess == Guess::Pointer);
    CHECK(at(0x2010).target == utils::format_address(kBase + 0x5000));

    CHECK(at(0x2018).guess == Guess::Double);
    CHECK(at(0x2018).value_text() == "12.3456");
    CHECK(at(0x2018).data_type() == scanner::DataType::Double);
    CHECK(at(0x201C).guess == Guess::Continued);
    CHECK(at(0x2020).guess == Guess::Int64);
    CHECK(at(0x2020).value_text() == "5000000000");

    CHECK(at(0x2028).guess == Guess::Text);
    CHECK(at(0x2028).value_text() == "'Cybe'");
    CHECK(at(0x202C).guess == Guess::Zero);
    CHECK(at(0x2030).guess == Guess::Other);
    CHECK(at(0x2030).value_text() == "0x8000F00D");
    CHECK(at(0x2034).guess == Guess::Int);
    CHECK(at(0x2034).value_text() == "-1");

    // Pointer-shaped, but the target has nothing there: two plain halves
    CHECK(at(0x2038).guess == Guess::Zero);
    CHECK(at(0x203C).guess == Guess::Int);
}

TEST_CASE("the memory view marks what changed and what the noise map ignores") {
    ViewFixture f;
    view::MemoryView v;
    v.set_address(kBase + 0x2000, 0, 8);
    v.refresh(*f.process, f.modules);
    CHECK(v.refreshes() == 1);
    for (const auto& slot : v.slots()) CHECK(slot.changes == 0);

    f.process->put<int32_t>(0x2000, 90);
    f.process->put<uint32_t>(0x201C, 0x40290000); // only the upper half of the double
    v.refresh(*f.process, f.modules);
    CHECK(v.slots()[0].changes == 1);
    CHECK(v.slots()[0].age == 0);
    CHECK(v.slots()[1].age == SIZE_MAX); // never changed
    CHECK(v.value_age(6) == 0);          // the double at +0x18 changed through its upper half

    v.refresh(*f.process, f.modules);
    CHECK(v.slots()[0].age == 1);
    CHECK(v.slots()[0].changes == 1);

    // A frame counter at +0x2004, learned as noise
    auto noise = std::make_shared<scanner::NoiseMap>();
    noise->begin(*f.process);
    for (int i = 1; i < 16; ++i) {
        f.process->put<int32_t>(0x2004, i);
        noise->sample(*f.process);
    }
    noise->finish();
    v.refresh(*f.process, f.modules, noise.get());
    CHECK(v.slots()[1].noisy);
    CHECK_FALSE(v.slots()[0].noisy);

    // A new address starts over
    v.set_address(kBase + 0x2000, 0, 8);
    v.refresh(*f.process, f.modules);
    CHECK(v.slots()[0].changes == 0);
    CHECK(v.slots()[0].age == SIZE_MAX);
}

TEST_CASE("on a 32-bit target any 4-aligned slot can hold a pointer") {
    ViewFixture f;
    f.process->set_pointer_size(4);
    f.process->put_pointer(0x2004, kBase + 0x100);
    view::MemoryView v;
    v.set_address(kBase + 0x2004, 1, 3);
    v.refresh(*f.process, f.modules);
    CHECK(v.slots()[0].guess == Guess::Int);
    CHECK(v.slots()[1].guess == Guess::Pointer);
    CHECK(v.slots()[1].value_text() == "-> game.exe+0x100");
    CHECK(v.slots()[1].data_type() == scanner::DataType::UInt32);
    CHECK(v.slots()[2].guess != Guess::Continued);
}

TEST_CASE("the memory view copes with unreadable memory and the start of the address space") {
    ViewFixture f;
    f.process->make_unreadable(0x3000, 0x1000);
    view::MemoryView v;
    v.set_address(kBase + 0x2FF8, 0, 4);
    v.refresh(*f.process, f.modules);
    CHECK(v.slots()[1].readable);
    CHECK_FALSE(v.slots()[2].readable);
    CHECK(v.slots()[2].value_text() == "??");
    CHECK(v.slots()[2].bytes_text() == "?? ?? ?? ??");

    v.set_address(8, 16, 4); // only 2 slots fit before it
    CHECK(v.slots().size() == 6);
    CHECK(v.slots()[0].address == 0);
    CHECK(v.focus() == 2);

    v.set_address(kBase + 0x2003, 1, 1); // unaligned: its slot is the aligned one holding it
    CHECK(v.slots()[1].address == kBase + 0x2000);
    CHECK(v.slots()[1].offset == -3);

    v.clear();
    CHECK(v.empty());

    // Through a session: once the target is gone the last values stay
    session::Session s(f.process);
    REQUIRE(s.attach(1).ok);
    v.set_address(kBase + 0x2000, 0, 2);
    s.refresh(v);
    CHECK(v.slots()[0].value_text() == "100");
    s.detach();
    s.refresh(v);
    CHECK(v.refreshes() == 1);
    CHECK(v.slots()[0].value_text() == "100");
}
