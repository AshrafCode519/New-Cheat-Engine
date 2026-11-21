#include <doctest/doctest.h>
#include "test_helpers.hpp"
#include "hal/hotkeys.hpp"
#include "session/session.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <set>
#include <thread>

using namespace nce;
using scanner::DataType;
using test::FakeProcess;
using Action = table::Hotkey::Action;

namespace {

constexpr uintptr_t kBase = FakeProcess::kBase;

// Hotkeys without the keyboard: set() records the combos, deliver() presses one
class FakeHotkeys : public hal::IHotkeys {
public:
    std::vector<std::string> registered;
    std::set<std::string> held_elsewhere; // combos another program has
    Handler handler;

    void on_press(Handler h) override { handler = std::move(h); }
    std::vector<std::string> set(const std::vector<std::string>& combos) override {
        registered.clear();
        std::vector<std::string> failed;
        for (const auto& c : combos) {
            if (held_elsewhere.count(c)) failed.push_back(c);
            else registered.push_back(c);
        }
        return failed;
    }
    bool deliver(const std::string& combo) override {
        if (std::find(registered.begin(), registered.end(), combo) == registered.end()) return false;
        handler(combo);
        return true;
    }
};

template <typename T>
T value_at(session::Session& s, FakeProcess& p, size_t offset) {
    return s.table().with([&](const auto&, const auto&) {
        T v{};
        p.read_raw(kBase + offset, &v, sizeof v);
        return v;
    });
}

template <typename Pred>
bool eventually(Pred pred) {
    for (int i = 0; i < 40; ++i) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

struct HotkeyFixture {
    std::shared_ptr<FakeProcess> process = std::make_shared<FakeProcess>(0x10000);
    FakeHotkeys* hotkeys = nullptr; // owned by the session
    std::unique_ptr<session::Session> s;
    std::vector<std::pair<std::string, session::Outcome>> heard;

    HotkeyFixture() {
        process->add_module("game.exe", 0x0, 0x1000);
        process->put<int32_t>(0x200, 100);   // Health
        process->put<float>(0x204, 10.0f);   // Mana
        process->put<uint8_t>(0x208, 250);   // Ammo
        auto fake = std::make_unique<FakeHotkeys>();
        hotkeys = fake.get();
        s = std::make_unique<session::Session>(process, std::move(fake));
        REQUIRE(s->attach(1).ok);
        REQUIRE(s->table().add_address(kBase + 0x200, DataType::Int32, "Health").ok);
        REQUIRE(s->table().add_address(kBase + 0x204, DataType::Float, "Mana").ok);
        REQUIRE(s->table().add_address(kBase + 0x208, DataType::UInt8, "Ammo").ok);
        s->table().on_hotkey([this](const std::string& combo, const session::Outcome& outcome) {
            heard.emplace_back(combo, outcome);
        });
    }
};

} // anonymous namespace

TEST_CASE("key combos are read in any case and order, and keys every program types need a modifier") {
    CHECK(hal::normalize_hotkey("ctrl+f1") == "Ctrl+F1");
    CHECK(hal::normalize_hotkey("Shift+Alt+num+") == "Alt+Shift+Num+");
    CHECK(hal::normalize_hotkey("numpad5") == "Num5");
    CHECK(hal::normalize_hotkey("Ctrl + PgUp") == "Ctrl+PageUp");
    CHECK(hal::normalize_hotkey("ctrl+alt+del") == "Ctrl+Alt+Delete");
    CHECK(hal::normalize_hotkey("F24") == "F24");
    CHECK(hal::normalize_hotkey("Win+Ctrl+Z") == "Ctrl+Win+Z");
    CHECK(hal::normalize_hotkey("Num*") == "Num*");

    std::string why;
    CHECK_FALSE(hal::parse_hotkey("F25", &why));
    CHECK(why.find("not a key") != std::string::npos);
    CHECK_FALSE(hal::parse_hotkey("W", &why));
    CHECK(why.find("stop you typing it") != std::string::npos);
    CHECK_FALSE(hal::parse_hotkey("Shift+W"));  // Shift alone still takes capital W away
    CHECK(hal::parse_hotkey("Alt+W"));
    CHECK_FALSE(hal::parse_hotkey("Ctrl+Space") == std::nullopt);
    CHECK_FALSE(hal::parse_hotkey("Up"));
    CHECK_FALSE(hal::parse_hotkey("Ctrl", &why));
    CHECK(why.find("has no key") != std::string::npos);
    CHECK_FALSE(hal::parse_hotkey(""));
    CHECK_FALSE(hal::parse_hotkey("Ctrl++"));
}

TEST_CASE("hotkeys toggle freezing, set values and add to them") {
    HotkeyFixture f;
    auto& table = f.s->table();

    const auto added = table.add_hotkey(0, "f1", Action::ToggleFreeze, "");
    REQUIRE(added.ok);
    CHECK(added.message == "#0 Health: F1: toggle freeze");
    CHECK(f.hotkeys->registered == std::vector<std::string>{"F1"});

    REQUIRE(f.hotkeys->deliver("F1"));
    REQUIRE(f.heard.size() == 1);
    CHECK(f.heard[0].first == "F1");
    CHECK(f.heard[0].second.message == "Health: frozen at 100");
    CHECK(table.entry(0)->frozen_value == "100");
    REQUIRE(f.hotkeys->deliver("F1"));
    CHECK(f.heard[1].second.message == "Health: unfrozen");
    CHECK_FALSE(table.entry(0)->frozen_value);

    REQUIRE(table.add_hotkey(0, "Ctrl+F2", Action::Set, "999").ok);
    CHECK(table.press("ctrl+f2").message == "Health: set to 999");
    CHECK(value_at<int32_t>(*f.s, *f.process, 0x200) == 999);

    REQUIRE(table.add_hotkey(1, "F3", Action::Add, "-2.5").ok);
    CHECK(table.press("F3").message == "Mana: 10 -> 7.5");
    CHECK(value_at<float>(*f.s, *f.process, 0x204) == 7.5f);

    // Integers are clamped to their type
    REQUIRE(table.add_hotkey(2, "F4", Action::Add, "+10").ok);
    CHECK(table.press("F4").message == "Ammo: 250 -> 255");
    CHECK(value_at<uint8_t>(*f.s, *f.process, 0x208) == 255);

    // A frozen entry stays frozen, at the new value
    REQUIRE(table.freeze(0, "50").ok);
    REQUIRE(table.add_hotkey(0, "F5", Action::Add, "25").ok);
    CHECK(table.press("F5").ok);
    CHECK(table.entry(0)->frozen_value == "75");

    // One combo, several entries; adding again on the same entry replaces its action
    REQUIRE(table.add_hotkey(1, "F1", Action::ToggleFreeze, "").ok);
    const auto both = table.press("F1");
    CHECK(both.message == "Health: unfrozen; Mana: frozen at 7.5");
    REQUIRE(table.add_hotkey(1, "F1", Action::Set, "1").ok);
    CHECK(table.entry(1)->hotkeys.size() == 2); // F3 and F1
    CHECK(f.hotkeys->registered.size() == 5);   // F1 Ctrl+F2 F3 F4 F5, each once
}

TEST_CASE("hotkeys explain what can't be bound or done") {
    HotkeyFixture f;
    auto& table = f.s->table();
    CHECK(table.add_hotkey(0, "W", Action::ToggleFreeze, "").message.find("stop you typing it") != std::string::npos);
    CHECK(table.add_hotkey(0, "F5", Action::Set, "abc").message == "'abc' is not a valid i32 value.");
    CHECK(table.add_hotkey(0, "F5", Action::Set, "").message == "Give the value the hotkey sets.");
    CHECK(table.add_hotkey(0, "F5", Action::Add, "lots").message.find("not an amount") != std::string::npos);
    CHECK(table.add_hotkey(9, "F5", Action::ToggleFreeze, "").message == "No table entry #9 (there are 3).");
    CHECK(table.press("F9").message == "No table entry has the hotkey F9.");
    CHECK_FALSE(table.press("nonsense").ok);
    CHECK_FALSE(table.remove_hotkey(0, "F9").ok);
    CHECK(f.hotkeys->registered.empty());

    // Text can be set but not added to
    f.process->put<char>(0x300, 'h');
    REQUIRE(table.with([&](table::CheatTable& t, const auto& modules) {
        t.entries.push_back(table::make_entry(kBase + 0x300, DataType::String, modules, "Name", 4));
        return true;
    }));
    CHECK(table.add_hotkey(3, "F6", Action::Add, "1").message.find("Only numbers") == 0);
    CHECK(table.add_hotkey(3, "F6", Action::Set, "abc").ok);

    // A combo another program holds is kept but won't fire
    f.hotkeys->held_elsewhere.insert("F7");
    const auto taken = table.add_hotkey(0, "F7", Action::ToggleFreeze, "");
    CHECK(taken.ok);
    CHECK(taken.message.find("Another program already holds F7") != std::string::npos);
    CHECK(table.hotkeys_taken() == std::vector<std::string>{"F7"});

    // Without the game, nothing is done
    REQUIRE(table.add_hotkey(0, "F8", Action::Set, "5").ok);
    f.s->detach();
    const auto detached = table.press("F8");
    CHECK_FALSE(detached.ok);
    CHECK(detached.message == "Health: not attached to the game");
}

TEST_CASE("hotkeys follow the table: removed with their entry, saved and loaded with it") {
    HotkeyFixture f;
    auto& table = f.s->table();
    REQUIRE(table.add_hotkey(0, "F1", Action::ToggleFreeze, "").ok);
    REQUIRE(table.add_hotkey(1, "Num5", Action::Add, "-1").ok);
    REQUIRE(table.add_hotkey(1, "Ctrl+F2", Action::Set, "3.5").ok);

    const auto file = (std::filesystem::temp_directory_path() / "nce_hotkeys_table.json").string();
    REQUIRE(table.save(file).ok);

    REQUIRE(table.remove_hotkey(1, "ctrl+f2").ok);
    CHECK(f.hotkeys->registered == std::vector<std::string>{"F1", "Num5"});
    REQUIRE(table.remove(0).ok);
    CHECK(f.hotkeys->registered == std::vector<std::string>{"Num5"});

    const auto loaded = table.load(file);
    std::filesystem::remove(file);
    REQUIRE(loaded.ok);
    CHECK(loaded.message.find("3 hotkeys") != std::string::npos);
    CHECK(f.hotkeys->registered == std::vector<std::string>{"F1", "Num5", "Ctrl+F2"});
    const auto mana = table.entry(1);
    REQUIRE(mana->hotkeys.size() == 2);
    CHECK(mana->hotkeys[1].keys == "Ctrl+F2");
    CHECK(mana->hotkeys[1].action == Action::Set);
    CHECK(mana->hotkeys[1].value == "3.5");
    CHECK(mana->hotkeys[1].to_string() == "Ctrl+F2: set to 3.5");

    // A table with a key this program doesn't know is refused
    table::CheatTable bad;
    bad.entries.push_back(*mana);
    bad.entries[0].hotkeys[0].keys = "F99";
    CHECK_FALSE(table::from_json(table::to_json(bad)));
}

TEST_CASE("the Windows hotkey thread registers combos and passes on presses") {
    auto hotkeys = hal::IHotkeys::create();
    std::mutex mutex;
    std::vector<std::string> pressed;
    hotkeys->on_press([&](const std::string& combo) {
        std::lock_guard<std::mutex> lock(mutex);
        pressed.push_back(combo);
    });
    auto presses = [&] {
        std::lock_guard<std::mutex> lock(mutex);
        return pressed.size();
    };

    const std::string combo = "Ctrl+Alt+Shift+F24"; // a combo nobody uses
    REQUIRE(hotkeys->set({combo}).empty());
    CHECK(hotkeys->deliver(combo)); // a WM_HOTKEY message to the hotkey thread: no keyboard input
    CHECK(eventually([&] { return presses() == 1; }));
    CHECK(pressed[0] == combo);
    CHECK_FALSE(hotkeys->deliver("Ctrl+Alt+Shift+F23"));

    // A combo is held by one registration system-wide: a second one sees it taken
    auto other = hal::IHotkeys::create();
    CHECK(other->set({combo}) == std::vector<std::string>{combo});
    CHECK(hotkeys->set({}).empty());
    CHECK_FALSE(hotkeys->deliver(combo));
    CHECK(other->set({combo}).empty()); // free again
}

TEST_CASE("a table hotkey registered with Windows changes the value when pressed") {
    auto process = std::make_shared<FakeProcess>(0x10000);
    process->add_module("game.exe", 0x0, 0x1000);
    process->put<int32_t>(0x200, 100);
    auto windows = hal::IHotkeys::create();
    auto* hotkeys = windows.get(); // owned by the session
    session::Session s(process, std::move(windows));
    REQUIRE(s.attach(1).ok);
    REQUIRE(s.table().add_address(kBase + 0x200, DataType::Int32, "Health").ok);

    std::atomic<int> heard{0};
    s.table().on_hotkey([&](const std::string&, const session::Outcome& outcome) {
        if (outcome.ok) ++heard;
    });
    const auto added = s.table().add_hotkey(0, "ctrl+alt+shift+f24", Action::Set, "777");
    REQUIRE(added.ok);
    CHECK(added.message.find("won't fire") == std::string::npos);
    CHECK(s.table().hotkeys_taken().empty());

    REQUIRE(hotkeys->deliver("Ctrl+Alt+Shift+F24"));
    CHECK(eventually([&] { return heard == 1; }));
    CHECK(value_at<int32_t>(s, *process, 0x200) == 777);

    REQUIRE(s.table().remove(0).ok); // its hotkey goes with it
    CHECK_FALSE(hotkeys->deliver("Ctrl+Alt+Shift+F24"));
}

TEST_CASE("review: a huge F number is no key (it used to throw), in a combo or a table file") {
    std::string why;
    CHECK_FALSE(hal::parse_hotkey("F99999999999", &why));
    CHECK(why.find("not a key") != std::string::npos);
    CHECK_FALSE(hal::parse_hotkey("Ctrl+F100"));
    CHECK(hal::normalize_hotkey("F09") == "F9");

    table::CheatTable t;
    t.entries.push_back(table::make_entry(kBase + 0x200, DataType::Int32, {}, "Gold"));
    t.entries[0].hotkeys.push_back({"F1", Action::ToggleFreeze, ""});
    auto text = table::to_json(t);
    text.replace(text.find("\"F1\""), 4, "\"F99999999999\"");
    CHECK_FALSE(table::from_json(text));
}

TEST_CASE("review: adding to 64-bit integers is exact and stops at the type's limits") {
    HotkeyFixture f;
    auto& table = f.s->table();
    f.process->put<int64_t>(0x400, 9007199254740993LL); // 2^53 + 1: a double can't hold it
    f.process->put<uint64_t>(0x408, UINT64_MAX - 1);
    f.process->put<int64_t>(0x410, INT64_MIN + 5);
    REQUIRE(table.add_address(kBase + 0x400, DataType::Int64, "Big").ok);
    REQUIRE(table.add_address(kBase + 0x408, DataType::UInt64, "Huge").ok);
    REQUIRE(table.add_address(kBase + 0x410, DataType::Int64, "Low").ok);
    REQUIRE(table.add_hotkey(3, "F13", Action::Add, "1").ok);
    REQUIRE(table.add_hotkey(4, "F14", Action::Add, "10").ok);
    REQUIRE(table.add_hotkey(5, "F15", Action::Add, "-10").ok);
    REQUIRE(table.add_hotkey(3, "F16", Action::Add, "1e30").ok);

    CHECK(table.press("F13").message == "Big: 9007199254740993 -> 9007199254740994");
    CHECK(value_at<int64_t>(*f.s, *f.process, 0x400) == 9007199254740994LL);
    CHECK(table.press("F14").ok);
    CHECK(value_at<uint64_t>(*f.s, *f.process, 0x408) == UINT64_MAX);
    CHECK(table.press("F15").ok);
    CHECK(value_at<int64_t>(*f.s, *f.process, 0x410) == INT64_MIN);
    const auto huge = table.press("F16");
    CHECK_FALSE(huge.ok);
    CHECK(value_at<int64_t>(*f.s, *f.process, 0x400) == 9007199254740994LL); // nothing written
}

TEST_CASE("review: a toggle unfreezes even without the game") {
    HotkeyFixture f;
    auto& table = f.s->table();
    REQUIRE(table.add_hotkey(0, "F1", Action::ToggleFreeze, "").ok);
    REQUIRE(table.press("F1").ok); // frozen at 100
    f.s->detach();
    const auto unfrozen = table.press("F1");
    CHECK(unfrozen.ok);
    CHECK(unfrozen.message == "Health: unfrozen");
    CHECK_FALSE(table.press("F1").ok); // freezing again does need the game
}
