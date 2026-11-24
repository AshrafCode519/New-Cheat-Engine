#include "../../include/session/session.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <type_traits>

namespace nce::session {

namespace {

bool equals_ignore_case(const std::string& a, const std::string& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

std::string no_entry(size_t index, size_t size) {
    return "No table entry #" + std::to_string(index) + " (there are " + std::to_string(size) + ").";
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// "2 entries, 1 frozen, 3 hotkeys"
std::string summary(const table::CheatTable& t) {
    size_t frozen = 0;
    size_t hotkeys = 0;
    for (const auto& e : t.entries) {
        frozen += e.frozen_value ? 1 : 0;
        hotkeys += e.hotkeys.size();
    }
    std::string text = std::to_string(t.entries.size()) + (t.entries.size() == 1 ? " entry" : " entries");
    if (frozen) text += ", " + std::to_string(frozen) + " frozen";
    if (hotkeys) text += ", " + std::to_string(hotkeys) + (hotkeys == 1 ? " hotkey" : " hotkeys");
    return text;
}

// Keeps <file>.bak as a copy of the file. The old copy is removed first: MinGW's copy_file fails when the
// target exists, even with overwrite_existing.
bool keep_copy(const std::filesystem::path& file) {
    const std::filesystem::path copy = file.string() + ".bak";
    std::error_code ec;
    std::filesystem::remove(copy, ec);
    std::filesystem::copy_file(file, copy, ec);
    return !ec;
}

bool write_text(const std::filesystem::path& file, const std::string& text) {
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out << text;
    return static_cast<bool>(out);
}

} // anonymous namespace

// ---- TableKeeper ---------------------------------------------------------------------------------

TableKeeper::TableKeeper(std::shared_ptr<hal::IProcess> process, std::unique_ptr<hal::IHotkeys> hotkeys)
    : m_process(std::move(process))
    , m_hotkeys(std::move(hotkeys))
{
    if (m_hotkeys) {
        m_hotkeys->on_press([this](const std::string& combo) {
            const Outcome outcome = press(combo);
            std::function<void(const std::string&, const Outcome&)> listener;
            {
                std::lock_guard<std::mutex> lock(m_listener_mutex);
                listener = m_listener;
            }
            if (listener) listener(combo, outcome);
        });
    }
    m_freeze_thread = std::thread([this] { freeze_loop(); });
}

TableKeeper::~TableKeeper() {
    m_hotkeys.reset(); // stops the hotkey thread first: its presses use this object
    m_running = false;
    if (m_freeze_thread.joinable()) m_freeze_thread.join();
    autosave(false); // the changes since the last automatic save
}

// Every 100 ms: writes the frozen values. Every 2 s: saves the table to the library if it changed.
void TableKeeper::freeze_loop() {
    for (size_t tick = 1; m_running; ++tick) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_process->is_attached() && m_process->can_write()) {
                for (const auto& e : m_table.entries) {
                    if (e.frozen_value) table::write_entry(e, *e.frozen_value, *m_process, m_modules);
                }
            }
        }
        if (tick % 20 == 0) autosave(false);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

TableKeeper::AttachResult TableKeeper::attach(uint32_t pid) {
    AttachResult result;
    bool table_changed = false;
    {
        std::lock_guard<std::mutex> saving(m_save_mutex);
        std::lock_guard<std::mutex> lock(m_mutex);
        result.attached = m_process->attach(pid);
        m_modules = result.attached ? m_process->get_modules() : std::vector<hal::ModuleInfo>{};
        if (result.attached) result.table_note = switch_table_locked(m_process->name(), table_changed);

        // Absolute addresses belong to an earlier process; module-relative entries only resolve if this one
        // has the same module, so they stay frozen
        for (auto& e : m_table.entries) {
            if (e.is_absolute() && e.frozen_value) {
                e.frozen_value.reset();
                ++result.unfrozen;
            }
        }
        // Permanent entries find their value now, before the freeze thread writes through last run's path
        if (result.attached) result.reconciled = reconcile_locked();

        // A fresh assembler for this process (its caves and symbols belong to the old one); then re-apply
        // the scripts the table saved as on, like freezes resume
        m_active.clear();
        if (result.attached) {
            m_assembler = std::make_unique<assembler::AutoAssembler>(m_process);
            result.scripts_note = reapply_scripts_locked();
        } else {
            m_assembler.reset();
        }
    }
    if (table_changed) rebind(); // the hotkeys of the table now open
    return result;
}

// On attach: re-enable the scripts the table saved as on. A script that fails (its pattern isn't found, a
// line won't assemble) is turned off and named in the note, so the user knows it isn't applied.
std::string TableKeeper::reapply_scripts_locked() {
    size_t on = 0;
    std::string failures;
    for (size_t i = 0; i < m_table.scripts.size(); ++i) {
        if (!m_table.scripts[i].enabled) continue;
        const auto outcome = set_script_enabled_locked(i, true);
        if (outcome.ok) ++on;
        else failures += (failures.empty() ? "" : "; ") + m_table.scripts[i].name + " (" + outcome.message + ")";
    }
    std::string note;
    if (on) note = "Re-applied " + std::to_string(on) + (on == 1 ? " script" : " scripts") + ".";
    if (!failures.empty()) note += (note.empty() ? "" : " ") + std::string("Could not apply: ") + failures + ".";
    return note;
}

// The same program again (a restart) keeps the table. Another program: the table goes to the library
// (if it has entries), and that program's table comes out of it, or a new one starts. A table that
// belongs to no program yet (made or loaded before attaching) is adopted, unless it is empty and the
// library has one for this program.
std::string TableKeeper::switch_table_locked(const std::string& program, bool& changed) {
    if (m_library.empty() || program.empty()) return {};
    const std::string owner = m_table.process_name;
    if (equals_ignore_case(owner, program)) return {};

    const auto file = library_file_locked(program);
    std::error_code ec;
    const bool in_library = std::filesystem::exists(file, ec);
    std::string note;
    if (owner.empty()) {
        if (!m_table.entries.empty() || !in_library) {
            m_table.process_name = program;
            m_saved_text.clear(); // the first save keeps the library's own table as .bak
            return in_library ? "This table is " + program + "'s now; the library's earlier table of it will be kept as " +
                                    library_file_locked(program).filename().string() + ".bak."
                              : std::string();
        }
    } else if (!m_table.entries.empty()) {
        const auto saved_to = library_file_locked(owner);
        if (m_saved_text.empty() && std::filesystem::exists(saved_to, ec)) { // not opened from there: keep that one
            keep_copy(saved_to);
        }
        note = write_text(saved_to, table::to_json(m_table))
            ? "Kept the table of " + owner + " (" + summary(m_table) + ") in the library. "
            : "Could not save the table of " + owner + " to " + saved_to.string() + "! ";
    }

    changed = true;
    if (in_library) {
        if (auto loaded = table::load_table(file.string())) {
            m_table = std::move(*loaded);
            m_table.process_name = program;
            m_saved_text = table::to_json(m_table);
            return note + "Opened the table of " + program + " from the library: " + summary(m_table) + ".";
        }
        note += "Could not read " + file.string() + "; ";
    }
    m_table = {};
    m_table.process_name = program;
    m_saved_text.clear();
    return note + "New table for " + program + ".";
}

void TableKeeper::detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Undo running scripts while the handle is still open, so the target isn't left patched. The enabled
    // flags stay as they are, so the next attach re-applies them.
    if (m_assembler) {
        for (auto& s : m_table.scripts) {
            if (const auto it = m_active.find(s.name); it != m_active.end()) m_assembler->disable(s.body, it->second);
        }
    }
    m_active.clear();
    m_assembler.reset();
    m_process->detach();
    m_modules.clear();
}

std::vector<TableKeeper::ReconcileLine> TableKeeper::reconcile() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return reconcile_locked();
}

std::vector<TableKeeper::ReconcileLine> TableKeeper::reconcile_locked() {
    std::vector<ReconcileLine> lines;
    if (!m_process->is_attached()) return lines;
    for (size_t i = 0; i < m_table.entries.size(); ++i) {
        auto& e = m_table.entries[i];
        if (e.alternatives.empty()) continue;
        lines.push_back({i, e.description.empty() ? e.location_string() : e.description,
                         table::reconcile(e, *m_process, m_modules)});
    }
    return lines;
}

Outcome TableKeeper::add_result(const scanner::ScanResults& results, size_t index, std::string description) {
    if (index >= results.count()) {
        return Outcome::fail("No result #" + std::to_string(index) + " (there are " + std::to_string(results.count()) + ").");
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(results.address(index), results.type(), m_modules,
                                                std::move(description), results.value_size()));
    const auto& e = m_table.entries.back();
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " + e.location_string() +
                            (e.is_absolute() ? "  (heap address: only valid until the target restarts)" : ""));
}

Outcome TableKeeper::add_address(uintptr_t address, scanner::DataType type, std::string description) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(address, type, m_modules, std::move(description)));
    const auto& e = m_table.entries.back();
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " + e.location_string() +
                            (e.is_absolute() ? "  (heap address: only valid until the target restarts)" : ""));
}

Outcome TableKeeper::add_pointer(const scanner::PointerPath& path, scanner::DataType type, std::string description) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.entries.push_back(table::make_entry(path, type, std::move(description)));
    return Outcome::success("Added #" + std::to_string(m_table.entries.size() - 1) + ": " +
                            m_table.entries.back().location_string());
}

Outcome TableKeeper::set_value(size_t index, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    auto& e = m_table.entries[index];
    if (!m_process->is_attached() || !table::write_entry(e, value, *m_process, m_modules)) {
        return Outcome::fail("Could not write '" + value + "' to #" + std::to_string(index) +
                             " (invalid value, text too long, aob entry, or address not resolvable).");
    }
    if (e.frozen_value) e.frozen_value = value; // keep a frozen entry at the new value
    return Outcome::success("#" + std::to_string(index) + " set to " + value);
}

Outcome TableKeeper::freeze(size_t index, std::optional<std::string> value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    auto& e = m_table.entries[index];
    if (!value) {
        auto current = m_process->is_attached() ? table::read_entry(e, *m_process, m_modules) : std::nullopt;
        if (!current) return Outcome::fail("Can't read #" + std::to_string(index) + " to freeze it; give a value.");
        value = value_text(*current);
    }
    e.frozen_value = *value;
    return Outcome::success("#" + std::to_string(index) + " frozen at " + *value);
}

Outcome TableKeeper::unfreeze(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
    m_table.entries[index].frozen_value.reset();
    return Outcome::success("#" + std::to_string(index) + " unfrozen.");
}

size_t TableKeeper::unfreeze_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (auto& e : m_table.entries) {
        if (e.frozen_value) {
            e.frozen_value.reset();
            ++count;
        }
    }
    return count;
}

Outcome TableKeeper::remove(size_t index) {
    bool had_hotkeys = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
        had_hotkeys = !m_table.entries[index].hotkeys.empty();
        m_table.entries.erase(m_table.entries.begin() + static_cast<std::ptrdiff_t>(index));
    }
    if (had_hotkeys) rebind();
    return Outcome::success("Removed #" + std::to_string(index) + ".");
}

Outcome TableKeeper::save(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_table.process_name.empty() && !m_modules.empty()) m_table.process_name = m_modules.front().name;
    if (!table::save_table(path, m_table)) return Outcome::fail("Could not write " + path + ".");
    return Outcome::success("Saved " + std::to_string(m_table.entries.size()) + " entries to " + path + ".");
}

Outcome TableKeeper::load(const std::string& path, std::vector<ReconcileLine>* reconciled) {
    auto loaded = table::load_table(path);
    if (!loaded) return Outcome::fail("Could not read a table from " + path + ".");
    std::string message;
    {
        std::lock_guard<std::mutex> saving(m_save_mutex);
        autosave_saving(false); // the open table's latest changes
        std::lock_guard<std::mutex> lock(m_mutex);
        // Undo the current table's running scripts before it is replaced, then forget them
        if (m_assembler) {
            for (size_t i = 0; i < m_table.scripts.size(); ++i) {
                if (m_table.scripts[i].enabled) set_script_enabled_locked(i, false);
            }
        }
        m_active.clear();
        m_table = std::move(*loaded);
        m_saved_text.clear(); // not from the library: the first save keeps the library's own table as .bak
        const std::string program = m_process->is_attached() ? m_process->name() : std::string();
        if (!m_library.empty() && !program.empty()) m_table.process_name = program;
        size_t frozen = 0;
        size_t hotkeys = 0;
        for (const auto& e : m_table.entries) {
            frozen += e.frozen_value ? 1 : 0;
            hotkeys += e.hotkeys.size();
        }
        message = "Loaded " + std::to_string(m_table.entries.size()) + " entries for '" + m_table.process_name + "'";
        if (frozen) message += ", " + std::to_string(frozen) + " frozen";
        if (hotkeys) message += ", " + std::to_string(hotkeys) + " hotkeys";
        if (!m_table.scripts.empty()) message += ", " + std::to_string(m_table.scripts.size()) + " scripts";
        message += ".";
        auto lines = m_process->is_attached() ? reconcile_locked() : std::vector<ReconcileLine>{};
        if (reconciled) *reconciled = std::move(lines);
        const std::string scripts_note = (m_assembler ? reapply_scripts_locked() : std::string());
        if (!scripts_note.empty()) message += " " + scripts_note;
    }
    rebind();
    return Outcome::success(message);
}

std::optional<table::TableEntry> TableKeeper::entry(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return std::nullopt;
    return m_table.entries[index];
}

Outcome TableKeeper::make_permanent(size_t index, const table::TableEntry& scanned,
                                    const std::vector<scanner::PointerPath>& paths) {
    if (paths.empty()) {
        return Outcome::fail("No static pointer path leads to it; it stays valid only until the target restarts.");
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid(index)) return Outcome::fail("The table changed during the search; try again.");
    auto& e = m_table.entries[index];
    const bool same = e.location.module_name == scanned.location.module_name &&
                      e.location.base_offset == scanned.location.base_offset &&
                      e.location.offsets == scanned.location.offsets;
    if (!same) return Outcome::fail("The table changed during the search; try again.");

    table::make_permanent(e, paths, *m_process, m_modules);
    return Outcome::success("#" + std::to_string(index) + " is permanent: " + e.location_string() + " (+" +
                            std::to_string(e.alternatives.size()) + " other paths that find it after a restart).");
}

size_t TableKeeper::size() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_table.entries.size();
}

std::vector<hal::ModuleInfo> TableKeeper::modules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_modules;
}

void TableKeeper::refresh_modules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_process->is_attached()) m_modules = m_process->get_modules();
}

// ---- Hotkeys -------------------------------------------------------------------------------------

namespace {

std::string entry_name(const table::TableEntry& e) {
    return e.description.empty() ? e.location_string() : e.description;
}

bool numeric_type(scanner::DataType type) {
    return scanner::dispatch_numeric(type, []<typename T>() {});
}

std::optional<double> parse_amount(std::string text) {
    if (!text.empty() && text[0] == '+') text.erase(0, 1);
    double amount = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), amount);
    if (text.empty() || ec != std::errc() || end != text.data() + text.size() || !std::isfinite(amount)) return std::nullopt;
    return amount;
}

// The value plus the amount, as text to write: integers are clamped to their type, floats keep every digit
std::optional<std::string> add_amount(const scanner::ScanValue& current, const std::string& amount_text) {
    const auto amount = parse_amount(amount_text);
    if (!amount) return std::nullopt;
    std::optional<std::string> result;
    scanner::dispatch_numeric(current.type, [&]<typename T>() {
        const T value = std::get<T>(current.value);
        T sum{};
        if constexpr (std::is_floating_point_v<T>) {
            sum = static_cast<T>(value + *amount);
        } else {
            // Exact integer arithmetic that stops at the type's limits (a double can't hold every 64-bit value)
            if (!(std::fabs(*amount) < 9.0e18)) return;
            const long long delta = std::llround(*amount);
            if constexpr (std::is_signed_v<T>) {
                long long total = 0;
                if (__builtin_add_overflow(static_cast<long long>(value), delta, &total)) {
                    total = delta > 0 ? std::numeric_limits<long long>::max() : std::numeric_limits<long long>::min();
                }
                sum = static_cast<T>(std::clamp<long long>(total, std::numeric_limits<T>::lowest(), std::numeric_limits<T>::max()));
            } else {
                const unsigned long long v = value;
                unsigned long long total = 0;
                if (delta >= 0) {
                    if (__builtin_add_overflow(v, static_cast<unsigned long long>(delta), &total)) {
                        total = std::numeric_limits<unsigned long long>::max();
                    }
                } else {
                    const unsigned long long down = 0ULL - static_cast<unsigned long long>(delta);
                    total = v < down ? 0 : v - down;
                }
                sum = static_cast<T>(std::min<unsigned long long>(total, std::numeric_limits<T>::max()));
            }
        }
        char text[64];
        const auto [end, ec] = std::to_chars(text, text + sizeof text, sum);
        if (ec == std::errc()) result = std::string(text, end);
    });
    return result;
}

} // anonymous namespace

Outcome TableKeeper::add_hotkey(size_t index, const std::string& keys, table::Hotkey::Action action, const std::string& value) {
    using Action = table::Hotkey::Action;
    std::string error;
    const auto combo = hal::parse_hotkey(keys, &error);
    if (!combo) return Outcome::fail(error);
    table::Hotkey hotkey{hal::format_hotkey(*combo), action, action == Action::ToggleFreeze ? std::string() : value};

    std::string name;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
        auto& e = m_table.entries[index];
        name = entry_name(e);
        if (action == Action::Set) {
            if (value.empty()) return Outcome::fail("Give the value the hotkey sets.");
            if (e.type == scanner::DataType::AOB) return Outcome::fail("An AOB entry can't be set; toggle freeze works.");
            if (numeric_type(e.type) && !utils::parse_scan_value(e.type, value)) {
                return Outcome::fail("'" + value + "' is not a valid " + utils::format_data_type(e.type) + " value.");
            }
        } else if (action == Action::Add) {
            if (!numeric_type(e.type)) return Outcome::fail("Only numbers can be added to; set or toggle freeze work.");
            if (!parse_amount(value)) return Outcome::fail("'" + value + "' is not an amount to add (like 100 or -10).");
        }
        auto existing = std::find_if(e.hotkeys.begin(), e.hotkeys.end(), [&](const auto& h) { return h.keys == hotkey.keys; });
        if (existing != e.hotkeys.end()) *existing = hotkey;
        else e.hotkeys.push_back(hotkey);
    }
    rebind();

    const auto taken = hotkeys_taken();
    std::string message = "#" + std::to_string(index) + " " + name + ": " + hotkey.to_string();
    if (std::find(taken.begin(), taken.end(), hotkey.keys) != taken.end()) {
        message += ". Another program already holds " + hotkey.keys + ", so it won't fire: pick another key.";
    }
    return Outcome::success(message);
}

Outcome TableKeeper::remove_hotkey(size_t index, const std::string& keys) {
    const std::string combo = hal::normalize_hotkey(keys);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!valid(index)) return Outcome::fail(no_entry(index, m_table.entries.size()));
        auto& hotkeys = m_table.entries[index].hotkeys;
        const auto it = std::find_if(hotkeys.begin(), hotkeys.end(), [&](const auto& h) { return h.keys == combo; });
        if (combo.empty() || it == hotkeys.end()) {
            return Outcome::fail("#" + std::to_string(index) + " has no hotkey " + keys + ".");
        }
        hotkeys.erase(it);
    }
    rebind();
    return Outcome::success("Removed the hotkey " + combo + " from #" + std::to_string(index) + ".");
}

Outcome TableKeeper::press(const std::string& keys) {
    const std::string combo = hal::normalize_hotkey(keys);
    if (combo.empty()) return Outcome::fail("'" + keys + "' is not a key combination.");

    std::vector<std::string> results;
    bool ok = true;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& e : m_table.entries) {
            for (const auto& h : e.hotkeys) {
                if (h.keys != combo) continue;
                const Outcome done = apply_hotkey(e, h);
                ok = ok && done.ok;
                results.push_back(entry_name(e) + ": " + done.message);
            }
        }
    }
    if (results.empty()) return Outcome::fail("No table entry has the hotkey " + combo + ".");

    std::string message;
    for (const auto& r : results) message += (message.empty() ? "" : "; ") + r;
    return {ok, message};
}

Outcome TableKeeper::apply_hotkey(table::TableEntry& e, const table::Hotkey& h) {
    using Action = table::Hotkey::Action;
    if (h.action == Action::ToggleFreeze && e.frozen_value) { // unfreezing needs no game
        e.frozen_value.reset();
        return Outcome::success("unfrozen");
    }
    if (!m_process->is_attached()) return Outcome::fail("not attached to the game");

    if (h.action == Action::ToggleFreeze) {
        const auto current = table::read_entry(e, *m_process, m_modules);
        if (!current) return Outcome::fail("can't read it to freeze it");
        e.frozen_value = value_text(*current);
        return Outcome::success("frozen at " + *e.frozen_value);
    }

    std::string next = h.value;
    std::string before;
    if (h.action == Action::Add) {
        // A frozen entry's value is the frozen one: memory may hold something else between two freeze writes
        const auto current = e.frozen_value ? utils::parse_scan_value(e.type, *e.frozen_value)
                                            : table::read_entry(e, *m_process, m_modules);
        if (!current) return Outcome::fail("can't read it");
        const auto sum = add_amount(*current, h.value);
        if (!sum) return Outcome::fail("can't add " + h.value);
        before = value_text(*current);
        next = *sum;
    }
    if (!table::write_entry(e, next, *m_process, m_modules)) return Outcome::fail("couldn't write " + next);
    if (e.frozen_value) e.frozen_value = next; // a frozen entry stays frozen, at the new value
    return Outcome::success(h.action == Action::Add ? before + " -> " + next : "set to " + next);
}

void TableKeeper::on_hotkey(std::function<void(const std::string&, const Outcome&)> listener) {
    std::lock_guard<std::mutex> lock(m_listener_mutex);
    m_listener = std::move(listener);
}

std::vector<std::string> TableKeeper::hotkeys_taken() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_taken;
}

// ---- Table library -------------------------------------------------------------------------------

std::filesystem::path default_library_folder() {
#ifdef _WIN32
    if (const wchar_t* appdata = _wgetenv(L"APPDATA"); appdata && *appdata) {
        return std::filesystem::path(appdata) / "NewCheatEngine" / "tables";
    }
#endif
    if (const char* config = std::getenv("XDG_CONFIG_HOME"); config && *config) {
        return std::filesystem::path(config) / "new-cheat-engine" / "tables";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".config" / "new-cheat-engine" / "tables";
    }
    return "tables";
}

// ---- Auto-Assembler scripts ----------------------------------------------------------------------

Outcome TableKeeper::add_script(const std::string& name, const std::string& body) {
    const std::string clean = name.empty() ? "script" : name;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& s : m_table.scripts) {
        if (s.name == clean) return Outcome::fail("A script named '" + clean + "' already exists.");
    }
    m_table.scripts.push_back({clean, body, false});
    return Outcome::success("Added script '" + clean + "' (off). Turn it on to apply it.");
}

Outcome TableKeeper::set_script_body(size_t index, const std::string& body) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid_script(index)) return Outcome::fail("No script #" + std::to_string(index) + ".");
    if (m_table.scripts[index].enabled) set_script_enabled_locked(index, false); // its old patch is undone first
    m_table.scripts[index].body = body;
    return Outcome::success("Updated script '" + m_table.scripts[index].name + "' (off).");
}

Outcome TableKeeper::set_script_enabled(size_t index, bool on) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return set_script_enabled_locked(index, on);
}

// Enables or disables the script by running its [ENABLE] / [DISABLE] through the assembler. With m_mutex
// held, so the freeze thread doesn't write while a script is patching.
Outcome TableKeeper::set_script_enabled_locked(size_t index, bool on) {
    if (!valid_script(index)) return Outcome::fail("No script #" + std::to_string(index) + ".");
    auto& s = m_table.scripts[index];
    if (!m_assembler) return Outcome::fail("Attach to the game first.");

    if (on) {
        if (m_active.count(s.name)) return Outcome::success("'" + s.name + "' is already on.");
        auto result = m_assembler->enable(s.body);
        if (!result.ok) { s.enabled = false; return Outcome::fail(result.message); }
        m_active[s.name] = std::move(result.effect);
        s.enabled = true;
        return Outcome::success("'" + s.name + "' on: " + result.message);
    }

    const auto it = m_active.find(s.name);
    if (it == m_active.end()) { s.enabled = false; return Outcome::success("'" + s.name + "' is already off."); }
    auto result = m_assembler->disable(s.body, it->second);
    m_active.erase(it);
    s.enabled = false;
    return Outcome::success("'" + s.name + "' off: " + result.message);
}

Outcome TableKeeper::remove_script(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid_script(index)) return Outcome::fail("No script #" + std::to_string(index) + ".");
    if (m_table.scripts[index].enabled) set_script_enabled_locked(index, false);
    const std::string name = m_table.scripts[index].name;
    m_table.scripts.erase(m_table.scripts.begin() + static_cast<std::ptrdiff_t>(index));
    return Outcome::success("Removed script '" + name + "'.");
}

std::optional<table::TableScript> TableKeeper::script(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!valid_script(index)) return std::nullopt;
    return m_table.scripts[index];
}

size_t TableKeeper::script_count() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_table.scripts.size();
}

void TableKeeper::set_library(std::filesystem::path folder) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_library = std::move(folder);
    m_saved_text.clear(); // the new folder doesn't have the table yet
}

std::filesystem::path TableKeeper::library() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_library;
}

std::filesystem::path TableKeeper::library_file() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return library_file_locked(m_table.process_name);
}

std::filesystem::path TableKeeper::library_file_locked(const std::string& program) const {
    if (m_library.empty() || program.empty()) return {};
    const std::string name = lower(program) + ".json";
    return m_library / std::filesystem::path(std::u8string(name.begin(), name.end()));
}

Outcome TableKeeper::save_to_library() {
    return autosave(true);
}

// Saves the open table to its library file if it changed since the last save. An empty table gets no new
// file: attaching to a program and adding nothing leaves nothing behind.
Outcome TableKeeper::autosave(bool force) {
    std::lock_guard<std::mutex> saving(m_save_mutex);
    return autosave_saving(force);
}

Outcome TableKeeper::autosave_saving(bool force) {
    std::filesystem::path file;
    std::string text;
    bool keep_old = false; // the file holds a table this run never opened from the library
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        file = library_file_locked(m_table.process_name);
        if (file.empty()) {
            return Outcome::fail(m_library.empty() ? "The table library is off."
                                                   : "The table belongs to no program yet: attach first.");
        }
        text = table::to_json(m_table);
        if (!force && text == m_saved_text) return Outcome::success();
        std::error_code ec;
        const bool exists = std::filesystem::exists(file, ec);
        if (m_table.entries.empty() && !exists) return Outcome::fail("The table is empty.");
        keep_old = exists && m_saved_text.empty();
    }
    if (keep_old && !keep_copy(file)) {
        return Outcome::fail("Could not keep a copy of " + file.string() + "; nothing was written over it.");
    }
    if (!write_text(file, text)) return Outcome::fail("Could not write " + file.string() + ".");
    std::lock_guard<std::mutex> lock(m_mutex);
    if (library_file_locked(m_table.process_name) == file) m_saved_text = text;
    return Outcome::success("Saved the table to " + file.string() + ".");
}

// The hotkey thread runs press(), which takes m_mutex, while set() waits for that thread to register the
// keys. Calling set() with m_mutex held could deadlock, so the combos are collected under the lock and
// registered after releasing it.
void TableKeeper::rebind() {
    if (!m_hotkeys) return;
    std::lock_guard<std::mutex> rebinding(m_rebind_mutex);
    std::vector<std::string> combos;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& e : m_table.entries) {
            for (const auto& h : e.hotkeys) {
                if (std::find(combos.begin(), combos.end(), h.keys) == combos.end()) combos.push_back(h.keys);
            }
        }
    }
    auto taken = m_hotkeys->set(combos);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_taken = std::move(taken);
}

std::string describe_reconcile(const table::ReconcileResult& r) {
    std::string text;
    if (r.resolved == 0) {
        return "none of its " + std::to_string(r.paths) + " paths resolve here (another program?)";
    }
    if (r.ambiguous) {
        return "close vote (" + std::to_string(r.agreeing) + " of " + std::to_string(r.resolved) + " paths agree on " +
               utils::format_address(r.address) + "): check the value; nothing dropped";
    }
    text = "found at " + utils::format_address(r.address) + " (" + std::to_string(r.agreeing) + " of " +
           std::to_string(r.resolved) + " paths lead there";
    if (r.context_words > 0) {
        text += "; surroundings match " + std::to_string(r.context_matches) + "/" + std::to_string(r.context_words) + " words";
    }
    if (r.value_matches) text += "; same value as when saved";
    if (r.by_context) text += "; chosen by its surroundings over the most-voted address";
    text += ")";
    if (r.changed) text += ", kept those paths";
    return text;
}

// ---- Session -------------------------------------------------------------------------------------

Session::Session(std::shared_ptr<hal::IProcess> process, std::unique_ptr<hal::IHotkeys> hotkeys)
    : m_process(std::move(process))
    , m_table(std::make_unique<TableKeeper>(m_process, std::move(hotkeys)))
{}

Session::AttachReport Session::attach(uint32_t pid) {
    m_watcher.stop(); // belonged to the previous process
    AttachReport report;
    const auto attached = m_table->attach(pid);
    report.ok = attached.attached;
    report.unfrozen = attached.unfrozen;
    report.table_note = attached.table_note;
    report.scripts_note = attached.scripts_note;
    m_scans.clear();
    m_noise.reset();
    if (!report.ok) {
        m_scanner.reset();
        m_scans.set_scanner(nullptr, nullptr);
        return report;
    }

    m_scanner = std::make_shared<scanner::MemoryScanner>(m_process);
    m_scans.set_scanner(m_scanner, m_process);
    report.read_only = !m_process->can_write();
    report.reconciled = attached.reconciled;
    return report;
}

void Session::detach() {
    m_watcher.stop();
    m_table->detach();
    m_scans.clear();
    m_scans.set_scanner(nullptr, nullptr);
    m_scanner.reset();
    m_noise.reset();
}

bool Session::watch(uintptr_t address, size_t size, debugger::WatchKind kind) {
    if (!attached()) return false;
    return m_watcher.start(m_process, address, size, kind);
}

std::optional<hal::ProcessInfo> Session::find_restart() const {
    const std::string name = m_process->name();
    if (name.empty() || m_process->get_pid() == 0) return std::nullopt;
    for (const auto& p : hal::IProcess::list_processes()) {
        if (p.pid != m_process->get_pid() && equals_ignore_case(p.name, name)) return p;
    }
    return std::nullopt;
}

std::shared_ptr<scanner::NoiseMap> Session::learn_noise(const scanner::NoiseOptions& options,
                                                        const std::atomic<bool>* stop) const {
    auto noise = std::make_shared<scanner::NoiseMap>();
    noise->learn(*m_process, options, stop);
    return noise;
}

void Session::set_noise(std::shared_ptr<scanner::NoiseMap> noise) {
    m_noise = std::move(noise);
    if (m_scanner) m_scanner->set_noise_map(m_noise);
}

std::string Session::describe_noise() const {
    if (!m_noise || m_noise->empty()) return "none known";
    std::string text = std::to_string(m_noise->noisy_slots()) + " addresses ignored";
    if (m_noise->skipped_bytes() > 0) text += ", " + format_size(m_noise->skipped_bytes()) + " skipped";
    return text;
}

void Session::refresh(view::MemoryView& view) {
    if (attached()) view.refresh(*m_process, m_table->modules(), m_noise.get());
}

std::unique_ptr<scanner::ValueTracker> Session::new_tracker(std::vector<scanner::DataType> types) const {
    auto tracker = std::make_unique<scanner::ValueTracker>(m_process, std::move(types));
    tracker->set_noise_map(m_noise);
    return tracker;
}

std::vector<scanner::PointerPath> Session::find_permanent_paths(const table::TableEntry& entry) {
    return table::find_permanent_paths(entry, m_process, m_table->modules());
}

} // namespace nce::session
