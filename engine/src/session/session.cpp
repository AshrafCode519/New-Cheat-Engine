#include "../../include/session/session.hpp"
#include "../../include/utils/hex_utils.hpp"
#include "table/ce_table_format.hpp"
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
            if (m_lua_runner) m_assembler->set_lua_runner(m_lua_runner);
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
    if (m_process) m_process->detach();
    m_modules.clear();
}

void TableKeeper::set_process(std::shared_ptr<hal::IProcess> process) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_active.clear();
    m_assembler.reset();
    m_modules.clear();
    m_process = std::move(process);
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

    std::string lower_path = lower(path);
    if (lower_path.size() >= 3 && lower_path.compare(lower_path.size() - 3, 3, ".ct") == 0) {
        std::string err;
        if (!table::save_ce_table_file(path, m_table, err)) return Outcome::fail("Could not write Cheat Engine table to " + path + ": " + err);
        return Outcome::success("Saved " + std::to_string(m_table.entries.size()) + " entries and " +
                               std::to_string(m_table.scripts.size()) + " scripts to " + path + " (Cheat Engine .CT format).");
    }

    if (!table::save_table(path, m_table)) return Outcome::fail("Could not write " + path + ".");
    return Outcome::success("Saved " + std::to_string(m_table.entries.size()) + " entries to " + path + ".");
}

Outcome TableKeeper::load(const std::string& path, std::vector<ReconcileLine>* reconciled) {
    std::string lower_path = lower(path);
    std::optional<table::CheatTable> loaded;
    if (lower_path.size() >= 3 && lower_path.compare(lower_path.size() - 3, 3, ".ct") == 0) {
        table::CheatTable ce_table;
        std::string err;
        if (table::load_ce_table_file(path, ce_table, err)) {
            loaded = std::move(ce_table);
        } else {
            return Outcome::fail("Could not read Cheat Engine table: " + err);
        }
    } else {
        loaded = table::load_table(path);
        if (!loaded) {
            table::CheatTable ce_table;
            std::string err;
            if (table::load_ce_table_file(path, ce_table, err)) {
                loaded = std::move(ce_table);
            }
        }
    }
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

void TableKeeper::set_lua_runner(assembler::AutoAssembler::LuaRunner runner) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lua_runner = std::move(runner);
    if (m_assembler) m_assembler->set_lua_runner(m_lua_runner);
}

std::string TableKeeper::lua_script() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_table.lua_script;
}

void TableKeeper::set_lua_script(std::string script) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_table.lua_script = std::move(script);
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
    , m_lua(std::make_unique<script::LuaEngine>(this))
    , m_plugins(std::make_unique<script::PluginManager>(this))
{
    m_table->set_lua_runner([this](const std::string& code, std::string& out_msg) -> bool {
        const auto res = run_lua(code);
        out_msg = res.success ? res.output : res.error;
        return res.success;
    });
    m_plugins->use_default_dirs();
    m_plugins->scan_plugins();
}

Session::AttachReport Session::attach(uint32_t pid) {
    m_watcher.stop(); // belonged to the previous process
    if (m_hook_engine) {
        m_hook_engine->remove_all_hooks();
        m_hook_engine.reset();
    }
    if (m_debugger) {
        m_debugger->detach();
        m_debugger.reset();
    }
    if (m_debug_coordinator) {
        m_debug_coordinator->detach();
        m_debug_coordinator.reset();
    }
    if (m_speedhack) {
        m_speedhack->detach();
        m_speedhack.reset();
    }
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
    {
        std::lock_guard<std::mutex> slock(m_sym_mutex);
        m_pe_cache.clear();
        m_elf_cache.clear();
        m_pdb_cache.clear();
        m_pdb_probed.clear();
    }
    m_remote_watching = false;
    m_remote_watch_addr = 0;
    m_remote_speed_on = false;
    m_remote_speed = 1.0;
    m_ultimap.clear();
    m_speedhack = std::make_unique<speedhack::Speedhack>(m_process);
    m_debug_coordinator = std::make_shared<debugger::DebugCoordinator>(m_process);
    m_debug_coordinator->set_breakpoint_callback([this](uint32_t tid, uintptr_t rip, debugger::Registers& regs) {
        return m_lua ? m_lua->on_breakpoint_hit(tid, rip, regs) : false;
    });
    m_watcher.set_coordinator(m_debug_coordinator);
    m_debugger = std::make_unique<debugger::StepDebugger>(m_process, m_debug_coordinator);
    m_hook_engine = std::make_unique<debugger::HookEngine>(m_process);
    if (m_lua) m_lua->set_session(this);
    if (m_plugins) m_plugins->dispatch_hook("onAttach");
    report.read_only = !m_process->can_write();
    report.reconciled = attached.reconciled;
    return report;
}

void Session::detach() {
    if (m_plugins && attached()) m_plugins->dispatch_hook("onDetach");
    if (is_remote() && m_remote) {
        m_remote->remote_watch_stop();
        m_remote->remote_speed_reset();
        m_remote->remote_dbg_detach();
    }
    m_remote_watching = false;
    m_remote_watch_addr = 0;
    m_remote_speed_on = false;
    m_remote_speed = 1.0;
    m_watcher.stop();
    if (m_hook_engine) {
        m_hook_engine->remove_all_hooks();
        m_hook_engine.reset();
    }
    if (m_speedhack) {
        m_speedhack->detach();
        m_speedhack.reset();
    }
    if (m_debugger) {
        m_debugger->detach();
        m_debugger.reset();
    }
    if (m_debug_coordinator) {
        m_debug_coordinator->detach();
        m_debug_coordinator.reset();
    }
    m_watcher.set_coordinator(nullptr);
    m_diff.clear();
    m_table->detach();
    m_scans.clear();
    m_scans.set_scanner(nullptr, nullptr);
    m_scanner.reset();
    {
        std::lock_guard<std::mutex> slock(m_sym_mutex);
        m_pe_cache.clear();
        m_elf_cache.clear();
        m_pdb_cache.clear();
        m_pdb_probed.clear();
    }
    m_ultimap.clear();
    m_timeline.clear();
    m_noise.reset();
    if (m_lua) m_lua->set_session(this);
}

bool Session::watch(uintptr_t address, size_t size, debugger::WatchKind kind) {
    if (!attached()) return false;
    if (is_remote() && m_remote) {
        uint8_t k = 0;
        if (kind == debugger::WatchKind::Access) k = 1;
        else if (kind == debugger::WatchKind::Execute) k = 2;
        else if (kind == debugger::WatchKind::GuardPage) k = 3;
        const bool ok = m_remote->remote_watch_start(address, size, k);
        if (ok) {
            m_remote_watching = true;
            m_remote_watch_addr = address;
        }
        return ok;
    }
    return m_watcher.start(m_process, address, size, kind);
}

void Session::stop_watch() {
    if (is_remote() && m_remote) {
        m_remote->remote_watch_stop();
        m_remote_watching = false;
        m_remote_watch_addr = 0;
        return;
    }
    m_watcher.stop();
}

void Session::stop_watch_address(uintptr_t address) {
    if (is_remote() && m_remote) {
        if (m_remote_watch_addr == address) stop_watch();
        return;
    }
    m_watcher.stop_address(address);
}

bool Session::watching() const {
    if (is_remote()) return m_remote_watching;
    return m_watcher.watching();
}

uintptr_t Session::watched_address() const {
    if (is_remote()) return m_remote_watch_addr;
    return m_watcher.address();
}

std::vector<uintptr_t> Session::watched_addresses() const {
    if (is_remote()) {
        if (m_remote_watching && m_remote_watch_addr != 0) return {m_remote_watch_addr};
        return {};
    }
    return m_watcher.watched_addresses();
}

std::vector<debugger::AccessHit> Session::watch_hits() const {
    if (is_remote() && m_remote) {
        bool active = false;
        std::vector<hal::RemoteWatchHit> rhits;
        if (!m_remote->remote_watch_poll(active, rhits)) return {};
        std::vector<debugger::AccessHit> out;
        out.reserve(rhits.size());
        for (const auto& rh : rhits) {
            debugger::AccessHit h;
            h.instruction = rh.instruction;
            h.location = rh.location;
            h.disassembly = rh.disassembly;
            h.bytes = rh.bytes;
            h.count = rh.count;
            h.base_register = rh.base_register;
            h.base_offset = rh.base_offset;
            h.registers.rax = rh.regs[0]; h.registers.rbx = rh.regs[1];
            h.registers.rcx = rh.regs[2]; h.registers.rdx = rh.regs[3];
            h.registers.rsi = rh.regs[4]; h.registers.rdi = rh.regs[5];
            h.registers.rbp = rh.regs[6]; h.registers.rsp = rh.regs[7];
            h.registers.rip = rh.regs[8];
            h.registers.r8  = rh.regs[9];  h.registers.r9  = rh.regs[10];
            h.registers.r10 = rh.regs[11]; h.registers.r11 = rh.regs[12];
            h.registers.r12 = rh.regs[13]; h.registers.r13 = rh.regs[14];
            h.registers.r14 = rh.regs[15]; h.registers.r15 = rh.regs[16];
            h.registers.eflags = rh.regs[17];
            out.push_back(std::move(h));
        }
        return out;
    }
    return m_watcher.hits();
}

std::optional<hal::ProcessInfo> Session::find_restart() const {
    const std::string name = m_process->name();
    if (name.empty() || m_process->get_pid() == 0) return std::nullopt;
    for (const auto& p : list_processes()) {
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

bool Session::set_speed(double multiplier) {
    if (is_remote() && m_remote && attached()) {
        std::string msg;
        const bool ok = m_remote->remote_speed_set(multiplier, msg);
        if (ok) {
            m_remote_speed_on = true;
            m_remote_speed = multiplier;
        }
        return ok;
    }
    if (!m_speedhack) return false;
    if (!m_speedhack->is_installed()) {
        if (!m_speedhack->attach()) return false;
    }
    return m_speedhack->set_speed(multiplier);
}

bool Session::enable_speedhack() {
    if (is_remote() && m_remote && attached()) {
        std::string msg;
        const bool ok = m_remote->remote_speed_set(m_remote_speed, msg);
        if (ok) m_remote_speed_on = true;
        return ok;
    }
    if (!m_speedhack) return false;
    if (!m_speedhack->is_installed()) {
        if (!m_speedhack->attach()) return false;
    }
    return m_speedhack->enable();
}

bool Session::disable_speedhack() {
    if (is_remote() && m_remote) {
        const bool ok = m_remote->remote_speed_reset();
        if (ok) {
            m_remote_speed_on = false;
            m_remote_speed = 1.0;
        }
        return ok;
    }
    if (!m_speedhack) return false;
    return m_speedhack->disable();
}

bool Session::speedhack_installed() const {
    if (is_remote()) return m_remote_speed_on;
    return m_speedhack && m_speedhack->is_installed();
}

bool Session::speedhack_enabled() const {
    if (is_remote()) return m_remote_speed_on;
    return m_speedhack && m_speedhack->is_enabled();
}

double Session::speedhack_speed() const {
    if (is_remote()) return m_remote_speed;
    return m_speedhack ? m_speedhack->get_speed() : 1.0;
}

bool Session::diff_snapshot_a(uintptr_t address, size_t size) {
    if (!attached()) return false;
    return m_diff.take_snapshot_a(*m_process, address, size);
}

bool Session::diff_snapshot_b() {
    if (!attached()) return false;
    return m_diff.take_snapshot_b(*m_process);
}

view::DiffSummary Session::diff_compare() const {
    return m_diff.compare();
}

std::optional<debugger::PEInfo> Session::analyze_module(const std::string& module_name) {
    if (!attached()) return std::nullopt;
    for (const auto& mod : m_process->get_modules()) {
        if (equals_ignore_case(mod.name, module_name)) {
            return debugger::PEAnalyzer::analyze(*m_process, mod.base_address);
        }
    }
    return std::nullopt;
}

std::optional<debugger::PEInfo> Session::analyze_pe(uintptr_t base_address) {
    if (!attached() || base_address == 0) return std::nullopt;
    return debugger::PEAnalyzer::analyze(*m_process, base_address);
}

std::optional<debugger::ELFInfo> Session::analyze_module_elf(const std::string& module_name) {
    if (!attached()) return std::nullopt;
    for (const auto& mod : m_process->get_modules()) {
        if (equals_ignore_case(mod.name, module_name)) {
            return debugger::ELFAnalyzer::analyze(*m_process, mod.base_address);
        }
    }
    return std::nullopt;
}

std::optional<debugger::ELFInfo> Session::analyze_elf(uintptr_t base_address) {
    if (!attached() || base_address == 0) return std::nullopt;
    return debugger::ELFAnalyzer::analyze(*m_process, base_address);
}

view::EngineDetection Session::detect_game_engine() const {
    if (!attached()) return {};
    return view::EngineInspector::detect(*m_process);
}

view::UnityMetadataReport Session::inspect_unity_metadata(
    const std::string& file_path, const std::string& filter, size_t max_types) const
{
    return view::EngineInspector::parse_unity_metadata_file(file_path, filter, max_types);
}

std::vector<view::UnrealNameEntry> Session::scan_unreal_names(
    uintptr_t fname_pool_addr, const view::UnrealOffsets& offsets,
    uint32_t max_blocks, size_t max_names) const
{
    if (!attached()) return {};
    return view::EngineInspector::scan_unreal_names(*m_process, fname_pool_addr, offsets, max_blocks, max_names);
}

std::vector<view::UnrealObjectInfo> Session::dump_unreal_objects(
    uintptr_t guobject_array_addr, uintptr_t fname_pool_addr,
    const view::UnrealOffsets& offsets, const std::string& filter,
    size_t max_objects) const
{
    if (!attached()) return {};
    return view::EngineInspector::dump_unreal_objects(
        *m_process, guobject_array_addr, fname_pool_addr, offsets, filter, max_objects);
}

view::UnityMetadataReport Session::inspect_unity_metadata_memory(
    uintptr_t metadata_addr, const std::string& filter, size_t max_types) const
{
    if (!attached()) return {};
    return view::EngineInspector::parse_unity_metadata_memory(*m_process, metadata_addr, filter, max_types);
}

view::StructLayout Session::dissect_unity_object(
    uintptr_t obj_addr, const view::Il2CppClassOffsets& offsets) const
{
    if (!attached()) return {};
    return view::EngineInspector::dissect_unity_object(*m_process, obj_addr, offsets);
}

view::UnrealGlobalsResult Session::find_unreal_globals(uintptr_t module_base) const {
    if (!attached()) return {};
    return view::EngineInspector::find_unreal_globals(*m_process, module_base);
}

view::StructLayout Session::dissect_unreal_object(
    uintptr_t uobject_addr, uintptr_t fname_pool_addr, const view::UnrealOffsets& offsets) const
{
    if (!attached()) return {};
    return view::EngineInspector::dissect_unreal_object(*m_process, uobject_addr, fname_pool_addr, offsets);
}

std::vector<view::UnrealActorInfo> Session::dump_unreal_actors(
    uintptr_t uworld_addr, uintptr_t fname_pool_addr, const view::UnrealOffsets& offsets, size_t max_actors) const
{
    if (!attached()) return {};
    return view::EngineInspector::dump_unreal_actors(*m_process, uworld_addr, fname_pool_addr, offsets, max_actors);
}

debugger::ControlFlowGraph Session::build_cfg(uintptr_t entry_address, size_t max_insns, size_t max_blocks) const {
    if (!attached()) return {};
    return debugger::Disassembler::build_cfg(*m_process, entry_address, max_insns, max_blocks);
}

std::string Session::generate_aob_hook_script(
    uintptr_t address, const std::string& label_name, size_t min_bytes) const
{
    if (!attached()) return {};
    return assembler::AutoAssembler::generate_aob_hook_script(*m_process, address, label_name, min_bytes);
}

std::vector<debugger::CrossReference> Session::find_references(
    uintptr_t target_address, uintptr_t module_base, size_t max_results) const
{
    if (!attached()) return {};
    return debugger::Disassembler::find_references(*m_process, target_address, module_base, max_results);
}

view::UnrealCalibrationResult Session::calibrate_unreal_offsets(
    uintptr_t world_or_actor_addr, uintptr_t fname_pool_addr, const view::UnrealOffsets& seed) const
{
    if (!attached()) return {};
    return view::EngineInspector::calibrate_unreal_offsets(*m_process, world_or_actor_addr, fname_pool_addr, seed);
}

bool Session::build_and_save_pointer_map(const std::string& path) const {
    if (!attached() || path.empty()) return false;
    scanner::PointerMap map;
    map.build(*m_process, m_process->query_regions(), m_process->pointer_size());
    return map.save(path);
}

scanner::PointerScanResult Session::scan_saved_pointer_map(
    const std::string& map_path, uintptr_t target_address, const scanner::PointerScanOptions& opts) const
{
    if (!attached() || map_path.empty()) return {};
    scanner::PointerMap map;
    if (!map.load(map_path)) return {};
    scanner::PointerScanner ps(m_process);
    return ps.scan_with_map(map, target_address, opts);
}

bool Session::dbg_attach(debugger::DebugBackend backend) {
    if (is_remote() && m_remote && attached()) {
        std::string err;
        return m_remote->remote_dbg_attach(backend == debugger::DebugBackend::VEH ? 1 : 0, err);
    }
    if (!m_debugger) return false;
    return m_debugger->attach(backend);
}

void Session::dbg_detach() {
    if (is_remote() && m_remote) {
        m_remote->remote_dbg_detach();
        return;
    }
    if (m_debugger) m_debugger->detach();
}

bool Session::dbg_set_bp(uintptr_t addr, const std::string& note, const std::string& condition, bool is_tracepoint) {
    if (is_remote() && m_remote) {
        return m_remote->remote_dbg_set_bp(addr, note, false, condition, is_tracepoint);
    }
    if (!m_debugger) return false;
    return m_debugger->set_breakpoint(addr, note, false, condition, is_tracepoint);
}

std::vector<hal::ThreadInfo> Session::list_threads() const {
    if (!attached()) return {};
    if (m_remote && m_remote->is_connected()) {
        return m_remote->list_remote_threads();
    }
    return hal::ProcessInjector::list_threads(m_process->get_pid());
}

bool Session::inject_dll(const std::string& dll_path, std::string& error_out) {
    if (!attached()) {
        error_out = "No target process attached.";
        return false;
    }
    if (is_remote()) {
        error_out = "DLL/.so injection is not supported over remote NCE2 connections.";
        return false;
    }
    return hal::ProcessInjector::inject_dll(m_process->get_pid(), dll_path, error_out);
}

bool Session::dbg_remove_bp(uintptr_t addr) {
    if (is_remote() && m_remote) return m_remote->remote_dbg_remove_bp(addr);
    if (!m_debugger) return false;
    return m_debugger->remove_breakpoint(addr);
}

bool Session::dbg_resume() {
    if (is_remote() && m_remote) return m_remote->remote_dbg_action(0);
    if (!m_debugger) return false;
    return m_debugger->resume();
}

bool Session::dbg_pause() {
    if (is_remote() && m_remote) return m_remote->remote_dbg_action(1);
    if (!m_debugger) return false;
    return m_debugger->pause();
}

bool Session::dbg_step_into() {
    if (is_remote() && m_remote) return m_remote->remote_dbg_action(2);
    if (!m_debugger) return false;
    return m_debugger->step_into();
}

bool Session::dbg_step_over() {
    if (is_remote() && m_remote) return m_remote->remote_dbg_action(3);
    if (!m_debugger) return false;
    return m_debugger->step_over();
}

bool Session::dbg_step_out() {
    if (is_remote() && m_remote) return m_remote->remote_dbg_action(4);
    if (!m_debugger) return false;
    return m_debugger->step_out();
}

script::ScriptResult Session::run_lua(const std::string& code) {
    if (!m_lua) m_lua = std::make_unique<script::LuaEngine>(this);
    return m_lua->execute_string(code);
}

script::ScriptResult Session::run_lua_file(const std::string& filepath) {
    if (!m_lua) m_lua = std::make_unique<script::LuaEngine>(this);
    return m_lua->execute_file(filepath);
}

void Session::reset_lua() {
    if (m_lua) {
        m_lua->reset();
        m_lua->set_session(this);
    }
}

std::optional<debugger::HookInfo> Session::hook_detour(uintptr_t target, uintptr_t destination) {
    if (!m_hook_engine || !attached()) return std::nullopt;
    if (!m_hook_engine->install_detour(target, destination)) return std::nullopt;
    for (const auto& h : m_hook_engine->get_active_hooks()) {
        if (h.target_address == target) return h;
    }
    return std::nullopt;
}

std::optional<debugger::HookInfo> Session::hook_payload(uintptr_t target, const std::vector<uint8_t>& payload) {
    if (!m_hook_engine || !attached()) return std::nullopt;
    return m_hook_engine->install_payload_hook(target, payload);
}

bool Session::unhook(uintptr_t target) {
    if (!m_hook_engine) return false;
    return m_hook_engine->remove_hook(target);
}

void Session::unhook_all() {
    if (m_hook_engine) m_hook_engine->remove_all_hooks();
}

std::vector<debugger::HookInfo> Session::active_hooks() const {
    if (!m_hook_engine) return {};
    return m_hook_engine->get_active_hooks();
}

std::string Session::resolve_symbol(uintptr_t address) const {
    if (address == 0 || !attached()) return {};
    if (m_debug_coordinator) {
        std::string dbg_sym = m_debug_coordinator->resolve_symbol(address);
        // Only treat DebugCoordinator result as authoritative if it resolved a named symbol (contains '!')
        // rather than a bare "mod+0x..." fallback, so PE exports can resolve exact DLL export names.
        if (dbg_sym.find('!') != std::string::npos) return dbg_sym;
    }

    const auto mods = m_process->get_modules();
    for (const auto& mod : mods) {
        if (address >= mod.base_address && address < mod.base_address + mod.size) {
            std::lock_guard<std::mutex> lock(m_sym_mutex);
            if (debugger::ELFAnalyzer::is_elf_magic(*m_process, mod.base_address)) {
                auto eit = m_elf_cache.find(mod.base_address);
                if (eit == m_elf_cache.end()) {
                    if (auto elf = debugger::ELFAnalyzer::analyze(*m_process, mod.base_address)) {
                        eit = m_elf_cache.emplace(mod.base_address, std::move(*elf)).first;
                    } else {
                        eit = m_elf_cache.emplace(mod.base_address, debugger::ELFInfo{}).first;
                    }
                }
                if (eit->second.is_valid) {
                    if (const auto* sym = debugger::ELFAnalyzer::find_symbol_by_address(eit->second, address)) {
                        if (address == sym->va) {
                            return mod.name + "!" + sym->name;
                        }
                        std::ostringstream ss;
                        ss << mod.name << "!" << sym->name << "+0x" << std::hex << std::uppercase << (address - sym->va);
                        return ss.str();
                    }
                }
            } else if (debugger::PEAnalyzer::is_pe_magic(*m_process, mod.base_address)) {
                auto it = m_pe_cache.find(mod.base_address);
                if (it == m_pe_cache.end()) {
                    if (auto pe = debugger::PEAnalyzer::analyze(*m_process, mod.base_address)) {
                        it = m_pe_cache.emplace(mod.base_address, std::move(*pe)).first;
                    } else {
                        it = m_pe_cache.emplace(mod.base_address, debugger::PEInfo{}).first;
                    }
                }
                if (it->second.is_valid) {
                    if (const auto* exp = debugger::PEAnalyzer::find_export_by_address(it->second, address)) {
                        return mod.name + "!" + (exp->name.empty() ? ("#" + std::to_string(exp->ordinal)) : exp->name);
                    }
                }
            }
            if (m_pdb_probed.find(mod.base_address) == m_pdb_probed.end()) {
                m_pdb_probed.insert(mod.base_address);
                const std::string comp = debugger::PDBReader::locate_companion_pdb(mod.path);
                if (!comp.empty()) {
                    debugger::PDBReader rdr;
                    if (rdr.load_file(comp)) {
                        m_pdb_cache.emplace(mod.base_address, std::move(rdr));
                    }
                }
            }
            auto pdb_it = m_pdb_cache.find(mod.base_address);
            if (pdb_it != m_pdb_cache.end() && pdb_it->second.is_loaded()) {
                const uint32_t rva = static_cast<uint32_t>(address - mod.base_address);
                if (auto sym = pdb_it->second.find_by_rva(rva)) {
                    if (sym->second == 0) return mod.name + "!" + sym->first.name;
                    std::ostringstream ss;
                    ss << mod.name << "!" << sym->first.name << "+0x" << std::hex << std::uppercase << sym->second;
                    return ss.str();
                }
            }
            std::ostringstream ss;
            ss << mod.name << "+0x" << std::hex << std::uppercase << (address - mod.base_address);
            return ss.str();
        }
    }
    return {};
}

void Session::annotate_disassembly(std::vector<debugger::DecodedInstruction>& instructions) const {
    if (!attached()) return;
    for (auto& insn : instructions) {
        if (insn.branch_target != 0) {
            insn.resolved_symbol = resolve_symbol(insn.branch_target);
        } else {
            const std::string here = resolve_symbol(insn.address);
            if (here.find('!') != std::string::npos) insn.resolved_symbol = here;
        }
    }
}

script::ScriptResult Session::eval_lua_expression(const std::string& expr) {
    if (!m_lua) m_lua = std::make_unique<script::LuaEngine>(this);
    m_lua->set_session(this);
    return m_lua->eval_expression(expr);
}

Outcome Session::run_table_lua_script() {
    std::string script_text;
    if (m_table) script_text = m_table->lua_script();
    if (script_text.empty()) return Outcome::fail("The loaded table has no embedded <LuaScript>.");
    const auto res = run_lua(script_text);
    if (!res.success) return Outcome::fail(res.error.empty() ? "Table Lua script failed." : res.error);
    return Outcome::success(res.output.empty() ? "Executed table <LuaScript>." : res.output);
}

Outcome Session::connect_remote(const std::string& host, uint16_t port, const std::string& auth_token) {
    auto remote = std::make_shared<hal::RemoteProcess>();
    if (!remote->connect(host, port, auth_token)) {
        const std::string err = remote->last_error();
        return Outcome::fail(err.empty() ? "Could not connect to remote server." : err);
    }
    detach();
    m_remote = remote;
    m_process = remote;
    if (m_table) m_table->set_process(remote);
    std::string msg = "Connected to NCE3 remote " + host + ":" + std::to_string(port);
    if (!remote->remote_os().empty()) {
        msg += " (" + remote->remote_os() + ", " + std::to_string(remote->pointer_size() * 8) + "-bit)";
    }
    if (remote->is_encrypted()) {
        msg += " [Encrypted SHA256-CTR+HMAC]";
    }
    return Outcome::success(std::move(msg));
}

void Session::disconnect_remote() {
    if (!m_remote) return;
    detach();
    m_remote->disconnect();
    m_remote.reset();
    auto local = hal::IProcess::create();
    m_process = std::shared_ptr<hal::IProcess>(std::move(local));
    if (m_table) m_table->set_process(m_process);
}

std::string Session::remote_endpoint() const {
    if (!m_remote || !m_remote->is_connected()) return {};
    return m_remote->host() + ":" + std::to_string(m_remote->port());
}

std::vector<hal::ProcessInfo> Session::list_processes() const {
    if (m_remote && m_remote->is_connected()) {
        return m_remote->list_remote_processes();
    }
    return hal::IProcess::list_processes();
}

debugger::DecompiledFunction Session::decompile_function(
    uintptr_t entry_address, uintptr_t struct_address, size_t max_insns) const
{
    if (!attached() || entry_address == 0) return {};
    const auto cfg = build_cfg(entry_address, max_insns, 48);
    debugger::DecompileOptions opts;
    if (struct_address != 0) {
        view::StructureDissector dissector(m_process);
        const auto layout = dissector.dissect(struct_address, 0x100, m_process->get_modules());
        opts = debugger::DecompileOptions::from_struct(layout);
    }
    opts.symbol_resolver = [this](uintptr_t a) { return resolve_symbol(a); };
#ifndef _WIN32
    opts.sysv_abi = !is_proton_or_wine();
#endif
    return debugger::PseudoCDecompiler::decompile(cfg, opts);
}

size_t Session::capture_timeline_from_trace(uintptr_t watch_address, size_t watch_bytes_len) {
    if (!m_debugger) return 0;
    const auto entries = m_debugger->get_trace_log();
    if (entries.empty()) return 0;
    m_timeline.record_trace(entries, attached() ? m_process.get() : nullptr, watch_address, watch_bytes_len);
    return entries.size();
}

size_t Session::capture_timeline_from_watch(uintptr_t watch_address, size_t watch_bytes_len) {
    const auto hits = m_watcher.hits();
    if (hits.empty()) return 0;
    const uintptr_t addr = (watch_address != 0) ? watch_address : m_watcher.address();
    m_timeline.record_hits(hits, attached() ? m_process.get() : nullptr, addr, watch_bytes_len);
    return hits.size();
}

std::vector<Session::HybridModuleInfo> Session::inspect_hybrid_modules() const {
    std::vector<HybridModuleInfo> out;
    if (!attached()) return out;
    const auto mods = m_process->get_modules();
    out.reserve(mods.size());
    for (const auto& mod : mods) {
        HybridModuleInfo info;
        info.name = mod.name;
        info.path = mod.path;
        info.base_address = mod.base_address;
        info.size = mod.size;
        info.format = "Unknown";

        std::lock_guard<std::mutex> lock(m_sym_mutex);
        if (debugger::ELFAnalyzer::is_elf_magic(*m_process, mod.base_address)) {
            info.format = "ELF";
            auto it = m_elf_cache.find(mod.base_address);
            if (it == m_elf_cache.end()) {
                if (auto elf = debugger::ELFAnalyzer::analyze(*m_process, mod.base_address)) {
                    it = m_elf_cache.emplace(mod.base_address, std::move(*elf)).first;
                } else {
                    it = m_elf_cache.emplace(mod.base_address, debugger::ELFInfo{}).first;
                }
            }
            if (it->second.is_valid) {
                info.is_64bit = it->second.is_64bit;
                info.export_or_symbol_count = it->second.symbols.size();
                info.has_dwarf = it->second.has_dwarf;
            }
        } else if (debugger::PEAnalyzer::is_pe_magic(*m_process, mod.base_address)) {
            info.format = "PE";
            auto it = m_pe_cache.find(mod.base_address);
            if (it == m_pe_cache.end()) {
                if (auto pe = debugger::PEAnalyzer::analyze(*m_process, mod.base_address)) {
                    it = m_pe_cache.emplace(mod.base_address, std::move(*pe)).first;
                } else {
                    it = m_pe_cache.emplace(mod.base_address, debugger::PEInfo{}).first;
                }
            }
            if (it->second.is_valid) {
                info.is_64bit = it->second.is_64bit;
                info.export_or_symbol_count = it->second.exports.size();
            }
        }
        out.push_back(std::move(info));
    }
    return out;
}

bool Session::is_proton_or_wine() const {
    if (!attached()) return false;
    bool has_pe = false;
    bool has_elf = false;
    for (const auto& mod : m_process->get_modules()) {
        std::string ln = mod.name;
        for (char& c : ln) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ln.find("wine") != std::string::npos || ln.find("proton") != std::string::npos ||
            ln.ends_with(".exe") || ln.ends_with(".dll")) {
            if (debugger::PEAnalyzer::is_pe_magic(*m_process, mod.base_address)) has_pe = true;
        }
        if (ln.ends_with(".so") || debugger::ELFAnalyzer::is_elf_magic(*m_process, mod.base_address)) {
            has_elf = true;
        }
        if (has_pe && has_elf) return true;
    }
    return false;
}

Outcome Session::anchor_entry_signature(size_t index, uintptr_t code_address, int64_t struct_offset) {
    if (!attached()) return Outcome::fail("Not attached to any process.");
    return m_table->with([&](table::CheatTable& t, const std::vector<hal::ModuleInfo>& mods) -> Outcome {
        if (index >= t.entries.size()) {
            return Outcome::fail("No table entry #" + std::to_string(index) + ".");
        }
        auto anchor = table::create_signature_anchor(*m_process, mods, code_address, struct_offset);
        if (!anchor) return Outcome::fail("Could not generate unique code signature at " + utils::format_address(code_address));
        const std::string pat = anchor->aob_pattern;
        const bool is_rip = anchor->is_rip_relative;
        t.entries[index].signature_anchor = std::move(*anchor);
        return Outcome::success("Anchored #" + std::to_string(index) + (is_rip ? " [RIP-rel AOB]: " : " [AOB]: ") + pat);
    });
}

table::SignatureMigrationReport Session::migrate_table_signatures() {
    if (!attached()) return {};
    return m_table->with([&](table::CheatTable& t, const std::vector<hal::ModuleInfo>& mods) {
        return table::migrate_table_by_signatures(t, *m_process, mods);
    });
}

debugger::EmulationResult Session::emulate_code(
    uintptr_t entry_rip,
    const debugger::Registers& regs,
    size_t max_steps,
    const std::vector<debugger::MemWritePatch>& patches) const
{
    if (!attached()) {
        debugger::EmulationResult r;
        r.fault_reason = "Not attached to any process.";
        return r;
    }
    const bool is_64 = (m_process->pointer_size() != 4);
    return debugger::MicroEmulator::emulate(m_process.get(), entry_rip, regs, max_steps, is_64, patches);
}

debugger::EmulationResult Session::dry_run_hook(
    uintptr_t target_address,
    const std::vector<uint8_t>& cave_code,
    uintptr_t cave_address,
    const debugger::Registers& regs,
    size_t max_steps) const
{
    if (!attached()) {
        debugger::EmulationResult r;
        r.fault_reason = "Not attached to any process.";
        return r;
    }
    return debugger::MicroEmulator::dry_run_hook(*m_process, target_address, cave_code, cave_address, regs, max_steps);
}

std::vector<debugger::TaintStep> Session::trace_backward_taint(
    uintptr_t entry_address,
    uintptr_t sink_address,
    const std::string& reg_name) const
{
    if (!attached()) return {};
    const auto cfg = build_cfg(entry_address, 256, 48);
    return debugger::MicroEmulator::backward_taint(cfg, sink_address, reg_name);
}

debugger::ProtectionReport Session::inspect_protections() const {
    if (!attached()) return {};
    return debugger::ProtectionInspector::inspect(*m_process);
}

bool Session::load_pdb(const std::string& module_name_or_base, const std::string& pdb_path, std::string& out_msg) {
    out_msg.clear();
    if (!attached()) {
        out_msg = "Not attached to any process.";
        return false;
    }
    const auto mods = m_process->get_modules();
    const hal::ModuleInfo* target_mod = nullptr;
    const bool looks_hex = module_name_or_base.rfind("0x", 0) == 0 || module_name_or_base.rfind("0X", 0) == 0;
    const uintptr_t parsed_base = looks_hex ? utils::parse_address(module_name_or_base) : 0;
    const bool has_addr = (parsed_base != 0);
    for (const auto& m : mods) {
        if ((has_addr && m.base_address == parsed_base) ||
            equals_ignore_case(m.name, module_name_or_base) ||
            equals_ignore_case(m.path, module_name_or_base)) {
            target_mod = &m;
            break;
        }
    }
    if (!target_mod) {
        out_msg = "Module not found: " + module_name_or_base;
        return false;
    }
    std::string chosen_pdb = pdb_path;
    if (chosen_pdb.empty()) {
        chosen_pdb = debugger::PDBReader::locate_companion_pdb(target_mod->path);
    }
    if (chosen_pdb.empty()) {
        out_msg = "No .pdb specified or located next to " + target_mod->path;
        return false;
    }
    debugger::PDBReader rdr;
    if (!rdr.load_file(chosen_pdb)) {
        out_msg = rdr.last_error().empty() ? "Failed to parse PDB file." : rdr.last_error();
        return false;
    }
    const size_t sym_count = rdr.symbols().size();
    {
        std::lock_guard<std::mutex> lock(m_sym_mutex);
        m_pdb_probed.insert(target_mod->base_address);
        m_pdb_cache[target_mod->base_address] = std::move(rdr);
    }
    out_msg = "Loaded " + std::to_string(sym_count) + " PDB symbols for " + target_mod->name;
    return true;
}

std::vector<std::pair<std::string, debugger::PDBSymbol>> Session::search_pdb_symbols(
    const std::string& query, size_t max_results) const
{
    std::vector<std::pair<std::string, debugger::PDBSymbol>> out;
    if (!attached()) return out;
    const auto mods = m_process->get_modules();
    std::lock_guard<std::mutex> lock(m_sym_mutex);
    for (const auto& [base, rdr] : m_pdb_cache) {
        if (!rdr.is_loaded()) continue;
        std::string mname;
        for (const auto& m : mods) {
            if (m.base_address == base) { mname = m.name; break; }
        }
        for (const auto& s : rdr.find_by_name(query, max_results)) {
            out.emplace_back(mname, s);
            if (out.size() >= max_results) return out;
        }
    }
    return out;
}

std::string Session::dump_sdk_header(const std::string& filter, size_t max_classes) const {
    if (!attached()) return "// Not attached to target process.\n";
    const auto det = detect_game_engine();
    if (det.kind == view::GameEngineKind::UnityIL2CPP || det.kind == view::GameEngineKind::UnityMono) {
        const auto meta = inspect_unity_metadata_memory(0, filter, max_classes);
        if (!meta.types.empty()) {
            return view::EngineInspector::generate_sdk_header_from_unity(meta, max_classes);
        }
    } else if (det.kind == view::GameEngineKind::UnrealEngine) {
        const auto ug = find_unreal_globals(0);
        if (ug.found_objects && ug.found_names) {
            const auto objs = dump_unreal_objects(ug.guobject_array_va, ug.fname_pool_va, {}, filter, max_classes);
            std::vector<view::SdkClassDef> defs;
            for (const auto& obj : objs) {
                auto lay = dissect_unreal_object(obj.address, ug.fname_pool_va);
                if (lay.fields.empty()) continue;
                view::SdkClassDef d;
                d.name = lay.class_name.empty() ? obj.name : lay.class_name;
                d.size = lay.size;
                d.fields = std::move(lay.fields);
                defs.push_back(std::move(d));
                if (defs.size() >= 64) break;
            }
            if (!defs.empty()) {
                return view::EngineInspector::generate_sdk_header(defs, "Unreal Engine Live SDK Dump");
            }
        }
    }
    return "// Engine: " + det.engine_name + "\n// " + det.details + "\n// No extractable runtime metadata/objects matched filter.\n";
}

bool Session::remote_encrypted() const noexcept {
    return m_remote && m_remote->is_encrypted();
}

std::optional<hal::RemoteDebugState> Session::remote_debug_state() const {
    if (!is_remote() || !m_remote) return std::nullopt;
    hal::RemoteDebugState st;
    if (!m_remote->remote_dbg_state(st)) return std::nullopt;
    return st;
}

} // namespace nce::session
