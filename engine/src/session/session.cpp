#include "../../include/session/session.hpp"
#include "../../include/utils/hex_utils.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
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

} // anonymous namespace

// ---- TableKeeper ---------------------------------------------------------------------------------

TableKeeper::TableKeeper(std::shared_ptr<hal::IProcess> process, std::unique_ptr<hal::IHotkeys> hotkeys)
    : m_process(std::move(process))
    , m_freeze_thread([this] { freeze_loop(); })
    , m_hotkeys(std::move(hotkeys))
{
    if (!m_hotkeys) return;
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

TableKeeper::~TableKeeper() {
    m_hotkeys.reset(); // stops the hotkey thread first: its presses use this object
    m_running = false;
    if (m_freeze_thread.joinable()) m_freeze_thread.join();
}

void TableKeeper::freeze_loop() {
    while (m_running) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_process->is_attached() && m_process->can_write()) {
                for (const auto& e : m_table.entries) {
                    if (e.frozen_value) table::write_entry(e, *e.frozen_value, *m_process, m_modules);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

size_t TableKeeper::attach(uint32_t pid, bool& attached) {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Absolute addresses belong to the old process; module-relative entries only resolve if the new one
    // has the same module, so they stay frozen
    size_t unfrozen = 0;
    for (auto& e : m_table.entries) {
        if (e.is_absolute() && e.frozen_value) {
            e.frozen_value.reset();
            ++unfrozen;
        }
    }
    attached = m_process->attach(pid);
    m_modules = attached ? m_process->get_modules() : std::vector<hal::ModuleInfo>{};
    return unfrozen;
}

void TableKeeper::detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_process->detach();
    m_modules.clear();
}

std::vector<TableKeeper::ReconcileLine> TableKeeper::reconcile() {
    std::lock_guard<std::mutex> lock(m_mutex);
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

Outcome TableKeeper::load(const std::string& path) {
    auto loaded = table::load_table(path);
    if (!loaded) return Outcome::fail("Could not read a table from " + path + ".");
    std::string message;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_table = std::move(*loaded);
        size_t frozen = 0;
        size_t hotkeys = 0;
        for (const auto& e : m_table.entries) {
            frozen += e.frozen_value ? 1 : 0;
            hotkeys += e.hotkeys.size();
        }
        message = "Loaded " + std::to_string(m_table.entries.size()) + " entries for '" + m_table.process_name + "'";
        if (frozen) message += ", " + std::to_string(frozen) + " frozen";
        if (hotkeys) message += ", " + std::to_string(hotkeys) + " hotkeys";
        message += ".";
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
            const long double total = static_cast<long double>(value) + static_cast<long double>(std::llround(*amount));
            sum = static_cast<T>(std::clamp(total, static_cast<long double>(std::numeric_limits<T>::lowest()),
                                            static_cast<long double>(std::numeric_limits<T>::max())));
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
    if (!m_process->is_attached()) return Outcome::fail("not attached to the game");

    if (h.action == Action::ToggleFreeze) {
        if (e.frozen_value) {
            e.frozen_value.reset();
            return Outcome::success("unfrozen");
        }
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
    AttachReport report;
    report.unfrozen = m_table->attach(pid, report.ok);
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
    report.reconciled = m_table->reconcile();
    return report;
}

void Session::detach() {
    m_table->detach();
    m_scans.clear();
    m_scans.set_scanner(nullptr, nullptr);
    m_scanner.reset();
    m_noise.reset();
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
