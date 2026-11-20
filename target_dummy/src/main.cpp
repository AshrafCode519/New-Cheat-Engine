#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Structure for multi-level pointer testing
struct Level3 {
    uint32_t pad1{0x1111};
    int32_t target_score{424242};
    uint32_t pad2{0x2222};
};

struct Level2 {
    uint32_t pad{0x3333};
    Level3* next{nullptr};
};

struct Level1 {
    uint32_t pad{0x4444};
    Level2* next{nullptr};
};

// Structure for Grouped Scan testing
struct PlayerStats {
    int32_t health{100};
    int32_t mana{50};
    float armor{25.5f};
};

// Structure for Encrypted / Obfuscated value testing
struct ObfuscatedValue {
    uint32_t xor_key{0xA5A5A5A5};
    uint32_t encrypted_val{777 ^ 0xA5A5A5A5};

    [[nodiscard]] uint32_t get() const { return encrypted_val ^ xor_key; }
    void set(uint32_t val) { encrypted_val = val ^ xor_key; }
};

// Global variables for deterministic address testing
static int32_t g_health = 1337;
static int64_t g_gold = 5000000000LL;
static float g_mana = 250.5f;
static double g_speed = 12.3456;
static char g_player_name[32] = "CyberWarrior";
static PlayerStats g_stats;
static ObfuscatedValue g_obfuscated;

// Multi-level pointer base
static Level1* g_pointer_base = nullptr;

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_auto_decay{false};

void print_addresses(uint32_t pid) {
    std::cout << "\n=======================================================\n";
    std::cout << "          TARGET DUMMY PROCESS - MEMORY MAP            \n";
    std::cout << "=======================================================\n";
    std::cout << " Process ID (PID)      : " << pid << "\n";
    std::cout << "-------------------------------------------------------\n";
    std::cout << " [Exact Int32]   g_health       @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_health) 
              << std::dec << " = " << g_health << "\n";
    std::cout << " [Exact Int64]   g_gold         @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_gold) 
              << std::dec << " = " << g_gold << "\n";
    std::cout << " [Exact Float]   g_mana         @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_mana) 
              << std::dec << " = " << g_mana << "\n";
    std::cout << " [Exact Double]  g_speed        @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_speed) 
              << std::dec << " = " << g_speed << "\n";
    std::cout << " [String ASCII]  g_player_name  @ 0x" << std::hex << reinterpret_cast<uintptr_t>(g_player_name) 
              << " = \"" << g_player_name << "\"\n";
    std::cout << "-------------------------------------------------------\n";
    std::cout << " [Grouped Scan]  g_stats        @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_stats) << std::dec << "\n";
    std::cout << "                 .health        @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_stats.health) 
              << std::dec << " = " << g_stats.health << "\n";
    std::cout << "                 .mana          @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_stats.mana) 
              << std::dec << " = " << g_stats.mana << "\n";
    std::cout << "                 .armor         @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_stats.armor) 
              << std::dec << " = " << g_stats.armor << "\n";
    std::cout << "-------------------------------------------------------\n";
    std::cout << " [Obfuscated]    g_obfuscated   @ 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_obfuscated) 
              << std::dec << " (Real Value = " << g_obfuscated.get() << ", XOR Key = 0x" 
              << std::hex << g_obfuscated.xor_key << std::dec << ")\n";
    std::cout << "-------------------------------------------------------\n";
    if (g_pointer_base && g_pointer_base->next && g_pointer_base->next->next) {
        Level2* l2 = g_pointer_base->next;
        Level3* l3 = l2->next;
        std::cout << " [Pointer Chain] (Static Base -> L1 -> L2 -> L3 -> Score)\n";
        std::cout << "   &g_pointer_base: 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_pointer_base) 
                  << " -> 0x" << reinterpret_cast<uintptr_t>(g_pointer_base) << "\n";
        std::cout << "   L1->next (L2)  : 0x" << reinterpret_cast<uintptr_t>(l2) << "\n";
        std::cout << "   L2->next (L3)  : 0x" << reinterpret_cast<uintptr_t>(l3) << "\n";
        std::cout << "   Target Score   : 0x" << reinterpret_cast<uintptr_t>(&l3->target_score) 
                  << std::dec << " = " << l3->target_score << "\n";
    }
    std::cout << "=======================================================\n";
}

// --noise: what a running game keeps changing on its own, to test the scanner's noise filtering
struct Particle {
    float x, y, vx, vy;
};
static volatile int32_t g_frame_counter = 0;
static float g_animation[4096];

std::thread start_noise_thread() {
    return std::thread([]() {
        std::vector<Particle> particles(10000, Particle{0, 0, 1.5f, -0.5f});
        std::vector<int16_t> audio(512 * 1024); // 1 MB of samples, rewritten all the time
        std::cout << " [Noise mode]    frame counter  @ 0x" << std::hex
                  << reinterpret_cast<uintptr_t>(&g_frame_counter) << ", audio buffer @ 0x"
                  << reinterpret_cast<uintptr_t>(audio.data()) << " (1 MB), particles @ 0x"
                  << reinterpret_cast<uintptr_t>(particles.data()) << std::dec << std::endl;

        uint32_t tick = 0;
        while (g_running) {
            ++tick;
            g_frame_counter = g_frame_counter + 1;
            for (size_t i = 0; i < 4096; ++i) {
                g_animation[i] = static_cast<float>((i * 31 + tick * 7) % 1000) * 0.001f;
            }
            for (auto& p : particles) {
                p.x += p.vx;
                p.y += p.vy;
            }
            for (size_t i = 0; i < audio.size(); ++i) {
                audio[i] = static_cast<int16_t>((i * 13 + tick * 101) & 0x7FFF);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });
}

int main(int argc, char** argv) {
    const bool noise_mode = (argc > 1 && std::string(argv[1]) == "--noise");
    uint32_t pid = 0;
#ifdef _WIN32
    pid = static_cast<uint32_t>(GetCurrentProcessId());
#else
    pid = static_cast<uint32_t>(getpid());
#endif

    // Setup multi-level pointer heap allocations
    auto* l3 = new Level3();
    auto* l2 = new Level2();
    l2->next = l3;
    auto* l1 = new Level1();
    l1->next = l2;
    g_pointer_base = l1;

    print_addresses(pid);
    std::thread noise_thread;
    if (noise_mode) noise_thread = start_noise_thread();

    // Background thread for optional auto-decay (simulate real-time gameplay changes)
    std::thread decay_thread([]() {
        while (g_running) {
            if (g_auto_decay) {
                g_health -= 10;
                g_mana -= 2.5f;
                std::cout << "\n[Auto-Decay Tick] Health is now: " << g_health 
                          << ", Mana is now: " << g_mana << "\n> " << std::flush;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    });

    std::cout << "\nCommands:\n"
              << "  [1] Modify Health (-100)\n"
              << "  [2] Set Exact Health\n"
              << "  [3] Modify Mana (-25.0)\n"
              << "  [4] Toggle Auto-Decay (Simulate game ticks)\n"
              << "  [5] Print Current State & Memory Check\n"
              << "  [q] Quit\n";

    std::string input;
    while (g_running) {
        std::cout << "\n[Dummy PID: " << pid << "] Enter command > ";
        if (!std::getline(std::cin, input)) break;

        if (input == "1") {
            g_health -= 100;
            std::cout << ">> Health modified to: " << g_health << "\n";
        } else if (input == "2") {
            std::cout << "Enter new health value: ";
            int32_t val;
            if (std::cin >> val) {
                g_health = val;
                std::cout << ">> Health set to: " << g_health << "\n";
            }
            std::cin.ignore(10000, '\n');
        } else if (input == "3") {
            g_mana -= 25.0f;
            std::cout << ">> Mana modified to: " << g_mana << "\n";
        } else if (input == "4") {
            g_auto_decay = !g_auto_decay;
            std::cout << ">> Auto-decay is now: " << (g_auto_decay ? "ON" : "OFF") << "\n";
        } else if (input == "5") {
            print_addresses(pid);
        } else if (input == "q" || input == "quit" || input == "exit") {
            break;
        }
    }

    g_running = false;
    if (decay_thread.joinable()) {
        decay_thread.join();
    }
    if (noise_thread.joinable()) {
        noise_thread.join();
    }

    delete l1;
    delete l2;
    delete l3;
    return 0;
}

