#pragma once

#include "../hal/process.hpp"
#include "structure_dissector.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nce::view {

enum class GameEngineKind {
    Unknown,
    UnityMono,
    UnityIL2CPP,
    UnrealEngine,
    Godot
};

struct EngineDetection {
    GameEngineKind kind{GameEngineKind::Unknown};
    std::string engine_name{"Unknown"};
    std::string runtime_module;
    uintptr_t runtime_base{0};
    std::map<std::string, uintptr_t> api_exports;
    uintptr_t gnames_hint{0};
    uintptr_t gobjects_hint{0};
    std::string details;
};

struct UnityFieldInfo {
    std::string name;
    int32_t type_index{0};
    int32_t token{0};
};

struct UnityTypeInfo {
    std::string name;
    std::string namespaze;
    int32_t token{0};
    int32_t field_start{0};
    uint16_t field_count{0};
    uint32_t flags{0};
    std::vector<UnityFieldInfo> fields;
};

struct UnityMetadataReport {
    bool valid{false};
    uint32_t sanity{0};
    int32_t version{0};
    size_t total_types{0};
    size_t total_fields{0};
    std::vector<UnityTypeInfo> types;
    std::string error;
};

struct UnrealOffsets {
    // FNamePool (UE4.23+ / UE5): +0x08 CurrentBlock, +0x0C CurrentByteCursor, +0x10 Blocks[block]
    size_t fname_pool_header_offset{0x08};
    size_t fname_pool_blocks_offset{0x10};
    uint32_t fname_stride{2};        // 2 bytes per FNameEntry alignment on UE4.23+/UE5
    uint32_t fname_len_shift{6};     // header >> 6 gives string length
    uint32_t fname_wide_mask{0x01};  // bit 0 = bIsWide

    // FUObjectArray::ObjObjects (FChunkedFixedUObjectArray at GUObjectArray + 0x10):
    // +0x00 Objects**, +0x10 MaxElements, +0x14 NumElements, +0x18 MaxChunks, +0x1C NumChunks
    size_t obj_array_chunks_offset{0x10};
    size_t obj_array_num_elements_offset{0x24};
    size_t obj_array_num_chunks_offset{0x2C};
    size_t obj_elements_per_chunk{65536};
    size_t uobject_item_stride{24};  // sizeof(FUObjectItem): Object* at +0

    // UObjectBase fields (64-bit UE4/UE5 standard)
    size_t uobject_class_offset{0x10};
    size_t uobject_name_offset{0x18};
    size_t uobject_outer_offset{0x20};

    // UStruct / FField runtime reflection (UE4.25+ / UE5 standard 64-bit layout)
    size_t ustruct_super_offset{0x40};
    size_t ustruct_child_props_offset{0x50};
    size_t ffield_class_offset{0x08};       // FField::ClassPrivate (FFieldClass*)
    size_t ffield_next_offset{0x20};        // FField::Next
    size_t ffield_name_offset{0x28};        // FField::NamePrivate (FName)
    size_t ffield_elem_size_offset{0x3C};   // FProperty::ElementSize (int32)
    size_t ffield_offset_internal{0x44};    // FProperty::Offset_Internal (int32)
    size_t ffield_class_name_offset{0x00};  // FFieldClass::Name (FName)

    // UWorld -> PersistentLevel -> AActor TArray -> RootComponent -> RelativeLocation
    size_t uworld_level_offset{0x30};
    size_t ulevel_actors_offset{0x98};      // TArray<AActor*> { AActor** Data, int32 Num }
    size_t tarray_count_offset{0x08};       // TArray::ArrayNum (int32)
    size_t actor_root_comp_offset{0x130};   // USceneComponent* RootComponent
    size_t scene_comp_location_offset{0x11C}; // FVector RelativeLocation
    bool   lwc_double_coords{false};        // True for UE5 Large World Coordinates (double x,y,z)
};

struct Il2CppClassOffsets {
    size_t class_name_ptr_offset{0x10};
    size_t class_ns_ptr_offset{0x18};
    size_t class_fields_ptr_offset{0x80};
    size_t class_field_count_offset{0x114};
    size_t field_info_stride{32};
    size_t field_name_ptr_offset{0x00};
    size_t field_offset_offset{0x18};
    size_t field_token_offset{0x1C};
};

struct UnrealGlobalsResult {
    uintptr_t fname_pool_va{0};
    uintptr_t guobject_array_va{0};
    uintptr_t gworld_va{0};
    std::string source_module;
    bool found_names{false};
    bool found_objects{false};
    bool found_world{false};
};

struct UnrealActorInfo {
    uint32_t index{0};
    uintptr_t address{0};
    std::string name;
    std::string class_name;
    bool has_location{false};
    double x{0.0};
    double y{0.0};
    double z{0.0};
};

struct UnrealNameEntry {
    uint32_t index{0};
    uintptr_t address{0};
    std::string name;
};

struct UnrealObjectInfo {
    uint32_t index{0};
    uintptr_t address{0};
    uintptr_t class_address{0};
    uintptr_t outer_address{0};
    uint32_t name_index{0};
    std::string name;
    std::string class_name;
};

struct SdkClassDef {
    std::string name;
    std::string namespaze;
    size_t size{0};
    std::vector<StructField> fields;
};

struct UnrealCalibrationResult {
    bool ok{false};
    UnrealOffsets offsets;
    std::vector<std::string> notes;
};

class EngineInspector {
public:
    /// Detects Unity (Mono / IL2CPP), Unreal Engine, or Godot in the target process and collects key exports/symbols.
    static EngineDetection detect(hal::IProcess& proc);

    /// Parses a Unity IL2CPP global-metadata.dat byte buffer and extracts classes and fields.
    static UnityMetadataReport parse_unity_metadata_bytes(
        const std::vector<uint8_t>& bytes,
        const std::string& filter = "",
        size_t max_types = 512);

    /// Loads and parses a Unity global-metadata.dat file from disk.
    static UnityMetadataReport parse_unity_metadata_file(
        const std::string& file_path,
        const std::string& filter = "",
        size_t max_types = 512);

    /// Locates and parses Unity IL2CPP global-metadata.dat directly from target process RAM (`0xFAB11BAF`).
    static UnityMetadataReport parse_unity_metadata_memory(
        hal::IProcess& proc,
        uintptr_t metadata_addr = 0,
        const std::string& filter = "",
        size_t max_types = 512);

    /// Dissects a live Unity IL2CPP object instance (`*(Il2CppClass**)obj`) into named fields + real memory offsets.
    static StructLayout dissect_unity_object(
        hal::IProcess& proc,
        uintptr_t obj_addr,
        const Il2CppClassOffsets& offsets = {});

    /// Scans executable code pages for RIP-relative references to Unreal FNamePool & FUObjectArray automatically.
    static UnrealGlobalsResult find_unreal_globals(
        hal::IProcess& proc,
        uintptr_t scan_module_base = 0);

    /// Reflects a live Unreal UObject via UStruct::SuperStruct & ChildProperties FField chain into a StructLayout.
    static StructLayout dissect_unreal_object(
        hal::IProcess& proc,
        uintptr_t uobject_addr,
        uintptr_t fname_pool_addr,
        const UnrealOffsets& offsets = {});

    /// Enumerates live AActors inside an Unreal UWorld (with names, classes, and RootComponent 3D coordinates).
    static std::vector<UnrealActorInfo> dump_unreal_actors(
        hal::IProcess& proc,
        uintptr_t uworld_addr,
        uintptr_t fname_pool_addr,
        const UnrealOffsets& offsets = {},
        size_t max_actors = 512);

    /// Reads an Unreal FNamePool table from target process memory and enumerates FNames.
    static std::vector<UnrealNameEntry> scan_unreal_names(
        hal::IProcess& proc,
        uintptr_t fname_pool_addr,
        const UnrealOffsets& offsets = {},
        uint32_t max_blocks = 8,
        size_t max_names = 2048);

    /// Resolves a single FName ComparisonIndex directly from an Unreal FNamePool in process memory.
    static std::string read_unreal_fname(
        hal::IProcess& proc,
        uintptr_t fname_pool_addr,
        uint32_t name_index,
        const UnrealOffsets& offsets = {});

    /// Walks Unreal FUObjectArray (GObjects) and resolves object names and classes via FNamePool.
    static std::vector<UnrealObjectInfo> dump_unreal_objects(
        hal::IProcess& proc,
        uintptr_t guobject_array_addr,
        uintptr_t fname_pool_addr,
        const UnrealOffsets& offsets = {},
        const std::string& filter = "",
        size_t max_objects = 1024);

    /// Auto-calibrates UWorld / AActor / RootComponent / RelativeLocation offsets & UE5 LWC double mode via FField reflection.
    static UnrealCalibrationResult calibrate_unreal_offsets(
        hal::IProcess& proc,
        uintptr_t world_or_actor_addr,
        uintptr_t fname_pool_addr,
        const UnrealOffsets& seed = {});

    /// Reflects a live Il2CppClass* pointer directly (supporting probing field offsets from live memory).
    static StructLayout dissect_il2cpp_class(
        hal::IProcess& proc,
        uintptr_t il2cpp_class_addr,
        uintptr_t instance_addr = 0,
        const Il2CppClassOffsets& offsets = {});

    /// Generates clean C++20 `SDK.hpp` header structs with static padding and offset checks.
    static std::string generate_sdk_header(
        const std::vector<SdkClassDef>& classes,
        const std::string& header_title = "NCE v3.0 Generated SDK");

    /// Converts parsed Unity IL2CPP metadata types into a C++ `SDK.hpp` header.
    static std::string generate_sdk_header_from_unity(
        const UnityMetadataReport& meta,
        size_t max_classes = 256);

    /// Generates an importable Cheat Engine `.CT` XML table from reflected SDK classes.
    static std::string generate_sdk_cheat_table_xml(
        const std::vector<SdkClassDef>& classes,
        uintptr_t base_instance = 0);
};

} // namespace nce::view
