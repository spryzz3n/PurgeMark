#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pm {

enum class Bus { Nvme, Sata, Usb, Scsi, Virtio, Mmc, Unknown };

std::string to_string(Bus bus);

struct Device {
    std::string name;  // kernel name, e.g. "nvme0n1", "sda"
    std::string path;  // "/dev/<name>"
    std::string model;
    std::string serial;    // empty when sysfs doesn't expose it (SATA: comes from IDENTIFY later)
    std::string firmware;
    Bus bus = Bus::Unknown;
    std::uint64_t size_bytes = 0;
    bool rotational = false;
    bool removable = false;
    bool read_only = false;
    std::vector<std::string> partitions;   // e.g. {"sda1", "sda2"}
    std::vector<std::string> mountpoints;  // of the disk or any of its partitions
    std::vector<std::string> holders;      // dm/md/LVM devices stacked on top
    std::vector<std::string> swaps;        // active swap areas on the disk or its partitions

    bool in_use() const { return !mountpoints.empty() || !holders.empty() || !swaps.empty(); }
};

// Roots are injectable so tests can point at a fake sysfs/procfs tree.
struct SystemRoots {
    std::filesystem::path sys = "/sys";
    std::filesystem::path mounts = "/proc/self/mounts";
    std::filesystem::path swaps = "/proc/swaps";
};

// Enumerates whole-disk block devices. Read-only: never opens a device node.
// Hides virtual devices (loop, dm, md, zram...) that are never erase targets.
std::vector<Device> list_devices(const SystemRoots& roots = {});

// Describes one disk by name or /dev path, including virtual ones that
// list_devices() hides (loop devices are used as test targets).
std::optional<Device> find_device(const std::string& name_or_path, const SystemRoots& roots = {});

}  // namespace pm
