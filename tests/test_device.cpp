// Builds a fake sysfs/procfs tree and checks list_devices() and erase_blockers() against it.

#include <filesystem>
#include <fstream>
#include <string>

#include "check.hpp"
#include "pm/device.hpp"
#include "pm/safety.hpp"

namespace fs = std::filesystem;

static void put(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << content << "\n";
}

// Mirrors the kernel layout: /sys/block/<name> symlinks into /sys/devices/...
static fs::path add_disk(const fs::path& sys, const std::string& device_path, const std::string& name,
                         const std::string& size_sectors, bool rotational) {
    const fs::path real = sys / "devices" / device_path / "block" / name;
    put(real / "size", size_sectors);
    put(real / "queue" / "rotational", rotational ? "1" : "0");
    put(real / "removable", "0");
    put(real / "ro", "0");
    fs::create_directories(real / "holders");
    fs::create_directories(sys / "block");
    fs::create_directory_symlink(real, sys / "block" / name);
    return real;
}

int main() {
    const fs::path root = fs::temp_directory_path() / "pm-test-sysfs";
    fs::remove_all(root);
    const fs::path sys = root / "sys";

    const auto nvme = add_disk(sys, "pci0000:00/0000:00:1d.0/nvme/nvme0", "nvme0n1", "1000215216", false);
    put(nvme / "device" / "model", "Samsung SSD 980 PRO 500GB  ");
    put(nvme / "device" / "serial", "S5GXNX0R123456");
    put(nvme / "device" / "firmware_rev", "5B2QGXA7");

    const auto sda = add_disk(sys, "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0", "sda",
                              "1953525168", true);
    put(sda / "device" / "model", "WDC WD10EZEX-08W");
    put(sda / "device" / "rev", "1A01");
    put(sda / "sda1" / "partition", "1");
    fs::create_directories(sda / "sda1" / "holders");
    put(sda / "sda2" / "partition", "2");
    fs::create_directories(sda / "sda2" / "holders");

    const auto usb = add_disk(sys, "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0",
                              "sdb", "60437492", false);
    put(usb / "ro", "1");
    const auto sdc = add_disk(sys, "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0", "sdc",
                              "500118192", false);
    fs::create_directories(sdc / "holders" / "dm-0");  // e.g. LUKS/LVM on top
    add_disk(sys, "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0", "sde", "500118192", false);

    // NVMe multipath path node: same disk as nvme0n1, flagged hidden, no /dev node.
    const auto path_node = add_disk(sys, "pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0c0n1", "nvme0c0n1",
                                    "1000215216", false);
    put(path_node / "hidden", "1");

    add_disk(sys, "virtual/block/loop0", "loop0", "1024", false);  // must be ignored
    add_disk(sys, "pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0/host2/target2:0:0/2:0:0:0", "sdd", "0",
             false);  // empty card reader: must be ignored

    const fs::path mounts = root / "mounts";
    put(mounts,
        "/dev/sda1 /mnt/my\\040data ext4 rw,relatime 0 0\n"
        "proc /proc proc rw 0 0\n"
        "tmpfs /run tmpfs rw 0 0");
    const fs::path swaps = root / "swaps";
    put(swaps,
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
        "/dev/sda2                               partition\t2097152\t\t0\t\t-2\n"
        "/swapfile                               file\t\t1048576\t\t0\t\t-3");

    const auto devs = pm::list_devices({sys, mounts, swaps});

    CHECK(devs.size() == 5);  // nvme0n1, sda, sdb, sdc, sde
    auto find = [&](const std::string& n) -> const pm::Device* {
        for (const auto& d : devs)
            if (d.name == n) return &d;
        return nullptr;
    };

    const auto* n = find("nvme0n1");
    CHECK(n != nullptr);
    if (n) {
        CHECK(n->bus == pm::Bus::Nvme);
        CHECK(n->model == "Samsung SSD 980 PRO 500GB");
        CHECK(n->serial == "S5GXNX0R123456");
        CHECK(n->firmware == "5B2QGXA7");
        CHECK(n->size_bytes == 1000215216ULL * 512);
        CHECK(!n->rotational);
        CHECK(pm::erase_blockers(*n).empty());
    }

    const auto* a = find("sda");
    CHECK(a != nullptr);
    if (a) {
        CHECK(a->bus == pm::Bus::Sata);
        CHECK(a->firmware == "1A01");
        CHECK(a->rotational);
        CHECK(a->partitions.size() == 2);
        CHECK(a->mountpoints.size() == 1 && a->mountpoints[0] == "/mnt/my data");
        CHECK(a->swaps.size() == 1 && a->swaps[0] == "/dev/sda2");
        CHECK(pm::erase_blockers(*a).size() == 2);  // mounted + swap
    }

    const auto* b = find("sdb");
    CHECK(b != nullptr && b->bus == pm::Bus::Usb);
    CHECK(b != nullptr && b->read_only && pm::erase_blockers(*b).size() == 1);

    const auto* c = find("sdc");
    CHECK(c != nullptr && c->holders.size() == 1 && c->in_use());

    const auto* e = find("sde");
    CHECK(e != nullptr && pm::erase_blockers(*e).empty());

    CHECK(find("loop0") == nullptr);
    CHECK(find("sdd") == nullptr);
    CHECK(find("nvme0c0n1") == nullptr);

    // A mounted nvme1n2 counts against nvme1n1, but not against nvme10n1, whose
    // name merely starts the same way.
    {
        const fs::path sys2 = root / "sys2";
        add_disk(sys2, "pci0000:00/0000:00:1c.0/nvme/nvme1", "nvme1n1", "2048", false);
        add_disk(sys2, "pci0000:00/0000:00:1c.0/nvme/nvme1", "nvme1n2", "2048", false);
        add_disk(sys2, "pci0000:00/0000:00:1b.0/nvme/nvme10", "nvme10n1", "2048", false);
        add_disk(sys2, "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0", "sdf", "2048", false);
        const fs::path mounts2 = root / "mounts2";
        put(mounts2, "/dev/nvme1n2 /data ext4 rw 0 0");
        const fs::path swaps2 = root / "swaps2";
        put(swaps2, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority");
        const pm::SystemRoots roots{sys2, mounts2, swaps2};

        const auto d1 = pm::find_device("nvme1n1", roots);
        CHECK(d1.has_value());
        if (d1) {
            CHECK(pm::erase_blockers(*d1).empty());  // the namespace itself is idle
            const auto busy = pm::sibling_blockers(*d1, roots);
            CHECK(busy.size() == 1 && busy.front() == "nvme1n2 mounted at /data");
        }
        const auto d10 = pm::find_device("nvme10n1", roots);
        CHECK(d10 && pm::sibling_blockers(*d10, roots).empty());
        const auto sata = pm::find_device("sdf", roots);
        CHECK(sata && pm::sibling_blockers(*sata, roots).empty());
    }

    fs::remove_all(root);
    return finish("device");
}
