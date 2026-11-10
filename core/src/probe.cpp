#include "pm/probe.hpp"

#include "pm/safety.hpp"

namespace pm {

ProbeResult probe(const Device& dev) {
    ProbeResult r;
    r.device = dev;
    r.blockers = erase_blockers(dev);

    switch (dev.bus) {
        case Bus::Nvme: {
            const auto raw = nvme_identify_ctrl_raw(dev.path);
            if (!raw) {
                r.identify_error = raw.error();
                break;
            }
            const auto id = parse_nvme_identify_ctrl(raw.value());
            if (!id) {
                r.identify_error = id.error();
                break;
            }
            r.nvme = id.value();
            // NN is only the highest valid NSID; the active list says how many really exist.
            if (const auto list = nvme_active_ns_list_raw(dev.path)) {
                r.nvme->active_namespaces = count_active_namespaces(list.value());
            }
            break;
        }
        case Bus::Sata:
        case Bus::Usb:
        case Bus::Scsi: {
            const auto raw = ata_identify_raw(dev.path);
            if (!raw) {
                r.identify_error = raw.error();
                break;
            }
            const auto id = parse_ata_identify(raw.value());
            if (id) r.ata = id.value();
            else r.identify_error = id.error();
            break;
        }
        case Bus::Virtio:
        case Bus::Mmc:
        case Bus::Unknown:
            r.identify_error = "no firmware sanitize path for " + to_string(dev.bus) + " devices";
            break;
    }

    // sysfs doesn't expose SATA serials; IDENTIFY does.
    if (r.device.serial.empty()) {
        if (r.ata) r.device.serial = r.ata->serial;
        else if (r.nvme) r.device.serial = r.nvme->serial;
    }

    r.methods = rank_methods(r.device, r.nvme, r.ata, dev.bus == Bus::Nvme ? sibling_blockers(dev) : std::vector<std::string>{});
    return r;
}

}  // namespace pm
