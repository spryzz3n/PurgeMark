// zerotrace: the full-screen terminal UI the live ISO boots into.
//
//   drive list ──Enter──▶ erase setup ──confirm──▶ progress ──▶ result
//        ▲                     │ Esc                               │ Enter
//        └─────────────────────┴───────────────────────────────────┘

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "zt/certificate.hpp"
#include "zt/device.hpp"
#include "zt/erase.hpp"
#include "zt/probe.hpp"
#include "zt/safety.hpp"

using namespace ftxui;
namespace fs = std::filesystem;

namespace {

struct Options {
    std::string out_dir = "certificates";
    std::string key_path;
    bool include_loop = false;  // list loop devices too, for testing without spare disks
};

std::string human_size(std::uint64_t bytes) {
    static constexpr const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 5) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
    return buf;
}

std::string or_dash(const std::string& s) { return s.empty() ? "-" : s; }

std::vector<zt::Device> discover(bool include_loop) {
    auto devices = zt::list_devices();
    if (include_loop) {
        std::error_code ec;
        for (const auto& e : fs::directory_iterator("/sys/block", ec)) {
            const auto name = e.path().filename().string();
            if (name.rfind("loop", 0) != 0) continue;
            if (auto d = zt::find_device(name)) devices.push_back(*d);
        }
    }
    return devices;
}

// FTXUI's Radiobox and Menu use Tab to cycle their own items, which traps focus
// in a form. This wrapper hands Tab to the parent container so it moves focus.
class PassTab : public ComponentBase {
public:
    explicit PassTab(Component child) { Add(std::move(child)); }
    bool OnEvent(Event e) override {
        if (e == Event::Tab || e == Event::TabReverse) return false;
        return ComponentBase::OnEvent(e);
    }
};

// The text the operator must type to confirm: the serial when known.
std::string confirm_token(const zt::Device& d) { return d.serial.empty() ? d.name : d.serial; }

class App {
public:
    explicit App(Options opts) : opts_(std::move(opts)) {}

    int run() {
        refresh();
        auto screen = ScreenInteractive::Fullscreen();
        screen_ = &screen;
        auto root = Container::Tab({list_screen(), setup_screen(), progress_screen(), result_screen()}, &page_);
        screen.Loop(root);
        if (worker_.joinable()) worker_.join();
        return 0;
    }

private:
    enum Page { kList, kSetup, kProgress, kResult };

    // --- state -------------------------------------------------------------
    Options opts_;
    ScreenInteractive* screen_ = nullptr;
    int page_ = kList;

    std::vector<zt::ProbeResult> drives_;
    std::vector<std::string> drive_labels_;
    int selected_ = 0;

    int pattern_ = 0;
    std::vector<std::string> pattern_labels_ = {"Random data (recommended)", "Zeros"};
    std::string operator_name_;
    std::string confirm_text_;
    std::string setup_error_;

    std::atomic<std::uint64_t> done_{0};
    std::atomic<std::uint64_t> total_{1};
    std::atomic<bool> cancel_{false};
    std::atomic<bool> verifying_{false};
    std::chrono::steady_clock::time_point started_;
    std::thread worker_;

    std::mutex result_mu_;
    zt::CertificateInput result_;
    std::string cert_path_;
    std::string cert_error_;
    std::string key_note_;

    const zt::ProbeResult* current() const {
        return selected_ >= 0 && selected_ < static_cast<int>(drives_.size()) ? &drives_[static_cast<std::size_t>(selected_)]
                                                                            : nullptr;
    }

    void refresh() {
        drives_.clear();
        drive_labels_.clear();
        for (const auto& d : discover(opts_.include_loop)) drives_.push_back(zt::probe(d));
        for (const auto& r : drives_) {
            char line[160];
            std::snprintf(line, sizeof line, "%-9s %10s  %-28.28s %s", r.device.name.c_str(),
                          human_size(r.device.size_bytes).c_str(), or_dash(r.device.model).c_str(),
                          r.blockers.empty() ? "" : "[in use]");
            drive_labels_.emplace_back(line);
        }
        selected_ = std::min(selected_, std::max(0, static_cast<int>(drives_.size()) - 1));
    }

    // --- screen 1: drive list -------------------------------------------------
    Component list_screen() {
        auto menu = Menu(&drive_labels_, &selected_);
        auto view = Renderer(menu, [this, menu] {
            Elements detail;
            if (const auto* r = current()) detail = drive_detail(*r);
            else detail.push_back(text("No drives found.") | dim);

            return vbox({
                       header("Select a drive"),
                       hbox({
                           window(text(" Drives "), menu->Render() | vscroll_indicator | frame) |
                               size(WIDTH, EQUAL, 64),
                           window(text(" Details "), vbox(std::move(detail))) | flex,
                       }) | flex,
                       footer("↑/↓ select   Enter erase   r rescan   q quit"),
                   }) |
                   flex;
        });
        return CatchEvent(view, [this](Event e) {
            if (e == Event::Character('q')) {
                screen_->Exit();
                return true;
            }
            if (e == Event::Character('r')) {
                refresh();
                return true;
            }
            if (e == Event::Return) {
                start_setup();
                return true;
            }
            return false;
        });
    }

    Elements drive_detail(const zt::ProbeResult& r) {
        const auto& d = r.device;
        Elements el = {
            text(or_dash(d.model)) | bold,
            text(d.path + "  ·  " + human_size(d.size_bytes) + "  ·  " + zt::to_string(d.bus) + "  ·  " +
                 (d.rotational ? "HDD" : "SSD")),
            text("serial " + or_dash(d.serial) + "   firmware " + or_dash(d.firmware)) | dim,
            separator(),
        };
        if (r.blockers.empty()) {
            el.push_back(text("✓ No blockers: this drive can be erased") | color(Color::GreenLight));
        } else {
            for (const auto& b : r.blockers) el.push_back(text("✗ " + b) | color(Color::RedLight));
        }
        if (r.ata && r.ata->security_frozen) {
            el.push_back(text("! Security-frozen: suspend and resume to unlock ATA erase") | color(Color::Yellow));
        }
        if (!r.identify_error.empty()) el.push_back(paragraph("identify: " + r.identify_error) | dim);
        el.push_back(separator());
        el.push_back(text("Erase methods, best first") | bold);
        for (const auto& m : r.methods) {
            auto row = hbox({
                text(m.available ? "● " : "○ "),
                text(zt::to_string(m.method)) | size(WIDTH, EQUAL, 40),
                text(zt::to_string(m.level)) | size(WIDTH, EQUAL, 7) |
                    color(m.level == zt::Level::Purge ? Color::GreenLight : Color::Yellow),
            });
            el.push_back(m.available ? row : row | dim);
            if (!m.note.empty()) el.push_back(text("    " + m.note) | dim);
        }
        el.push_back(separator());
        el.push_back(paragraph("This build erases by overwrite (NIST Clear). Firmware sanitize methods "
                               "are detected but not yet executed.") |
                     dim);
        return el;
    }

    void start_setup() {
        const auto* r = current();
        if (!r || !r->blockers.empty()) return;
        operator_name_.clear();
        confirm_text_.clear();
        setup_error_.clear();
        page_ = kSetup;
    }

    // --- screen 2: erase setup ---------------------------------------------------
    Component setup_screen() {
        auto patterns = Make<PassTab>(Radiobox(&pattern_labels_, &pattern_));
        auto op = Input(&operator_name_, "optional");
        auto confirm = Input(&confirm_text_, "type the serial shown above");
        auto erase = Button(" ERASE ", [this] { start_erase(); }, ButtonOption::Simple());
        auto back = Button(" Back ", [this] { page_ = kList; }, ButtonOption::Simple());
        auto form = Container::Vertical({patterns, op, confirm, Container::Horizontal({erase, back})});

        auto view = Renderer(form, [=, this] {
            const auto* r = current();
            if (!r) return text("");
            const auto& d = r->device;
            return vbox({
                       header("Confirm erase"),
                       window(text(" Target "),
                              vbox({
                                  text(or_dash(d.model) + "  " + human_size(d.size_bytes)) | bold,
                                  text(d.path + "   serial " + or_dash(d.serial)),
                              })),
                       window(text(" Method "),
                              vbox({
                                  text("Software overwrite, single pass, then read-back verification"),
                                  patterns->Render(),
                              })),
                       window(text(" Certificate "),
                              vbox({
                                  hbox({text("Operator  "), op->Render() | flex}),
                                  text(opts_.key_path.empty() ? "Signed with a one-off key (self-attested)"
                                                              : "Signed with operator key " + opts_.key_path) |
                                      dim,
                                  text("Saved to " + opts_.out_dir) | dim,
                              })),
                       window(text(" ALL DATA ON THIS DRIVE WILL BE DESTROYED ") | color(Color::RedLight),
                              vbox({
                                  hbox({text("Type "), text(confirm_token(d)) | bold, text(" to confirm: "),
                                        confirm->Render() | flex}),
                                  text(setup_error_) | color(Color::RedLight),
                              })),
                       hbox({erase->Render() | color(Color::RedLight), text("  "), back->Render()}),
                       filler(),
                       footer("Tab/↑/↓ move   Enter activate   Esc back"),
                   }) |
                   flex;
        });
        return CatchEvent(view, [this](Event e) {
            if (e == Event::Escape) {
                page_ = kList;
                return true;
            }
            return false;
        });
    }

    void start_erase() {
        const auto* r = current();
        if (!r) return;
        if (confirm_text_ != confirm_token(r->device)) {
            setup_error_ = "Confirmation does not match. Nothing was written.";
            return;
        }
        // Re-check right before writing: the drive may have been mounted meanwhile.
        const auto fresh = zt::find_device(r->device.name);
        if (!fresh || !zt::erase_blockers(*fresh).empty()) {
            setup_error_ = "Drive is now in use. Rescan and try again.";
            return;
        }

        std::optional<zt::SigningKey> key;
        auto attestation = zt::Attestation::SelfAttested;
        if (!opts_.key_path.empty()) {
            auto k = zt::SigningKey::load_private_pem(opts_.key_path);
            if (!k) {
                setup_error_ = k.error();
                return;
            }
            key = k.value();
            attestation = zt::Attestation::OperatorKey;
        } else {
            key = zt::SigningKey::generate();
        }

        zt::EraseJob job;
        job.target_path = r->device.path;
        job.device = r->device;
        job.pattern = pattern_ == 0 ? zt::Pattern::Random : zt::Pattern::Zero;
        job.progress = [this](std::uint64_t done, std::uint64_t total) {
            done_ = done;
            total_ = total;
            if (done == total) verifying_ = true;
            screen_->PostEvent(Event::Custom);
            return !cancel_.load();
        };

        done_ = 0;
        total_ = std::max<std::uint64_t>(1, r->device.size_bytes);
        cancel_ = false;
        verifying_ = false;
        started_ = std::chrono::steady_clock::now();
        page_ = kProgress;

        if (worker_.joinable()) worker_.join();
        worker_ = std::thread([this, job, key = *key, attestation, op = operator_name_] {
            auto input = zt::run_erase(job);
            input.operator_name = op;
            const auto cert = zt::sign_certificate(zt::make_certificate_body(input), key, attestation);
            std::string path, error;
            if (!cert) {
                error = cert.error();
            } else if (auto saved = zt::save_certificate(cert.value(), opts_.out_dir)) {
                path = saved.value();
            } else {
                error = saved.error();
            }
            {
                std::lock_guard lock(result_mu_);
                result_ = std::move(input);
                cert_path_ = path;
                cert_error_ = error;
                key_note_ = (attestation == zt::Attestation::OperatorKey ? "operator key " : "self-attested key ") +
                            zt::key_id(key.public_raw());
            }
            screen_->Post([this] { page_ = kResult; });
            screen_->PostEvent(Event::Custom);
        });
    }

    // --- screen 3: progress --------------------------------------------------------
    Component progress_screen() {
        auto view = Renderer([this] {
            const double done = static_cast<double>(done_.load());
            const double total = static_cast<double>(total_.load());
            const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
            const double rate = secs > 0 ? done / secs : 0;
            const long eta = rate > 0 ? static_cast<long>((total - done) / rate) : 0;
            char stats[128];
            std::snprintf(stats, sizeof stats, "%.1f%%   %s/s   ETA %ldm%02lds", 100.0 * done / total,
                          human_size(static_cast<std::uint64_t>(rate)).c_str(), eta / 60, eta % 60);
            const auto* r = current();
            return vbox({
                       header("Erasing"),
                       window(text(" " + (r ? r->device.path + "  " + or_dash(r->device.model) : "") + " "),
                              vbox({
                                  text(verifying_ ? "Verifying: reading back sampled regions..." : "Overwriting..."),
                                  gauge(static_cast<float>(done / total)) | color(Color::Cyan),
                                  text(stats),
                              })),
                       text(cancel_ ? "Cancelling..." : "") | color(Color::Yellow),
                       filler(),
                       footer("Esc cancel (the drive will be left partially erased)"),
                   }) |
                   flex;
        });
        return CatchEvent(view, [this](Event e) {
            if (e == Event::Escape) {
                cancel_ = true;
                return true;
            }
            return true;  // swallow everything else while writing
        });
    }

    // --- screen 4: result -------------------------------------------------------------
    Component result_screen() {
        auto view = Renderer([this] {
            std::lock_guard lock(result_mu_);
            const auto& s = result_.sanitization;
            const auto& v = result_.verification;
            const bool ok = s.completed && v.passed() && cert_error_.empty();
            Elements el = {
                text(ok ? "✓ Drive sanitized and verified" : "✗ Erase did not complete successfully") | bold |
                    color(ok ? Color::GreenLight : Color::RedLight),
                separator(),
                text("Method        " + zt::to_string(s.method) + " (NIST " + zt::to_string(s.level) + ")"),
                text("Written       " + human_size(s.bytes_written)),
            };
            if (!s.error.empty()) el.push_back(text("Error         " + s.error) | color(Color::RedLight));
            if (s.completed) {
                el.push_back(text("Verification  " + std::string(v.passed() ? "passed" : "FAILED") + ", " +
                                  std::to_string(v.samples) + " samples, " + std::to_string(v.mismatches) +
                                  " mismatches"));
            }
            el.push_back(separator());
            if (!cert_path_.empty()) {
                el.push_back(text("Certificate   " + cert_path_));
                el.push_back(text("Signed with   " + key_note_) | dim);
            } else {
                el.push_back(text("Certificate NOT saved: " + cert_error_) | color(Color::RedLight));
            }
            return vbox({header("Result"), window(text(" Summary "), vbox(std::move(el))), filler(),
                         footer("Enter back to drive list   q quit")}) |
                   flex;
        });
        return CatchEvent(view, [this](Event e) {
            if (e == Event::Return) {
                refresh();
                page_ = kList;
                return true;
            }
            if (e == Event::Character('q')) {
                screen_->Exit();
                return true;
            }
            return false;
        });
    }

    static Element header(const std::string& title) {
        return hbox({text(" ZeroTrace ") | bold | inverted, text("  " + title) | bold, filler(),
                     text("verifiable drive sanitization ") | dim});
    }
    static Element footer(const std::string& keys) { return text(" " + keys) | dim; }
};

}  // namespace

int main(int argc, char** argv) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) opts.out_dir = argv[++i];
        else if (a == "--key" && i + 1 < argc) opts.key_path = argv[++i];
        else if (a == "--include-loop") opts.include_loop = true;
        else {
            std::cerr << "usage: zerotrace [--out DIR] [--key PRIVATE.pem] [--include-loop]\n";
            return 2;
        }
    }
    if (::geteuid() != 0) {
        std::cerr << "zerotrace needs root to query and erase drives.\n";
        return 1;
    }
    return App(opts).run();
}
