// purgemark-gui: the graphical front end the live ISO boots into, under Cage.
//
//   drive list -> erase setup -> progress -> result
//
// Plain GTK4 with no icons and no extra theme, so the image stays small.

#include <unistd.h>

#include <gtk/gtk.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "pm/certificate.hpp"
#include "pm/device.hpp"
#include "pm/erase.hpp"
#include "pm/probe.hpp"
#include "pm/safety.hpp"

namespace fs = std::filesystem;

namespace {

constexpr const char* kCss = R"(
window, .page { background: #14171c; color: #e6e8eb; font-size: 15px; }
headerbar { background: #1b1f26; color: #e6e8eb; box-shadow: none; border-bottom: 1px solid #2b313a; }
.topbar { background: #1b1f26; padding: 12px 20px; border-bottom: 1px solid #2b313a; }
.brand { font-weight: 700; font-size: 18px; }
.subtitle, .muted { color: #98a1ad; }
.title { font-weight: 700; font-size: 20px; }
.section { font-weight: 700; margin-top: 8px; }
.card { background: #1b1f26; border: 1px solid #2b313a; border-radius: 8px; padding: 16px; }
.danger { border-color: #a33a3a; }
.ok { color: #6fcf8e; }
.bad { color: #ef7b7b; }
.warn { color: #e5c07b; }
.banner { background: #3a3120; border-bottom: 1px solid #6b5a30; padding: 10px 20px; color: #e5c07b; }
.bottombar { padding: 12px 20px; border-top: 1px solid #2b313a; }
list { background: transparent; }
list row { padding: 10px 12px; border-radius: 6px; color: #e6e8eb; }
list row:selected { background: #2c3a4f; color: #ffffff; }
button { padding: 8px 16px; background: #262c35; color: #e6e8eb; border: 1px solid #39414d;
         border-radius: 6px; box-shadow: none; background-image: none; }
button:hover { background: #2f3641; }
button.primary { background: #2f6fb5; border-color: #2f6fb5; color: #ffffff; }
button.primary:hover { background: #3a7cc4; }
button.erase { background: #b23b3b; border-color: #b23b3b; color: #ffffff; font-weight: 700; }
button.erase:hover { background: #c44848; }
button:disabled { background: #1f232a; color: #5f6773; border-color: #2b313a; }
entry { background: #101318; color: #e6e8eb; border: 1px solid #39414d; border-radius: 6px; padding: 6px 8px;
        background-image: none; box-shadow: none; }
check, radio { background: #101318; background-image: none; border: 1px solid #4a5361; color: #ffffff; box-shadow: none; }
check:checked, radio:checked { background: #2f6fb5; border-color: #2f6fb5; }
progressbar trough { border: none; background: #262c35; min-height: 14px; border-radius: 7px; }
progressbar progress { border: none; background: #2f6fb5; min-height: 14px; border-radius: 7px; }
)";

struct Options {
    std::string out_dir = "certificates";
    std::string key_path;
    bool include_loop = false;
    bool loop_only = false;  // show nothing but loop devices, for testing on a machine with real disks
    bool experimental = false;
    bool kiosk = false;
    bool certs_volatile = false;  // the kiosk found no PM-CERTS stick
    std::string started_file;  // created once the window is up; the kiosk uses it to decide on the terminal fallback
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

std::string confirm_token(const pm::Device& d) { return d.serial.empty() ? d.name : d.serial; }

std::vector<pm::ProbeResult> scan(const Options& o) {
    std::vector<pm::Device> devices;
    if (!o.loop_only) devices = pm::list_devices();
    if (o.include_loop || o.loop_only) {
        std::error_code ec;
        for (const auto& e : fs::directory_iterator("/sys/block", ec)) {
            const auto name = e.path().filename().string();
            if (name.rfind("loop", 0) != 0) continue;
            if (auto d = pm::find_device(name); d && d->size_bytes > 0) devices.push_back(*d);
        }
    }
    std::vector<pm::ProbeResult> out;
    for (const auto& d : devices) out.push_back(pm::probe(d));
    return out;
}

// Runs f on the GTK main thread.
void post(std::function<void()> f) {
    g_idle_add_full(
        G_PRIORITY_DEFAULT,
        [](gpointer d) -> gboolean {
            (*static_cast<std::function<void()>*>(d))();
            return G_SOURCE_REMOVE;
        },
        new std::function<void()>(std::move(f)),
        [](gpointer d) { delete static_cast<std::function<void()>*>(d); });
}

GtkWidget* label(const std::string& text, const char* css = nullptr, bool wrap = false) {
    GtkWidget* w = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(w), 0);
    if (wrap) {
        gtk_label_set_wrap(GTK_LABEL(w), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(w), PANGO_WRAP_WORD_CHAR);
    }
    if (css) gtk_widget_add_css_class(w, css);
    return w;
}

GtkWidget* vbox(int spacing) { return gtk_box_new(GTK_ORIENTATION_VERTICAL, spacing); }
GtkWidget* hbox(int spacing) { return gtk_box_new(GTK_ORIENTATION_HORIZONTAL, spacing); }

GtkWidget* card() {
    GtkWidget* b = vbox(8);
    gtk_widget_add_css_class(b, "card");
    return b;
}

GtkWidget* button(const char* text, const char* css = nullptr) {
    GtkWidget* b = gtk_button_new_with_label(text);
    if (css) gtk_widget_add_css_class(b, css);
    return b;
}

void clear(GtkWidget* box) {
    while (GtkWidget* c = gtk_widget_get_first_child(box)) gtk_box_remove(GTK_BOX(box), c);
}

void append(GtkWidget* box, GtkWidget* child) { gtk_box_append(GTK_BOX(box), child); }

GtkWidget* spacer() {
    GtkWidget* s = hbox(0);
    gtk_widget_set_hexpand(s, TRUE);
    return s;
}

void set_margins(GtkWidget* w, int m) {
    gtk_widget_set_margin_top(w, m);
    gtk_widget_set_margin_bottom(w, m);
    gtk_widget_set_margin_start(w, m);
    gtk_widget_set_margin_end(w, m);
}

GtkWidget* scrolled(GtkWidget* content) {
    GtkWidget* s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), content);
    gtk_widget_set_vexpand(s, TRUE);
    return s;
}

class App {
public:
    explicit App(Options o) : opts_(std::move(o)) {}

    ~App() {
        if (scan_thread_.joinable()) scan_thread_.join();
        if (worker_.joinable()) worker_.join();
    }

    void activate(GtkApplication* gtk_app) {
        gtk_app_ = gtk_app;
        GtkCssProvider* css = gtk_css_provider_new();
        gtk_css_provider_load_from_string(css, kCss);
        gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
                                                   GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        g_object_unref(css);

        window_ = gtk_application_window_new(gtk_app);
        gtk_window_set_title(GTK_WINDOW(window_), "PurgeMark");
        gtk_window_set_default_size(GTK_WINDOW(window_), 1180, 760);
        g_signal_connect(window_, "close-request", G_CALLBACK(+[](GtkWindow*, gpointer p) -> gboolean {
                             auto* a = static_cast<App*>(p);
                             return a->busy_ || a->opts_.kiosk;
                         }), this);

        GtkWidget* root = vbox(0);
        gtk_widget_add_css_class(root, "page");
        append(root, topbar());
        if (opts_.certs_volatile) append(root, certs_banner());

        stack_ = gtk_stack_new();
        gtk_widget_set_vexpand(stack_, TRUE);
        gtk_stack_add_named(GTK_STACK(stack_), list_page(), "list");
        setup_page_ = vbox(12);
        set_margins(setup_page_, 20);
        gtk_stack_add_named(GTK_STACK(stack_), scrolled(setup_page_), "setup");
        gtk_stack_add_named(GTK_STACK(stack_), progress_page(), "progress");
        result_page_ = vbox(12);
        set_margins(result_page_, 20);
        gtk_stack_add_named(GTK_STACK(stack_), scrolled(result_page_), "result");
        append(root, stack_);

        gtk_window_set_child(GTK_WINDOW(window_), root);
        if (opts_.kiosk) gtk_window_fullscreen(GTK_WINDOW(window_));
        gtk_window_present(GTK_WINDOW(window_));
        if (!opts_.started_file.empty()) {
            if (FILE* f = std::fopen(opts_.started_file.c_str(), "w")) std::fclose(f);
        }
        rescan();
    }

    bool power_off_requested() const { return power_off_; }

private:
    Options opts_;
    GtkApplication* gtk_app_ = nullptr;
    GtkWidget* window_ = nullptr;
    GtkWidget* stack_ = nullptr;

    // Drive list
    GtkWidget* drive_list_ = nullptr;
    GtkWidget* detail_ = nullptr;
    GtkWidget* erase_next_ = nullptr;
    GtkWidget* rescan_btn_ = nullptr;
    GtkWidget* stick_btn_ = nullptr;
    GtkWidget* power_btn_ = nullptr;
    std::vector<pm::ProbeResult> drives_;
    int selected_ = -1;
    bool scanning_ = false;
    bool power_armed_ = false;
    bool power_off_ = false;
    std::thread scan_thread_;

    // Setup
    GtkWidget* setup_page_ = nullptr;
    std::vector<pm::Method> method_choices_;
    std::vector<GtkWidget*> method_checks_;
    GtkWidget* how_label_ = nullptr;
    GtkWidget* pattern_box_ = nullptr;
    GtkWidget* pattern_random_ = nullptr;
    GtkWidget* operator_entry_ = nullptr;
    GtkWidget* confirm_entry_ = nullptr;
    GtkWidget* erase_btn_ = nullptr;
    GtkWidget* setup_error_ = nullptr;

    // Progress
    GtkWidget* progress_title_ = nullptr;
    GtkWidget* progress_state_ = nullptr;
    GtkWidget* progress_bar_ = nullptr;
    GtkWidget* progress_stats_ = nullptr;
    GtkWidget* cancel_btn_ = nullptr;
    bool cancel_armed_ = false;
    guint tick_ = 0;
    std::atomic<std::uint64_t> done_{0};
    std::atomic<std::uint64_t> total_{1};
    std::atomic<bool> cancel_{false};
    std::atomic<bool> verifying_{false};
    std::atomic<bool> busy_{false};
    std::chrono::steady_clock::time_point started_;
    pm::Method running_method_ = pm::Method::Overwrite;
    std::thread worker_;

    // Result
    GtkWidget* result_page_ = nullptr;
    std::mutex result_mu_;
    pm::CertificateInput result_;
    std::string cert_path_;
    std::string cert_error_;
    std::string key_note_;

    const pm::ProbeResult* current() const {
        return selected_ >= 0 && selected_ < static_cast<int>(drives_.size())
                   ? &drives_[static_cast<std::size_t>(selected_)]
                   : nullptr;
    }

    GtkWidget* topbar() {
        GtkWidget* b = hbox(12);
        gtk_widget_add_css_class(b, "topbar");
        append(b, label("PurgeMark", "brand"));
        append(b, spacer());
        append(b, label("Verifiable drive sanitization", "subtitle"));
        return b;
    }

    GtkWidget* certs_banner() {
        GtkWidget* b = hbox(12);
        gtk_widget_add_css_class(b, "banner");
        append(b, label("No USB stick labelled PM-CERTS. Certificates are kept in RAM and lost at power-off."));
        append(b, spacer());
        GtkWidget* again = stick_btn_ = button("Look for the stick again");
        g_signal_connect(again, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             // The kiosk service restarts us and mounts the stick if it's there.
                             auto* a = static_cast<App*>(p);
                             if (!a->busy_) g_application_quit(G_APPLICATION(a->gtk_app_));
                         }), this);
        append(b, again);
        return b;
    }

    // --- drive list -------------------------------------------------------
    GtkWidget* list_page() {
        GtkWidget* page = vbox(0);
        GtkWidget* body = hbox(16);
        gtk_widget_set_vexpand(body, TRUE);
        set_margins(body, 20);

        GtkWidget* left = card();
        gtk_widget_set_size_request(left, 420, -1);
        append(left, label("Drives", "title"));
        drive_list_ = gtk_list_box_new();
        g_signal_connect(drive_list_, "row-selected",
                         G_CALLBACK(+[](GtkListBox*, GtkListBoxRow* row, gpointer p) {
                             auto* a = static_cast<App*>(p);
                             a->selected_ = row ? gtk_list_box_row_get_index(row) : -1;
                             a->show_detail();
                         }), this);
        // Tab leaves the list instead of walking its rows, which would change the selected drive.
        // Up and Down still move the selection.
        GtkEventController* keys = gtk_event_controller_key_new();
        gtk_event_controller_set_propagation_phase(keys, GTK_PHASE_CAPTURE);
        g_signal_connect(keys, "key-pressed",
                         G_CALLBACK(+[](GtkEventControllerKey*, guint key, guint, GdkModifierType, gpointer p) -> gboolean {
                             if (key != GDK_KEY_Tab) return FALSE;
                             gtk_widget_grab_focus(static_cast<App*>(p)->rescan_btn_);
                             return TRUE;
                         }), this);
        gtk_widget_add_controller(drive_list_, keys);
        append(left, scrolled(drive_list_));
        append(body, left);

        detail_ = vbox(8);
        GtkWidget* right = card();
        gtk_widget_set_hexpand(right, TRUE);
        append(right, scrolled(detail_));
        append(body, right);
        append(page, body);

        GtkWidget* bar = hbox(10);
        gtk_widget_add_css_class(bar, "bottombar");
        rescan_btn_ = button("Rescan");
        g_signal_connect(rescan_btn_, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             static_cast<App*>(p)->rescan();
                         }), this);
        append(bar, rescan_btn_);
        power_btn_ = button(opts_.kiosk ? "Power off" : "Quit");
        g_signal_connect(power_btn_, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             static_cast<App*>(p)->power_clicked();
                         }), this);
        append(bar, power_btn_);
        append(bar, spacer());
        erase_next_ = button("Erase this drive...", "primary");
        gtk_widget_set_sensitive(erase_next_, FALSE);
        g_signal_connect(erase_next_, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             static_cast<App*>(p)->start_setup();
                         }), this);
        append(bar, erase_next_);
        append(page, bar);
        return page;
    }

    void power_clicked() {
        if (!opts_.kiosk) {
            g_application_quit(G_APPLICATION(gtk_app_));
            return;
        }
        if (power_armed_) {
            power_off_ = true;
            g_application_quit(G_APPLICATION(gtk_app_));
            return;
        }
        power_armed_ = true;
        gtk_button_set_label(GTK_BUTTON(power_btn_), "Click again to power off");
        g_timeout_add_seconds(
            4,
            +[](gpointer p) -> gboolean {
                auto* a = static_cast<App*>(p);
                a->power_armed_ = false;
                gtk_button_set_label(GTK_BUTTON(a->power_btn_), "Power off");
                return G_SOURCE_REMOVE;
            },
            this);
    }

    void rescan() {
        if (scanning_) return;
        scanning_ = true;
        gtk_widget_set_sensitive(rescan_btn_, FALSE);
        gtk_widget_set_sensitive(erase_next_, FALSE);
        clear(detail_);
        append(detail_, label("Looking for drives...", "muted"));
        if (scan_thread_.joinable()) scan_thread_.join();
        scan_thread_ = std::thread([this] {
            std::vector<pm::ProbeResult> found;
            std::string error;
            try {
                found = scan(opts_);
            } catch (const std::exception& e) {
                error = e.what();
            }
            post([this, found = std::move(found), error]() mutable { scan_done(std::move(found), error); });
        });
    }

    void scan_done(std::vector<pm::ProbeResult> found, const std::string& error) {
        scanning_ = false;
        gtk_widget_set_sensitive(rescan_btn_, TRUE);
        gtk_list_box_remove_all(GTK_LIST_BOX(drive_list_));
        selected_ = -1;
        drives_ = std::move(found);
        for (const auto& r : drives_) {
            GtkWidget* row = vbox(2);
            GtkWidget* top = hbox(8);
            append(top, label(or_dash(r.device.model)));
            append(top, spacer());
            append(top, label(human_size(r.device.size_bytes), "muted"));
            append(row, top);
            GtkWidget* bottom = hbox(8);
            append(bottom, label(r.device.name + "  " + pm::to_string(r.device.bus), "muted"));
            append(bottom, spacer());
            if (!r.blockers.empty()) append(bottom, label("In use", "bad"));
            append(row, bottom);
            gtk_list_box_append(GTK_LIST_BOX(drive_list_), row);
        }
        clear(detail_);
        if (!error.empty()) {
            append(detail_, label("Could not list drives: " + error, "bad", true));
        } else if (drives_.empty()) {
            append(detail_, label("No drives found.", "muted"));
        } else {
            gtk_list_box_select_row(GTK_LIST_BOX(drive_list_),
                                    gtk_list_box_get_row_at_index(GTK_LIST_BOX(drive_list_), 0));
            if (GtkListBoxRow* row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(drive_list_), 0)) gtk_widget_grab_focus(GTK_WIDGET(row));
        }
    }

    bool runnable(pm::Method m) const {
        const auto s = pm::support(m);
        return s == pm::Support::Implemented || (s == pm::Support::Experimental && opts_.experimental);
    }

    bool can_erase(const pm::ProbeResult& r) const {
        if (!r.blockers.empty()) return false;
        return std::any_of(r.methods.begin(), r.methods.end(),
                           [this](const auto& c) { return c.available && runnable(c.method); });
    }

    void show_detail() {
        const auto* r = current();
        gtk_widget_set_sensitive(erase_next_, r && can_erase(*r) && !scanning_);
        if (!r) return;
        clear(detail_);
        const auto& d = r->device;
        append(detail_, label(or_dash(d.model), "title", true));
        append(detail_, label(d.path + "  |  " + human_size(d.size_bytes) + "  |  " + pm::to_string(d.bus) + "  |  " +
                              (d.rotational ? "HDD" : "SSD")));
        append(detail_, label("Serial " + or_dash(d.serial) + "    Firmware " + or_dash(d.firmware), "muted", true));

        if (r->blockers.empty()) {
            append(detail_, label("Nothing is using this drive. It can be erased.", "ok", true));
        } else {
            for (const auto& b : r->blockers) append(detail_, label(b, "bad", true));
        }
        if (r->ata && r->ata->security_frozen) {
            append(detail_, label("Security-frozen: suspend and resume the machine to unlock ATA erase.", "warn", true));
        }
        if (!r->identify_error.empty()) append(detail_, label("Identify: " + r->identify_error, "muted", true));

        append(detail_, label("Erase methods, best first", "section"));
        GtkWidget* grid = gtk_grid_new();
        gtk_grid_set_column_spacing(GTK_GRID(grid), 24);
        gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
        int y = 0;
        for (const auto& m : r->methods) {
            gtk_grid_attach(GTK_GRID(grid), label(pm::to_string(m.method), m.available ? nullptr : "muted"), 0, y, 1, 1);
            const char* level_css = !m.available ? "muted" : m.level == pm::Level::Purge ? "ok" : "warn";
            gtk_grid_attach(GTK_GRID(grid), label(pm::to_string(m.level), level_css), 1, y, 1, 1);
            const char* state = !m.available ? "Not available"
                                : pm::support(m.method) == pm::Support::Experimental ? "Untested"
                                                                                     : "Available";
            gtk_grid_attach(GTK_GRID(grid), label(state, "muted"), 2, y, 1, 1);
            ++y;
            if (!m.note.empty()) {
                gtk_grid_attach(GTK_GRID(grid), label(m.note, "muted", true), 0, y, 3, 1);
                ++y;
            }
        }
        append(detail_, grid);
    }

    // --- setup ------------------------------------------------------------
    pm::Method chosen_method() const {
        for (std::size_t i = 0; i < method_checks_.size(); ++i)
            if (gtk_check_button_get_active(GTK_CHECK_BUTTON(method_checks_[i]))) return method_choices_[i];
        return method_choices_.front();
    }

    void update_method() {
        const bool overwrite = chosen_method() == pm::Method::Overwrite;
        gtk_widget_set_visible(pattern_box_, overwrite);
        gtk_label_set_text(GTK_LABEL(how_label_),
                           overwrite ? "Single pass, then read-back verification."
                                     : "The drive's firmware erases itself. Canaries planted first must be gone afterwards.");
    }

    void update_confirm() {
        const auto* r = current();
        gtk_widget_set_sensitive(erase_btn_,
                                 r && confirm_token(r->device) == gtk_editable_get_text(GTK_EDITABLE(confirm_entry_)));
    }

    void start_setup() {
        const auto* r = current();
        if (!r || !can_erase(*r)) return;
        clear(setup_page_);
        method_choices_.clear();
        method_checks_.clear();
        const auto& d = r->device;

        append(setup_page_, label("Confirm erase", "title"));
        GtkWidget* target = card();
        append(target, label(or_dash(d.model) + "  " + human_size(d.size_bytes), "section"));
        append(target, label(d.path + "    Serial " + or_dash(d.serial), "muted", true));
        append(setup_page_, target);

        GtkWidget* method = card();
        append(method, label("Method", "section"));
        GtkWidget* group = nullptr;
        int preselect = -1;
        for (const auto& c : r->methods) {
            if (!c.available || !runnable(c.method)) continue;
            std::string text = pm::to_string(c.method) + "   (NIST " + pm::to_string(c.level) + ")";
            if (pm::support(c.method) == pm::Support::Experimental) text += "   untested";
            else if (preselect < 0) preselect = static_cast<int>(method_checks_.size());
            GtkWidget* check = gtk_check_button_new_with_label(text.c_str());
            if (group) gtk_check_button_set_group(GTK_CHECK_BUTTON(check), GTK_CHECK_BUTTON(group));
            else group = check;
            method_choices_.push_back(c.method);
            method_checks_.push_back(check);
            append(method, check);
        }
        // Untested methods only run when picked on purpose.
        gtk_check_button_set_active(GTK_CHECK_BUTTON(method_checks_[static_cast<std::size_t>(std::max(preselect, 0))]), TRUE);
        for (GtkWidget* check : method_checks_) {
            g_signal_connect(check, "toggled", G_CALLBACK(+[](GtkCheckButton*, gpointer p) {
                                 static_cast<App*>(p)->update_method();
                             }), this);
        }
        how_label_ = label("", "muted", true);
        append(method, how_label_);
        pattern_box_ = vbox(4);
        append(pattern_box_, label("Overwrite pattern", "section"));
        pattern_random_ = gtk_check_button_new_with_label("Random data (recommended)");
        GtkWidget* zeros = gtk_check_button_new_with_label("Zeros");
        gtk_check_button_set_group(GTK_CHECK_BUTTON(zeros), GTK_CHECK_BUTTON(pattern_random_));
        gtk_check_button_set_active(GTK_CHECK_BUTTON(pattern_random_), TRUE);
        append(pattern_box_, pattern_random_);
        append(pattern_box_, zeros);
        append(method, pattern_box_);
        append(setup_page_, method);

        GtkWidget* cert = card();
        append(cert, label("Certificate", "section"));
        operator_entry_ = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(operator_entry_), "Operator name (optional)");
        append(cert, operator_entry_);
        append(cert, label(opts_.key_path.empty() ? "Signed with a one-off key (self-attested)"
                                                  : "Signed with operator key " + opts_.key_path,
                           "muted", true));
        append(cert, label("Saved to " + opts_.out_dir, "muted", true));
        append(setup_page_, cert);

        GtkWidget* danger = card();
        gtk_widget_add_css_class(danger, "danger");
        append(danger, label("All data on this drive will be destroyed", "bad"));
        append(danger, label("Type " + confirm_token(d) + " to confirm:", nullptr, true));
        confirm_entry_ = gtk_entry_new();
        g_signal_connect(confirm_entry_, "changed", G_CALLBACK(+[](GtkEditable*, gpointer p) {
                             static_cast<App*>(p)->update_confirm();
                         }), this);
        append(danger, confirm_entry_);
        setup_error_ = label("", "bad", true);
        append(danger, setup_error_);
        append(setup_page_, danger);

        GtkWidget* actions = hbox(10);
        GtkWidget* back = button("Back");
        g_signal_connect(back, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             gtk_stack_set_visible_child_name(GTK_STACK(static_cast<App*>(p)->stack_), "list");
                         }), this);
        append(actions, back);
        append(actions, spacer());
        erase_btn_ = button("Erase", "erase");
        gtk_widget_set_sensitive(erase_btn_, FALSE);
        g_signal_connect(erase_btn_, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             static_cast<App*>(p)->start_erase();
                         }), this);
        append(actions, erase_btn_);
        append(setup_page_, actions);

        update_method();
        gtk_stack_set_visible_child_name(GTK_STACK(stack_), "setup");
        gtk_widget_grab_focus(confirm_entry_);
    }

    void start_erase() {
        const auto* r = current();
        if (!r || busy_) return;
        if (confirm_token(r->device) != gtk_editable_get_text(GTK_EDITABLE(confirm_entry_))) {
            gtk_label_set_text(GTK_LABEL(setup_error_), "Confirmation does not match. Nothing was written.");
            return;
        }
        // Re-check right before writing: the drive may have been mounted meanwhile.
        const auto fresh = pm::find_device(r->device.name);
        if (!fresh || !pm::erase_blockers(*fresh).empty()) {
            gtk_label_set_text(GTK_LABEL(setup_error_), "Drive is now in use. Go back, rescan and try again.");
            return;
        }

        std::optional<pm::SigningKey> key;
        auto attestation = pm::Attestation::SelfAttested;
        if (!opts_.key_path.empty()) {
            auto k = pm::SigningKey::load_private_pem(opts_.key_path);
            if (!k) {
                gtk_label_set_text(GTK_LABEL(setup_error_), k.error().c_str());
                return;
            }
            key = k.value();
            attestation = pm::Attestation::OperatorKey;
        } else {
            key = pm::SigningKey::generate();
        }

        pm::EraseJob job;
        job.target_path = r->device.path;
        job.device = r->device;
        job.method = chosen_method();
        job.allow_experimental = opts_.experimental;
        job.pattern = gtk_check_button_get_active(GTK_CHECK_BUTTON(pattern_random_)) ? pm::Pattern::Random : pm::Pattern::Zero;
        running_method_ = job.method;
        job.progress = [this](std::uint64_t done, std::uint64_t total) {
            done_ = done;
            total_ = total;
            if (done == total) verifying_ = true;
            return !cancel_.load();
        };

        done_ = 0;
        total_ = std::max<std::uint64_t>(1, r->device.size_bytes);
        cancel_ = false;
        verifying_ = false;
        cancel_armed_ = false;
        busy_ = true;
        if (stick_btn_) gtk_widget_set_sensitive(stick_btn_, FALSE);
        started_ = std::chrono::steady_clock::now();
        gtk_label_set_text(GTK_LABEL(progress_title_), (r->device.path + "  " + or_dash(r->device.model)).c_str());
        gtk_button_set_label(GTK_BUTTON(cancel_btn_), "Cancel");
        gtk_widget_set_sensitive(cancel_btn_, TRUE);
        gtk_stack_set_visible_child_name(GTK_STACK(stack_), "progress");
        tick_ = g_timeout_add(
            200,
            +[](gpointer p) -> gboolean {
                static_cast<App*>(p)->update_progress();
                return G_SOURCE_CONTINUE;
            },
            this);
        update_progress();

        if (worker_.joinable()) worker_.join();
        const std::string op = gtk_editable_get_text(GTK_EDITABLE(operator_entry_));
        worker_ = std::thread([this, job, key = *key, attestation, op] {
            pm::CertificateInput input;
            std::string path, error;
            // An exception escaping a std::thread would take the whole kiosk down.
            try {
                input = pm::run_erase(job);
                input.operator_name = op;
                const auto cert = pm::sign_certificate(pm::make_certificate_body(input), key, attestation);
                if (!cert) {
                    error = cert.error();
                } else if (auto saved = pm::save_certificate(cert.value(), opts_.out_dir)) {
                    path = saved.value();
                } else {
                    error = saved.error();
                }
            } catch (const std::exception& e) {
                error = std::string("internal error: ") + e.what();
            } catch (...) {
                error = "internal error";
            }
            {
                std::lock_guard lock(result_mu_);
                result_ = std::move(input);
                cert_path_ = path;
                cert_error_ = error;
                key_note_ = (attestation == pm::Attestation::OperatorKey ? "operator key " : "self-attested key ") +
                            pm::key_id(key.public_raw());
            }
            post([this] { erase_finished(); });
        });
    }

    // --- progress ---------------------------------------------------------
    GtkWidget* progress_page() {
        GtkWidget* page = vbox(14);
        set_margins(page, 20);
        append(page, label("Erasing", "title"));
        GtkWidget* c = card();
        progress_title_ = label("", "section", true);
        append(c, progress_title_);
        progress_state_ = label("");
        append(c, progress_state_);
        progress_bar_ = gtk_progress_bar_new();
        append(c, progress_bar_);
        progress_stats_ = label("", "muted");
        append(c, progress_stats_);
        append(page, c);
        append(page, label("Do not remove the drive or turn off the machine.", "warn"));
        GtkWidget* grow = vbox(0);
        gtk_widget_set_vexpand(grow, TRUE);
        append(page, grow);
        GtkWidget* actions = hbox(10);
        cancel_btn_ = button("Cancel");
        g_signal_connect(cancel_btn_, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             static_cast<App*>(p)->cancel_clicked();
                         }), this);
        append(actions, cancel_btn_);
        append(page, actions);
        return page;
    }

    void cancel_clicked() {
        if (!cancel_armed_) {
            cancel_armed_ = true;
            gtk_button_set_label(GTK_BUTTON(cancel_btn_), "Really cancel? The drive stays partly erased");
            return;
        }
        cancel_ = true;
        gtk_button_set_label(GTK_BUTTON(cancel_btn_), "Cancelling...");
        gtk_widget_set_sensitive(cancel_btn_, FALSE);
    }

    void update_progress() {
        const double done = static_cast<double>(done_.load());
        const double total = static_cast<double>(total_.load());
        const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
        const double rate = secs > 0 ? done / secs : 0;
        const long eta = rate > 0 ? static_cast<long>((total - done) / rate) : 0;
        char stats[128];
        std::snprintf(stats, sizeof stats, "%.1f%%    %s/s    about %ldm %02lds left", 100.0 * done / total,
                      human_size(static_cast<std::uint64_t>(rate)).c_str(), eta / 60, eta % 60);
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar_), done / total);
        gtk_label_set_text(GTK_LABEL(progress_stats_), stats);
        const std::string state = verifying_ ? "Verifying: reading back sampled regions..."
                                             : pm::to_string(running_method_) + "...";
        gtk_label_set_text(GTK_LABEL(progress_state_), state.c_str());
    }

    // --- result -----------------------------------------------------------
    void erase_finished() {
        if (tick_) g_source_remove(tick_);
        tick_ = 0;
        busy_ = false;
        if (stick_btn_) gtk_widget_set_sensitive(stick_btn_, TRUE);
        if (worker_.joinable()) worker_.join();
        show_result();
    }

    static void result_row(GtkWidget* grid, int y, const std::string& name, const std::string& value,
                           const char* css = nullptr) {
        gtk_grid_attach(GTK_GRID(grid), label(name, "muted"), 0, y, 1, 1);
        GtkWidget* v = label(value, css, true);
        gtk_widget_set_hexpand(v, TRUE);
        gtk_grid_attach(GTK_GRID(grid), v, 1, y, 1, 1);
    }

    void show_result() {
        clear(result_page_);
        std::lock_guard lock(result_mu_);
        const auto& s = result_.sanitization;
        const auto& v = result_.verification;
        const bool ok = s.completed && v.passed() && cert_error_.empty();
        GtkWidget* heading = label(ok ? "Drive sanitized and verified" : "Erase did not complete successfully",
                                   ok ? "ok" : "bad");
        gtk_widget_add_css_class(heading, "title");
        append(result_page_, heading);

        GtkWidget* c = card();
        GtkWidget* grid = gtk_grid_new();
        gtk_grid_set_column_spacing(GTK_GRID(grid), 24);
        gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
        int y = 0;
        result_row(grid, y++, "Method", pm::to_string(s.method) + " (NIST " + pm::to_string(s.level) + ")");
        if (s.bytes_written) result_row(grid, y++, "Written", human_size(s.bytes_written));
        if (!s.error.empty()) result_row(grid, y++, "Error", s.error, "bad");
        if (s.completed) {
            result_row(grid, y++, "Verification",
                       std::string(v.passed() ? "Passed" : "FAILED") + ", " + std::to_string(v.samples) + " samples, " +
                           std::to_string(v.mismatches) + " mismatches",
                       v.passed() ? "ok" : "bad");
        }
        if (!cert_path_.empty()) {
            result_row(grid, y++, "Certificate", cert_path_);
            result_row(grid, y++, "Signed with", key_note_);
        } else {
            result_row(grid, y++, "Certificate", "Not saved: " + cert_error_, "bad");
        }
        append(c, grid);
        append(result_page_, c);

        GtkWidget* actions = hbox(10);
        append(actions, spacer());
        GtkWidget* done = button("Back to drive list", "primary");
        g_signal_connect(done, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
                             auto* a = static_cast<App*>(p);
                             gtk_stack_set_visible_child_name(GTK_STACK(a->stack_), "list");
                             a->rescan();
                         }), this);
        append(actions, done);
        append(result_page_, actions);
        gtk_stack_set_visible_child_name(GTK_STACK(stack_), "result");
    }
};

}  // namespace

int main(int argc, char** argv) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) opts.out_dir = argv[++i];
        else if (a == "--key" && i + 1 < argc) opts.key_path = argv[++i];
        else if (a == "--include-loop") opts.include_loop = true;
        else if (a == "--loop-only") opts.loop_only = true;
        else if (a == "--experimental") opts.experimental = true;
        else if (a == "--kiosk") opts.kiosk = true;
        else if (a == "--certs-volatile") opts.certs_volatile = true;
        else if (a == "--started-file" && i + 1 < argc) opts.started_file = argv[++i];
        else {
            std::cerr << "usage: purgemark-gui [--out DIR] [--key PRIVATE.pem] [--include-loop] [--loop-only]\n"
                         "                     [--experimental] [--kiosk] [--certs-volatile] [--started-file PATH]\n";
            return 2;
        }
    }
    if (::geteuid() != 0) {
        std::cerr << "purgemark-gui needs root to query and erase drives.\n";
        return 1;
    }

    int rc = 0;
    bool power_off = false;
    {
        App app(opts);
        GtkApplication* gtk_app = gtk_application_new("org.purgemark.gui", G_APPLICATION_NON_UNIQUE);
        g_signal_connect(gtk_app, "activate", G_CALLBACK(+[](GtkApplication* g, gpointer p) {
                             static_cast<App*>(p)->activate(g);
                         }), &app);
        rc = g_application_run(G_APPLICATION(gtk_app), 0, nullptr);
        g_object_unref(gtk_app);
        power_off = app.power_off_requested();
    }
    if (power_off) {
        ::execl("/usr/bin/systemctl", "systemctl", "poweroff", static_cast<char*>(nullptr));
        std::perror("systemctl poweroff");
        return 1;
    }
    return rc;
}
