#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <storage/storage.h>
#include <toolbox/path.h>

#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>

#define NFC_CONVERT_FOLDER    "/ext/nfc"
#define NFC_CONVERT_EXTENSION ".nfc"

#define NFC_CONVERT_MAX_FILES (64)
#define NFC_CONVERT_NAME_LEN  (64)

// Menu index for the "Scan card" entry, placed past the file indices.
#define NFC_CONVERT_SCAN_INDEX (NFC_CONVERT_MAX_FILES)

// Page 3 of every NTAG holds the NDEF Capability Container. Byte 2 encodes the
// usable NDEF area in units of 8 bytes; it is part of what makes a dump read as
// a given variant, so it has to be rewritten along with the page count.
#define NTAG_CC_BYTE_0 (0xE1)
#define NTAG_CC_BYTE_1 (0x10)

// Default contents of the dynamic lock page on a blank NTAG21x.
#define NTAG_DYNAMIC_LOCK_RFUI (0xBD)

typedef enum {
    NfcConvertViewSubmenu,
    NfcConvertViewTargets,
    NfcConvertViewResult,
} NfcConvertView;

typedef enum {
    // Posted by the scanner callback (NFC worker thread) once a card is found.
    NfcConvertCustomEventCardDetected = 100,
} NfcConvertCustomEvent;

typedef struct {
    MfUltralightType type;
    const char* name;
    uint8_t cc_size; // CC byte 2 (NDEF area / 8)
    uint8_t storage_size; // GET_VERSION byte 6
} NfcConvertTarget;

// Restricted to the three NTAG21x variants on purpose: these are the only types
// whose CC and GET_VERSION values are interchangeable by a pure layout rewrite.
static const NfcConvertTarget nfc_convert_targets[] = {
    {MfUltralightTypeNTAG213, "NTAG213", 0x12, 0x0F},
    {MfUltralightTypeNTAG215, "NTAG215", 0x3E, 0x11},
    {MfUltralightTypeNTAG216, "NTAG216", 0x6D, 0x13},
};

#define NFC_CONVERT_TARGET_COUNT COUNT_OF(nfc_convert_targets)

typedef struct {
    MfUltralightType type;
    uint16_t user_end; // first page after the user data area
} NfcConvertSource;

// Where user memory stops on each source type. This cannot be derived from
// mf_ultralight_get_config_page_num(): only some variants put a dynamic lock
// page directly below the config block, and the ones without a config block at
// all still reserve trailing pages for lock bytes, counters or keys.
static const NfcConvertSource nfc_convert_sources[] = {
    {MfUltralightTypeOrigin, 16}, // 4-15 user, nothing after
    {MfUltralightTypeNTAG203, 40}, // then lock bytes + counter
    {MfUltralightTypeMfulC, 40}, // then lock, AUTH0/AUTH1, 3DES key
    {MfUltralightTypeUL11, 16}, // then config; no dynamic lock page
    {MfUltralightTypeUL21, 36}, // then dynamic lock + config
    {MfUltralightTypeNTAG213, 40}, // then dynamic lock + config
    {MfUltralightTypeNTAG215, 130},
    {MfUltralightTypeNTAG216, 226},
};

#define NFC_CONVERT_SOURCE_COUNT COUNT_OF(nfc_convert_sources)

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    Submenu* targets;
    TextBox* text_box;

    FuriString* text;
    FuriString* display;
    FuriString* load_path;

    NfcDevice* device;
    bool loaded;
    NfcConvertView current_view;

    // Populated from /ext/nfc each time the main menu is shown.
    char files[NFC_CONVERT_MAX_FILES][NFC_CONVERT_NAME_LEN];
    size_t file_num;

    // Live scanning. `nfc` is only held for the duration of a scan.
    Nfc* nfc;
    NfcScanner* scanner;
    FuriMutex* mutex;
    bool ultralight_seen;
} NfcConvert;

static void
    nfc_convert_build_target_menu(NfcConvert* app, MfUltralightType current, const char* name);

static void nfc_convert_switch_to(NfcConvert* app, NfcConvertView view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

/* ---------- */
/* Conversion */
/* ---------- */

static const NfcConvertSource* nfc_convert_find_source(MfUltralightType type) {
    for(size_t i = 0; i < NFC_CONVERT_SOURCE_COUNT; i++) {
        if(nfc_convert_sources[i].type == type) return &nfc_convert_sources[i];
    }
    return NULL;
}

/**
 * Rewrite `data` in place so it describes `target` instead of its current type.
 *
 * User data is preserved up to whatever the target can hold; growing a dump
 * zero-fills the new pages, shrinking one discards the overflow. Lock bytes are
 * reset to blank defaults because they index a memory map that no longer
 * applies. The password/PACK config block is carried over if the source had one.
 */
static void nfc_convert_retype(MfUltralightData* data, const NfcConvertTarget* target) {
    const uint16_t old_total = data->pages_total;
    const uint16_t old_cfg = mf_ultralight_get_config_page_num(data->type);
    const uint16_t new_total = mf_ultralight_get_pages_total(target->type);
    const uint16_t new_cfg = mf_ultralight_get_config_page_num(target->type);

    // Stash the source config block before the page array is reshuffled.
    MfUltralightConfigPages old_config;
    bool have_config = false;
    if(old_cfg != 0 && old_cfg + 3 < old_total) {
        memcpy(&old_config, &data->page[old_cfg], sizeof(MfUltralightConfigPages));
        have_config = true;
    }

    // Where the source's user data stops is variant-specific; see the table.
    const NfcConvertSource* source = nfc_convert_find_source(data->type);
    furi_check(source); // callers reject source types without a known layout
    const uint16_t old_user_end = source->user_end;
    const uint16_t new_user_end = new_cfg - 1;
    const uint16_t keep_end = MIN(old_user_end, new_user_end);

    // Everything above the retained user data starts from a blank slate.
    for(uint16_t i = keep_end; i < new_total; i++) {
        memset(data->page[i].data, 0, MF_ULTRALIGHT_PAGE_SIZE);
    }
    for(uint16_t i = new_total; i < old_total && i < MF_ULTRALIGHT_MAX_PAGE_NUM; i++) {
        memset(data->page[i].data, 0, MF_ULTRALIGHT_PAGE_SIZE);
    }

    // Static lock bytes (page 2 bytes 2-3) and the dynamic lock page.
    data->page[2].data[2] = 0x00;
    data->page[2].data[3] = 0x00;
    data->page[new_user_end].data[0] = 0x00;
    data->page[new_user_end].data[1] = 0x00;
    data->page[new_user_end].data[2] = 0x00;
    data->page[new_user_end].data[3] = NTAG_DYNAMIC_LOCK_RFUI;

    // Capability Container.
    data->page[3].data[0] = NTAG_CC_BYTE_0;
    data->page[3].data[1] = NTAG_CC_BYTE_1;
    data->page[3].data[2] = target->cc_size;
    data->page[3].data[3] = 0x00;

    // Config block: carry the old one over, otherwise write blank defaults.
    MfUltralightConfigPages new_config;
    if(have_config) {
        new_config = old_config;
    } else {
        memset(&new_config, 0, sizeof(new_config));
        new_config.auth0 = 0xFF; // no page is password protected
        memset(new_config.password.data, 0xFF, MF_ULTRALIGHT_AUTH_PASSWORD_SIZE);
    }

    // MIRROR_PAGE points into the old layout and would land out of bounds.
    new_config.mirror_page = 0;
    new_config.mirror.mirror_conf = MfUltralightMirrorNone;
    memcpy(&data->page[new_cfg], &new_config, sizeof(MfUltralightConfigPages));

    // GET_VERSION response. Readers use byte 6 to size the tag.
    data->version.header = 0x00;
    data->version.vendor_id = 0x04; // NXP
    data->version.prod_type = 0x04; // NTAG
    data->version.prod_subtype = 0x02; // 50 pF
    data->version.prod_ver_major = 0x01;
    data->version.prod_ver_minor = 0x00;
    data->version.storage_size = target->storage_size;
    data->version.protocol_type = 0x03; // ISO14443-3

    data->type = target->type;
    data->pages_total = new_total;
    data->pages_read = new_total;
}

/* ----------- */
/* UI plumbing */
/* ----------- */

// TextBox rather than Widget: these readouts run longer than the 128x64 screen,
// so the text needs to wrap and scroll.
static void nfc_convert_show_result(NfcConvert* app, const char* header) {
    furi_string_printf(app->display, "%s\n%s", header, furi_string_get_cstr(app->text));
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->display));
    nfc_convert_switch_to(app, NfcConvertViewResult);
}

// Accept the loaded/scanned card and move straight to picking a target. The
// source variant is read from the data, never asked for.
static bool nfc_convert_accept_device(NfcConvert* app) {
    if(nfc_device_get_protocol(app->device) != NfcProtocolMfUltralight) {
        furi_string_printf(
            app->text,
            "Not an Ultralight/NTAG card.\nProtocol: %s",
            nfc_device_get_protocol_name(nfc_device_get_protocol(app->device)));
        app->loaded = false;
        nfc_convert_show_result(app, "Wrong type");
        return false;
    }

    const MfUltralightData* data = nfc_device_get_data(app->device, NfcProtocolMfUltralight);

    // Anything with a known user-data boundary can be read; the NTAG I2C family
    // is excluded because it pages memory through SECTOR_SELECT rather than
    // laying it out linearly.
    if(nfc_convert_find_source(data->type) == NULL) {
        furi_string_printf(
            app->text,
            "%s has a sectored memory map this app cannot rewrite.",
            mf_ultralight_get_device_name(data, NfcDeviceNameTypeFull));
        app->loaded = false;
        nfc_convert_show_result(app, "Unsupported");
        return false;
    }

    app->loaded = true;
    nfc_convert_build_target_menu(
        app, data->type, mf_ultralight_get_device_name(data, NfcDeviceNameTypeFull));
    nfc_convert_switch_to(app, NfcConvertViewTargets);
    return true;
}

/* ------------- */
/* Live scanning */
/* ------------- */

static void nfc_convert_scan_stop(NfcConvert* app) {
    if(app->scanner) {
        nfc_scanner_stop(app->scanner);
        nfc_scanner_free(app->scanner);
        app->scanner = NULL;
    }
    if(app->nfc) {
        nfc_free(app->nfc);
        app->nfc = NULL;
    }
}

// Runs on the NFC worker thread, so it only records a flag and hands off.
static void nfc_convert_scanner_callback(NfcScannerEvent event, void* context) {
    NfcConvert* app = context;
    if(event.type != NfcScannerEventTypeDetected) return;

    bool ultralight = false;
    for(size_t i = 0; i < event.data.protocol_num; i++) {
        if(event.data.protocols[i] == NfcProtocolMfUltralight) {
            ultralight = true;
            break;
        }
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->ultralight_seen = ultralight;
    furi_mutex_release(app->mutex);

    view_dispatcher_send_custom_event(app->view_dispatcher, NfcConvertCustomEventCardDetected);
}

static void nfc_convert_scan_start(NfcConvert* app) {
    app->loaded = false;
    furi_string_set(app->text, "Hold the card against\nthe back of Flipper...");
    nfc_convert_show_result(app, "Scanning");

    app->nfc = nfc_alloc();
    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, nfc_convert_scanner_callback, app);
}

static void nfc_convert_on_card_detected(NfcConvert* app) {
    if(!app->scanner) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    const bool ultralight = app->ultralight_seen;
    furi_mutex_release(app->mutex);

    // The scanner owns the radio; release it before issuing our own commands,
    // but keep the Nfc instance alive for the read that follows.
    nfc_scanner_stop(app->scanner);
    nfc_scanner_free(app->scanner);
    app->scanner = NULL;

    if(!ultralight) {
        nfc_convert_scan_stop(app);
        furi_string_set(app->text, "That card is not an\nUltralight/NTAG type.");
        nfc_convert_show_result(app, "Wrong type");
        return;
    }

    MfUltralightData* data = mf_ultralight_alloc();
    MfUltralightPollerAuthContext auth = {.skip_auth = true};
    const MfUltralightError err = mf_ultralight_poller_sync_read_card(app->nfc, data, &auth);
    nfc_convert_scan_stop(app);

    if(err != MfUltralightErrorNone) {
        furi_string_printf(app->text, "Read failed (error %d).\nTry holding it steadier.", err);
        mf_ultralight_free(data);
        nfc_convert_show_result(app, "Read failed");
        return;
    }

    // Name scanned cards after their UID so the output filename is meaningful.
    size_t uid_len = 0;
    const uint8_t* uid = mf_ultralight_get_uid(data, &uid_len);
    FuriString* name = furi_string_alloc();
    for(size_t i = 0; i < uid_len; i++) {
        furi_string_cat_printf(name, "%02X", uid[i]);
    }
    furi_string_printf(
        app->load_path,
        "%s/%s%s",
        NFC_CONVERT_FOLDER,
        furi_string_get_cstr(name),
        NFC_CONVERT_EXTENSION);
    furi_string_free(name);

    nfc_device_set_data(app->device, NfcProtocolMfUltralight, data);
    mf_ultralight_free(data);

    nfc_convert_accept_device(app);
}

/* --------------- */
/* Saved card list */
/* --------------- */

static bool nfc_convert_has_extension(const char* name) {
    const size_t name_len = strlen(name);
    const size_t ext_len = strlen(NFC_CONVERT_EXTENSION);
    if(name_len <= ext_len) return false;
    return strcasecmp(name + name_len - ext_len, NFC_CONVERT_EXTENSION) == 0;
}

static void nfc_convert_scan_folder(NfcConvert* app) {
    app->file_num = 0;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);

    if(storage_dir_open(dir, NFC_CONVERT_FOLDER)) {
        FileInfo info;
        char name[NFC_CONVERT_NAME_LEN];
        while(app->file_num < NFC_CONVERT_MAX_FILES &&
              storage_dir_read(dir, &info, name, (uint16_t)sizeof(name))) {
            if(file_info_is_dir(&info)) continue;
            if(!nfc_convert_has_extension(name)) continue;
            strncpy(app->files[app->file_num], name, NFC_CONVERT_NAME_LEN - 1);
            app->files[app->file_num][NFC_CONVERT_NAME_LEN - 1] = '\0';
            app->file_num++;
        }
        storage_dir_close(dir);
    }

    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
}

static void nfc_convert_load_file(NfcConvert* app, size_t index) {
    furi_check(index < app->file_num);

    furi_string_printf(app->load_path, "%s/%s", NFC_CONVERT_FOLDER, app->files[index]);
    app->loaded = false;

    if(!nfc_device_load(app->device, furi_string_get_cstr(app->load_path))) {
        furi_string_printf(app->text, "Could not read\n%s", app->files[index]);
        nfc_convert_show_result(app, "Load failed");
        return;
    }

    nfc_convert_accept_device(app);
}

/* ----- */
/* Menus */
/* ----- */

static void nfc_convert_do_convert(NfcConvert* app, const NfcConvertTarget* target) {
    MfUltralightData* data = mf_ultralight_alloc();
    nfc_device_copy_data(app->device, NfcProtocolMfUltralight, data);

    const uint16_t before = data->pages_total;
    nfc_convert_retype(data, target);
    nfc_device_set_data(app->device, NfcProtocolMfUltralight, data);

    // Save alongside the source as "<name>_NTAG215.nfc".
    FuriString* out = furi_string_alloc();
    FuriString* name = furi_string_alloc();
    path_extract_filename(app->load_path, name, true);
    furi_string_printf(
        out,
        "%s/%s_%s%s",
        NFC_CONVERT_FOLDER,
        furi_string_get_cstr(name),
        target->name,
        NFC_CONVERT_EXTENSION);

    const bool saved = nfc_device_save(app->device, furi_string_get_cstr(out));

    if(saved) {
        FuriString* out_name = furi_string_alloc();
        path_extract_filename(out, out_name, true);
        furi_string_printf(
            app->text,
            "%u -> %u pages\nSaved: %s\nNeeds a magic NTAG to write to a real tag.",
            before,
            data->pages_total,
            furi_string_get_cstr(out_name));
        furi_string_free(out_name);
        // The device now holds the converted dump, so a second conversion would
        // chain off it. Keep the target list honest about that.
        nfc_convert_build_target_menu(app, target->type, target->name);
        nfc_convert_show_result(app, target->name);
    } else {
        furi_string_set(app->text, "Could not write the output file.");
        nfc_convert_show_result(app, "Save failed");
    }

    furi_string_free(name);
    furi_string_free(out);
    mf_ultralight_free(data);
}

static void nfc_convert_target_callback(void* context, uint32_t index) {
    NfcConvert* app = context;
    furi_check(index < NFC_CONVERT_TARGET_COUNT);
    nfc_convert_do_convert(app, &nfc_convert_targets[index]);
}

static void
    nfc_convert_build_target_menu(NfcConvert* app, MfUltralightType current, const char* name) {
    submenu_reset(app->targets);
    // Header states the detected source variant; the list is only the targets.
    // Local buffer, not app->display: that one backs the TextBox text.
    char header[48];
    snprintf(header, sizeof(header), "%s ->", name);
    submenu_set_header(app->targets, header);

    for(size_t i = 0; i < NFC_CONVERT_TARGET_COUNT; i++) {
        if(nfc_convert_targets[i].type == current) continue;
        submenu_add_item(
            app->targets, nfc_convert_targets[i].name, i, nfc_convert_target_callback, app);
    }
}

static void nfc_convert_main_callback(void* context, uint32_t index) {
    NfcConvert* app = context;
    if(index == NFC_CONVERT_SCAN_INDEX) {
        nfc_convert_scan_start(app);
    } else {
        nfc_convert_load_file(app, index);
    }
}

static void nfc_convert_build_main_menu(NfcConvert* app) {
    nfc_convert_scan_folder(app);

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "NTAG Convert");
    submenu_add_item(
        app->submenu, "Scan card", NFC_CONVERT_SCAN_INDEX, nfc_convert_main_callback, app);

    for(size_t i = 0; i < app->file_num; i++) {
        submenu_add_item(app->submenu, app->files[i], i, nfc_convert_main_callback, app);
    }
}

static void nfc_convert_back_to_main(NfcConvert* app) {
    nfc_convert_scan_stop(app);
    // Rebuild so a card just written shows up in the list.
    nfc_convert_build_main_menu(app);
    nfc_convert_switch_to(app, NfcConvertViewSubmenu);
}

static bool nfc_convert_custom_event_callback(void* context, uint32_t event) {
    NfcConvert* app = context;
    if(event == NfcConvertCustomEventCardDetected) {
        nfc_convert_on_card_detected(app);
    }
    return true;
}

static bool nfc_convert_navigation_callback(void* context) {
    NfcConvert* app = context;

    if(app->current_view == NfcConvertViewSubmenu) return false;

    // A result reached from a loaded card steps back to the target list; a
    // scan still in progress, or a failure, goes all the way back.
    if(app->current_view == NfcConvertViewResult && app->loaded && !app->scanner) {
        nfc_convert_switch_to(app, NfcConvertViewTargets);
    } else {
        nfc_convert_back_to_main(app);
    }
    return true;
}

/* --------- */
/* Lifecycle */
/* --------- */

static NfcConvert* nfc_convert_alloc(void) {
    NfcConvert* app = malloc(sizeof(NfcConvert));
    memset(app, 0, sizeof(NfcConvert));

    app->text = furi_string_alloc();
    app->display = furi_string_alloc();
    app->load_path = furi_string_alloc();
    app->device = nfc_device_alloc();
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);

    app->gui = furi_record_open(RECORD_GUI);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, nfc_convert_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, nfc_convert_navigation_callback);

    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcConvertViewSubmenu, submenu_get_view(app->submenu));

    app->targets = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcConvertViewTargets, submenu_get_view(app->targets));

    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcConvertViewResult, text_box_get_view(app->text_box));

    nfc_convert_build_main_menu(app);

    return app;
}

static void nfc_convert_free(NfcConvert* app) {
    nfc_convert_scan_stop(app);

    view_dispatcher_remove_view(app->view_dispatcher, NfcConvertViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, NfcConvertViewTargets);
    view_dispatcher_remove_view(app->view_dispatcher, NfcConvertViewResult);
    submenu_free(app->submenu);
    submenu_free(app->targets);
    text_box_free(app->text_box);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);

    nfc_device_free(app->device);
    furi_mutex_free(app->mutex);
    furi_string_free(app->load_path);
    furi_string_free(app->display);
    furi_string_free(app->text);
    free(app);
}

int32_t nfc_convert_app(void* p) {
    UNUSED(p);

    NfcConvert* app = nfc_convert_alloc();
    nfc_convert_switch_to(app, NfcConvertViewSubmenu);
    view_dispatcher_run(app->view_dispatcher);
    nfc_convert_free(app);

    return 0;
}
