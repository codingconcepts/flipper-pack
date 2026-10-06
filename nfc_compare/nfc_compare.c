#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>

#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>

#define NFC_COMPARE_NAME_LEN (40)

// How many differing page numbers to spell out before truncating the list.
#define NFC_COMPARE_MAX_LISTED (8)

// Pages 0-2 hold the UID, the internal byte and the static lock bytes. That is
// card identity, not content, and the UID is already reported on its own line,
// so counting them would make every pair of distinct cards differ by default.
#define NFC_COMPARE_FIRST_DATA_PAGE (3)

typedef enum {
    NfcCompareViewMenu,
    NfcCompareViewPrompt,
    NfcCompareViewResult,
} NfcCompareView;

typedef enum {
    // Posted by the scanner callback (NFC worker thread) once a card is found.
    NfcCompareCustomEventCardDetected = 100,
} NfcCompareCustomEvent;

typedef enum {
    NfcCompareMenuScan,
} NfcCompareMenuIndex;

typedef struct {
    NfcDevice* device;
    char name[NFC_COMPARE_NAME_LEN];
    bool deep; // page-level data available (NTAG/Ultralight only)
    bool valid;
} NfcCompareSlot;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* menu;
    Submenu* prompt;
    TextBox* text_box;

    FuriString* text;
    FuriString* display;

    NfcCompareView current_view;
    NfcCompareSlot slot[2];
    size_t scanning; // slot the in-flight scan will fill

    // Live scanning. `nfc` is only held for the duration of a scan.
    Nfc* nfc;
    NfcScanner* scanner;
    FuriMutex* mutex;
    NfcProtocol detected[NfcProtocolNum];
    size_t detected_num;
} NfcCompare;

static void nfc_compare_switch_to(NfcCompare* app, NfcCompareView view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

// TextBox rather than Widget: these readouts run longer than the 128x64 screen,
// so the text needs to wrap and scroll.
static void nfc_compare_show_result(NfcCompare* app, const char* header) {
    furi_string_printf(app->display, "%s\n%s", header, furi_string_get_cstr(app->text));
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->display));
    nfc_compare_switch_to(app, NfcCompareViewResult);
}

/* ---------- */
/* Comparison */
/* ---------- */

static bool nfc_compare_same_uid(const NfcCompareSlot* a, const NfcCompareSlot* b) {
    size_t a_len = 0;
    size_t b_len = 0;
    const uint8_t* a_uid = nfc_device_get_uid(a->device, &a_len);
    const uint8_t* b_uid = nfc_device_get_uid(b->device, &b_len);
    if(a_len != b_len) return false;
    return memcmp(a_uid, b_uid, a_len) == 0;
}

// Pages that only one card actually returned would read as all-zero and show up
// as spurious differences, so say when a dump is incomplete.
static void nfc_compare_note_partial(NfcCompare* app, const MfUltralightData* data, int which) {
    if(data->pages_read < data->pages_total) {
        furi_string_cat_printf(
            app->text,
            "\nCard %d only read %u of %u pages.",
            which,
            data->pages_read,
            data->pages_total);
    }
}

static void nfc_compare_report_ultralight(NfcCompare* app) {
    const MfUltralightData* a = nfc_device_get_data(app->slot[0].device, NfcProtocolMfUltralight);
    const MfUltralightData* b = nfc_device_get_data(app->slot[1].device, NfcProtocolMfUltralight);

    const uint16_t pages = MIN(a->pages_total, b->pages_total);
    const uint16_t compared =
        pages > NFC_COMPARE_FIRST_DATA_PAGE ? pages - NFC_COMPARE_FIRST_DATA_PAGE : 0;
    uint16_t diff_num = 0;
    FuriString* list = furi_string_alloc();

    for(uint16_t i = NFC_COMPARE_FIRST_DATA_PAGE; i < pages; i++) {
        if(memcmp(a->page[i].data, b->page[i].data, MF_ULTRALIGHT_PAGE_SIZE) == 0) continue;
        if(diff_num < NFC_COMPARE_MAX_LISTED) {
            furi_string_cat_printf(list, diff_num ? ", %u" : "%u", i);
        }
        diff_num++;
    }
    if(diff_num > NFC_COMPARE_MAX_LISTED) furi_string_cat_str(list, "...");

    const bool same_uid = nfc_compare_same_uid(&app->slot[0], &app->slot[1]);

    furi_string_printf(
        app->text, "%s\nUID: %s\n", app->slot[0].name, same_uid ? "match" : "differ");

    if(diff_num == 0) {
        furi_string_cat_printf(app->text, "All %u data pages identical.", compared);
    } else {
        furi_string_cat_printf(
            app->text,
            "%u of %u data pages differ:\n%s",
            diff_num,
            compared,
            furi_string_get_cstr(list));
    }

    nfc_compare_note_partial(app, a, 1);
    nfc_compare_note_partial(app, b, 2);

    // A card left on the antenna gets read twice and looks like a perfect match.
    if(same_uid && diff_num == 0) {
        furi_string_cat_str(app->text, "\nSame UID - was card 1 still on the antenna?");
    }

    nfc_compare_show_result(app, diff_num == 0 ? "Match" : "Differ");
    furi_string_free(list);
}

static void nfc_compare_report_shallow(NfcCompare* app) {
    const bool equal = nfc_device_is_equal(app->slot[0].device, app->slot[1].device);
    const bool same_uid = nfc_compare_same_uid(&app->slot[0], &app->slot[1]);

    furi_string_printf(
        app->text,
        "%s\nUID: %s\nATQA/SAK: %s\nIdentity only - page data is read for NTAG/Ultralight.",
        app->slot[0].name,
        same_uid ? "match" : "differ",
        equal ? "match" : "differ");

    nfc_compare_show_result(app, equal ? "Match" : "Differ");
}

static void nfc_compare_report(NfcCompare* app) {
    NfcCompareSlot* a = &app->slot[0];
    NfcCompareSlot* b = &app->slot[1];

    // Different variants: the answer is the pair of names, nothing else. There
    // is no meaningful byte comparison across two different memory maps.
    if(strcmp(a->name, b->name) != 0) {
        furi_string_printf(app->text, "one: %s\ntwo: %s", a->name, b->name);
        nfc_compare_show_result(app, "Different types");
        return;
    }

    if(a->deep && b->deep) {
        nfc_compare_report_ultralight(app);
    } else {
        nfc_compare_report_shallow(app);
    }
}

/* ------------- */
/* Live scanning */
/* ------------- */

static void nfc_compare_scan_stop(NfcCompare* app) {
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

// Runs on the NFC worker thread, so it only records the protocol list and hands
// off; the actual read has to happen on the app thread.
static void nfc_compare_scanner_callback(NfcScannerEvent event, void* context) {
    NfcCompare* app = context;
    if(event.type != NfcScannerEventTypeDetected) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->detected_num = MIN(event.data.protocol_num, (size_t)NfcProtocolNum);
    for(size_t i = 0; i < app->detected_num; i++) {
        app->detected[i] = event.data.protocols[i];
    }
    furi_mutex_release(app->mutex);

    view_dispatcher_send_custom_event(app->view_dispatcher, NfcCompareCustomEventCardDetected);
}

static void nfc_compare_scan_start(NfcCompare* app, size_t slot) {
    app->scanning = slot;
    app->slot[slot].valid = false;

    furi_string_printf(
        app->text, "Hold card %u against\nthe back of Flipper...", (unsigned)(slot + 1));
    nfc_compare_show_result(app, "Scanning");

    app->nfc = nfc_alloc();
    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, nfc_compare_scanner_callback, app);
}

static void nfc_compare_prompt_callback(void* context, uint32_t index);

static void nfc_compare_show_prompt(NfcCompare* app) {
    submenu_reset(app->prompt);
    char header[NFC_COMPARE_NAME_LEN + 12];
    snprintf(header, sizeof(header), "1: %s", app->slot[0].name);
    submenu_set_header(app->prompt, header);
    submenu_add_item(app->prompt, "Scan card 2", 0, nfc_compare_prompt_callback, app);
    nfc_compare_switch_to(app, NfcCompareViewPrompt);
}

// Pick the most descriptive protocol the scanner reported. Everything in the
// 13.56 MHz family also answers to ISO14443-3A, so that one is the fallback.
static NfcProtocol nfc_compare_best_protocol(const NfcProtocol* protocols, size_t num) {
    for(size_t i = 0; i < num; i++) {
        if(protocols[i] != NfcProtocolIso14443_3a) return protocols[i];
    }
    return protocols[0];
}

static void nfc_compare_on_card_detected(NfcCompare* app) {
    if(!app->scanner) return;

    NfcProtocol protocols[NfcProtocolNum];
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    const size_t protocol_num = app->detected_num;
    for(size_t i = 0; i < protocol_num; i++) {
        protocols[i] = app->detected[i];
    }
    furi_mutex_release(app->mutex);

    // The scanner owns the radio; release it before issuing our own commands,
    // but keep the Nfc instance alive for the read that follows.
    nfc_scanner_stop(app->scanner);
    nfc_scanner_free(app->scanner);
    app->scanner = NULL;

    if(protocol_num == 0) {
        nfc_compare_scan_stop(app);
        furi_string_set(app->text, "Could not identify that card.");
        nfc_compare_show_result(app, "Read failed");
        return;
    }

    bool ultralight = false;
    bool iso3a = false;
    for(size_t i = 0; i < protocol_num; i++) {
        if(protocols[i] == NfcProtocolMfUltralight) ultralight = true;
        if(protocols[i] == NfcProtocolIso14443_3a) iso3a = true;
    }

    NfcCompareSlot* slot = &app->slot[app->scanning];

    if(ultralight) {
        MfUltralightData* data = mf_ultralight_alloc();
        MfUltralightPollerAuthContext auth = {.skip_auth = true};
        const MfUltralightError err = mf_ultralight_poller_sync_read_card(app->nfc, data, &auth);
        nfc_compare_scan_stop(app);

        if(err != MfUltralightErrorNone) {
            mf_ultralight_free(data);
            furi_string_printf(
                app->text, "Read failed (error %d).\nTry holding it steadier.", err);
            nfc_compare_show_result(app, "Read failed");
            return;
        }

        nfc_device_set_data(slot->device, NfcProtocolMfUltralight, data);
        mf_ultralight_free(data);
        slot->deep = true;
    } else if(iso3a) {
        Iso14443_3aData iso_data = {};
        const Iso14443_3aError err = iso14443_3a_poller_sync_read(app->nfc, &iso_data);
        nfc_compare_scan_stop(app);

        if(err != Iso14443_3aErrorNone) {
            furi_string_printf(
                app->text, "Read failed (error %d).\nTry holding it steadier.", err);
            nfc_compare_show_result(app, "Read failed");
            return;
        }

        nfc_device_set_data(slot->device, NfcProtocolIso14443_3a, &iso_data);
        slot->deep = false;
    } else {
        nfc_compare_scan_stop(app);
        furi_string_printf(
            app->text,
            "%s is not a card type this app can read.",
            nfc_device_get_protocol_name(protocols[0]));
        nfc_compare_show_result(app, "Unsupported");
        return;
    }

    // Name the variant from the read data where we have it, otherwise from the
    // most specific protocol the scanner saw.
    if(slot->deep) {
        strncpy(
            slot->name,
            nfc_device_get_name(slot->device, NfcDeviceNameTypeFull),
            NFC_COMPARE_NAME_LEN - 1);
    } else {
        strncpy(
            slot->name,
            nfc_device_get_protocol_name(nfc_compare_best_protocol(protocols, protocol_num)),
            NFC_COMPARE_NAME_LEN - 1);
    }
    slot->name[NFC_COMPARE_NAME_LEN - 1] = '\0';
    slot->valid = true;

    if(app->scanning == 0) {
        nfc_compare_show_prompt(app);
    } else {
        nfc_compare_report(app);
    }
}

/* ----- */
/* Menus */
/* ----- */

static void nfc_compare_prompt_callback(void* context, uint32_t index) {
    UNUSED(index);
    nfc_compare_scan_start(context, 1);
}

static void nfc_compare_menu_callback(void* context, uint32_t index) {
    NfcCompare* app = context;
    if(index == NfcCompareMenuScan) {
        app->slot[0].valid = false;
        app->slot[1].valid = false;
        nfc_compare_scan_start(app, 0);
    }
}

static void nfc_compare_build_menu(NfcCompare* app) {
    submenu_reset(app->menu);
    submenu_set_header(app->menu, "NFC Compare");
    submenu_add_item(app->menu, "Scan", NfcCompareMenuScan, nfc_compare_menu_callback, app);
}

static void nfc_compare_back_to_menu(NfcCompare* app) {
    nfc_compare_scan_stop(app);
    nfc_compare_switch_to(app, NfcCompareViewMenu);
}

static bool nfc_compare_custom_event_callback(void* context, uint32_t event) {
    NfcCompare* app = context;
    if(event == NfcCompareCustomEventCardDetected) {
        nfc_compare_on_card_detected(app);
    }
    return true;
}

static bool nfc_compare_navigation_callback(void* context) {
    NfcCompare* app = context;

    if(app->current_view == NfcCompareViewMenu) return false;

    // Backing out of a failed second scan returns to the prompt so card 1 does
    // not have to be scanned again; anything else starts over.
    if(app->current_view == NfcCompareViewResult && app->scanning == 1 && !app->scanner &&
       !app->slot[1].valid) {
        nfc_compare_scan_stop(app);
        nfc_compare_switch_to(app, NfcCompareViewPrompt);
    } else {
        nfc_compare_back_to_menu(app);
    }
    return true;
}

/* --------- */
/* Lifecycle */
/* --------- */

static NfcCompare* nfc_compare_alloc(void) {
    NfcCompare* app = malloc(sizeof(NfcCompare));
    memset(app, 0, sizeof(NfcCompare));

    app->text = furi_string_alloc();
    app->display = furi_string_alloc();
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->slot[0].device = nfc_device_alloc();
    app->slot[1].device = nfc_device_alloc();

    app->gui = furi_record_open(RECORD_GUI);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, nfc_compare_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, nfc_compare_navigation_callback);

    app->menu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcCompareViewMenu, submenu_get_view(app->menu));

    app->prompt = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcCompareViewPrompt, submenu_get_view(app->prompt));

    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcCompareViewResult, text_box_get_view(app->text_box));

    nfc_compare_build_menu(app);

    return app;
}

static void nfc_compare_free(NfcCompare* app) {
    nfc_compare_scan_stop(app);

    view_dispatcher_remove_view(app->view_dispatcher, NfcCompareViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, NfcCompareViewPrompt);
    view_dispatcher_remove_view(app->view_dispatcher, NfcCompareViewResult);
    submenu_free(app->menu);
    submenu_free(app->prompt);
    text_box_free(app->text_box);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);

    nfc_device_free(app->slot[0].device);
    nfc_device_free(app->slot[1].device);
    furi_mutex_free(app->mutex);
    furi_string_free(app->display);
    furi_string_free(app->text);
    free(app);
}

int32_t nfc_compare_app(void* p) {
    UNUSED(p);

    NfcCompare* app = nfc_compare_alloc();
    nfc_compare_switch_to(app, NfcCompareViewMenu);
    view_dispatcher_run(app->view_dispatcher);
    nfc_compare_free(app);

    return 0;
}
