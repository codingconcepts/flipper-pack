#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>

#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_listener.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller_sync.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>

#include <toolbox/bit_buffer.h>

typedef enum {
    NfcIdentViewSubmenu,
    NfcIdentViewResult,
} NfcIdentView;

typedef enum {
    NfcIdentMenuScanCard,
    NfcIdentMenuDetectReader,
} NfcIdentMenuIndex;

typedef enum {
    // Posted by the scanner callback (NFC worker thread) once protocols are known.
    NfcIdentCustomEventCardDetected = 100,
    // Posted by the listener callback whenever the reader state changes.
    NfcIdentCustomEventReaderUpdate,
} NfcIdentCustomEvent;

#define NFC_IDENT_MAX_PROTOCOLS (NfcProtocolNum)
#define NFC_IDENT_MAX_FRAME     (16)

// Shortest gap between reader-detect redraws. An engaged reader sends frames
// far faster than the screen can usefully be refreshed.
#define NFC_IDENT_UPDATE_PERIOD_MS (200)

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box;
    FuriString* display;
    FuriString* text;

    NfcIdentView current_view;

    Nfc* nfc;
    NfcScanner* scanner;
    NfcListener* listener;

    // Written by the NFC worker thread, read by the app thread. Guarded by `mutex`.
    FuriMutex* mutex;
    NfcProtocol protocols[NFC_IDENT_MAX_PROTOCOLS];
    size_t protocol_num;

    // Reader-detection state, also guarded by `mutex`.
    uint32_t reader_frames;
    uint32_t reader_field_off;
    uint32_t last_update_tick;
    uint8_t first_frame[NFC_IDENT_MAX_FRAME];
    size_t first_frame_len;
} NfcIdent;

/* ------- */
/* Helpers */
/* ------- */

static void nfc_ident_switch_to(NfcIdent* app, NfcIdentView view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

// TextBox rather than Widget: the screen is 128x64 and most of these readouts
// run longer than that, so the text needs to wrap and scroll.
static void nfc_ident_show_text(NfcIdent* app, const char* header) {
    furi_string_printf(app->display, "%s\n%s", header, furi_string_get_cstr(app->text));
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->display));
}

// NTAG/Ultralight variants only differ in silicon; the GET_VERSION response is
// the authoritative way to tell them apart.
static void nfc_ident_describe_ultralight(NfcIdent* app) {
    MfUltralightVersion version = {};
    MfUltralightError err = mf_ultralight_poller_sync_read_version(app->nfc, &version);

    if(err != MfUltralightErrorNone) {
        furi_string_cat_printf(app->text, "GET_VERSION failed (%d)\nLikely UL / NTAG203\n", err);
        return;
    }

    MfUltralightType type = mf_ultralight_get_type_by_version(&version);
    uint16_t pages = mf_ultralight_get_pages_total(type);
    uint32_t features = mf_ultralight_get_feature_support_set(type);

    MfUltralightData* data = mf_ultralight_alloc();
    data->type = type;
    furi_string_cat_printf(
        app->text, "Variant: %s\n", mf_ultralight_get_device_name(data, NfcDeviceNameTypeFull));
    mf_ultralight_free(data);

    furi_string_cat_printf(app->text, "Pages: %u (%u B)\n", pages, pages * 4);
    furi_string_cat_printf(
        app->text,
        "Ver: %02X%02X%02X%02X%02X%02X%02X%02X\n",
        version.header,
        version.vendor_id,
        version.prod_type,
        version.prod_subtype,
        version.prod_ver_major,
        version.prod_ver_minor,
        version.storage_size,
        version.protocol_type);
    furi_string_cat_printf(
        app->text,
        "Pwd auth: %s\n",
        mf_ultralight_support_feature(features, MfUltralightFeatureSupportPasswordAuth) ? "yes" :
                                                                                          "no");
}

/* ------------- */
/* Card scanning */
/* ------------- */

// Runs on the NFC worker thread. Copy out and hand over to the app thread;
// `event.data.protocols` is only valid for the duration of this call.
static void nfc_ident_scanner_callback(NfcScannerEvent event, void* context) {
    NfcIdent* app = context;
    if(event.type != NfcScannerEventTypeDetected) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->protocol_num = MIN(event.data.protocol_num, (size_t)NFC_IDENT_MAX_PROTOCOLS);
    for(size_t i = 0; i < app->protocol_num; i++) {
        app->protocols[i] = event.data.protocols[i];
    }
    furi_mutex_release(app->mutex);

    view_dispatcher_send_custom_event(app->view_dispatcher, NfcIdentCustomEventCardDetected);
}

static void nfc_ident_scan_start(NfcIdent* app) {
    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "Hold card against\nthe back of Flipper...");
    nfc_ident_show_text(app, "Scanning");
    nfc_ident_switch_to(app, NfcIdentViewResult);

    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, nfc_ident_scanner_callback, app);
}

static void nfc_ident_scan_stop(NfcIdent* app) {
    if(app->scanner) {
        nfc_scanner_stop(app->scanner);
        nfc_scanner_free(app->scanner);
        app->scanner = NULL;
    }
}

static void nfc_ident_on_card_detected(NfcIdent* app) {
    // The scanner owns the NFC hardware; release it before issuing our own commands.
    nfc_ident_scan_stop(app);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    NfcProtocol protocols[NFC_IDENT_MAX_PROTOCOLS];
    size_t protocol_num = app->protocol_num;
    memcpy(protocols, app->protocols, sizeof(protocols));
    furi_mutex_release(app->mutex);

    furi_string_reset(app->text);

    for(size_t i = 0; i < protocol_num; i++) {
        furi_string_cat_printf(app->text, "%s\n", nfc_device_get_protocol_name(protocols[i]));
    }

    // ISO14443-3A carries the UID/ATQA/SAK that most other 13.56 MHz types sit on top of.
    Iso14443_3aData iso_data = {};
    if(iso14443_3a_poller_sync_read(app->nfc, &iso_data) == Iso14443_3aErrorNone) {
        furi_string_cat_str(app->text, "UID: ");
        for(size_t i = 0; i < iso_data.uid_len; i++) {
            furi_string_cat_printf(app->text, "%02X", iso_data.uid[i]);
        }
        furi_string_cat_printf(
            app->text,
            "\nATQA: %02X%02X  SAK: %02X\n",
            iso_data.atqa[1],
            iso_data.atqa[0],
            iso_data.sak);
    }

    for(size_t i = 0; i < protocol_num; i++) {
        if(protocols[i] == NfcProtocolMfUltralight) {
            nfc_ident_describe_ultralight(app);
            break;
        }
    }

    nfc_ident_show_text(app, "Card");
}

/* --------------------- */
/* Reader fingerprinting */
/* --------------------- */

// Runs on the NFC worker thread.
static NfcCommand nfc_ident_listener_callback(NfcGenericEvent event, void* context) {
    NfcIdent* app = context;
    furi_assert(event.protocol == NfcProtocolIso14443_3a);
    Iso14443_3aListenerEvent* iso_event = event.event_data;

    // Always redraw for the events that change what the screen says; for the
    // steady stream of frames, redraw on a timer so the dispatcher queue does
    // not fill faster than the app thread drains it.
    bool notify = false;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(iso_event->type == Iso14443_3aListenerEventTypeFieldOff) {
        app->reader_field_off++;
        notify = true;
    } else if(
        iso_event->type == Iso14443_3aListenerEventTypeReceivedStandardFrame ||
        iso_event->type == Iso14443_3aListenerEventTypeReceivedData) {
        app->reader_frames++;
        if(app->first_frame_len == 0 && iso_event->data->buffer) {
            size_t len = MIN(
                bit_buffer_get_size_bytes(iso_event->data->buffer), (size_t)NFC_IDENT_MAX_FRAME);
            memcpy(app->first_frame, bit_buffer_get_data(iso_event->data->buffer), len);
            app->first_frame_len = len;
            notify = true;
        }
    }

    const uint32_t now = furi_get_tick();
    if(now - app->last_update_tick >= furi_ms_to_ticks(NFC_IDENT_UPDATE_PERIOD_MS)) {
        notify = true;
    }
    if(notify) app->last_update_tick = now;
    furi_mutex_release(app->mutex);

    if(notify) {
        view_dispatcher_send_custom_event(app->view_dispatcher, NfcIdentCustomEventReaderUpdate);
    }
    return NfcCommandContinue;
}

static void nfc_ident_reader_start(NfcIdent* app) {
    app->reader_frames = 0;
    app->reader_field_off = 0;
    app->first_frame_len = 0;
    app->last_update_tick = 0;

    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "Present Flipper to\nthe reader...");
    nfc_ident_show_text(app, "Detect Reader");
    nfc_ident_switch_to(app, NfcIdentViewResult);

    // Emulate a plain NTAG-shaped ISO14443-3A target so the reader engages us
    // and reveals which commands it tries.
    Iso14443_3aData* iso_data = iso14443_3a_alloc();
    const uint8_t uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    iso14443_3a_set_uid(iso_data, uid, sizeof(uid));
    const uint8_t atqa[2] = {0x44, 0x00};
    iso14443_3a_set_atqa(iso_data, atqa);
    iso14443_3a_set_sak(iso_data, 0x00);

    app->listener = nfc_listener_alloc(app->nfc, NfcProtocolIso14443_3a, iso_data);
    nfc_listener_start(app->listener, nfc_ident_listener_callback, app);
    iso14443_3a_free(iso_data);
}

static void nfc_ident_reader_stop(NfcIdent* app) {
    if(app->listener) {
        nfc_listener_stop(app->listener);
        nfc_listener_free(app->listener);
        app->listener = NULL;
    }
}

// Map the first command byte the reader sent onto the card family it expects.
static const char* nfc_ident_guess_reader(uint8_t cmd) {
    switch(cmd) {
    case 0x60:
    case 0x61:
        return "MIFARE Classic auth";
    case 0x30:
        return "UL/NTAG read";
    case 0x3A:
        return "UL/NTAG fast read";
    case 0xA2:
        return "UL/NTAG write";
    case 0x1B:
        return "UL/NTAG pwd auth";
    case 0xE0:
        return "RATS (ISO-DEP)";
    case 0x5A:
        return "DESFire select app";
    case 0x90:
        return "DESFire wrapped APDU";
    case 0x00:
    case 0x02:
    case 0x03:
        return "ISO-DEP block";
    default:
        return "unknown";
    }
}

static void nfc_ident_on_reader_update(NfcIdent* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint32_t frames = app->reader_frames;
    uint32_t field_off = app->reader_field_off;
    uint8_t frame[NFC_IDENT_MAX_FRAME];
    size_t frame_len = app->first_frame_len;
    memcpy(frame, app->first_frame, sizeof(frame));
    furi_mutex_release(app->mutex);

    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "Frames: %lu  Off: %lu\n", frames, field_off);

    if(frame_len > 0) {
        furi_string_cat_str(app->text, "First cmd: ");
        for(size_t i = 0; i < frame_len; i++) {
            furi_string_cat_printf(app->text, "%02X ", frame[i]);
        }
        furi_string_cat_printf(app->text, "\n-> %s\n", nfc_ident_guess_reader(frame[0]));
    } else {
        furi_string_cat_str(app->text, "Field seen, no cmds yet\n");
    }

    nfc_ident_show_text(app, "Detect Reader");
}

/* ---------- */
/* Navigation */
/* ---------- */

static void nfc_ident_submenu_callback(void* context, uint32_t index) {
    NfcIdent* app = context;
    if(index == NfcIdentMenuScanCard) {
        nfc_ident_scan_start(app);
    } else if(index == NfcIdentMenuDetectReader) {
        nfc_ident_reader_start(app);
    }
}

static bool nfc_ident_custom_event_callback(void* context, uint32_t event) {
    NfcIdent* app = context;
    if(event == NfcIdentCustomEventCardDetected) {
        nfc_ident_on_card_detected(app);
    } else if(event == NfcIdentCustomEventReaderUpdate) {
        nfc_ident_on_reader_update(app);
    }
    return true;
}

static bool nfc_ident_navigation_callback(void* context) {
    NfcIdent* app = context;

    // Back from a result view returns to the menu; back from the menu exits.
    // Keyed on the current view, not on whether a scan is still running: a
    // finished card scan has already released the scanner.
    if(app->current_view == NfcIdentViewSubmenu) return false;

    nfc_ident_scan_stop(app);
    nfc_ident_reader_stop(app);
    nfc_ident_switch_to(app, NfcIdentViewSubmenu);
    return true;
}

/* --------- */
/* Lifecycle */
/* --------- */

static NfcIdent* nfc_ident_alloc(void) {
    NfcIdent* app = malloc(sizeof(NfcIdent));
    memset(app, 0, sizeof(NfcIdent));

    app->text = furi_string_alloc();
    app->display = furi_string_alloc();
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->nfc = nfc_alloc();

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, nfc_ident_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, nfc_ident_navigation_callback);

    app->submenu = submenu_alloc();
    submenu_set_header(app->submenu, "NFC Ident");
    submenu_add_item(
        app->submenu, "Identify Card", NfcIdentMenuScanCard, nfc_ident_submenu_callback, app);
    submenu_add_item(
        app->submenu, "Detect Reader", NfcIdentMenuDetectReader, nfc_ident_submenu_callback, app);
    view_dispatcher_add_view(
        app->view_dispatcher, NfcIdentViewSubmenu, submenu_get_view(app->submenu));

    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, NfcIdentViewResult, text_box_get_view(app->text_box));

    return app;
}

static void nfc_ident_free(NfcIdent* app) {
    nfc_ident_scan_stop(app);
    nfc_ident_reader_stop(app);

    view_dispatcher_remove_view(app->view_dispatcher, NfcIdentViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, NfcIdentViewResult);
    submenu_free(app->submenu);
    text_box_free(app->text_box);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    nfc_free(app->nfc);
    furi_mutex_free(app->mutex);
    furi_string_free(app->display);
    furi_string_free(app->text);
    free(app);
}

int32_t nfc_ident_app(void* p) {
    UNUSED(p);

    NfcIdent* app = nfc_ident_alloc();
    nfc_ident_switch_to(app, NfcIdentViewSubmenu);
    view_dispatcher_run(app->view_dispatcher);
    nfc_ident_free(app);

    return 0;
}
