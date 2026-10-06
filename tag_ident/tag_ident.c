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

#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>

#include <toolbox/bit_buffer.h>
#include <toolbox/protocols/protocol_dict.h>

typedef enum {
    TagIdentViewSubmenu,
    TagIdentViewResult,
} TagIdentView;

typedef enum {
    TagIdentMenuScanTag,
    TagIdentMenuDetectReader,
} TagIdentMenuIndex;

typedef enum {
    // Posted by the NFC scanner callback (NFC worker thread) once protocols are known.
    TagIdentCustomEventHfDetected = 100,
    // Posted by the LF worker callback once a 125 kHz protocol has been decoded.
    TagIdentCustomEventLfDetected,
    // Posted by the LF worker callback when a tag loads the field but has not decoded yet.
    TagIdentCustomEventLfSensed,
    // Posted by the band timer: the current band's turn is up.
    TagIdentCustomEventSwitchBand,
    // Posted by the listener callback whenever the reader state changes.
    TagIdentCustomEventReaderUpdate,
} TagIdentCustomEvent;

// The two radios are separate hardware with separate antennas, so a scan can
// only listen on one at a time. Sweep between them until something answers.
typedef enum {
    TagIdentBandHf,
    TagIdentBandLf,
} TagIdentBand;

#define TAG_IDENT_MAX_PROTOCOLS (NfcProtocolNum)
#define TAG_IDENT_MAX_FRAME     (16)

// How long each radio gets per sweep. HF polling either answers almost at once
// or there is nothing there; the LF decoders need longer because
// LFRFIDWorkerReadTypeAuto works through ASK and then PSK demodulation.
#define TAG_IDENT_HF_PHASE_MS (1000)
#define TAG_IDENT_LF_PHASE_MS (3000)

// Shortest gap between reader-detect redraws. An engaged reader sends frames
// far faster than the screen can usefully be refreshed.
#define TAG_IDENT_UPDATE_PERIOD_MS (200)

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box;
    FuriString* display;
    FuriString* text;

    TagIdentView current_view;

    Nfc* nfc;
    NfcScanner* scanner;
    NfcListener* listener;

    ProtocolDict* lf_dict;
    LFRFIDWorker* lf_worker;
    bool lf_thread_running;

    // Band sweep state. Only touched on the app thread.
    FuriTimer* band_timer;
    TagIdentBand band;
    bool scanning;

    // Written by the NFC worker thread, read by the app thread. Guarded by `mutex`.
    FuriMutex* mutex;
    NfcProtocol protocols[TAG_IDENT_MAX_PROTOCOLS];
    size_t protocol_num;

    // Written by the LF worker thread, read by the app thread. Guarded by `mutex`.
    ProtocolId lf_protocol;
    bool lf_sensed;

    // Reader-detection state, also guarded by `mutex`.
    uint32_t reader_frames;
    uint32_t reader_field_off;
    uint32_t last_update_tick;
    uint8_t first_frame[TAG_IDENT_MAX_FRAME];
    size_t first_frame_len;
} TagIdent;

/* ------- */
/* Helpers */
/* ------- */

static void tag_ident_switch_to(TagIdent* app, TagIdentView view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

// TextBox rather than Widget: the screen is 128x64 and most of these readouts
// run longer than that, so the text needs to wrap and scroll.
static void tag_ident_show_text(TagIdent* app, const char* header) {
    furi_string_printf(app->display, "%s\n%s", header, furi_string_get_cstr(app->text));
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->display));
}

// NTAG/Ultralight variants only differ in silicon; the GET_VERSION response is
// the authoritative way to tell them apart.
static void tag_ident_describe_ultralight(TagIdent* app) {
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

/* ----------- */
/* Band sweep  */
/* ----------- */

// Runs on the NFC worker thread. Copy out and hand over to the app thread;
// `event.data.protocols` is only valid for the duration of this call.
static void tag_ident_scanner_callback(NfcScannerEvent event, void* context) {
    TagIdent* app = context;
    if(event.type != NfcScannerEventTypeDetected) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->protocol_num = MIN(event.data.protocol_num, (size_t)TAG_IDENT_MAX_PROTOCOLS);
    for(size_t i = 0; i < app->protocol_num; i++) {
        app->protocols[i] = event.data.protocols[i];
    }
    furi_mutex_release(app->mutex);

    view_dispatcher_send_custom_event(app->view_dispatcher, TagIdentCustomEventHfDetected);
}

// Runs on the LF worker thread. `protocol` is only meaningful for ReadDone.
static void
    tag_ident_lf_callback(LFRFIDWorkerReadResult result, ProtocolId protocol, void* context) {
    TagIdent* app = context;

    if(result == LFRFIDWorkerReadDone) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->lf_protocol = protocol;
        furi_mutex_release(app->mutex);
        view_dispatcher_send_custom_event(app->view_dispatcher, TagIdentCustomEventLfDetected);
    } else if(result == LFRFIDWorkerReadSenseCardStart) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->lf_sensed = true;
        furi_mutex_release(app->mutex);
        view_dispatcher_send_custom_event(app->view_dispatcher, TagIdentCustomEventLfSensed);
    } else if(result == LFRFIDWorkerReadSenseCardEnd) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->lf_sensed = false;
        furi_mutex_release(app->mutex);
    }
}

static void tag_ident_band_timer_callback(void* context) {
    TagIdent* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, TagIdentCustomEventSwitchBand);
}

static void tag_ident_hf_stop(TagIdent* app) {
    if(app->scanner) {
        nfc_scanner_stop(app->scanner);
        nfc_scanner_free(app->scanner);
        app->scanner = NULL;
    }
}

static void tag_ident_lf_stop(TagIdent* app) {
    if(app->lf_thread_running) {
        lfrfid_worker_stop(app->lf_worker);
        lfrfid_worker_stop_thread(app->lf_worker);
        app->lf_thread_running = false;
    }
}

static void tag_ident_scan_stop(TagIdent* app) {
    app->scanning = false;
    furi_timer_stop(app->band_timer);
    tag_ident_hf_stop(app);
    tag_ident_lf_stop(app);
}

static void tag_ident_show_sweep(TagIdent* app) {
    furi_string_reset(app->text);
    furi_string_cat_str(
        app->text, app->band == TagIdentBandHf ? "HF 13.56MHz...\n" : "LF 125kHz...\n");
    furi_string_cat_str(app->text, "Hold tag against\nthe back of Flipper");
    tag_ident_show_text(app, "Scanning");
}

// Hand the radio over to `app->band` and arm the timer for that band's turn.
static void tag_ident_band_start(TagIdent* app) {
    if(app->band == TagIdentBandHf) {
        app->scanner = nfc_scanner_alloc(app->nfc);
        nfc_scanner_start(app->scanner, tag_ident_scanner_callback, app);
        furi_timer_start(app->band_timer, furi_ms_to_ticks(TAG_IDENT_HF_PHASE_MS));
    } else {
        lfrfid_worker_start_thread(app->lf_worker);
        app->lf_thread_running = true;
        lfrfid_worker_read_start(
            app->lf_worker, LFRFIDWorkerReadTypeAuto, tag_ident_lf_callback, app);
        furi_timer_start(app->band_timer, furi_ms_to_ticks(TAG_IDENT_LF_PHASE_MS));
    }

    tag_ident_show_sweep(app);
}

static void tag_ident_scan_start(TagIdent* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->lf_protocol = PROTOCOL_NO;
    app->lf_sensed = false;
    app->protocol_num = 0;
    furi_mutex_release(app->mutex);

    app->scanning = true;
    app->band = TagIdentBandHf;

    tag_ident_switch_to(app, TagIdentViewResult);
    tag_ident_band_start(app);
}

static void tag_ident_on_switch_band(TagIdent* app) {
    // A detection already stopped the sweep; this is a timer event that was
    // queued behind it.
    if(!app->scanning) return;

    // A tag is loading the LF field but has not decoded yet - some protocols
    // need several field cycles. Give it another turn rather than cutting away.
    if(app->band == TagIdentBandLf) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        bool sensed = app->lf_sensed;
        furi_mutex_release(app->mutex);

        if(sensed) {
            furi_timer_start(app->band_timer, furi_ms_to_ticks(TAG_IDENT_LF_PHASE_MS));
            return;
        }
    }

    if(app->band == TagIdentBandHf) {
        tag_ident_hf_stop(app);
        app->band = TagIdentBandLf;
    } else {
        tag_ident_lf_stop(app);
        app->band = TagIdentBandHf;
    }

    tag_ident_band_start(app);
}

static void tag_ident_on_lf_sensed(TagIdent* app) {
    if(!app->scanning || app->band != TagIdentBandLf) return;

    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "LF 125kHz...\nTag found, decoding");
    tag_ident_show_text(app, "Scanning");
}

static void tag_ident_on_hf_detected(TagIdent* app) {
    if(!app->scanning) return;

    // The scanner owns the NFC hardware; release it before issuing our own
    // commands, and park the LF radio so the two do not overlap.
    tag_ident_scan_stop(app);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    NfcProtocol protocols[TAG_IDENT_MAX_PROTOCOLS];
    size_t protocol_num = app->protocol_num;
    memcpy(protocols, app->protocols, sizeof(protocols));
    furi_mutex_release(app->mutex);

    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "Band: HF 13.56MHz\n");

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
            tag_ident_describe_ultralight(app);
            break;
        }
    }

    tag_ident_show_text(app, "Tag");
}

static void tag_ident_on_lf_detected(TagIdent* app) {
    if(!app->scanning) return;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    ProtocolId protocol = app->lf_protocol;
    furi_mutex_release(app->mutex);

    // The decoded data lives in the dict the worker was given, so read it out
    // before stopping the worker.
    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "Band: LF 125kHz\n");

    if(protocol == PROTOCOL_NO) {
        furi_string_cat_str(app->text, "Tag present, but no\nknown protocol matched\n");
    } else {
        furi_string_cat_printf(app->text, "%s\n", protocol_dict_get_name(app->lf_dict, protocol));

        const char* manufacturer = protocol_dict_get_manufacturer(app->lf_dict, protocol);
        if(manufacturer && strlen(manufacturer) > 0) {
            furi_string_cat_printf(app->text, "Mfr: %s\n", manufacturer);
        }

        FuriString* rendered = furi_string_alloc();
        protocol_dict_render_data(app->lf_dict, rendered, protocol);
        furi_string_cat_printf(app->text, "%s\n", furi_string_get_cstr(rendered));
        furi_string_free(rendered);
    }

    tag_ident_scan_stop(app);
    tag_ident_show_text(app, "Tag");
}

/* --------------------- */
/* Reader fingerprinting */
/* --------------------- */

// Runs on the NFC worker thread.
static NfcCommand tag_ident_listener_callback(NfcGenericEvent event, void* context) {
    TagIdent* app = context;
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
                bit_buffer_get_size_bytes(iso_event->data->buffer), (size_t)TAG_IDENT_MAX_FRAME);
            memcpy(app->first_frame, bit_buffer_get_data(iso_event->data->buffer), len);
            app->first_frame_len = len;
            notify = true;
        }
    }

    const uint32_t now = furi_get_tick();
    if(now - app->last_update_tick >= furi_ms_to_ticks(TAG_IDENT_UPDATE_PERIOD_MS)) {
        notify = true;
    }
    if(notify) app->last_update_tick = now;
    furi_mutex_release(app->mutex);

    if(notify) {
        view_dispatcher_send_custom_event(app->view_dispatcher, TagIdentCustomEventReaderUpdate);
    }
    return NfcCommandContinue;
}

static void tag_ident_reader_start(TagIdent* app) {
    app->reader_frames = 0;
    app->reader_field_off = 0;
    app->first_frame_len = 0;
    app->last_update_tick = 0;

    furi_string_reset(app->text);
    furi_string_cat_str(app->text, "Present Flipper to\nthe reader...");
    tag_ident_show_text(app, "Detect Reader");
    tag_ident_switch_to(app, TagIdentViewResult);

    // Emulate a plain NTAG-shaped ISO14443-3A target so the reader engages us
    // and reveals which commands it tries.
    Iso14443_3aData* iso_data = iso14443_3a_alloc();
    const uint8_t uid[7] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    iso14443_3a_set_uid(iso_data, uid, sizeof(uid));
    const uint8_t atqa[2] = {0x44, 0x00};
    iso14443_3a_set_atqa(iso_data, atqa);
    iso14443_3a_set_sak(iso_data, 0x00);

    app->listener = nfc_listener_alloc(app->nfc, NfcProtocolIso14443_3a, iso_data);
    nfc_listener_start(app->listener, tag_ident_listener_callback, app);
    iso14443_3a_free(iso_data);
}

static void tag_ident_reader_stop(TagIdent* app) {
    if(app->listener) {
        nfc_listener_stop(app->listener);
        nfc_listener_free(app->listener);
        app->listener = NULL;
    }
}

// Map the first command byte the reader sent onto the card family it expects.
static const char* tag_ident_guess_reader(uint8_t cmd) {
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

static void tag_ident_on_reader_update(TagIdent* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint32_t frames = app->reader_frames;
    uint32_t field_off = app->reader_field_off;
    uint8_t frame[TAG_IDENT_MAX_FRAME];
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
        furi_string_cat_printf(app->text, "\n-> %s\n", tag_ident_guess_reader(frame[0]));
    } else {
        furi_string_cat_str(app->text, "Field seen, no cmds yet\n");
    }

    tag_ident_show_text(app, "Detect Reader");
}

/* ---------- */
/* Navigation */
/* ---------- */

static void tag_ident_submenu_callback(void* context, uint32_t index) {
    TagIdent* app = context;
    if(index == TagIdentMenuScanTag) {
        tag_ident_scan_start(app);
    } else if(index == TagIdentMenuDetectReader) {
        tag_ident_reader_start(app);
    }
}

static bool tag_ident_custom_event_callback(void* context, uint32_t event) {
    TagIdent* app = context;
    if(event == TagIdentCustomEventHfDetected) {
        tag_ident_on_hf_detected(app);
    } else if(event == TagIdentCustomEventLfDetected) {
        tag_ident_on_lf_detected(app);
    } else if(event == TagIdentCustomEventLfSensed) {
        tag_ident_on_lf_sensed(app);
    } else if(event == TagIdentCustomEventSwitchBand) {
        tag_ident_on_switch_band(app);
    } else if(event == TagIdentCustomEventReaderUpdate) {
        tag_ident_on_reader_update(app);
    }
    return true;
}

static bool tag_ident_navigation_callback(void* context) {
    TagIdent* app = context;

    // Back from a result view returns to the menu; back from the menu exits.
    // Keyed on the current view, not on whether a scan is still running: a
    // finished scan has already released both radios.
    if(app->current_view == TagIdentViewSubmenu) return false;

    tag_ident_scan_stop(app);
    tag_ident_reader_stop(app);
    tag_ident_switch_to(app, TagIdentViewSubmenu);
    return true;
}

/* --------- */
/* Lifecycle */
/* --------- */

static TagIdent* tag_ident_alloc(void) {
    TagIdent* app = malloc(sizeof(TagIdent));
    memset(app, 0, sizeof(TagIdent));

    app->text = furi_string_alloc();
    app->display = furi_string_alloc();
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->nfc = nfc_alloc();

    app->lf_dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    app->lf_worker = lfrfid_worker_alloc(app->lf_dict);
    app->lf_protocol = PROTOCOL_NO;

    app->band_timer = furi_timer_alloc(tag_ident_band_timer_callback, FuriTimerTypeOnce, app);

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, tag_ident_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, tag_ident_navigation_callback);

    app->submenu = submenu_alloc();
    submenu_set_header(app->submenu, "Tag Ident");
    submenu_add_item(
        app->submenu, "Identify Tag", TagIdentMenuScanTag, tag_ident_submenu_callback, app);
    submenu_add_item(
        app->submenu, "Detect Reader", TagIdentMenuDetectReader, tag_ident_submenu_callback, app);
    view_dispatcher_add_view(
        app->view_dispatcher, TagIdentViewSubmenu, submenu_get_view(app->submenu));

    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, TagIdentViewResult, text_box_get_view(app->text_box));

    return app;
}

static void tag_ident_free(TagIdent* app) {
    tag_ident_scan_stop(app);
    tag_ident_reader_stop(app);

    view_dispatcher_remove_view(app->view_dispatcher, TagIdentViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, TagIdentViewResult);
    submenu_free(app->submenu);
    text_box_free(app->text_box);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    furi_timer_free(app->band_timer);
    lfrfid_worker_free(app->lf_worker);
    protocol_dict_free(app->lf_dict);
    nfc_free(app->nfc);
    furi_mutex_free(app->mutex);
    furi_string_free(app->display);
    furi_string_free(app->text);
    free(app);
}

int32_t tag_ident_app(void* p) {
    UNUSED(p);

    TagIdent* app = tag_ident_alloc();
    tag_ident_switch_to(app, TagIdentViewSubmenu);
    view_dispatcher_run(app->view_dispatcher);
    tag_ident_free(app);

    return 0;
}
