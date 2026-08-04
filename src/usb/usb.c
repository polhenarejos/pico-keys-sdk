/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "usb.h"
#include "led/led.h"
#include "button.h"
#include "pico_time.h"
#if defined(PICO_PLATFORM)
#include "pico/bootrom.h"
#include "boot/picoboot_constants.h"
#include "pico/multicore.h"
#include "pico/time.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "hardware/structs/scb.h"
#include "hardware/powman.h"
#define multicore_launch_func_core1(a) multicore_launch_core1((void (*) (void))a)
#endif
#include "apdu.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#else
#include "emulation.h"
#endif

// Device specific functions
static uint32_t *timeout_counter = NULL;
static uint8_t card_locked_itf = 0; // no locked
static void *(*card_locked_func)(void *) = NULL;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
#endif
#if !defined(PICO_PLATFORM) && !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#ifdef _MSC_VER
#include "compat/pthread_win32.h"
#endif
pthread_t hcore0, hcore1;
#endif

#ifdef USB_ITF_HID
    uint8_t ITF_HID_CTAP = ITF_INVALID, ITF_HID_KB = ITF_INVALID;
    uint8_t ITF_HID = ITF_INVALID, ITF_KEYBOARD = ITF_INVALID;
    uint8_t ITF_HID_TOTAL = 0;
    extern void hid_init(void);
#endif

#ifdef USB_ITF_CCID
    uint8_t ITF_SC_CCID = ITF_INVALID, ITF_SC_WCID = ITF_INVALID;
    uint8_t ITF_CCID = ITF_INVALID, ITF_WCID = ITF_INVALID;
    uint8_t ITF_SC_TOTAL = 0;
    extern void ccid_init(void);
#endif

#ifdef USB_ITF_LWIP
    uint8_t ITF_LWIP_NET = ITF_INVALID, ITF_LWIP = ITF_INVALID;
    uint8_t ITF_LWIP_TOTAL = 0;
    extern void lwip_init(void);
#endif
uint8_t ITF_TOTAL = 0;

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    timeout_counter[itf] = v;
}

queue_t usb_to_card_q = {0};
queue_t card_to_usb_q = {0};

#ifndef ENABLE_EMULATION
extern tusb_desc_device_t desc_device;
extern char *string_desc_itf[5], *string_desc_arr[];
#endif
void usb_init(void)
{
#ifndef ENABLE_EMULATION
    if (phy_data.vidpid_present) {
        desc_device.idVendor = phy_data.vid;
        desc_device.idProduct = phy_data.pid;
    }
    else {
        phy_data.vid = desc_device.idVendor;
        phy_data.pid = desc_device.idProduct;
        phy_data.vidpid_present = true;
    }
    mutex_init(&mutex);
#endif
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);

    uint8_t enabled_usb_itf = PHY_USB_ITF_ALL;
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_usb_itf_present) {
        enabled_usb_itf = phy_data.enabled_usb_itf;
    }
#endif

#ifdef USB_ITF_HID
    ITF_HID_TOTAL = 0;
#endif
#ifdef USB_ITF_CCID
    ITF_SC_TOTAL = 0;
#endif
#ifdef USB_ITF_LWIP
    ITF_LWIP_TOTAL = 0;
#endif
    ITF_TOTAL = 0;
#ifdef USB_ITF_HID
    if (enabled_usb_itf & PHY_USB_ITF_HID) {
        ITF_HID_CTAP = ITF_HID_TOTAL++;
        ITF_HID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[6];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_KB) {
        ITF_HID_KB = ITF_HID_TOTAL++;
        ITF_KEYBOARD = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[7];
#endif
    }
#endif
#ifdef USB_ITF_CCID
    if (enabled_usb_itf & PHY_USB_ITF_CCID) {
        ITF_SC_CCID = ITF_SC_TOTAL++;
        ITF_CCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[8];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_WCID) {
        ITF_SC_WCID = ITF_SC_TOTAL++;
        ITF_WCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[9];
#endif
    }
#endif
#ifdef USB_ITF_LWIP
    if (enabled_usb_itf & PHY_USB_ITF_LWIP) {
        ITF_LWIP_NET = ITF_LWIP_TOTAL++;
        ITF_LWIP = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[10];
#endif
    }
#endif
    card_locked_itf = ITF_TOTAL;
    if (timeout_counter == NULL) {
        timeout_counter = (uint32_t *)calloc(ITF_TOTAL, sizeof(uint32_t));
    }
#ifdef USB_ITF_HID
    if (ITF_HID_TOTAL > 0) {
        hid_init();
    }
#endif
#ifdef USB_ITF_CCID
    if (ITF_SC_TOTAL > 0) {
        ccid_init();
    }
#endif
#ifdef USB_ITF_LWIP
    if (ITF_LWIP_TOTAL > 0) {
#ifndef ESP_PLATFORM
        lwip_itf_init();
#endif
    }
#endif
#ifdef ESP_PLATFORM
    usb_desc_setup();
#endif
    set_atr();
}

#ifdef PICO_PLATFORM
extern char __end__, __HeapLimit;
extern char __StackBottom, __StackTop;
extern char __StackOneBottom, __StackOneTop;
static uint8_t reboot_temp_stack[1024] __attribute__((aligned(8)));

static inline void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *) ptr;
    while (len--) {
        *p++ = 0xFF;
    }
}

static void __attribute__((noreturn, noinline)) usb_secure_reboot_now(void) {
    uintptr_t heap_start = (uintptr_t) &__end__;
    uintptr_t heap_end = (uintptr_t) &__HeapLimit;
    uintptr_t stack0_start = (uintptr_t) &__StackBottom;
    uintptr_t stack0_end = (uintptr_t) &__StackTop;
    uintptr_t stack1_start = (uintptr_t) &__StackOneBottom;
    uintptr_t stack1_end = (uintptr_t) &__StackOneTop;

    (void) save_and_disable_interrupts();
    multicore_reset_core1();

    if (stack1_end > stack1_start) {
        secure_bzero((void *) stack1_start, stack1_end - stack1_start);
    }

    uintptr_t new_sp = (((uintptr_t) reboot_temp_stack) + sizeof(reboot_temp_stack)) & ~(uintptr_t)0x7;
#if defined(__arm__) || defined(__thumb__)
    __asm volatile ("msr msp, %0" :: "r"(new_sp) : "memory");
#endif

    if (heap_end > heap_start) {
        secure_bzero((void *) heap_start, heap_end - heap_start);
    }
    if (stack0_end > stack0_start) {
        secure_bzero((void *) stack0_start, stack0_end - stack0_start);
    }
    secure_bzero(reboot_temp_stack, sizeof(reboot_temp_stack));

    reset_usb_boot(0, 0);
    while (true) {
        tight_loop_contents();
    }
}
#endif

uint32_t timeout = 0;
void timeout_stop(void) {
    timeout = 0;
}

void timeout_start(void) {
    timeout = board_millis();
}

bool is_busy(void) {
    return timeout > 0;
}

#if defined(PICO_PLATFORM)
/* State for the core1 dead-man's switch (card_watchdog_task(), bottom of file). */
#define CARD_PING_INTERVAL_MS   2000
#define CARD_PING_TIMEOUT_MS    1000
#define CMD_DEADLINE_MS         300000u   /* 180s commit cap + erase margin */

static volatile bool cmd_in_flight = false;
static uint64_t cmd_started_ms = 0;
static uint64_t ping_sent_ms = 0;         /* 0 = no ping outstanding */
static uint64_t core1_last_ok_ms = 0;
static uint64_t wd_last_run_ms = 0;

static void card_note_core1_alive(void);
#endif

void usb_send_event(uint32_t flag) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
#if defined(PICO_PLATFORM)
        cmd_in_flight = true;
        cmd_started_ms = board_millis();
#endif
    }
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif

    if (flag != EV_CMD_AVAILABLE) {
        uint32_t m;
        queue_remove_blocking(&card_to_usb_q , &m);
    }
}

/* Core1 liveness flag, cleared by card_start() before each launch and set by
 * card_init_core1() — the first thing every launched card function runs (apdu.c).
 * Exists because the SDK's multicore launch handshake CAN report success while core1
 * never starts: measured 2026-08-02 via SWD on a live failure — core1 parked in the
 * bootrom's wait-for-launch loop (polling SIO FIFO_ST), one unread word in the FIFO
 * (VLD=1), core0 convinced the launch succeeded. The card then enumerates USB (TinyUSB
 * runs on core0) but never answers an APDU. */
static volatile bool core1_alive = false;

void card_init_core1(void) {
    core1_alive = true;
    low_flash_init_core1();
}

volatile uint16_t finished_data_size = 0;

#if defined(PICO_PLATFORM)
/* Full-chip reset via the BOOTROM's own reboot facility. Why not the alternatives:
 *  - AIRCR.SYSRESETREQ: resets only the asserting core on RP2040/RP2350 (the datasheet's
 *    generic ARM text is wrong for these parts; measured here 2026-08-02 as a complete
 *    no-op — RAM statics survived the write).
 *  - SDK watchdog_reboot(): full-chip, but measured to wedge the post-reset boot ~7% of
 *    cycles (shapes A/B in the forensic record).
 *  - rom_reboot(): still watchdog-based, but it is the bootrom's own sequenced path — the
 *    same mechanism every UF2 flash-update reboot uses, the most field-exercised warm
 *    reset this chip has.
 * Quiesce flash first: no flash op may be in flight when the reset lands. */
static void chip_reset_now(bool deep) {
    /* Two measured-good configurations (2026-08-03/04):
     *  - deep == false (scheduled reset after INITIALIZE): drain-guarded, then
     *    rom_reboot with the POWMAN_WDSEL deep-reset bits CLEARED. This combination
     *    ran 22/23 post-wipe recovery cycles; deep resets after a wipe came back
     *    mute in 4/4 attempts. main.c re-arms WDSEL on every boot.
     *  - deep == true (recovery resets): watchdog_reboot with WDSEL armed —
     *    power-cycles the switched core domain; hammered 100/100 on an idle card.
     * Quiesce flash first either way: no flash op may be in flight at the reset. */
    low_flash_quiesce();
    if (deep) {
        printf("CARD: rebooting via watchdog (deep: SWCORE power-cycle)\n");
        watchdog_reboot(0, 0, 0);
    }
    else {
        powman_clear_bits(&powman_hw->wdsel,
                          POWMAN_WDSEL_RESET_POWMAN_ASYNC_BITS |
                          POWMAN_WDSEL_RESET_SWCORE_BITS |
                          POWMAN_WDSEL_RESET_PSM_BITS);
        printf("CARD: rebooting via rom_reboot (shallow)\n");
        rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL, 1, 0, 0);
    }
    /* Unreachable if the reset took. Stay alive and working if it did not. */
    busy_wait_ms(2000);
    low_flash_unquiesce();
    printf("CARD: ERROR reset did not fire (deep=%d) — staying alive\n", (int) deep);
}

/* Deferred chip reset, fired by card_watchdog_task() from core0's main loop. Exists
 * because a reset must never run inside an APDU handler: the response is transmitted
 * after the handler returns, so a synchronous reset lands mid-command (measured:
 * Transmit failed on the host). */
static uint64_t scheduled_reset_at_ms = 0;   /* 0 = none pending */

void schedule_chip_reset(uint32_t delay_ms) {
    scheduled_reset_at_ms = board_millis() + delay_ms;
}

/* Hard reset via AIRCR.SYSRESETREQ, with a bounded attempt budget kept in watchdog
 * scratch[1] (survives warm resets). Used when core1 cannot be launched: each boot is
 * an independent dice roll, so resetting again converges — but a device that NEVER
 * gets core1 back must stop rolling and stay alive-dark (enumerated, not answering)
 * rather than reset-loop forever. */
#define CORE1_BOOT_ATTEMPTS_MAX 5

static void chip_reset_bounded(void) {
    watchdog_hw->scratch[4] += 1;
    uint32_t attempts = watchdog_hw->scratch[1] + 1;
    watchdog_hw->scratch[1] = attempts;
    if (attempts > CORE1_BOOT_ATTEMPTS_MAX) {
        printf("CARD: core1 unrecoverable after %lu boots — staying alive-dark\n",
               (unsigned long) attempts);
        return;
    }
    printf("CARD: core1 launch failed, resetting chip (attempt %lu)\n", (unsigned long) attempts);
    chip_reset_now(true);
}

/* Launch func on core1 and VERIFY it actually started (the launch handshake can
 * complete against stale FIFO data while core1 stays parked in the bootrom — the
 * failure core1_alive exists to catch). Returns core1_alive. */
static bool card_launch_verified(void *(*func)(void *)) {
    for (int attempt = 0; attempt < 3 && !core1_alive; attempt++) {
        if (attempt > 0) {
            printf("CARD: core1 did not start, relaunching (attempt %d)\n", attempt + 1);
        }
        watchdog_hw->scratch[3] += 1;
        core1_alive = false;
        multicore_reset_core1();
        multicore_launch_func_core1(func);
        for (int waited = 0; waited < 500 && !core1_alive; waited += 10) {
            busy_wait_ms(10);
        }
    }
    if (core1_alive) {
        watchdog_hw->scratch[1] = 0;
    }
    return core1_alive;
}
#endif

void card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
#if defined(PICO_PLATFORM)
            if (!card_launch_verified(func)) {
                chip_reset_bounded();
                /* If the reset fired, unreachable. If it didn't (budget exhausted or the
                 * AIRCR write failed), fall through and stay alive-dark: the host will
                 * time out, which is honest. */
            }
#else
            multicore_reset_core1();
            multicore_launch_func_core1(func);
#endif
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
}

void card_exit(void) {
    if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
        usb_send_event(EV_EXIT);
        uint32_t m;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
#ifndef ENABLE_EMULATION
            mutex_enter_blocking(&mutex);
#endif
            if (queue_try_remove(&card_to_usb_q, &m) == false) {
                break;
            }
#ifndef ENABLE_EMULATION
            mutex_exit(&mutex);
#endif
        }
        led_set_mode(MODE_SUSPENDED);
#ifdef ESP_PLATFORM
        hcore1 = NULL;
#endif
    }
    card_locked_itf = ITF_TOTAL;
    card_locked_func = NULL;
}
extern void hid_task(void);
extern void ccid_task(void);
void usb_task(void) {
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef ENABLE_EMULATION
    emul_task();
#else
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
}

int card_status(uint8_t itf) {
    if (card_locked_itf == itf) {
        if (timeout == 0) {
            return PICOKEYS_ERR_FILE_NOT_FOUND;
        }
        uint32_t m = 0x0;
#ifndef ENABLE_EMULATION
        mutex_enter_blocking(&mutex);
#endif
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
        mutex_exit(&mutex);
#endif
        //if (m != 0)
        //    printf("\n ------ M = %lu\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                timeout_stop();
                led_set_mode(MODE_MOUNTED);
#if defined(PICO_PLATFORM)
                cmd_in_flight = false;
                card_note_core1_alive();
#endif
                return PICOKEYS_OK;
            }
#if defined(PICO_PLATFORM)
            else if (m == EV_PING_ECHO) {
                card_note_core1_alive();
            }
#endif
#ifndef ENABLE_EMULATION
            else if (m == EV_PRESS_BUTTON) {
                int ret = button_wait();
                uint32_t flag = EV_BUTTON_PRESSED;
                if (ret == 1) { //timeout
                    flag = EV_BUTTON_TIMEOUT;
                }
                else if (ret == 2) { //cancelled
                    flag = EV_BUTTON_CANCELLED;
                }
                queue_try_add(&usb_to_card_q, &flag);
            }
#endif
#ifdef PICO_PLATFORM
            else if (m == EV_RESET) {
                usb_secure_reboot_now();
            }
#endif
            return PICOKEYS_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return PICOKEYS_ERR_BLOCKED;
                }
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

#if defined(PICO_PLATFORM)
/* ---- Core1 dead-man's switch ----------------------------------------------------
 * The launch-time check in card_start() catches a core1 that never starts, but core1
 * can ALSO be lost mid-session (measured 2026-08-02 via SWD: core1 parked in a bootrom
 * FIFO wait after it had been serving APDUs, core0 healthy, card mute). So: while a
 * card function is active and NO command is in flight, ping core1 through the existing
 * queue protocol (apdu_thread echoes any non-EV_CMD_AVAILABLE message back +1) and
 * treat a missing echo as death. While a command IS in flight — an INITIALIZE wipe
 * legitimately runs 60-90s+ — never probe; but a command outstanding beyond
 * CMD_DEADLINE_MS is death too, since even the 180s commit cap bounds real work.
 * Recovery is the same ladder as launch: relaunch, then bounded chip reset. */

static void card_note_core1_alive(void) {
    core1_last_ok_ms = board_millis();
    ping_sent_ms = 0;
}

/* Recover a lost core1. Measured 2026-08-02: relaunching core1 alone is NOT enough —
 * core0's CCID slot state (TPDU sequencing, block state) belongs to the dead session,
 * so the card connects but every APDU transmit fails ("Transmit failed" at PC/SC).
 * The only coherent recovery from a mid-session core1 death is a full chip reset:
 * both sides reinitialise, the host re-enumerates and reconnects. */
static void card_recover_core1(void) {
    watchdog_hw->scratch[2] += 1;
    printf("CARD: core1 lost mid-session, resetting chip\n");
    cmd_in_flight = false;
    ping_sent_ms = 0;
    chip_reset_bounded();
}

void card_watchdog_task(void) {
    uint64_t now = board_millis();
    if (now - wd_last_run_ms < 50) {
        return;
    }
    wd_last_run_ms = now;

    /* A scheduled chip reset outranks everything else on this pass — but never fire
     * it while the flash layer still has lazy work queued: a reset landing mid-drain
     * leaves a half-written file system and the next boot can fail to present the
     * card. Wait for the drain, bounded so a stuck queue cannot defer it forever. */
    if (scheduled_reset_at_ms != 0 && (long long) (now - scheduled_reset_at_ms) >= 0) {
        if (low_flash_busy() && (long long) (now - scheduled_reset_at_ms) < 30000) {
            return;   /* retry next pass */
        }
        scheduled_reset_at_ms = 0;
        printf("CARD: scheduled reset firing\n");
        chip_reset_now(false);
        return;
    }

    if (card_locked_itf == ITF_TOTAL || card_locked_func == NULL) {
        ping_sent_ms = 0;
        cmd_in_flight = false;
        return;
    }

    /* Consume anything core1 sent — every message is proof of life. The CCID layer
     * does the same via card_status(); both run on core0, so whoever pops first wins
     * and the handling is identical. */
    uint32_t m = 0;
    if (queue_try_remove(&card_to_usb_q, &m)) {
        if (m == EV_PING_ECHO || m == EV_EXEC_FINISHED) {
            cmd_in_flight = false;
        }
        else if (m == EV_RESET) {
            usb_secure_reboot_now();
        }
        card_note_core1_alive();
    }

    if (cmd_in_flight) {
        if (now - cmd_started_ms > CMD_DEADLINE_MS) {
            printf("CARD: command outstanding >%lus — core1 presumed dead\n",
                   (unsigned long) (CMD_DEADLINE_MS / 1000));
            card_recover_core1();
        }
        return;
    }

    if (ping_sent_ms != 0) {
        if (now - ping_sent_ms > CARD_PING_TIMEOUT_MS) {
            card_recover_core1();
        }
        return;
    }

    if (now - core1_last_ok_ms > CARD_PING_INTERVAL_MS) {
        uint32_t ping = EV_PING;
        if (queue_try_add(&usb_to_card_q, &ping)) {
            ping_sent_ms = now;
        }
    }
}
#endif

#ifndef USB_ITF_CCID
#include "device/usbd_pvt.h"
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 0;
    return NULL;
}
#endif
