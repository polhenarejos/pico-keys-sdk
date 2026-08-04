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
#include "button.h"
#include <stdio.h>
#if !defined(ENABLE_EMULATION)
#include "tusb.h"
#endif
#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "rom/gpio.h"
#include "tinyusb.h"
#elif defined(PICO_PLATFORM)
#include "bsp/board.h"
#include "hardware/structs/ioqspi.h"
#include "pico/stdio.h"
#include "pico/bootrom.h"
#include "boot/picoboot_constants.h"
#include "hardware/powman.h"
#include "hardware/structs/psm.h"
#include "hardware/regs/psm.h"
#endif

#if defined(PICO_PLATFORM)
/* The SDK's hard_assertion_failure() is __weak; override it. The default path is
 * panic() -> __breakpoint -> _exit: a silent, permanent brick that needs a physical
 * replug — measured 2026-08-03 (a corrupt flash_pages entry hit
 * hard_assert(flash_offs + count <= PICO_FLASH_SIZE_BYTES) and the device sat
 * catatonic for a day). A smartcard that cannot recover itself is not one. Reboot
 * via the bootrom instead: each boot is a fresh roll, and the core1 launch-verify
 * and dead-man's switch do their jobs from there. */
void hard_assertion_failure(void) {
    printf("PANIC: hard assert failed — rebooting via rom_reboot\n");
    rom_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL, 1, 0, 0);
    while (1) {
        tight_loop_contents();
    }
}
#endif

#include "random.h"
#include "hwrng.h"
#include "apdu.h"
#include "usb.h"
#include "flash.h"
#include "otp.h"
#include "led/led.h"
#include "pico_time.h"
#include "serial.h"
#include "mbedtls/sha256.h"

extern int rescue_migrate_keydev(void);

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

bool app_exists(const_byte_array_t aid) {
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(CONST_BYTE_ARRAY(aid + 1, aid[0]))) {
        return 1;
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const_byte_array_t aid) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid.data || (aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])))) {
        current_app->select_aid(current_app, 0);
        return PICOKEYS_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            if (current_app) {
                if (current_app->aid && aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])) {
                    current_app->select_aid(current_app, 1);
                    return PICOKEYS_OK;
                }
                if (current_app->unload) {
                    current_app->unload();
                }
            }
            current_app = &apps[a];
            if (current_app->select_aid(current_app, 1) == PICOKEYS_OK) {
                return PICOKEYS_OK;
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}


WEAK int picokey_init(void) {
    return 0;
}

void execute_tasks(void);
void execute_tasks(void) {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    tud_task(); // tinyusb device task
#endif
#ifdef USB_ITF_LWIP
#if !defined(ENABLE_EMULATION)
    service_traffic();
#endif
    rest_task();
#endif
    usb_task();
#ifdef PICO_PLATFORM
    card_watchdog_task();
#endif
    led_blinking_task();
#ifdef ENABLE_LVGL_UI
    platform_ui_task();
#endif
}

static void core0_loop(void *arg) {
    (void)arg;
#if defined(ESP_PLATFORM) && defined(USB_ITF_LWIP)
    if (ITF_LWIP_TOTAL > 0) {
        lwip_itf_init();
    }
#endif
    while (1) {
        execute_tasks();
        hwrng_task();
        flash_task();
        button_task();
#ifdef PICO_PLATFORM
        // Avoid a pure busy loop on core0; gives the system a scheduling hint.
        tight_loop_contents();
#endif
#ifdef ESP_PLATFORM
        vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
}

#ifdef ESP_PLATFORM
extern tinyusb_config_t tusb_cfg;
extern const uint8_t desc_config[];
extern char *string_desc_arr[];
extern char *string_desc_itf[];
TaskHandle_t hcore0 = NULL, hcore1 = NULL;
int app_main(void) {
#else
int main(void) {
#endif

    serial_init();

#ifndef ENABLE_EMULATION
#ifdef PICO_PLATFORM
    board_init();
    stdio_init_all();

    /* Make EVERY watchdog-family reset a FULL switched-core power cycle. The default
     * watchdog reset (PSM_WDSEL minus ROSC/XOSC) leaves the switched core domain
     * powered and was measured to wedge the warm boot ~5-10% of resets on RP2350B —
     * cores never start, identically across watchdog_reboot() and rom_reboot()
     * (2026-08-02/03 forensic record in regalia hardware/pico-hsm/). POWMAN_WDSEL
     * RESET_SWCORE makes the reset power-cycle the switched domain and run the full
     * PSM sequence — "the same effect as a power-on reset for the switched core
     * power domain" (RP2350 datasheet). RESET_POWMAN_ASYNC restores powman defaults
     * without depending on clk_ref; because it restores defaults, this register must
     * be re-armed on EVERY boot — hence here, first thing. PSM_WDSEL all-ones per
     * the datasheet note (powman ignores watchdog resets that don't select CLOCKS
     * or earlier). */
    powman_set_bits(&powman_hw->wdsel,
                    POWMAN_WDSEL_RESET_POWMAN_ASYNC_BITS |
                    POWMAN_WDSEL_RESET_SWCORE_BITS |
                    POWMAN_WDSEL_RESET_PSM_BITS);
    psm_hw->wdsel = PSM_WDSEL_BITS;
#endif

#else
    emul_init("127.0.0.1", 35963);
#endif

    random_init();

    otp_init();

    low_flash_init();

    file_scan_flash();

    if (rescue_migrate_keydev() != PICOKEYS_OK) {
        printf("Device attestation key migration failed\n");
    }

    init_rtc();

#ifndef ENABLE_EMULATION
    phy_init();
#endif

    led_init();

    usb_init();

#ifndef ENABLE_EMULATION
#ifdef ESP_PLATFORM
    gpio_pad_select_gpio(BOOT_PIN);
    gpio_set_direction(BOOT_PIN, GPIO_MODE_INPUT);
    gpio_pulldown_dis(BOOT_PIN);

    tusb_cfg.string_descriptor[3] = pico_serial_str;
    if (phy_data.usb_product_present) {
        tusb_cfg.string_descriptor[2] = phy_data.usb_product;
    }
    static char tmps[5][32];
    const int max_desc_slots = 8 - 6;
    const int itf_desc_count = ITF_TOTAL < max_desc_slots ? ITF_TOTAL : max_desc_slots;
    for (int i = 0; i < itf_desc_count; i++) {
        strlcpy(tmps[i], tusb_cfg.string_descriptor[2], sizeof(tmps[0]));
        strlcat(tmps[i], " ", sizeof(tmps[0]));
        strlcat(tmps[i], string_desc_itf[i], sizeof(tmps[0]));
        tusb_cfg.string_descriptor[i+6] = tmps[i];
    }
    tusb_cfg.string_descriptor_count = 6 + itf_desc_count;
    tusb_cfg.configuration_descriptor = desc_config;

    tinyusb_driver_install(&tusb_cfg);
#else
    tusb_init();
#endif
#endif

#ifndef ENABLE_EMULATION
    picokey_init();
#endif

#ifdef ESP_PLATFORM
    xTaskCreatePinnedToCore(core0_loop, "core0", 4096*ITF_TOTAL*2, NULL, CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0, ESP32_CORE0);
#else
    core0_loop(NULL);
#endif

    return 0;
}
