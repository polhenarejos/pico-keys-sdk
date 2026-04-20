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

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

bool app_exists(const uint8_t *aid, size_t aid_len) {
    for (int a = 0; a < num_apps; a++) {
        if (aid_len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(aid + 1, aid[0])) {
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

int select_app(const uint8_t *aid, size_t aid_len) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid || (aid_len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid, current_app->aid[0])))) {
        current_app->select_aid(current_app, 0);
        return PICOKEYS_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (aid_len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid, apps[a].aid[0])) {
            if (current_app) {
                if (current_app->aid && aid_len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid, current_app->aid[0])) {
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


__attribute__((weak)) int picokey_init(void) {
    return 0;
}

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
    led_blinking_task();
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
#endif

#else
    emul_init("127.0.0.1", 35963);
#endif

    random_init();

    otp_init_files();

    low_flash_init();

    file_scan_flash();

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
