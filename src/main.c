/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

// Pico

#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "tusb.h"
#include "driver/gpio.h"
#include "rom/gpio.h"
#include "tinyusb.h"
#include "esp_efuse.h"
#define BOOT_PIN GPIO_NUM_0
#else
#include "pico/stdlib.h"
#include "bsp/board.h"
#include "pico/aon_timer.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#endif

#include "random.h"
#include "pico_keys.h"
#include "apdu.h"
#include "usb.h"
extern void do_flash();
extern void low_flash_init();
extern void init_otp_files();

app_t apps[8];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const uint8_t *aid, size_t aid_len) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid || !memcmp(current_app->aid + 1, aid, aid_len))) {
        current_app->select_aid(current_app, 0);
        return PICOKEY_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (!memcmp(apps[a].aid + 1, aid, MIN(aid_len, apps[a].aid[0]))) {
            if (current_app) {
                if (current_app->aid && !memcmp(current_app->aid + 1, aid, aid_len)) {
                    current_app->select_aid(current_app, 1);
                    return PICOKEY_OK;
                }
                if (current_app->unload) {
                    current_app->unload();
                }
            }
            current_app = &apps[a];
            if (current_app->select_aid(current_app, 1) == PICOKEY_OK) {
                return PICOKEY_OK;
            }
        }
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

int (*button_pressed_cb)(uint8_t) = NULL;

void execute_tasks();

static bool req_button_pending = false;

bool is_req_button_pending() {
    return req_button_pending;
}

bool cancel_button = false;

#ifdef ENABLE_EMULATION
#ifdef _MSC_VER
#include <windows.h>
struct timezone
{
    __int32  tz_minuteswest; /* minutes W of Greenwich */
    bool  tz_dsttime;     /* type of dst correction */
};
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    (void)tzp;
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif
#else
#ifdef ESP_PLATFORM
bool picok_board_button_read() {
    int boot_state = gpio_get_level(BOOT_PIN);
    return boot_state == 0;
}
#else
bool __no_inline_not_in_flash_func(picok_get_bootsel_button)() {
    const uint CS_PIN_INDEX = 1;

    // Must disable interrupts, as interrupt handlers may be in flash, and we
    // are about to temporarily disable flash access!
    uint32_t flags = save_and_disable_interrupts();

    // Set chip select to Hi-Z
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // Note we can't call into any sleep functions in flash right now
    for (volatile int i = 0; i < 1000; ++i);

    // The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
    // Note the button pulls the pin *low* when pressed.
#if PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool button_state = !(sio_hw->gpio_hi_in & CS_BIT);

    // Need to restore the state of chip select, else we are going to have a
    // bad time when we return to code in flash!
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}
uint32_t picok_board_button_read(void)
{
  return picok_get_bootsel_button();
}
#endif
bool button_pressed_state = false;
uint32_t button_pressed_time = 0;
uint8_t button_press = 0;
bool wait_button() {
    uint32_t button_timeout = 15000;
    if (phy_data.up_btn_present) {
        button_timeout = phy_data.up_btn * 1000;
        if (button_timeout == 0) {
            return false;
        }
    }
    uint32_t start_button = board_millis();
    bool timeout = false;
    cancel_button = false;
    led_set_mode(MODE_BUTTON);
    req_button_pending = true;
    while (picok_board_button_read() == false && cancel_button == false) {
        execute_tasks();
        //sleep_ms(10);
        if (start_button + button_timeout < board_millis()) { /* timeout */
            timeout = true;
            break;
        }
    }
    if (!timeout) {
        while (picok_board_button_read() == true && cancel_button == false) {
            execute_tasks();
            //sleep_ms(10);
            if (start_button + 15000 < board_millis()) { /* timeout */
                timeout = true;
                break;
            }
        }
    }
    led_set_mode(MODE_PROCESSING);
    req_button_pending = false;
    return timeout || cancel_button;
}
#endif

struct apdu apdu;

void init_rtc() {
#ifdef PICO_PLATFORM
    struct timespec tv = {0};
    tv.tv_sec = 1577836800; // 2020-01-01
    aon_timer_start(&tv);
#endif
}

extern void neug_task();
extern void usb_task();
void execute_tasks()
{
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    tud_task(); // tinyusb device task
#endif
    usb_task();
    led_blinking_task();
}

void core0_loop() {
    while (1) {
        execute_tasks();
        neug_task();
        do_flash();
#ifndef ENABLE_EMULATION
        if (button_pressed_cb && board_millis() > 1000 && !is_busy()) { // wait 1 second to boot up
            bool current_button_state = picok_board_button_read();
            if (current_button_state != button_pressed_state) {
                if (current_button_state == false) { // unpressed
                    if (button_pressed_time == 0 || button_pressed_time + 1000 > board_millis()) {
                        button_press++;
                    }
                    button_pressed_time = board_millis();
                }
                button_pressed_state = current_button_state;
            }
            if (button_pressed_time > 0 && button_press > 0 && button_pressed_time + 1000 < board_millis() && button_pressed_state == false) {
                if (button_pressed_cb != NULL) {
                    (*button_pressed_cb)(button_press);
                }
                button_pressed_time = button_press = 0;
            }
        }
#endif
#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
}

char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
pico_unique_board_id_t pico_serial;
#ifdef ESP_PLATFORM
#define pico_get_unique_board_id(a) do { uint32_t value; esp_efuse_read_block(EFUSE_BLK1, &value, 0, 32); memcpy((uint8_t *)(a), &value, sizeof(uint32_t)); esp_efuse_read_block(EFUSE_BLK1, &value, 32, 32); memcpy((uint8_t *)(a)+4, &value, sizeof(uint32_t)); } while(0)
extern tinyusb_config_t tusb_cfg;
extern const uint8_t desc_config[];
TaskHandle_t hcore0 = NULL, hcore1 = NULL;
int app_main() {
#else
#ifdef ENABLE_EMULATION
#define pico_get_unique_board_id(a) memset(a, 0, sizeof(*(a)))
#endif
int main(void) {
#endif
    pico_get_unique_board_id(&pico_serial);
    memset(pico_serial_str, 0, sizeof(pico_serial_str));
    for (int i = 0; i < sizeof(pico_serial); i++) {
        snprintf(&pico_serial_str[2 * i], 3, "%02X", pico_serial.id[i]);
    }

#ifndef ENABLE_EMULATION
#ifndef ESP_PLATFORM
    board_init();
    stdio_init_all();
#endif
    led_init();

#else
    emul_init("127.0.0.1", 35963);
#endif

    random_init();

    init_otp_files();

    low_flash_init();

    scan_flash();

    init_rtc();

#ifndef ENABLE_EMULATION
    phy_init();
#endif

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
    static char tmps[4][32];
    for (int i = 4; i < tusb_cfg.string_descriptor_count; i++) {
        strlcpy(tmps[i-4], tusb_cfg.string_descriptor[2], sizeof(tmps[0]));
        strlcat(tmps[i-4], " ", sizeof(tmps[0]));
        strlcat(tmps[i-4], tusb_cfg.string_descriptor[i], sizeof(tmps[0]));
        tusb_cfg.string_descriptor[i] = tmps[i-4];
    }
    tusb_cfg.configuration_descriptor = desc_config;

    tinyusb_driver_install(&tusb_cfg);
#else
    tusb_init();
#endif
#endif

#ifdef ESP_PLATFORM
    xTaskCreatePinnedToCore(core0_loop, "core0", 4096*ITF_TOTAL*2, NULL, CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0, 0);
#else
    core0_loop();
#endif

    return 0;
}
