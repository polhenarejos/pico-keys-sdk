/*
 * This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
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

// Pico
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#else
#include <sys/time.h>
#include "emulation.h"
#endif

// For memcpy
#include <string.h>

#ifndef ENABLE_EMULATION
// Include descriptor struct definitions
//#include "usb_common.h"
// USB register definitions from pico-sdk
#include "hardware/regs/usb.h"
// USB hardware struct definitions from pico-sdk
#include "hardware/structs/usb.h"
// For interrupt enable and numbers
#include "hardware/irq.h"
// For resetting the USB controller
#include "hardware/resets.h"

#include "pico/multicore.h"
#endif

#include "random.h"
#include "hsm.h"
#include "apdu.h"
#ifndef ENABLE_EMULATION
#include "usb.h"
#include "hardware/rtc.h"
#include "bsp/board.h"
#endif

extern void do_flash();
extern void low_flash_init();

app_t apps[4];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

int register_app(app_t * (*select_aid)(app_t *, const uint8_t *, uint8_t)) {
    if (num_apps < sizeof(apps)/sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        num_apps++;
        return 1;
    }
    return 0;
}

static uint32_t blink_interval_ms = BLINK_NOT_MOUNTED;

void led_set_blink(uint32_t mode) {
    blink_interval_ms = mode;
}

uint32_t timeout = 0;
void timeout_stop() {
    timeout = 0;
}

void timeout_start() {
    timeout = board_millis();
}

void execute_tasks();

static bool req_button_pending = false;

bool is_req_button_pending() {
    return req_button_pending;
}

uint32_t button_timeout = 15000;
bool cancel_button = false;

#ifdef ENABLE_EMULATION
uint32_t board_millis() {
    struct timeval start;
    gettimeofday(&start, NULL);
    return (start.tv_sec * 1000 + start.tv_usec/1000);
}

#else
bool wait_button() {
    uint32_t start_button = board_millis();
    bool timeout = false;
    cancel_button = false;
    led_set_blink((1000 << 16) | 100);
    req_button_pending = true;
    while (board_button_read() == false && cancel_button == false) {
        execute_tasks();
        //sleep_ms(10);
        if (start_button + button_timeout < board_millis()) { /* timeout */
            timeout = true;
            break;
        }
    }
    if (!timeout) {
        while (board_button_read() == true && cancel_button == false) {
            execute_tasks();
            //sleep_ms(10);
            if (start_button + 15000 < board_millis()) { /* timeout */
                timeout = true;
                break;
            }
        }
    }
    led_set_blink(BLINK_PROCESSING);
    req_button_pending = false;
    return timeout || cancel_button;
}
#endif

struct apdu apdu;

void led_blinking_task() {
#ifdef PICO_DEFAULT_LED_PIN
    static uint32_t start_ms = 0;
    static uint8_t led_state = false;
    static uint8_t led_color = PICO_DEFAULT_LED_PIN;
#ifdef PICO_DEFAULT_LED_PIN_INVERTED
    uint32_t interval = !led_state ? blink_interval_ms & 0xffff : blink_interval_ms >> 16;
#else
    uint32_t interval = led_state ? blink_interval_ms & 0xffff : blink_interval_ms >> 16;
#endif


    // Blink every interval ms
    if (board_millis() - start_ms < interval)
        return; // not enough time
    start_ms += interval;

    gpio_put(led_color, led_state);
    led_state ^= 1; // toggle
#endif
}

void led_off_all() {
#ifdef PIMORONI_TINY2040
    gpio_put(TINY2040_LED_R_PIN, 1);
    gpio_put(TINY2040_LED_G_PIN, 1);
    gpio_put(TINY2040_LED_B_PIN, 1);
#else
#ifdef PICO_DEFAULT_LED_PIN
    gpio_put(PICO_DEFAULT_LED_PIN, 0);
#endif
#endif
}

void init_rtc() {
#ifndef ENABLE_EMULATION
    rtc_init();
    datetime_t dt = {
            .year  = 2020,
            .month = 1,
            .day   = 1,
            .dotw  = 3, // 0 is Sunday, so 5 is Friday
            .hour  = 00,
            .min   = 00,
            .sec   = 00
    };
    rtc_set_datetime(&dt);
#endif
}

extern void neug_task();
extern void usb_task();

void execute_tasks() {
    usb_task();
#ifndef ENABLE_EMULATION
    tud_task(); // tinyusb device task
#endif
    led_blinking_task();
}

int main(void) {
#ifndef ENABLE_EMULATION
    usb_init();

    board_init();
    stdio_init_all();

#ifdef PIMORONI_TINY2040
    gpio_init(TINY2040_LED_R_PIN);
    gpio_set_dir(TINY2040_LED_R_PIN, GPIO_OUT);
    gpio_init(TINY2040_LED_G_PIN);
    gpio_set_dir(TINY2040_LED_G_PIN, GPIO_OUT);
    gpio_init(TINY2040_LED_B_PIN);
    gpio_set_dir(TINY2040_LED_B_PIN, GPIO_OUT);
#else
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif
#endif

    led_off_all();

    tusb_init();

    //prepare_ccid();
#else
    emul_init("localhost",35963);
#endif

    random_init();

    low_flash_init();

    init_rtc();

    //ccid_prepare_receive(&ccid);

    while (1) {
        execute_tasks();
        neug_task();
        do_flash();
    }

    return 0;
}