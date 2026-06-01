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
#include "led/led.h"
#include "pico_time.h"
#if defined(PICO_PLATFORM)
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/gpio.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#endif
#include "usb.h"
#include "signal.h"

extern void execute_tasks(void);

int (*button_pressed_cb)(uint8_t) = NULL;

static bool req_button_pending = false;

bool is_req_button_pending(void) {
    return req_button_pending;
}

bool cancel_button = false;
bool touch_accept_button = false;

#if !defined(ENABLE_EMULATION)
#ifdef ESP_PLATFORM
static bool picok_board_button_read(void) {
    int boot_state = gpio_get_level(BOOT_PIN);
    return boot_state == 0;
}
#elif defined(PICO_PLATFORM)
static bool __no_inline_not_in_flash_func(picok_get_bootsel_button)(void) {
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
#ifdef PICO_RP2040
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
static bool picok_board_button_read(void) {
  return picok_get_bootsel_button();
}
#else
static bool picok_board_button_read(void) {
    return true; // always unpressed
}
#endif
static bool button_pressed_state = false;
static uint32_t button_pressed_time = 0;
static uint8_t button_press = 0;

int button_wait(void) {
    /* Disabled by default. As LED may not be properly configured,
       it will not be possible to indicate button press unless it
       is commissioned. */
    uint32_t button_timeout = 0;
    if (phy_data.up_btn_present) {
        button_timeout = phy_data.up_btn * 1000;
    }
    if (button_timeout == 0) {
        signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
        return 0;
    }
    signal_user_presence_request_data_t data = {
        .timeout = button_timeout / 1000,
    };
    signal_emit_param(SIGNAL_USER_PRESENCE_REQUEST, &data);
    uint32_t start_button = board_millis();
    const uint32_t button_poll_interval_ms = 2;
    uint32_t next_button_poll_ms = start_button;
    bool button_pressed = picok_board_button_read();
    bool timeout = false;
    cancel_button = false;
    uint32_t led_mode = led_get_mode();
    led_set_mode(MODE_BUTTON);
    req_button_pending = true;
    while (button_pressed == false && cancel_button == false) {
        execute_tasks();
        uint32_t now = board_millis();
        if (now >= next_button_poll_ms) {
            button_pressed = picok_board_button_read();
            next_button_poll_ms = now + button_poll_interval_ms;
        }
        //sleep_ms(10);
        if (start_button + button_timeout < now) { /* timeout */
            timeout = true;
            break;
        }
    }
    if (!timeout) {
        while (button_pressed == true && cancel_button == false) {
            execute_tasks();
            uint32_t now = board_millis();
            if (now >= next_button_poll_ms) {
                button_pressed = picok_board_button_read();
                next_button_poll_ms = now + button_poll_interval_ms;
            }
            //sleep_ms(10);
            if (start_button + 15000 < now) { /* timeout */
                timeout = true;
                break;
            }
        }
    }
    led_set_mode(led_mode);
    req_button_pending = false;
    if (timeout) {
        signal_emit(SIGNAL_USER_PRESENCE_TIMEOUT);
        return 1;
    }
    else if (cancel_button) {
        signal_emit(SIGNAL_USER_PRESENCE_CANCELLED);
        return 2;
    }
    signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
    return 0;
}
#endif

void button_task(void) {
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
}
