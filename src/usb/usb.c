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

#include <stdio.h>
#include "pico_keys.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "hardware/sync.h"
#include "bsp/board.h"
#endif
#include "usb.h"
#include "apdu.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#else
#include "emulation.h"
#endif

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint32_t *timeout_counter = NULL;
static uint8_t card_locked_itf = 0; // no locked
static void *(*card_locked_func)(void *) = NULL;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
#endif
#if !defined(PICO_PLATFORM) && !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#ifdef _MSC_VER
#include "pthread_win32.h"
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
extern char *string_desc_itf[4], *string_desc_arr[];
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
        lwip_itf_init();
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

void usb_send_event(uint32_t flag) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
    if (flag != EV_CMD_AVAILABLE) {
        uint32_t m;
        queue_remove_blocking(&card_to_usb_q , &m);
    }
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif
}

void card_init_core1(void) {
    low_flash_init_core1();
}

uint16_t finished_data_size = 0;

void card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
            multicore_reset_core1();
            multicore_launch_func_core1(func);
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
            return PICOKEY_ERR_FILE_NOT_FOUND;
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
                return PICOKEY_OK;
            }
#ifndef ENABLE_EMULATION
            else if (m == EV_PRESS_BUTTON) {
                uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
                queue_try_add(&usb_to_card_q, &flag);
            }
#endif
#ifdef PICO_PLATFORM
            else if (m == EV_RESET) {
                usb_secure_reboot_now();
            }
#endif
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return PICOKEY_ERR_BLOCKED;
                }
            }
        }
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

#ifndef USB_ITF_CCID
#include "device/usbd_pvt.h"
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 0;
    return NULL;
}
#endif
