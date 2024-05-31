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

#ifndef _PICO_KEYS_H_
#define _PICO_KEYS_H_

#include "file.h"
#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
#include <stdint.h>
#ifdef ENABLE_EMULATION
extern uint32_t board_millis();
#endif
#if !defined(MIN)
#if defined(_MSC_VER)
#define MIN(a,b) (((a)<(b))?(a):(b))
#else
#define MIN(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })
#endif
#endif
#if !defined(MAX)
#if defined(_MSC_VER)
#define MAX(a,b) (((a)>(b))?(a):(b))
#else
#define MAX(a, b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })
#endif
#endif
#else
#include "pico/unique_id.h"
#endif
#include <string.h>

#if defined(ENABLE_EMULATION)
#include <stdbool.h>
#elif defined(ESP_PLATFORM)
#include "esp_compat.h"
#else
#include "pico/util/queue.h"
#endif

extern bool wait_button();

extern void low_flash_init_core1();

static inline uint16_t make_uint16_t(uint8_t b1, uint8_t b2) {
    return (b1 << 8) | b2;
}
static inline uint16_t get_uint16_t(const uint8_t *b, uint16_t offset) {
    return make_uint16_t(b[offset], b[offset + 1]);
}
static inline void put_uint16_t(uint16_t n, uint8_t *b) {
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
}

extern void low_flash_available();
extern int flash_clear_file(file_t *file);

extern void timeout_stop();
extern void timeout_start();

extern int (*button_pressed_cb)(uint8_t);

enum  {
    BLINK_NOT_MOUNTED = (250 << 16) | 250,
    BLINK_MOUNTED     = (250 << 16) | 250,
    BLINK_SUSPENDED   = (500 << 16) | 1000,
    BLINK_PROCESSING  = (50 << 16) | 50,

    BLINK_ALWAYS_ON   = UINT32_MAX,
    BLINK_ALWAYS_OFF  = 0
};
extern void led_set_blink(uint32_t mode);

extern bool is_req_button_pending();
extern uint32_t button_timeout;

#define SW_BYTES_REMAINING_00()             set_res_sw(0x61, 0x00)
#define SW_WARNING_STATE_UNCHANGED()        set_res_sw(0x62, 0x00)
#define SW_WARNING_CORRUPTED()              set_res_sw(0x62, 0x81)
#define SW_WARNING_EOF()                    set_res_sw(0x62, 0x82)
#define SW_WARNING_EF_DEACTIVATED()         set_res_sw(0x62, 0x83)
#define SW_WARNING_WRONG_FCI()              set_res_sw(0x62, 0x84)
#define SW_WARNING_EF_TERMINATED()          set_res_sw(0x62, 0x85)

#define SW_WARNING_NOINFO()                 set_res_sw(0x63, 0x00)
#define SW_WARNING_FILLUP()                 set_res_sw(0x63, 0x81)

#define SW_EXEC_ERROR()                     set_res_sw(0x64, 0x00)

#define SW_MEMORY_FAILURE()                 set_res_sw(0x65, 0x81)

#define SW_SECURE_MESSAGE_EXEC_ERROR()      set_res_sw(0x66, 0x00)

#define SW_WRONG_LENGTH()                   set_res_sw(0x67, 0x00)
#define SW_WRONG_DATA()                     set_res_sw(0x67, 0x00)

#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED()  set_res_sw(0x68, 0x81)
#define SW_SECURE_MESSAGING_NOT_SUPPORTED() set_res_sw(0x68, 0x82)

#define SW_COMMAND_INCOMPATIBLE()           set_res_sw(0x69, 0x81)
#define SW_SECURITY_STATUS_NOT_SATISFIED()  set_res_sw(0x69, 0x82)
#define SW_PIN_BLOCKED()                    set_res_sw(0x69, 0x83)
#define SW_DATA_INVALID()                   set_res_sw(0x69, 0x84)
#define SW_CONDITIONS_NOT_SATISFIED()       set_res_sw(0x69, 0x85)
#define SW_COMMAND_NOT_ALLOWED()            set_res_sw(0x69, 0x86)
#define SW_SECURE_MESSAGING_MISSING_DO()    set_res_sw(0x69, 0x87)
#define SW_SECURE_MESSAGING_INCORRECT_DO()  set_res_sw(0x69, 0x88)
#define SW_APPLET_SELECT_FAILED()           set_res_sw(0x69, 0x99)

#define SW_INCORRECT_PARAMS()               set_res_sw(0x6A, 0x80)
#define SW_FUNC_NOT_SUPPORTED()             set_res_sw(0x6A, 0x81)
#define SW_FILE_NOT_FOUND()                 set_res_sw(0x6A, 0x82)
#define SW_RECORD_NOT_FOUND()               set_res_sw(0x6A, 0x83)
#define SW_FILE_FULL()                      set_res_sw(0x6A, 0x84)
#define SW_WRONG_NE()                       set_res_sw(0x6A, 0x85)
#define SW_INCORRECT_P1P2()                 set_res_sw(0x6A, 0x86)
#define SW_WRONG_NC()                       set_res_sw(0x6A, 0x87)
#define SW_REFERENCE_NOT_FOUND()            set_res_sw(0x6A, 0x88)
#define SW_FILE_EXISTS()                    set_res_sw(0x6A, 0x89)

#define SW_WRONG_P1P2()                     set_res_sw(0x6B, 0x00)

#define SW_CORRECT_LENGTH_00()              set_res_sw(0x6C, 0x00)

#define SW_INS_NOT_SUPPORTED()              set_res_sw(0x6D, 0x00)

#define SW_CLA_NOT_SUPPORTED()              set_res_sw(0x6E, 0x00)

#define SW_UNKNOWN()                        set_res_sw(0x6F, 0x00)

#define SW_OK()                             set_res_sw(0x90, 0x00)

#define CCID_OK                              0
#define CCID_ERR_NO_MEMORY                   -1000
#define CCID_ERR_MEMORY_FATAL                -1001
#define CCID_ERR_NULL_PARAM                  -1002
#define CCID_ERR_FILE_NOT_FOUND              -1003
#define CCID_ERR_BLOCKED                     -1004
#define CCID_NO_LOGIN                        -1005
#define CCID_EXEC_ERROR                      -1006
#define CCID_WRONG_LENGTH                    -1007
#define CCID_WRONG_DATA                      -1008
#define CCID_WRONG_DKEK                      -1009
#define CCID_WRONG_SIGNATURE                 -1010
#define CCID_WRONG_PADDING                   -1011
#define CCID_VERIFICATION_FAILED             -1012

#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
typedef struct { uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES]; } pico_unique_board_id_t;
#endif
extern pico_unique_board_id_t pico_serial;
extern char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];

#endif
