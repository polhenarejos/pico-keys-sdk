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

#if defined(PICO_RP2040) || defined(PICO_RP2350)
#define PICO_PLATFORM
#endif

#include "file.h"
#include "led/led.h"
#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
#include <stdint.h>
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
#include "debug.h"

#if defined(ENABLE_EMULATION)
#include <stdbool.h>
#elif defined(ESP_PLATFORM)
#include "esp_compat.h"
#else
#include "pico/util/queue.h"
#endif

extern bool wait_button();

extern void low_flash_init_core1();

static inline uint16_t make_uint16_t_be(uint8_t b1, uint8_t b2) {
    return (b1 << 8) | b2;
}
static inline uint16_t make_uint16_t_le(uint8_t b1, uint8_t b2) {
    return (b2 << 8) | b1;
}
static inline uint16_t get_uint16_t_be(const uint8_t *b) {
    return make_uint16_t_be(b[0], b[1]);
}
static inline uint16_t get_uint16_t_le(const uint8_t *b) {
    return make_uint16_t_le(b[0], b[1]);
}
static inline uint32_t put_uint16_t_be(uint16_t n, uint8_t *b) {
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 2;
}
static inline uint32_t put_uint16_t_le(uint16_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b = (n >> 8) & 0xff;
    return 2;
}

static inline uint32_t make_uint32_t_be(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}
static inline uint32_t make_uint32_t_le(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
    return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
}
static inline uint32_t get_uint32_t_be(const uint8_t *b) {
    return make_uint32_t_be(b[0], b[1], b[2], b[3]);
}
static inline uint32_t get_uint32_t_le(const uint8_t *b) {
    return make_uint32_t_le(b[0], b[1], b[2], b[3]);
}
static inline uint32_t put_uint32_t_be(uint32_t n, uint8_t *b) {
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 4;
}
static inline uint32_t put_uint32_t_le(uint32_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b = (n >> 24) & 0xff;
    return 4;
}

static inline uint64_t make_uint64_t_be(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7, uint8_t b8) {
    return ((uint64_t) b1 << 56) | ((uint64_t) b2 << 48) | ((uint64_t) b3 << 40) | ((uint64_t) b4 << 32) | ((uint64_t) b5 << 24) | ((uint64_t) b6 << 16) | ((uint64_t) b7 << 8) | b8;
}
static inline uint64_t make_uint64_t_le(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7, uint8_t b8) {
    return ((uint64_t) b8 << 56) | ((uint64_t) b7 << 48) | ((uint64_t) b6 << 40) | ((uint64_t) b5 << 32) | ((uint64_t) b4 << 24) | ((uint64_t) b3 << 16) | ((uint64_t) b2 << 8) | b1;
}
static inline uint64_t get_uint64_t_be(const uint8_t *b) {
    return make_uint64_t_be(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}
static inline uint64_t get_uint64_t_le(const uint8_t *b) {
    return make_uint64_t_le(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}
static inline uint32_t put_uint64_t_be(uint64_t n, uint8_t *b) {
    *b++ = (n >> 56) & 0xff;
    *b++ = (n >> 48) & 0xff;
    *b++ = (n >> 40) & 0xff;
    *b++ = (n >> 32) & 0xff;
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
    return 8;
}
static inline uint32_t put_uint64_t_le(uint64_t n, uint8_t *b) {
    *b++ = n & 0xff;
    *b++ = (n >> 8) & 0xff;
    *b++ = (n >> 16) & 0xff;
    *b++ = (n >> 24) & 0xff;
    *b++ = (n >> 32) & 0xff;
    *b++ = (n >> 40) & 0xff;
    *b++ = (n >> 48) & 0xff;
    *b = (n >> 56) & 0xff;
    return 8;
}

extern void low_flash_available();
extern int flash_clear_file(file_t *file);

extern int (*button_pressed_cb)(uint8_t);

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

#define PICOKEY_OK                              0
#define PICOKEY_ERR_NO_MEMORY                   -1000
#define PICOKEY_ERR_MEMORY_FATAL                -1001
#define PICOKEY_ERR_NULL_PARAM                  -1002
#define PICOKEY_ERR_FILE_NOT_FOUND              -1003
#define PICOKEY_ERR_BLOCKED                     -1004
#define PICOKEY_NO_LOGIN                        -1005
#define PICOKEY_EXEC_ERROR                      -1006
#define PICOKEY_WRONG_LENGTH                    -1007
#define PICOKEY_WRONG_DATA                      -1008
#define PICOKEY_WRONG_DKEK                      -1009
#define PICOKEY_WRONG_SIGNATURE                 -1010
#define PICOKEY_WRONG_PADDING                   -1011
#define PICOKEY_VERIFICATION_FAILED             -1012

#define PICOKEY_CHECK(x) do { ret = (x); if (ret != PICOKEY_OK) goto err; } while (0)

#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
typedef struct { uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES]; } pico_unique_board_id_t;
#endif
extern pico_unique_board_id_t pico_serial;
extern char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];

#endif
