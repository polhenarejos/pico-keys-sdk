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

#include "pico_keys.h"
#include "apdu.h"
#include "pico_keys_version.h"
#include "otp.h"
#ifdef PICO_PLATFORM
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#include "pico/aon_timer.h"
#else
#include <sys/time.h>
#include <time.h>
#endif
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "random.h"

#ifdef PICO_PLATFORM
extern char __flash_binary_start;
extern char __flash_binary_end;
#endif

int rescue_process_apdu();
int rescue_unload();
bool set_rtc = false;

const uint8_t rescue_aid[] = {
    8,
    0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21
};

#ifdef PICO_RP2350
#define PICO_MCU 1
#elif defined(ESP_PLATFORM)
#define PICO_MCU 2
#elif defined(ENABLE_EMULATION)
#define PICO_MCU 3
#else
#define PICO_MCU 0
#endif

extern uint8_t PICO_PRODUCT;
extern uint8_t PICO_VERSION_MAJOR;
extern uint8_t PICO_VERSION_MINOR;

int rescue_select(app_t *a, uint8_t force) {
    a->process_apdu = rescue_process_apdu;
    a->unload = rescue_unload;
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = PICO_MCU;
    res_APDU[res_APDU_size++] = PICO_PRODUCT;
    res_APDU[res_APDU_size++] = PICO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_VERSION_MINOR;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, sizeof(pico_serial.id));
    res_APDU_size += sizeof(pico_serial.id);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_flash();
    }
    return PICOKEY_OK;
}

INITIALIZER ( rescue_ctor ) {
    register_app(rescue_select, rescue_aid);
}

int rescue_unload() {
    return PICOKEY_OK;
}

int cmd_keydev_sign() {
    uint8_t p1 = P1(apdu);
    if (p1 == 0x01) {
        if (apdu.nc != 32) {
            return SW_WRONG_LENGTH();
        }
        if (!otp_key_2) {
            return SW_INS_NOT_SUPPORTED();
        }
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256K1, &ecdsa, otp_key_2, 32);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        uint16_t key_size = 2 * (int)((mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256K1)->bit_size + 7) / 8);
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        ret = mbedtls_ecdsa_sign(&ecdsa.MBEDTLS_PRIVATE(grp), &r, &s, &ecdsa.MBEDTLS_PRIVATE(d), apdu.data, apdu.nc, random_gen, NULL);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            return SW_EXEC_ERROR();
        }

        mbedtls_mpi_write_binary(&r, res_APDU, key_size / 2); res_APDU_size = key_size / 2;
        mbedtls_mpi_write_binary(&s, res_APDU + res_APDU_size, key_size / 2); res_APDU_size += key_size / 2;
        mbedtls_ecdsa_free(&ecdsa);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    }
    else if (p1 == 0x02) {
        // Return public key
        if (!otp_key_2) {
            return SW_INS_NOT_SUPPORTED();
        }
        if (apdu.nc != 0) {
            return SW_WRONG_LENGTH();
        }
        mbedtls_ecp_keypair ecp;
        mbedtls_ecp_keypair_init(&ecp);
        int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256K1, &ecp, otp_key_2, 32);
        if (ret != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        ret = mbedtls_ecp_mul(&ecp.MBEDTLS_PRIVATE(grp), &ecp.MBEDTLS_PRIVATE(Q), &ecp.MBEDTLS_PRIVATE(d), &ecp.MBEDTLS_PRIVATE(grp).G, random_gen, NULL);
        if (ret != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        ret = mbedtls_ecp_point_write_binary(&ecp.MBEDTLS_PRIVATE(grp), &ecp.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, res_APDU, 4096);
        if (ret != 0) {
            mbedtls_ecp_keypair_free(&ecp);
            return SW_EXEC_ERROR();
        }
        res_APDU_size = (uint16_t)olen;
        mbedtls_ecp_keypair_free(&ecp);
    }
    else if (p1 == 0x03) {
        // Upload device attestation certificate
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
        file_t *ef_devcert = file_new(0x2F02); // EF_DEVCERT
        if (!ef_devcert) {
            return SW_FILE_NOT_FOUND();
        }
        file_put_data(ef_devcert, apdu.data, (uint16_t)apdu.nc);
        res_APDU_size = 0;
        low_flash_available();
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}

// Blocking CORE1
void led_3_blinks() {
#ifndef ENABLE_EMULATION
    uint32_t mode = led_get_mode();
    led_set_mode(MODE_PROCESSING);
    sleep_ms(500);
    led_set_mode(mode);
#endif
}

int cmd_write() {
    if (apdu.nc < 2) {
        return SW_WRONG_LENGTH();
    }

    uint8_t p1 = P1(apdu), p2 = P2(apdu);

    if (p1 == 0x1) { // PHY
#ifndef ENABLE_EMULATION
        int ret = phy_unserialize_data(apdu.data, (uint16_t)apdu.nc, &phy_data);
        if (ret == PICOKEY_OK) {
            if (phy_save() != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
#endif
    }
    else if (p1 == 0x2) { // SET TIME
        time_t tv_sec = 0;
        if (p2 != 0x1 && p2 != 0x2) {
            return SW_INCORRECT_P1P2();
        }
        if (p2 == 0x1) {
            if (apdu.nc != 8) {
                return SW_WRONG_LENGTH();
            }
            struct tm tm;
            tm.tm_year = get_uint16_t_be(apdu.data) - 1900;
            tm.tm_mon = apdu.data[2];
            tm.tm_mday = apdu.data[3];
            tm.tm_wday = apdu.data[4];
            tm.tm_hour = apdu.data[5];
            tm.tm_min = apdu.data[6];
            tm.tm_sec = apdu.data[7];
            tv_sec = mktime(&tm);
        }
        else if (p2 == 0x2) {
            if (apdu.nc != 4) {
                return SW_WRONG_LENGTH();
            }
            uint32_t t = (apdu.data[0] << 24) | (apdu.data[1] << 16) | (apdu.data[2] << 8) | apdu.data[3];
            tv_sec = (time_t)t;
        }
#ifdef PICO_PLATFORM
        struct timespec tv = {.tv_sec = tv_sec, .tv_nsec = 0};
        aon_timer_set_time(&tv);
#else
        struct timeval tv = {.tv_sec = tv_sec, .tv_usec = 0};
        settimeofday(&tv, NULL);
#endif
        set_rtc = true;
    }
    led_3_blinks();
    return SW_OK();
}

int cmd_read() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p1 == 0x1) { // PHY
#ifndef ENABLE_EMULATION
        uint16_t len = 0;
        int ret = phy_serialize_data(&phy_data, apdu.rdata, &len);
        if (ret != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = len;
#endif
    }
    else if (p1 == 0x2) { // FLASH INFO
        res_APDU_size = 0;
        uint32_t free = flash_free_space(), total = flash_total_space(), used = flash_used_space(), nfiles = flash_num_files(), size = flash_size();
        res_APDU_size += put_uint32_t_be(free, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(used, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(total, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(nfiles, res_APDU + res_APDU_size);
        res_APDU_size += put_uint32_t_be(size, res_APDU + res_APDU_size);
#ifdef PICO_PLATFORM
        uintptr_t start = (uintptr_t) &__flash_binary_start;
        uintptr_t end = (uintptr_t) &__flash_binary_end;
        uint32_t fw_size = (uint32_t)(end - start);
        res_APDU_size += put_uint32_t_be(fw_size, res_APDU + res_APDU_size);
#endif
    }
    else if (p1 == 0x3) { // OTP SECURE BOOT STATUS
        res_APDU_size = 0;
        uint8_t bootkey = 0xFF;
        bool enabled = otp_is_secure_boot_enabled(&bootkey);
        bool locked = otp_is_secure_boot_locked();
        res_APDU[res_APDU_size++] = enabled ? 0x1 : 0x0;
        res_APDU[res_APDU_size++] = locked ? 0x1 : 0x0;
        res_APDU[res_APDU_size++] = bootkey;
    }
    else if (p1 == 0x4) { // GET TIME
        if (p2 != 0x1 && p2 != 0x2) {
            return SW_INCORRECT_P1P2();
        }
        if (!set_rtc) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        res_APDU_size = 0;
#ifdef PICO_PLATFORM
        struct timespec tv;
        aon_timer_get_time(&tv);
#else
        struct timeval tv;
        gettimeofday(&tv, NULL);
#endif
        if (p2 == 0x1) {
            struct tm *tm = localtime(&tv.tv_sec);
            res_APDU_size += put_uint16_t_be(tm->tm_year + 1900, res_APDU);
            res_APDU[res_APDU_size++] = tm->tm_mon;
            res_APDU[res_APDU_size++] = tm->tm_mday;
            res_APDU[res_APDU_size++] = tm->tm_wday;
            res_APDU[res_APDU_size++] = tm->tm_hour;
            res_APDU[res_APDU_size++] = tm->tm_min;
            res_APDU[res_APDU_size++] = tm->tm_sec;
        }
        else if (p2 == 0x2) {
            res_APDU_size += put_uint32_t_be((uint32_t)tv.tv_sec, res_APDU);
        }
    }
    return SW_OK();
}

#if defined(PICO_RP2350) || defined(ESP_PLATFORM)
int cmd_secure() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    uint8_t bootkey = P1(apdu);
    bool secure_lock = P2(apdu) == 0x1;

    int ret = otp_enable_secure_boot(bootkey, secure_lock);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    led_3_blinks();
    return SW_OK();
}
#endif

#ifdef PICO_PLATFORM
int cmd_reboot_bootsel() {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }

    if (P1(apdu) == 0x1) {
        // Reboot to BOOTSEL
        reset_usb_boot(0, 0);
    }
    else if (P1(apdu) == 0x0) {
        // Reboot to normal mode
        watchdog_reboot(0, 0, 100);
    }
    else {
        return SW_INCORRECT_P1P2();
    }

    return SW_OK();
}
#endif

#define INS_KEYDEV_SIGN      0x10
#define INS_WRITE            0x1C
#define INS_SECURE           0x1D
#define INS_READ             0x1E
#define INS_REBOOT_BOOTSEL   0x1F

static const cmd_t cmds[] = {
    { INS_KEYDEV_SIGN, cmd_keydev_sign },
    { INS_WRITE, cmd_write },
#if defined(PICO_RP2350) || defined(ESP_PLATFORM)
    { INS_SECURE, cmd_secure },
#endif
    { INS_READ, cmd_read },
#ifdef PICO_PLATFORM
    { INS_REBOOT_BOOTSEL, cmd_reboot_bootsel },
#endif
    { 0x00, 0x0 }
};

int rescue_process_apdu() {
    if (CLA(apdu) != 0x80) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
