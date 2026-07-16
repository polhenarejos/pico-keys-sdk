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
#include "picokeys.h"
#include "otp.h"
#include "otp_platform.h"

#include "random.h"
#include "mbedtls/ecdsa.h"

#include "esp_efuse.h"
#include "esp_efuse_table.h"

#define OTP_KEY_1    EFUSE_BLK_KEY3
#define OTP_KEY_2    EFUSE_BLK_KEY4

uint8_t _otp_key_1[32] = {0};
uint8_t _otp_key_2[32] = {0};

static const uint8_t esp_secure_boot_digest[32] = {
    0x0c, 0x1e, 0xce, 0xf3, 0xb4, 0x8f, 0x4a, 0x81,
    0x45, 0x6c, 0x85, 0x39, 0x15, 0xcc, 0x05, 0x36,
    0xbe, 0x23, 0x24, 0xee, 0xac, 0x8e, 0x3b, 0xb5,
    0x77, 0x6f, 0x2d, 0xb9, 0x62, 0x38, 0x75, 0x6a
};

#ifndef SECURE_BOOT_BOOTKEY_INDEX
#define SECURE_BOOT_BOOTKEY_INDEX 0
#endif
#ifndef PICOKEYS_REQUIRE_SECURE_BOOT_BEFORE_LOCK
#define PICOKEYS_REQUIRE_SECURE_BOOT_BEFORE_LOCK 1
#endif

static esp_efuse_purpose_t esp_secure_boot_purpose(uint8_t digest_idx) {
    switch (digest_idx) {
        case 0: return ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0;
        case 1: return ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1;
        case 2: return ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2;
        default: return ESP_EFUSE_KEY_PURPOSE_MAX;
    }
}

static bool esp_find_secure_boot_block(uint8_t digest_idx, esp_efuse_block_t *out_block) {
    esp_efuse_purpose_t purpose = esp_secure_boot_purpose(digest_idx);
    if (purpose == ESP_EFUSE_KEY_PURPOSE_MAX) {
        return false;
    }
    for (esp_efuse_block_t blk = EFUSE_BLK_KEY0; blk < EFUSE_BLK_KEY_MAX; blk++) {
        if (esp_efuse_get_key_purpose(blk) == purpose) {
            if (out_block) {
                *out_block = blk;
            }
            return true;
        }
    }
    return false;
}

static esp_err_t esp_provision_secure_boot_digest(uint8_t digest_idx, esp_efuse_block_t *out_block) {
    esp_efuse_purpose_t purpose = esp_secure_boot_purpose(digest_idx);
    if (purpose == ESP_EFUSE_KEY_PURPOSE_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_efuse_block_t block = EFUSE_BLK_KEY_MAX;
    if (esp_find_secure_boot_block(digest_idx, &block)) {
        const esp_efuse_desc_t **key_desc = esp_efuse_get_key(block);
        if (!key_desc) {
            return ESP_FAIL;
        }
        uint8_t existing[32] = {0};
        esp_err_t err = esp_efuse_read_field_blob(key_desc, existing, sizeof(existing) * 8);
        if (err != ESP_OK) {
            return err;
        }
        if (memcmp(existing, esp_secure_boot_digest, sizeof(existing)) != 0) {
            return ESP_ERR_INVALID_STATE;
        }
        if (out_block) {
            *out_block = block;
        }
        return ESP_OK;
    }

    block = esp_efuse_find_unused_key_block();
    if (block == EFUSE_BLK_KEY_MAX) {
        return ESP_ERR_NOT_FOUND;
    }

    esp_err_t err = esp_efuse_batch_write_begin();
    if (err != ESP_OK) {
        return err;
    }

    err = esp_efuse_set_key_purpose(block, purpose);
    if (err == ESP_OK) {
        const esp_efuse_desc_t **key_desc = esp_efuse_get_key(block);
        if (!key_desc) {
            err = ESP_FAIL;
        } else {
            err = esp_efuse_write_field_blob(key_desc, esp_secure_boot_digest, sizeof(esp_secure_boot_digest) * 8);
        }
    }

    if (err == ESP_OK) {
        err = esp_efuse_batch_write_commit();
    } else {
        esp_efuse_batch_write_cancel();
    }

    if (err == ESP_OK && out_block) {
        *out_block = block;
    }
    return err;
}

static esp_err_t esp_disable_debug_interfaces(void) {
    esp_err_t err = ESP_OK;

#ifdef ESP_EFUSE_SOFT_DIS_JTAG
    err = esp_efuse_write_field_bit(ESP_EFUSE_SOFT_DIS_JTAG);
    if (err != ESP_OK) {
        return err;
    }
#endif
#ifdef ESP_EFUSE_HARD_DIS_JTAG
    err = esp_efuse_write_field_bit(ESP_EFUSE_HARD_DIS_JTAG);
    if (err != ESP_OK) {
        return err;
    }
#endif
#ifdef ESP_EFUSE_DIS_USB_JTAG
    err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_USB_JTAG);
    if (err != ESP_OK) {
        return err;
    }
#endif
#ifdef ESP_EFUSE_DIS_USB_SERIAL_JTAG
    err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_USB_SERIAL_JTAG);
    if (err != ESP_OK) {
        return err;
    }
#endif
#ifdef ESP_EFUSE_DIS_PAD_JTAG
    err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_PAD_JTAG);
    if (err != ESP_OK) {
        return err;
    }
#endif

    return err;
}

static esp_err_t read_key_from_efuse(esp_efuse_block_t block, uint8_t *key, size_t key_len) {
    const esp_efuse_desc_t **key_desc = esp_efuse_get_key(block);
    if (!key_desc) {
        return ESP_FAIL;
    }
    return esp_efuse_read_field_blob(key_desc, key, key_len * 8);
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    if (!esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)) {
        return false;
    }

    uint8_t preferred = SECURE_BOOT_BOOTKEY_INDEX;
    if (preferred <= 2 && esp_find_secure_boot_block(preferred, NULL)
        && !esp_efuse_get_digest_revoke(preferred)) {
        if (bootkey) {
            *bootkey = preferred;
        }
        return true;
    }

    for (uint8_t idx = 0; idx <= 2; idx++) {
        if (esp_find_secure_boot_block(idx, NULL) && !esp_efuse_get_digest_revoke(idx)) {
            if (bootkey) {
                *bootkey = idx;
            }
            return true;
        }
    }
    return false;
}

bool otp_platform_is_secure_boot_locked(void) {
    uint8_t bootkey_idx = 0xFF;
    if (!otp_platform_is_secure_boot_enabled(&bootkey_idx)) {
        return false;
    }

    for (uint8_t idx = 0; idx <= 2; idx++) {
        if (idx == bootkey_idx) {
            continue;
        }
        if (!esp_efuse_get_digest_revoke(idx)) {
            return false;
        }
    }
    return true;
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    if (bootkey > 2) {
        return ESP_ERR_INVALID_ARG;
    }

    if (secure_lock && PICOKEYS_REQUIRE_SECURE_BOOT_BEFORE_LOCK && !esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)) {
        printf("Secure lock requires SECURE_BOOT_EN already set. Enable secure boot first.\n");
        return ESP_ERR_INVALID_STATE;
    }

    esp_efuse_block_t key_block = EFUSE_BLK_KEY_MAX;
    esp_err_t err = esp_provision_secure_boot_digest(bootkey, &key_block);
    if (err != ESP_OK) {
        printf("Error provisioning secure boot digest %u [%d]\n", bootkey, err);
        return err;
    }

    if (!esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)) {
        err = esp_efuse_write_field_bit(ESP_EFUSE_SECURE_BOOT_EN);
        if (err != ESP_OK) {
            printf("Error enabling secure boot [%d]\n", err);
            return err;
        }
    }

    if (secure_lock) {
        for (uint8_t idx = 0; idx <= 2; idx++) {
            if (idx == bootkey) {
                continue;
            }
            err = esp_efuse_set_digest_revoke(idx);
            if (err != ESP_OK) {
                printf("Error revoking secure boot digest %u [%d]\n", idx, err);
                return err;
            }
        }

        err = esp_efuse_set_key_dis_write(key_block);
        if (err != ESP_OK) {
            printf("Error setting secure boot key block read only [%d]\n", err);
            return err;
        }
        err = esp_efuse_set_keypurpose_dis_write(key_block);
        if (err != ESP_OK) {
            printf("Error setting secure boot key purpose read only [%d]\n", err);
            return err;
        }

        /* // Not sure if it allows future upgrades if ROM download mode is disabled, so leaving it enabled for now
        err = esp_efuse_disable_rom_download_mode();
        if (err != ESP_OK) {
            printf("Error disabling ROM download mode [%d]\n", err);
            return err;
        }
        */

        err = esp_disable_debug_interfaces();
        if (err != ESP_OK) {
            printf("Error disabling JTAG interfaces [%d]\n", err);
            return err;
        }
    }

    return PICOKEYS_OK;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    esp_err_t ret = 0;
    uint16_t write_otp[2] = {0xFFFF, 0xFFFF};

    if (esp_efuse_key_block_unused(OTP_KEY_1)) {
        uint8_t mkek[32] = {0};
        random_fill_buffer(mkek, sizeof(mkek));
        ret = esp_efuse_write_key(OTP_KEY_1, ESP_EFUSE_KEY_PURPOSE_USER, mkek, sizeof(mkek));
        if (ret != 0) {
            printf("Error writing OTP key 1 [%d]\n", ret);
        }
        mbedtls_platform_zeroize(mkek, sizeof(mkek));
        write_otp[0] = OTP_KEY_1;
    }
    ret = read_key_from_efuse(OTP_KEY_1, _otp_key_1, sizeof(_otp_key_1));
    if (ret != ESP_OK) {
        printf("Error reading OTP key 1 [%d]\n", ret);
    }
    *otp_key_1_out = _otp_key_1;

    if (esp_efuse_key_block_unused(OTP_KEY_2)) {
        mbedtls_ecdsa_context ecdsa;
        size_t olen = 0;
        uint8_t pkey[MBEDTLS_ECP_MAX_BYTES];
        while (olen != 32) {
            mbedtls_ecdsa_init(&ecdsa);
            mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256K1;
            mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_fill_iterator, NULL);
            mbedtls_ecp_write_key_ext(&ecdsa, &olen, pkey, sizeof(pkey));
            mbedtls_ecdsa_free(&ecdsa);
        }
        ret = esp_efuse_write_key(OTP_KEY_2, ESP_EFUSE_KEY_PURPOSE_USER, pkey, olen);
        if (ret != 0) {
            printf("Error writing OTP key 2 [%d]\n", ret);
        }
        mbedtls_platform_zeroize(pkey, sizeof(pkey));
        write_otp[1] = OTP_KEY_2;
    }
    ret = read_key_from_efuse(OTP_KEY_2, _otp_key_2, sizeof(_otp_key_2));
    if (ret != ESP_OK) {
        printf("Error reading OTP key 2 [%d]\n", ret);
    }
    *otp_key_2_out = _otp_key_2;

    for (size_t i = 0; i < sizeof(write_otp) / sizeof(write_otp[0]); i++) {
        if (write_otp[i] != 0xFFFF) {
            ret = esp_efuse_set_key_dis_write(write_otp[i]);
            if (ret != ESP_OK) {
                printf("Error setting OTP key %d to read only [%d]\n", i, ret);
            }
            ret = esp_efuse_set_keypurpose_dis_write(write_otp[i]);
            if (ret != ESP_OK) {
                printf("Error setting OTP key %d purpose to read only [%d]\n", i, ret);
            }
        }
    }
}
