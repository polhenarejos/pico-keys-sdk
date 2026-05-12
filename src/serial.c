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
#include "serial.h"
#include "mbedtls/sha256.h"
#if defined(ESP_PLATFORM)
#include "esp_efuse.h"
#endif
#include <stdio.h>
#include <string.h>
#ifndef ESP_PLATFORM
#include <time.h>
#endif

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

static int get_macos_serial(uint8_t *out) {
    io_service_t platformExpert;
    CFTypeRef serialNumberAsCFString;
    char serial[32] = {0};
    if (!out) {
        return -1;
    }
    out[0] = '\0';
    platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!platformExpert) {
        return -2;
    }
    serialNumberAsCFString = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
    IOObjectRelease(platformExpert);
    if (!serialNumberAsCFString) {
        return -3;
    }
    Boolean ok = CFStringGetCString(serialNumberAsCFString, serial, sizeof(serial), kCFStringEncodingUTF8);
    CFRelease(serialNumberAsCFString);
    if (ok) {
        mbedtls_sha256((const unsigned char *)serial, strlen(serial), pico_serial_hash, false);
        memcpy(out, pico_serial_hash, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    }
    return ok ? 0 : -4;
}
#elif defined(_MSC_VER)
#include <windows.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

static int get_system_uuid(char *out) {
    char serial[64] = {0};
    HRESULT hr;
    IWbemLocator *locator = NULL;
    IWbemServices *svc = NULL;
    IEnumWbemClassObject *enumerator = NULL;
    IWbemClassObject *obj = NULL;
    ULONG returned = 0;
    VARIANT vtProp;
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
        return -1;
    hr = CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        CoUninitialize();
        return -2;
    }
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *)&locator);
    if (FAILED(hr)) {
        CoUninitialize();
        return -3;
    }
    hr = locator->lpVtbl->ConnectServer(locator, L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &svc);
    if (FAILED(hr)) {
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return -4;
    }
    hr = CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        svc->lpVtbl->Release(svc);
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return -5;
    }
    hr = svc->lpVtbl->ExecQuery(svc, L"WQL", L"SELECT UUID FROM Win32_ComputerSystemProduct", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &enumerator);
    if (FAILED(hr) || !enumerator) {
        svc->lpVtbl->Release(svc);
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return -6;
    }
    hr = enumerator->lpVtbl->Next( enumerator, WBEM_INFINITE, 1, &obj, &returned);
    if (returned == 0 || !obj) {
        enumerator->lpVtbl->Release(enumerator);
        svc->lpVtbl->Release(svc);
        locator->lpVtbl->Release(locator);
        CoUninitialize();
        return -7;
    }
    VariantInit(&vtProp);
    hr = obj->lpVtbl->Get(obj, L"UUID", 0, &vtProp, NULL, NULL);
    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
        WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, serial, (int)sizeof(serial), NULL, NULL);
    }
    VariantClear(&vtProp);
    obj->lpVtbl->Release(obj);
    enumerator->lpVtbl->Release(enumerator);
    svc->lpVtbl->Release(svc);
    locator->lpVtbl->Release(locator);
    CoUninitialize();
    if (serial[0]) {
        mbedtls_sha256((const unsigned char *)serial, strlen(serial), pico_serial_hash, false);
        memcpy(out, pico_serial_hash, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    }
    return serial[0] ? 0 : -8;
}
#elif defined(__linux__)
#include <string.h>
#include <ctype.h>

static int read_first_line(const char *path, char *out, size_t out_len) {
    FILE *f;
    if (!out || out_len == 0) {
        return -1;
    }
    out[0] = '\0';
    f = fopen(path, "r");
    if (!f) {
        return -2;
    }
    if (!fgets(out, out_len, f)) {
        fclose(f);
        return -3;
    }
    fclose(f);
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] ? 0 : -4;
}

static int is_bad_value(const char *s) {
    if (!s || !s[0])
        return 1;
    if (strcasecmp(s, "None") == 0)
        return 1;
    if (strcasecmp(s, "Unknown") == 0)
        return 1;
    if (strcasecmp(s, "Default string") == 0)
        return 1;
    if (strcasecmp(s, "To be filled by O.E.M.") == 0)
        return 1;
    if (strcmp(s, "00000000-0000-0000-0000-000000000000") == 0)
        return 1;
    if (strcmp(s, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") == 0)
        return 1;
    return 0;
}

static int append_field(char *out, size_t out_len, const char *prefix,const char *path) {
    char value[256];
    if (read_first_line(path, value, sizeof(value)) != 0) {
        return -1;
    }
    if (is_bad_value(value)) {
        return -2;
    }
    strncat(out, prefix, out_len - strlen(out) - 1);
    strncat(out, value, out_len - strlen(out) - 1);
    strncat(out, ";", out_len - strlen(out) - 1);
    return 0;
}

static int get_linux_hardware_id(char *out) {
    if (!out) {
        return -1;
    }
    char serial[256] = {0};
    append_field(serial, sizeof(serial), "UUID=", "/sys/class/dmi/id/product_uuid");
    append_field(serial, sizeof(serial), "BOARD=", "/sys/class/dmi/id/board_serial");
    append_field(serial, sizeof(serial), "PRODUCT=", "/sys/class/dmi/id/product_serial");
    append_field(serial, sizeof(serial), "CHASSIS=", "/sys/class/dmi/id/chassis_serial");
    append_field(serial, sizeof(serial), "MACHINE=", "/etc/machine-id");
    if (serial[0]) {
        mbedtls_sha256((const unsigned char *)serial, strlen(serial), pico_serial_hash, false);
        memcpy(out, pico_serial_hash, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    }
    return serial[0] ? 0 : -2;
}
#endif

char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
uint8_t pico_serial_hash[32];
picokey_serial_t pico_serial;

static int serial_id_is_zero(const uint8_t *id, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (id[i] != 0) {
            return 0;
        }
    }
    return 1;
}

#if defined(ESP_PLATFORM)
#define pico_get_unique_board_id(a) do { uint32_t value; esp_efuse_read_block(EFUSE_BLK1, &value, 0, 32); memcpy((uint8_t *)(a), &value, sizeof(uint32_t)); esp_efuse_read_block(EFUSE_BLK1, &value, 32, 32); memcpy((uint8_t *)(a)+4, &value, sizeof(uint32_t)); } while(0)
#elif defined(__APPLE__)
#define pico_get_unique_board_id(a) get_macos_serial((uint8_t *)(a))
#elif defined(_MSC_VER)
#define pico_get_unique_board_id(a) get_system_uuid((char *)(a))
#elif defined(__linux__)
#define pico_get_unique_board_id(a) get_linux_hardware_id((char *)(a))
#endif

void serial_init(void) {
    int serial_rc = 0;

#if defined(__APPLE__) || defined(_MSC_VER) || defined(__linux__)
    serial_rc = pico_get_unique_board_id(&pico_serial);
#else
    pico_get_unique_board_id(&pico_serial);
#endif

    if (serial_rc != 0 || serial_id_is_zero(pico_serial.id, sizeof(pico_serial.id))) {
        printf("serial init: failed to read stable hardware id (rc=%d); using fallback id\n", serial_rc);
        memset(pico_serial.id, 0, sizeof(pico_serial.id));
    }

    memset(pico_serial_str, 0, sizeof(pico_serial_str));
    for (size_t i = 0; i < sizeof(pico_serial); i++) {
        snprintf(&pico_serial_str[2 * i], 3, "%02X", pico_serial.id[i]);
    }
    mbedtls_sha256(pico_serial.id, sizeof(pico_serial.id), pico_serial_hash, false);
}
