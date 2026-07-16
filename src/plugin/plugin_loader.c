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

#include "picokeys_plugin_api.h"
#include "signal.h"

#include "apdu.h"
#include "crypto_utils.h"
#include "file.h"
#include "flash.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/sha256.h"
#include "pico_time.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static pk_plugin_imports_t plugin_imports;
static const pk_plugin_header_t *active_plugin;

_Static_assert(sizeof(pk_plugin_sha256_context_t) >= sizeof(mbedtls_sha256_context),
               "pk_plugin_sha256_context_t too small for mbedtls_sha256_context");

static void pk_plugin_mbedtls_sha256_init(pk_plugin_sha256_context_t *ctx) {
    mbedtls_sha256_init((mbedtls_sha256_context *)ctx);
}

static void pk_plugin_mbedtls_sha256_free(pk_plugin_sha256_context_t *ctx) {
    mbedtls_sha256_free((mbedtls_sha256_context *)ctx);
}

static int pk_plugin_mbedtls_sha256_starts(pk_plugin_sha256_context_t *ctx, int is224) {
    return mbedtls_sha256_starts((mbedtls_sha256_context *)ctx, is224);
}

static int pk_plugin_mbedtls_sha256_update(pk_plugin_sha256_context_t *ctx, const unsigned char *input, size_t ilen) {
    return mbedtls_sha256_update((mbedtls_sha256_context *)ctx, input, ilen);
}

static int pk_plugin_mbedtls_sha256_finish(pk_plugin_sha256_context_t *ctx, unsigned char *output) {
    return mbedtls_sha256_finish((mbedtls_sha256_context *)ctx, output);
}

static int pk_plugin_mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char output[32], int is224) {
    return mbedtls_sha256(input, ilen, output, is224);
}

static int pk_plugin_mbedtls_ct_memcmp(const void *a, const void *b, size_t n) {
    return mbedtls_ct_memcmp(a, b, n);
}

static int pk_plugin_flash_add_page(void *page) {
    return flash_add_page((page_flash_t *)page);
}

static int pk_plugin_has_set_rtc(void) {
    return has_set_rtc() ? 1 : 0;
}

static int64_t pk_plugin_get_rtc_time(void) {
    return (int64_t)get_rtc_time();
}

static uint8_t *pk_plugin_get_res_apdu(void) {
    return apdu.rdata;
}

static uint16_t pk_plugin_get_res_apdu_size(void) {
    return apdu.rlen;
}

static void pk_plugin_set_res_apdu_size(uint16_t size) {
    apdu.rlen = size;
}

static uint8_t pk_plugin_get_apdu_cla(void) {
    return apdu.header ? CLA(apdu) : 0;
}

static uint8_t pk_plugin_get_apdu_ins(void) {
    return apdu.header ? INS(apdu) : 0;
}

static uint8_t pk_plugin_get_apdu_p1(void) {
    return apdu.header ? P1(apdu) : 0;
}

static uint8_t pk_plugin_get_apdu_p2(void) {
    return apdu.header ? P2(apdu) : 0;
}

static const uint8_t *pk_plugin_get_apdu_data(void) {
    return apdu.data;
}

static size_t pk_plugin_get_apdu_data_size(void) {
    return apdu.nc;
}

static void *pk_plugin_file_search(uint16_t fid) {
    return file_search(fid);
}

static void *pk_plugin_file_new(uint16_t fid) {
    return file_new(fid);
}

static int pk_plugin_file_has_data(const void *file) {
    return file_has_data((const file_t *)file) ? 1 : 0;
}

static const uint8_t *pk_plugin_file_get_data(const void *file) {
    return file_get_data((const file_t *)file);
}

static uint16_t pk_plugin_file_get_size(const void *file) {
    return file_get_size((const file_t *)file);
}

static int pk_plugin_file_put_data(void *file, const uint8_t *data, uint16_t len) {
    return file_put_data((file_t *)file, data, len);
}

static int pk_plugin_file_delete(void *file) {
    return file_delete((file_t *)file);
}

static int pk_plugin_has_call(const pk_plugin_header_t *plugin) {
    return plugin &&
           plugin->header_size >= offsetof(pk_plugin_header_t, call) + sizeof(plugin->call) &&
           plugin->call;
}

void pk_plugin_dispatch_event(const pk_plugin_event_t *event) {
    if (event) {
        signal_emit_param(PICOKEYS_PLUGIN_SIGNAL_EVENT, (void *)event);
    }
}

int pk_plugin_call(uint32_t hook, void *data) {
    if (!pk_plugin_has_call(active_plugin)) {
        return PK_PLUGIN_CALL_UNHANDLED;
    }
    return active_plugin->call(hook, data);
}

#ifdef ENABLE_EMULATION
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <stdlib.h>

#ifndef PICOKEYS_EMULATION_PLUGIN_PATH
#define PICOKEYS_EMULATION_PLUGIN_PATH ""
#endif

static const pk_plugin_header_t *pk_plugin_get_valid(void) {
    const char *path = getenv("PICOKEYS_PLUGIN_PATH");
    if (!path || !path[0]) {
        path = PICOKEYS_EMULATION_PLUGIN_PATH;
    }
    if (!path || !path[0]) {
        printf("No plugin path configured\n");
        return NULL;
    }

#ifdef _WIN32
    HMODULE handle = LoadLibraryA(path);
    if (!handle) {
        printf("Plugin LoadLibrary failed: %lu\n", (unsigned long)GetLastError());
        return NULL;
    }

    const pk_plugin_header_t *plugin = (const pk_plugin_header_t *)GetProcAddress(handle, "pk_plugin");
    if (!plugin) {
        printf("Plugin GetProcAddress failed: %lu\n", (unsigned long)GetLastError());
        return NULL;
    }
#else
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        printf("Plugin dlopen failed: %s\n", dlerror());
        return NULL;
    }

    dlerror();
    const pk_plugin_header_t *plugin = (const pk_plugin_header_t *)dlsym(handle, "pk_plugin");
    const char *err = dlerror();
    if (err) {
        printf("Plugin dlsym failed: %s\n", err);
        return NULL;
    }
#endif

    printf("Plugin loaded from %s: magic=0x%08lx abi=%lu header=%lu image=%lu hello=%p\n",
           path,
           (unsigned long)plugin->magic,
           (unsigned long)plugin->abi_version,
           (unsigned long)plugin->header_size,
           (unsigned long)plugin->image_size,
           (void *)plugin->init);
    if (plugin->magic != PICOKEYS_PLUGIN_MAGIC) {
        printf("Plugin rejected: bad magic\n");
        return NULL;
    }
    if (plugin->abi_version != PICOKEYS_PLUGIN_ABI_VERSION) {
        printf("Plugin rejected: bad ABI\n");
        return NULL;
    }
    if (plugin->header_size < sizeof(*plugin)) {
        printf("Plugin rejected: short header\n");
        return NULL;
    }
    if (!plugin->init) {
        printf("Plugin rejected: missing entry point\n");
        return NULL;
    }
    return plugin;
}
#else
static const pk_plugin_header_t *pk_plugin_header(void) {
    return (const pk_plugin_header_t *)(uintptr_t)PICOKEYS_PLUGIN_FLASH_BASE;
}

static int pk_plugin_ptr_in_range(const void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    addr &= ~(uintptr_t)1u;
    return addr >= (uintptr_t)PICOKEYS_PLUGIN_FLASH_BASE &&
           addr < ((uintptr_t)PICOKEYS_PLUGIN_FLASH_BASE + (uintptr_t)PICOKEYS_PLUGIN_FLASH_SIZE);
}

static int pk_plugin_ram_range_valid(uintptr_t start, uint32_t size) {
    uintptr_t ram_base = (uintptr_t)PICOKEYS_PLUGIN_RAM_BASE;
    uintptr_t ram_end = ram_base + (uintptr_t)PICOKEYS_PLUGIN_RAM_SIZE;
    uintptr_t end = start + (uintptr_t)size;

    if (size == 0u) {
        return 1;
    }
    if (end < start) {
        return 0;
    }
    return start >= ram_base && end <= ram_end;
}

static int pk_plugin_flash_range_valid(uintptr_t start, uint32_t size) {
    uintptr_t flash_base = (uintptr_t)PICOKEYS_PLUGIN_FLASH_BASE;
    uintptr_t flash_end = flash_base + (uintptr_t)PICOKEYS_PLUGIN_FLASH_SIZE;
    uintptr_t end = start + (uintptr_t)size;

    if (size == 0u) {
        return 1;
    }
    if (end < start) {
        return 0;
    }
    return start >= flash_base && end <= flash_end;
}

static int pk_plugin_runtime_init(const pk_plugin_header_t *plugin) {
    if (!pk_plugin_ram_range_valid(plugin->data_start, plugin->data_size) ||
        !pk_plugin_ram_range_valid(plugin->bss_start, plugin->bss_size) ||
        !pk_plugin_flash_range_valid(plugin->data_load_start, plugin->data_size)) {
        printf("Plugin rejected: bad RAM image\n");
        return 0;
    }

    if (plugin->data_size != 0u) {
        memcpy((void *)plugin->data_start, (const void *)plugin->data_load_start, plugin->data_size);
    }
    if (plugin->bss_size != 0u) {
        memset((void *)plugin->bss_start, 0, plugin->bss_size);
    }
    return 1;
}

static const pk_plugin_header_t *pk_plugin_get_valid(void) {
    const pk_plugin_header_t *plugin = pk_plugin_header();

    printf("Plugin header @ 0x%08lx: magic=0x%08lx abi=%lu header=%lu image=%lu init=0x%08lx\n",
           (unsigned long)PICOKEYS_PLUGIN_FLASH_BASE,
           (unsigned long)plugin->magic,
           (unsigned long)plugin->abi_version,
           (unsigned long)plugin->header_size,
           (unsigned long)plugin->image_size,
           (unsigned long)(uintptr_t)plugin->init);
    if (plugin->magic != PICOKEYS_PLUGIN_MAGIC) {
        printf("Plugin rejected: bad magic\n");
        return NULL;
    }
    if (plugin->abi_version != PICOKEYS_PLUGIN_ABI_VERSION) {
        printf("Plugin rejected: bad ABI\n");
        return NULL;
    }
    if (plugin->header_size < sizeof(*plugin)) {
        printf("Plugin rejected: short header\n");
        return NULL;
    }
    if (plugin->image_size != 0u &&
        (plugin->image_size < plugin->header_size || plugin->image_size > PICOKEYS_PLUGIN_FLASH_SIZE)) {
        printf("Plugin rejected: bad image size\n");
        return NULL;
    }
    if (!plugin->init || !pk_plugin_ptr_in_range((const void *)plugin->init)) {
        printf("Plugin rejected: init pointer out of range\n");
        return NULL;
    }
    if (plugin->header_size >= offsetof(pk_plugin_header_t, call) + sizeof(plugin->call) &&
        plugin->call && !pk_plugin_ptr_in_range((const void *)plugin->call)) {
        printf("Plugin rejected: call pointer out of range\n");
        return NULL;
    }
    return plugin;
}
#endif

void plugin_init(void) {
    const pk_plugin_header_t *plugin = pk_plugin_get_valid();
    if (!plugin) {
        printf("No valid plugin found\n");
        return;
    }
#ifndef ENABLE_EMULATION
    if (!pk_plugin_runtime_init(plugin)) {
        printf("No valid plugin found\n");
        return;
    }
#endif

    active_plugin = plugin;
    plugin_imports = (pk_plugin_imports_t){
        .abi_version = PICOKEYS_PLUGIN_ABI_VERSION,
        .struct_size = sizeof(plugin_imports),
        .printf = printf,
        .signal_add = signal_add,
        .mbedtls_sha256_init = pk_plugin_mbedtls_sha256_init,
        .mbedtls_sha256_free = pk_plugin_mbedtls_sha256_free,
        .mbedtls_sha256_starts = pk_plugin_mbedtls_sha256_starts,
        .mbedtls_sha256_update = pk_plugin_mbedtls_sha256_update,
        .mbedtls_sha256_finish = pk_plugin_mbedtls_sha256_finish,
        .mbedtls_sha256 = pk_plugin_mbedtls_sha256,
        .mbedtls_ct_memcmp = pk_plugin_mbedtls_ct_memcmp,
        .memcpy = memcpy,
        .memset = memset,
        .flash_add_page = pk_plugin_flash_add_page,
        .flash_commit = flash_commit,
        .flash_read = flash_read,
        .has_set_rtc = pk_plugin_has_set_rtc,
        .get_rtc_time = pk_plugin_get_rtc_time,
        .pin_derive_verifier = pin_derive_verifier,
        .get_res_apdu = pk_plugin_get_res_apdu,
        .get_res_apdu_size = pk_plugin_get_res_apdu_size,
        .set_res_apdu_size = pk_plugin_set_res_apdu_size,
        .get_apdu_cla = pk_plugin_get_apdu_cla,
        .get_apdu_ins = pk_plugin_get_apdu_ins,
        .get_apdu_p1 = pk_plugin_get_apdu_p1,
        .get_apdu_p2 = pk_plugin_get_apdu_p2,
        .get_apdu_data = pk_plugin_get_apdu_data,
        .get_apdu_data_size = pk_plugin_get_apdu_data_size,
        .set_res_sw = set_res_sw,
        .file_search = pk_plugin_file_search,
        .file_new = pk_plugin_file_new,
        .file_has_data = pk_plugin_file_has_data,
        .file_get_data = pk_plugin_file_get_data,
        .file_get_size = pk_plugin_file_get_size,
        .file_put_data = pk_plugin_file_put_data,
        .file_delete = pk_plugin_file_delete,
    };
    plugin->init(&plugin_imports);
}
