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

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static pk_plugin_imports_t plugin_imports;

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

    plugin_imports = (pk_plugin_imports_t){
        .abi_version = PICOKEYS_PLUGIN_ABI_VERSION,
        .struct_size = sizeof(plugin_imports),
        .printf = printf,
        .signal_add = signal_add,
    };
    plugin->init(&plugin_imports);
}
