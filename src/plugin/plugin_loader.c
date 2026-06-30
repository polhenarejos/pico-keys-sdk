/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2026 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "picokeys_plugin_api.h"

#include <stddef.h>
#include <stdio.h>

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
           (void *)plugin->hello);
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
    if (!plugin->hello) {
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

static const pk_plugin_header_t *pk_plugin_get_valid(void) {
    const pk_plugin_header_t *plugin = pk_plugin_header();

    printf("Plugin header @ 0x%08lx: magic=0x%08lx abi=%lu header=%lu image=%lu hello=0x%08lx\n",
           (unsigned long)PICOKEYS_PLUGIN_FLASH_BASE,
           (unsigned long)plugin->magic,
           (unsigned long)plugin->abi_version,
           (unsigned long)plugin->header_size,
           (unsigned long)plugin->image_size,
           (unsigned long)(uintptr_t)plugin->hello);
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
    if (!plugin->hello || !pk_plugin_ptr_in_range((const void *)plugin->hello)) {
        printf("Plugin rejected: hello pointer out of range\n");
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

    const pk_plugin_imports_t imports = {
        .abi_version = PICOKEYS_PLUGIN_ABI_VERSION,
        .struct_size = sizeof(imports),
        .printf = printf,
    };
    printf("Calling plugin hello function\n");
    plugin->hello(&imports);
    printf("Plugin hello function returned\n");
}
