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

#if !defined(PICO_PLATFORM)
#define XIP_BASE                0
#ifdef ENABLE_EMULATION
#define FLASH_SECTOR_SIZE       0x4000
#else
#define FLASH_SECTOR_SIZE       0x1000
#endif
#ifdef ESP_PLATFORM
uint32_t FLASH_SIZE_BYTES = (1 * 1024 * 1024);
#else
#define FLASH_SIZE_BYTES   (8 * 1024 * 1024)
#endif
#else
uint32_t FLASH_SIZE_BYTES = (2 * 1024 * 1024);
#include "hardware/flash.h"
#endif
#include "file.h"

extern void low_flash_task(void);
extern void low_flash_commit(void);
extern bool low_flash_commit_sync(uint32_t timeout_ms);

/*
 * ------------------------------------------------------
 * |                                                    |
 * | next_addr | prev_addr | fid | len16 | payload       | legacy
 * | next_addr | prev_addr | fid | FFFF  | len32 | data | extended
 * |                                                    |
 * ------------------------------------------------------
 */

#define FLASH_DATA_HEADER_SIZE (sizeof(uintptr_t) + sizeof(uint32_t))
#define FLASH_PERMANENT_REGION (4 * FLASH_SECTOR_SIZE) // 4 sectors (16kb) of permanent memory

//To avoid possible future allocations, data region starts at the end of flash and goes upwards to the center region
uintptr_t end_flash, end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;

uintptr_t last_base;
uint32_t num_files = 0;

void flash_set_bounds(uintptr_t start, uintptr_t end) {
    end_flash = end;
    end_rom_pool = end_flash - FLASH_DATA_HEADER_SIZE - 4;
    start_rom_pool = end_rom_pool - FLASH_PERMANENT_REGION;
    end_data_pool = start_rom_pool - FLASH_DATA_HEADER_SIZE;
    start_data_pool = start;

    last_base = end_data_pool;
}

static size_t flash_record_length_size(uintptr_t base) {
    uintptr_t length_addr = base + 2 * sizeof(uintptr_t) + sizeof(uint16_t);
    return flash_read_uint16(length_addr) == FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
}

static uint32_t flash_record_payload_size(uintptr_t base) {
    uintptr_t length_addr = base + 2 * sizeof(uintptr_t) + sizeof(uint16_t);
    uint16_t length = flash_read_uint16(length_addr);
    return length == FLASH_FILE_EXTENDED_LENGTH ? flash_read_uint32(length_addr + sizeof(uint16_t)) : length;
}

static size_t flash_record_size(uintptr_t base) {
    return 2 * sizeof(uintptr_t) + sizeof(uint16_t) + flash_record_length_size(base) + flash_record_payload_size(base);
}

static uintptr_t allocate_free_addr(uint32_t size, bool persistent) {
    size_t length_size = size >= FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
    size_t overhead = 2 * sizeof(uintptr_t) + sizeof(uint16_t) + length_size;
    size_t real_size = 0;
    uintptr_t next_base = 0x0, endp = end_data_pool, startp = start_data_pool;

    if (size > SIZE_MAX - overhead) {
        return 0x0;
    }
    real_size = overhead + size;
    if (persistent) {
        endp = end_rom_pool;
        startp = start_rom_pool;
    }
    if (real_size > endp - startp) {
        return 0x0;
    }
    for (uintptr_t base = endp; base >= startp; base = next_base) {
        if (base < real_size) {
            return 0x0;
        }
        uintptr_t potential_addr = base - real_size;
        next_base = flash_read_uintptr(base);

        uintptr_t gap_start = startp;
        bool gap_reusable = true;
        if (next_base != 0x0) {
            if (next_base >= base) {
                return 0x0;
            }
            size_t next_size = flash_record_size(next_base);
            if (next_size > base - next_base) {
                return 0x0;
            }
            gap_start = next_base + next_size;
            gap_reusable = (flash_read_uint16(next_base + 2 * sizeof(uintptr_t)) & 0x1000) != 0x1000;
        }

        if (gap_reusable && potential_addr >= gap_start && potential_addr >= startp) {
            flash_program_uintptr(potential_addr, next_base);
            flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
            if (next_base != 0x0) {
                flash_program_uintptr(next_base + sizeof(uintptr_t), potential_addr);
            }
            flash_program_uintptr(base, potential_addr);
            return potential_addr;
        }
        if (next_base == 0x0) {
            break;
        }
    }
    return 0x0;
}

static size_t file_length_size(const file_t *file) {
    return flash_read_uint16((uintptr_t)file->data) == FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
}

static int write_file_length(const file_t *file, uint32_t len) {
    if (len >= FLASH_FILE_EXTENDED_LENGTH) {
        int r = flash_program_halfword((uintptr_t)file->data, FLASH_FILE_EXTENDED_LENGTH);
        if (r != PICOKEYS_OK) {
            return r;
        }
        return flash_program_word((uintptr_t)file->data + sizeof(uint16_t), len);
    }
    return flash_program_halfword((uintptr_t)file->data, (uint16_t)len);
}

static int copy_file_range(const file_t *source, uint32_t source_offset, uintptr_t destination, uint32_t len) {
    uint8_t buffer[256];

    while (len > 0) {
        size_t chunk = MIN(sizeof(buffer), len);
        int r = file_read_at(source, source_offset, buffer, chunk);
        if (r != PICOKEYS_OK) {
            return r;
        }
        r = flash_program_block(destination, buffer, chunk);
        if (r != PICOKEYS_OK) {
            return r;
        }
        source_offset += chunk;
        destination += chunk;
        len -= chunk;
    }
    return PICOKEYS_OK;
}

static int flash_write_data_to_file_internal(file_t *file, const uint8_t *data, uint32_t len, uint32_t offset, bool partial) {
    if (!file || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint32_t old_size = file_get_size(file);
    if (offset > UINT32_MAX - len || (partial && offset > old_size)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint32_t write_end = offset + len;
    uint32_t new_size = partial ? MAX(old_size, write_end) : len;
    bool extended_size = file->data && flash_read_uint16((uintptr_t)file->data) == FLASH_FILE_EXTENDED_LENGTH;

    if (file->data && ((partial && write_end <= old_size) || (!partial && len <= old_size && (extended_size || len < FLASH_FILE_EXTENDED_LENGTH)))) {
        size_t length_size = file_length_size(file);
        int r = PICOKEYS_OK;
        if (!partial) {
            r = extended_size ? flash_program_word((uintptr_t)file->data + sizeof(uint16_t), len) : flash_program_halfword((uintptr_t)file->data, (uint16_t)len);
        }
        if (r == PICOKEYS_OK && len > 0) {
            r = flash_program_block((uintptr_t)file->data + length_size + offset, data, len);
        }
        if (r == PICOKEYS_OK && old_size > FLASH_SECTOR_SIZE && !flash_commit_sync(5000u)) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
        return r;
    }

    file_t old_file = *file;
    bool replacing = old_file.data != NULL;
    uintptr_t new_addr = allocate_free_addr(new_size, (file_get_type(file) & FILE_PERSISTENT) == FILE_PERSISTENT);
    if (new_addr == 0x0) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (new_addr < last_base) {
        last_base = new_addr;
    }

    file_t new_file = {
        .data = (uint8_t *)new_addr + 2 * sizeof(uintptr_t) + sizeof(uint16_t),
        .fid = file->fid
    };
    size_t length_size = new_size >= FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
    uintptr_t payload = (uintptr_t)new_file.data + length_size;
    int r = flash_program_halfword(new_addr + 2 * sizeof(uintptr_t), new_file.fid);

    if (r == PICOKEYS_OK) {
        r = write_file_length(&new_file, new_size);
    }
    num_files++;

    if (r == PICOKEYS_OK && partial && replacing && offset > 0) {
        r = copy_file_range(&old_file, 0, payload, offset);
    }
    if (r == PICOKEYS_OK && len > 0) {
        r = flash_program_block(payload + offset, data, len);
    }
    if (r == PICOKEYS_OK && partial && replacing && write_end < old_size) {
        r = copy_file_range(&old_file, write_end, payload + write_end, old_size - write_end);
    }
    if (r == PICOKEYS_OK && 2 * sizeof(uintptr_t) + sizeof(uint16_t) + length_size + new_size > FLASH_SECTOR_SIZE && !flash_commit_sync(5000u)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        flash_clear_file(&new_file);
        return r;
    }
    if (replacing && flash_clear_file(&old_file) != PICOKEYS_OK) {
        flash_clear_file(&new_file);
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (replacing && 2 * sizeof(uintptr_t) + sizeof(uint16_t) + length_size + new_size > FLASH_SECTOR_SIZE && !flash_commit_sync(5000u)) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    *file = new_file;
    return PICOKEYS_OK;
}

int flash_write_data_to_file(file_t *file, const uint8_t *data, uint32_t len) {
    return flash_write_data_to_file_internal(file, data, len, 0, false);
}

int flash_write_data_to_file_offset(file_t *file, const uint8_t *data, uint32_t len, uint32_t offset) {
    return flash_write_data_to_file_internal(file, data, len, offset, true);
}

uint32_t flash_free_space(void) {
    return (uint32_t)(last_base - start_data_pool);
}

uint32_t flash_used_space(void) {
    return (uint32_t)(end_data_pool - last_base);
}

uint32_t flash_total_space(void) {
    return (uint32_t)(end_data_pool - start_data_pool);
}

uint32_t flash_num_files(void) {
    return num_files;
}

uint32_t flash_size(void) {
    return FLASH_SIZE_BYTES;
}

void flash_task(void) {
    low_flash_task();
}

void flash_commit(void) {
    low_flash_commit();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    return low_flash_commit_sync(timeout_ms);
}
