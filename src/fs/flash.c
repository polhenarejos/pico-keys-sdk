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


#include <stdint.h>
#include <string.h>
#include "pico_keys.h"

#if !defined(PICO_PLATFORM)
#define XIP_BASE                0
#define FLASH_SECTOR_SIZE       4096
#ifdef ESP_PLATFORM
uint32_t FLASH_SIZE_BYTES = (1 * 1024 * 1024);
#else
#define FLASH_SIZE_BYTES   (8 * 1024 * 1024)
#endif
#else
uint32_t FLASH_SIZE_BYTES = (2 * 1024 * 1024);
#include "pico/stdlib.h"
#include "hardware/flash.h"
#endif
#include "file.h"
#include <stdio.h>

/*
 * ------------------------------------------------------
 * |                                                    |
 * | next_addr | prev_addr | fid | data (len + payload) |
 * |                                                    |
 * ------------------------------------------------------
 */

#define FLASH_DATA_HEADER_SIZE (sizeof(uintptr_t) + sizeof(uint32_t))
#define FLASH_PERMANENT_REGION (4 * FLASH_SECTOR_SIZE) // 4 sectors (16kb) of permanent memory

//To avoid possible future allocations, data region starts at the end of flash and goes upwards to the center region
uintptr_t end_flash, end_rom_pool, start_rom_pool, end_data_pool, start_data_pool;

extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern int flash_program_halfword(uintptr_t addr, uint16_t data);
extern int flash_program_uintptr(uintptr_t, uintptr_t);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);

extern void low_flash_available();

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

uintptr_t allocate_free_addr(uint16_t size, bool persistent) {
    if (size > FLASH_SECTOR_SIZE) {
        return 0x0; //ERROR
    }
    size_t real_size = size + sizeof(uint16_t) + sizeof(uintptr_t) + sizeof(uint16_t) + sizeof(uintptr_t); //len+len size+next address+fid+prev_addr size
    uintptr_t next_base = 0x0, endp = end_data_pool, startp = start_data_pool;
    if (persistent) {
        endp = end_rom_pool;
        startp = start_rom_pool;
    }
    for (uintptr_t base = endp; base >= startp; base = next_base) {
        uintptr_t addr_alg = base & -FLASH_SECTOR_SIZE; //start address of sector
        uintptr_t potential_addr = base - real_size;
        next_base = flash_read_uintptr(base);
        //printf("nb %x %x %x %x\n",base,next_base,addr_alg,potential_addr);
        //printf("fid %x\n",flash_read_uint16(next_base+sizeof(uintptr_t)));
        if (next_base == 0x0) { //we are at the end
            //now we check if we fit in the current sector
            if (addr_alg <= potential_addr) { //it fits in the current sector
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
                flash_program_uintptr(base, potential_addr);
                return potential_addr;
            }
            else if (addr_alg - FLASH_SECTOR_SIZE >= startp) {   //check whether it fits in the next sector, so we take addr_aligned as the base
                potential_addr = addr_alg - real_size;
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
                flash_program_uintptr(base, potential_addr);
                return potential_addr;
            }
            return 0x0;
        }
        //we check if |base-(next_addr+size_next_addr)| > |base-potential_addr| only if fid != 1xxx (not size blocked)
        else if (addr_alg <= potential_addr
            && base - (next_base + flash_read_uint16(next_base + sizeof(uintptr_t) + sizeof(uintptr_t) + sizeof(uint16_t)) + 2 * sizeof(uint16_t) + 2 * sizeof(uintptr_t)) > base - potential_addr
            && (flash_read_uint16(next_base + 2 * sizeof(uintptr_t)) & 0x1000) != 0x1000) {
            flash_program_uintptr(potential_addr, next_base);
            flash_program_uintptr(next_base + sizeof(uintptr_t), potential_addr);
            flash_program_uintptr(potential_addr + sizeof(uintptr_t), base);
            flash_program_uintptr(base, potential_addr);
            return potential_addr;
        }
    }
    return 0x0; //probably never reached
}

int flash_clear_file(file_t *file) {
    if (file == NULL || file->data == NULL) {
        return PICOKEY_OK;
    }
    uintptr_t base_addr = (uintptr_t)(file->data - sizeof(uintptr_t) - sizeof(uint16_t) - sizeof(uintptr_t));
    uintptr_t prev_addr = flash_read_uintptr(base_addr + sizeof(uintptr_t));
    uintptr_t next_addr = flash_read_uintptr(base_addr);
    //printf("nc %lx->%lx   %lx->%lx\n",prev_addr,flash_read_uintptr(prev_addr),base_addr,next_addr);
    flash_program_uintptr(prev_addr, next_addr);
    flash_program_halfword((uintptr_t) file->data, 0);
    if (next_addr > 0) {
        flash_program_uintptr(next_addr + sizeof(uintptr_t), prev_addr);
    }
    flash_program_uintptr(base_addr, 0);
    flash_program_uintptr(base_addr + sizeof(uintptr_t), 0);
    file->data = NULL;
    num_files--;
    //printf("na %lx->%lx\n",prev_addr,flash_read_uintptr(prev_addr));
    return PICOKEY_OK;
}

int flash_write_data_to_file_offset(file_t *file, const uint8_t *data, uint16_t len, uint16_t offset) {
    if (!file) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint16_t size_file_flash = file->data ? flash_read_uint16((uintptr_t) file->data) : 0;
    uint8_t *old_data = NULL;
    if (offset + len > FLASH_SECTOR_SIZE || offset > size_file_flash) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    if (file->data) { //already in flash
        if (offset + len <= size_file_flash) { //it fits, no need to move it
            flash_program_halfword((uintptr_t) file->data, offset + len);
            if (data) {
                flash_program_block((uintptr_t) file->data + sizeof(uint16_t) + offset, data, len);
            }
            return PICOKEY_OK;
        }
        else {   //we clear the old file
            flash_clear_file(file);
            if (offset > 0) {
                old_data = (uint8_t *) calloc(1, offset + len);
                memcpy(old_data, flash_read((uintptr_t) (file->data + sizeof(uint16_t))), offset);
                memcpy(old_data + offset, data, len);
                len = offset + len;
                data = old_data;
            }
        }
    }

    uintptr_t new_addr = allocate_free_addr(len, (file->type & FILE_PERSISTENT) == FILE_PERSISTENT);
    //printf("na %x\n",new_addr);
    if (new_addr == 0x0) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    if (new_addr < last_base) {
        last_base = new_addr;
    }
    file->data = (uint8_t *) new_addr + sizeof(uintptr_t) + sizeof(uint16_t) + sizeof(uintptr_t); //next addr+fid+prev addr
    flash_program_halfword(new_addr + sizeof(uintptr_t) + sizeof(uintptr_t), file->fid);
    flash_program_halfword((uintptr_t) file->data, len);
    if (data) {
        flash_program_block((uintptr_t) file->data + sizeof(uint16_t), data, len);
    }
    if (old_data) {
        free(old_data);
    }
    num_files++;
    return PICOKEY_OK;
}

int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len) {
    return flash_write_data_to_file_offset(file, data, len, 0);
}

uint32_t flash_free_space() {
    return (uint32_t)(last_base - start_data_pool);
}

uint32_t flash_used_space() {
    return (uint32_t)(end_data_pool - last_base);
}

uint32_t flash_total_space() {
    return (uint32_t)(end_data_pool - start_data_pool);
}

uint32_t flash_num_files() {
    return num_files;
}

uint32_t flash_size() {
    return FLASH_SIZE_BYTES;
}
