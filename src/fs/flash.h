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

#ifndef _FLASH_H
#define _FLASH_H

#include <stdint.h>
#include <stdbool.h>

extern uint32_t flash_free_space(void);
extern uint32_t flash_used_space(void);
extern uint32_t flash_total_space(void);
extern uint32_t flash_num_files(void);
extern uint32_t flash_size(void);

extern void flash_set_bounds(uintptr_t start, uintptr_t end);
extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern int flash_program_halfword(uintptr_t addr, uint16_t data);
extern int flash_program_word(uintptr_t addr, uint32_t data);
extern int flash_program_uintptr(uintptr_t addr, uintptr_t data);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t flash_read_uint8(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);
extern int flash_erase_page(uintptr_t addr, size_t page_size);
extern bool flash_check_blank(const uint8_t *p_start, size_t size);
extern void flash_task(void);
extern void low_flash_init(void);
extern void flash_commit(void);

#endif // _FLASH_H
