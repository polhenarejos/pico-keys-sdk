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


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pico_keys.h"
#include <string.h>
#ifdef PICO_PLATFORM
 #include "pico/stdlib.h"
 #include "hardware/flash.h"
 #include "hardware/sync.h"
 #include "pico/mutex.h"
 #include "pico/sem.h"
 #include "pico/multicore.h"
 #include "pico/bootrom.h"
 #include "boot/picobin.h"
#else
 #ifdef _MSC_VER
  #include <windows.h>
  #include <io.h>
  #define O_RDWR _O_RDWR
  #define O_CREAT _O_CREAT
  #define open _open
  #define write _write
  #define mode_t unsigned short
  #define lseek _lseek
  #include "mman.h"
 #else
  #ifdef ESP_PLATFORM
   #include "esp_compat.h"
   #include "esp_partition.h"
   const esp_partition_t *part0;
   #define save_and_disable_interrupts() 1
   #define flash_range_erase(a,b) esp_partition_erase_range(part0, a, b)
   #define flash_range_program(a,b,c) esp_partition_write(part0, a, b, c);
   #define restore_interrupts(a) (void)a
  #else
   #include <unistd.h>
   #include <sys/mman.h>
   #include "emulation.h"
  #endif
 #endif
 #define FLASH_SECTOR_SIZE       4096
 #ifdef ESP_PLATFORM
 extern uint32_t PICO_FLASH_SIZE_BYTES;
 #else
 #define PICO_FLASH_SIZE_BYTES   (8 * 1024 * 1024)
 #endif
 #define XIP_BASE 0
 int fd_map = 0;
 uint8_t *map = NULL;
 #include <fcntl.h>
#endif

#define TOTAL_FLASH_PAGES 6

extern void flash_set_bounds(uintptr_t start, uintptr_t end);

extern const uintptr_t start_data_pool;
extern const uintptr_t end_rom_pool;

typedef struct page_flash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
    size_t page_size; //this param is for easy erase. It allows to erase with a single call. IT DOES NOT APPLY TO WRITE
} page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;
static semaphore_t sem_flash;

#ifndef ENABLE_EMULATION
static bool locked_out = false;
#else
static bool locked_out = true;
#endif

static uint8_t ready_pages = 0;

bool flash_available = false;


//this function has to be called from the core 0
void do_flash() {
    if (mutex_try_enter(&mtx_flash, NULL) == true) {
        if (locked_out == true && flash_available == true && ready_pages > 0) {
            //printf(" DO_FLASH AVAILABLE\n");
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
                if (flash_pages[r].ready == true) {
#ifndef ENABLE_EMULATION
                    //printf("WRITTING %X\n",flash_pages[r].address-XIP_BASE);
                    while (multicore_lockout_start_timeout_us(1000) == false) {
                        ;
                    }
                    //printf("WRITTING %X\n",flash_pages[r].address-XIP_BASE);
                    uint32_t ints = save_and_disable_interrupts();
                    flash_range_erase(flash_pages[r].address - XIP_BASE, FLASH_SECTOR_SIZE);
                    flash_range_program(flash_pages[r].address - XIP_BASE, flash_pages[r].page, FLASH_SECTOR_SIZE);
                    restore_interrupts(ints);
                    while (multicore_lockout_end_timeout_us(1000) == false) {
                        ;
                    }
                    //printf("WRITEN %X !\n",flash_pages[r].address);
#else
                    memcpy(map + flash_pages[r].address, flash_pages[r].page, FLASH_SECTOR_SIZE);
#endif
                    flash_pages[r].ready = false;
                    ready_pages--;
                }
                else if (flash_pages[r].erase == true) {
#ifndef ENABLE_EMULATION
                    while (multicore_lockout_start_timeout_us(1000) == false) {
                        ;
                    }
                    //printf("WRITTING\n");
                    flash_range_erase(flash_pages[r].address - XIP_BASE, flash_pages[r].page_size ? ((int) (flash_pages[r].page_size / FLASH_SECTOR_SIZE)) * FLASH_SECTOR_SIZE : FLASH_SECTOR_SIZE);
                    while (multicore_lockout_end_timeout_us(1000) == false) {
                        ;
                    }
#else
                    memset(map + flash_pages[r].address, 0, FLASH_SECTOR_SIZE);
#endif
                    flash_pages[r].erase = false;
                    ready_pages--;
                }
            }
#ifdef ENABLE_EMULATION
            msync(map, PICO_FLASH_SIZE_BYTES, MS_SYNC);
#endif
            if (ready_pages != 0) {
                printf("ERROR: DO FLASH DOES NOT HAVE ZERO PAGES\n");
            }
        }
        flash_available = false;
#ifdef ESP_PLATFORM
        esp_partition_munmap(fd_map);
        esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
#endif
        mutex_exit(&mtx_flash);
    }
    sem_release(&sem_flash);
}

//this function has to be called from the core 0
void low_flash_init() {
    memset(flash_pages, 0, sizeof(page_flash_t) * TOTAL_FLASH_PAGES);
    mutex_init(&mtx_flash);
    sem_init(&sem_flash, 0, 1);

    uint32_t data_start_addr;
    uint32_t data_end_addr;
#if defined(ENABLE_EMULATION)
    fd_map = open("memory.flash", O_RDWR | O_CREAT, (mode_t) 0600);
    lseek(fd_map, PICO_FLASH_SIZE_BYTES - 1, SEEK_SET);
    write(fd_map, "", 1);
    map = mmap(0, PICO_FLASH_SIZE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map, 0);
    data_start_addr = 0;
    data_end_addr = PICO_FLASH_SIZE_BYTES;
#elif defined(ESP_PLATFORM)
    part0 = esp_partition_find_first(0x40, 0x1, "part0");
    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);
    data_start_addr = 0;
    data_end_addr = part0->size;
    PICO_FLASH_SIZE_BYTES = part0->size;
#elif defined(PICO_PLATFORM)
#ifdef PICO_RP2350
    __attribute__((aligned(4))) uint8_t workarea[4 * 1024];
    int rc = rom_load_partition_table(workarea, sizeof(workarea), false);
    if (rc) {
        reset_usb_boot(0, 0);
    }

    uint8_t boot_partition = 1;
    rc = rom_get_partition_table_info((uint32_t*)workarea, 0x8, PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION | (boot_partition << 24));

    if (rc != 3) {
        data_start_addr = (PICO_FLASH_SIZE_BYTES >> 1);
        data_end_addr = PICO_FLASH_SIZE_BYTES;
    } else {
        uint16_t first_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        uint16_t last_sector_number = (((uint32_t*)workarea)[1] & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
        data_start_addr = first_sector_number * FLASH_SECTOR_SIZE;
        data_end_addr = (last_sector_number + 1) * FLASH_SECTOR_SIZE;
    }
    data_end_addr -= 2 * FLASH_SECTOR_SIZE;
#else
    data_start_addr = (PICO_FLASH_SIZE_BYTES >> 1);
    data_end_addr = PICO_FLASH_SIZE_BYTES;
#endif

    data_start_addr += XIP_BASE;
    data_end_addr += XIP_BASE;
#endif
    flash_set_bounds(data_start_addr, data_end_addr);
}

void low_flash_init_core1() {
    mutex_enter_blocking(&mtx_flash);
    multicore_lockout_victim_init();
    locked_out = true;
    mutex_exit(&mtx_flash);
}

void wait_flash_finish() {
    sem_acquire_blocking(&sem_flash); //blocks until released
    //wake up
    sem_acquire_blocking(&sem_flash); //decrease permits
}

void low_flash_available() {
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    page_flash_t *p = NULL;
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if ((!flash_pages[r].ready && !flash_pages[r].erase) ||
            flash_pages[r].address == addr_alg) {                                                   //first available
            p = &flash_pages[r];
            if (!flash_pages[r].ready && !flash_pages[r].erase) {
#ifdef PICO_PLATFORM
                memcpy(p->page, (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
#else
                memcpy(p->page, (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) ? (uint8_t *) (map + addr_alg) : (uint8_t *) addr_alg, FLASH_SECTOR_SIZE);
#endif
                ready_pages++;
                p->address = addr_alg;
                p->ready = true;
            }
            return p;
        }
    }
    return NULL;
}

int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len) {
    page_flash_t *p = NULL;

    if (!data || len == 0) {
        return PICOKEY_ERR_NULL_PARAM;
    }

    mutex_enter_blocking(&mtx_flash);
    if (ready_pages == TOTAL_FLASH_PAGES) {
        mutex_exit(&mtx_flash);
        printf("ERROR: ALL FLASH PAGES CACHED\n");
        return PICOKEY_ERR_NO_MEMORY;
    }
    if (!(p = find_free_page(addr))) {
        mutex_exit(&mtx_flash);
        printf("ERROR: FLASH CANNOT FIND A PAGE (rare error)\n");
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    memcpy(&p->page[addr & (FLASH_SECTOR_SIZE - 1)], data, len);
    //printf("Flash: modified page %X with data %x at [%x]\n",(uintptr_t)addr,(uintptr_t)data,addr&(FLASH_SECTOR_SIZE-1));
    mutex_exit(&mtx_flash);
    return PICOKEY_OK;
}

int flash_program_halfword(uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, (const uint8_t *) &data, sizeof(uint16_t));
}

int flash_program_word(uintptr_t addr, uint32_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uint32_t));
}

int flash_program_uintptr(uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr,  (const uint8_t *) &data, sizeof(uintptr_t));
}

uint8_t *flash_read(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr & (FLASH_SECTOR_SIZE - 1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    uint8_t *v = (uint8_t *) addr;
    mutex_exit(&mtx_flash);
#if defined(ENABLE_EMULATION) || defined(ESP_PLATFORM)
    if (addr >= start_data_pool && addr <= end_rom_pool + sizeof(uintptr_t)) {
        v += (uintptr_t) map;
    }
#endif
    return v;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uintptr_t v = 0x0;
    for (int i = 0; i < sizeof(uintptr_t); i++) {
        v |= (uintptr_t) p[i] << (8 * i);
    }
    return v;
}
uint16_t flash_read_uint16(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uint16_t v = 0x0;
    for (int i = 0; i < sizeof(uint16_t); i++) {
        v |= p[i] << (8 * i);
    }
    return v;
}
uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page(uintptr_t addr, size_t page_size) {
    page_flash_t *p = NULL;

    mutex_enter_blocking(&mtx_flash);
    if (ready_pages == TOTAL_FLASH_PAGES) {
        mutex_exit(&mtx_flash);
        printf("ERROR: ALL FLASH PAGES CACHED\n");
        return PICOKEY_ERR_NO_MEMORY;
    }
    if (!(p = find_free_page(addr))) {
        printf("ERROR: FLASH CANNOT FIND A PAGE (rare error)\n");
        mutex_exit(&mtx_flash);
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    p->erase = true;
    p->ready = false;
    p->page_size = page_size;
    mutex_exit(&mtx_flash);

    return PICOKEY_OK;
}

bool flash_check_blank(const uint8_t *p_start, size_t size) {
    const uint8_t *p;

    for (p = p_start; p < p_start + size; p++) {
        if (*p != 0xff) {
            return false;
        }
    }
    return true;
}
