/* 
 * This file is part of the Pico CCID distribution (https://github.com/polhenarejos/pico-ccid).
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

#include "file.h"
#include "tusb.h"
#include "ccid2040.h"
#include <string.h>

extern const uintptr_t end_data_pool;
extern const uintptr_t start_data_pool;
extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern int flash_program_halfword (uintptr_t addr, uint16_t data);
extern int flash_program_word (uintptr_t addr, uint32_t data);
extern int flash_program_uintptr (uintptr_t addr, uintptr_t data);
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t flash_read_uint8(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);
extern void low_flash_available();

//puts FCI in the RAPDU
void process_fci(const file_t *pe) {
    uint8_t *p = res_APDU;
    uint8_t buf[64];
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0x6f;
    res_APDU[res_APDU_size++] = 0x00; //computed later
    
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 2;
    if (pe->data) {
        if ((pe->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            uint16_t len = ((int (*)(const file_t *, int))(pe->data))(pe, 0);
            res_APDU[res_APDU_size++] = (len >> 8) & 0xff;
            res_APDU[res_APDU_size++] = len & 0xff;
        }
        else {
            res_APDU[res_APDU_size++] = pe->data[1];
            res_APDU[res_APDU_size++] = pe->data[0];
        }
    }
    else {
        memset(res_APDU+res_APDU_size, 0, 2);
        res_APDU_size += 2;
    }
    
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size] = 0;
    if (pe->type == FILE_TYPE_INTERNAL_EF)
        res_APDU[res_APDU_size++] |= 0x08;
    else if (pe->type == FILE_TYPE_WORKING_EF)
        res_APDU[res_APDU_size++] |= pe->ef_structure & 0x7;
    else if (pe->type == FILE_TYPE_DF)
        res_APDU[res_APDU_size++] |= 0x38;
    
    res_APDU[res_APDU_size++] = 0x83;
    res_APDU[res_APDU_size++] = 2;
    put_uint16_t(pe->fid, res_APDU+res_APDU_size);
    res_APDU_size += 2;
    res_APDU[1] = res_APDU_size-2;
}

#define MAX_DYNAMIC_FILES 64
uint16_t dynamic_files = 0;
file_t dynamic_file[MAX_DYNAMIC_FILES];

bool card_terminated = false;

bool is_parent(const file_t *child, const file_t *parent) {
    if (child == parent)
        return true;
    if (child == MF)
        return false;
    return is_parent(&file_entries[child->parent], parent);
}

file_t *get_parent(file_t *f) {
    return &file_entries[f->parent];
}

file_t *search_by_name(uint8_t *name, uint16_t namelen) {
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->name && *p->name == apdu.cmd_apdu_data_len && memcmp(p->name+1, name, namelen) == 0) {
            return p;
        }
    }
    return NULL;
}

file_t *search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->fid != 0x0000 && p->fid == fid) {
            if (!parent || (parent && is_parent(p, parent))) {
                if (!sp || sp == SPECIFY_ANY || (((sp & SPECIFY_EF) && (p->type & FILE_TYPE_INTERNAL_EF)) || ((sp & SPECIFY_DF) && p->type == FILE_TYPE_DF)))
                    return p;
            }
        }
    }
    return NULL;
}

uint8_t make_path_buf(const file_t *pe, uint8_t *buf, uint8_t buflen, const file_t *top) {
    if (!buflen)
        return 0;
    if (pe == top) //MF or relative DF
        return 0;
    put_uint16_t(pe->fid, buf);
    return make_path_buf(&file_entries[pe->parent], buf+2, buflen-2, top)+2;
}

uint8_t make_path(const file_t *pe, const file_t *top, uint8_t *path) {
    uint8_t buf[MAX_DEPTH*2], *p = path;
    put_uint16_t(pe->fid, buf);
    uint8_t depth = make_path_buf(&file_entries[pe->parent], buf+2, sizeof(buf)-2, top)+2;
    for (int d = depth-2; d >= 0; d -= 2) {
        memcpy(p, buf+d, 2);
        p += 2;
    }
    return depth;
}

file_t *search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent) {
    uint8_t path[MAX_DEPTH*2];
    if (pathlen > sizeof(path)) {
        return NULL;
    }
    for (file_t *p = file_entries; p != file_last; p++) {
        uint8_t depth = make_path(p, parent, path);
        if (pathlen == depth && memcmp(path, pe_path, depth) == 0)
            return p;
    }
    return NULL;
}

file_t *currentEF = NULL;
file_t *currentDF = NULL;
const file_t *selected_applet = NULL;
bool isUserAuthenticated = false;

bool authenticate_action(const file_t *ef, uint8_t op) {
    uint8_t acl = ef->acl[op];
    if (acl == 0x0)
        return true;
    else if (acl == 0xff)
        return false;
    else if (acl == 0x90 || acl & 0x9F == 0x10) {
            // PIN required.
        if(isUserAuthenticated) {
            return true;
        } 
        else {
            return false;
        }
    }
    return false;
}

void initialize_chain(file_chain_t **chain) {
    file_chain_t *next;
    for (file_chain_t *f = *chain; f; f = next) {
        next = f->next;
        free(f);
    }
    *chain = NULL;
}

void initialize_flash(bool hard) {
    if (hard) {
        const uint8_t empty[8] = { 0 };
        flash_program_block(end_data_pool, empty, sizeof(empty));
        low_flash_available();
    }
    for (file_t *f = file_entries; f != file_last; f++) {
        if ((f->type & FILE_DATA_FLASH) == FILE_DATA_FLASH)
            f->data = NULL;
    }
    dynamic_files = 0;
}

void scan_flash() {
    initialize_flash(false); //soft initialization
    if (*(uintptr_t *)end_data_pool == 0xffffffff && *(uintptr_t *)(end_data_pool+sizeof(uintptr_t)) == 0xffffffff) 
    {
        printf("First initialization (or corrupted!)\r\n");
        const uint8_t empty[8] = { 0 };
        flash_program_block(end_data_pool, empty, sizeof(empty));
        //low_flash_available();
        //wait_flash_finish();
    }
    printf("SCAN\r\n");

    uintptr_t base = flash_read_uintptr(end_data_pool);
    for (uintptr_t base = flash_read_uintptr(end_data_pool); base >= start_data_pool; base = flash_read_uintptr(base)) {
        if (base == 0x0) //all is empty
            break;
        
        uint16_t fid = flash_read_uint16(base+sizeof(uintptr_t)+sizeof(uintptr_t));
        printf("[%x] scan fid %x, len %d\r\n",base,fid,flash_read_uint16(base+sizeof(uintptr_t)+sizeof(uintptr_t)+sizeof(uint16_t)));
        file_t *file = (file_t *)search_by_fid(fid, NULL, SPECIFY_EF);
        if (file) 
            file->data = (uint8_t *)(base+sizeof(uintptr_t)+sizeof(uintptr_t)+sizeof(uint16_t));
        if (flash_read_uintptr(base) == 0x0) {
            break;
        }
    }
}

uint8_t *file_read(const uint8_t *addr) {
    return flash_read((uintptr_t)addr);
}
uint16_t file_read_uint16(const uint8_t *addr) {
    return flash_read_uint16((uintptr_t)addr);
}
uint8_t file_read_uint8(const uint8_t *addr) {
    return flash_read_uint8((uintptr_t)addr);
}

file_t *search_dynamic_file(uint16_t fid) {
    for (int i = 0; i < dynamic_files; i++) {
        if (dynamic_file[i].fid == fid)
            return &dynamic_file[i];
    }
    return NULL;
}

int delete_dynamic_file(file_t *f) {
    for (int i = 0; i < dynamic_files; i++) {
        if (dynamic_file[i].fid == f->fid) {
            for (int j = i+1; j < dynamic_files; j++)
                memcpy(&dynamic_file[j-1], &dynamic_file[j], sizeof(file_t));
            dynamic_files--;
            return CCID_OK;
        }
    }
    return CCID_ERR_FILE_NOT_FOUND;
}

file_t *file_new(uint16_t fid) {
    file_t *f;
    if ((f = search_dynamic_file(fid)))
        return f;
    if (dynamic_files == MAX_DYNAMIC_FILES)
        return NULL;
    f = &dynamic_file[dynamic_files];
    dynamic_files++;
    file_t file = {
        .fid = fid,
        .parent = 5,
        .name = NULL,
        .type = FILE_TYPE_WORKING_EF,
        .ef_structure = FILE_EF_TRANSPARENT,
        .data = NULL,
        .acl = {0}
    };
    memcpy(f, &file, sizeof(file_t));
    //memset((uint8_t *)f->acl, 0x90, sizeof(f->acl));
    return f;
}

file_chain_t *add_file_to_chain(file_t *file, file_chain_t **chain) {
    if (search_file_chain(file->fid, *chain))
        return NULL;
    file_chain_t *fc = (file_chain_t *)malloc(sizeof(file_chain_t));
    fc->file = file;
    fc->next = *chain;
    *chain = fc;
    return fc;
}

file_t *search_file_chain(uint16_t fid, file_chain_t *chain) {
    for (file_chain_t *fc = chain; fc; fc = fc->next) {
        if (fid == fc->file->fid) {
            return fc->file;
        }
    }
    return NULL;
}