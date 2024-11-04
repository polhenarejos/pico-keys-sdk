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

#include "file.h"
#include "pico_keys.h"
#include <string.h>
#include <stdio.h>
#include "asn1.h"
#include "apdu.h"

extern const uintptr_t end_data_pool;
extern const uintptr_t start_data_pool;
extern const uintptr_t end_rom_pool;
extern const uintptr_t start_rom_pool;
extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern uint8_t flash_read_uint8(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);
extern int flash_clear_file(file_t *ef);
extern void low_flash_available();

#ifndef ENABLE_EMULATION
file_t sef_phy = {.fid = EF_PHY, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff}};
file_t *ef_phy = &sef_phy;
#endif

//puts FCI in the RAPDU
void process_fci(const file_t *pe, int fmd) {
    res_APDU_size = 0;
    if (fmd) {
        res_APDU[res_APDU_size++] = 0x6f;
        res_APDU[res_APDU_size++] = 0x00; //computed later
    }

    res_APDU[res_APDU_size++] = 0x62;
    res_APDU[res_APDU_size++] = 0x00; //computed later

    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 2;
    if (pe->data) {
        if ((pe->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            uint16_t len = (uint16_t)((int (*)(const file_t *, int))(pe->data))(pe, 0);
            res_APDU[res_APDU_size++] = (len >> 8) & 0xff;
            res_APDU[res_APDU_size++] = len & 0xff;
        }
        else {
            uint16_t v = file_get_size(pe);
            res_APDU[res_APDU_size++] = v >> 8;
            res_APDU[res_APDU_size++] = v & 0xff;
        }
    }
    else {
        memset(res_APDU + res_APDU_size, 0, 2);
        res_APDU_size += 2;
    }

    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size] = 0;
    if (pe->type & FILE_TYPE_INTERNAL_EF) {
        res_APDU[res_APDU_size++] |= 0x08;
    }
    else if (pe->type & FILE_TYPE_WORKING_EF) {
        res_APDU[res_APDU_size++] |= pe->ef_structure & 0x7;
    }
    else if (pe->type & FILE_TYPE_DF) {
        res_APDU[res_APDU_size++] |= 0x38;
    }
    else {
        res_APDU_size++;
    }

    res_APDU[res_APDU_size++] = 0x83;
    res_APDU[res_APDU_size++] = 2;
    put_uint16_t(pe->fid, res_APDU + res_APDU_size);
    res_APDU_size += 2;
    if (pe->name) {
        res_APDU[res_APDU_size++] = 0x84;
        res_APDU[res_APDU_size++] = MIN(pe->name[0], 16);
        memcpy(res_APDU + res_APDU_size, pe->name + 2, MIN(pe->name[0], 16));
        res_APDU_size += MIN(pe->name[0], 16);
    }
    memcpy(res_APDU + res_APDU_size, "\x8A\x01\x05", 3); //life-cycle (5 -> activated)
    res_APDU_size += 3;
    uint8_t *meta_data = NULL;
    uint16_t meta_size = meta_find(pe->fid, &meta_data);
    if (meta_size > 0 && meta_data != NULL) {
        res_APDU[res_APDU_size++] = 0xA5;
        res_APDU[res_APDU_size++] = 0x81;
        res_APDU[res_APDU_size++] = (uint8_t )meta_size;
        memcpy(res_APDU + res_APDU_size, meta_data, meta_size);
        res_APDU_size += meta_size;
    }
    res_APDU[1] = (uint8_t)res_APDU_size - 2;
    if (fmd) {
        res_APDU[3] = (uint8_t )res_APDU_size - 4;
    }
}

#define MAX_DYNAMIC_FILES 128
uint16_t dynamic_files = 0;
file_t dynamic_file[MAX_DYNAMIC_FILES];

bool card_terminated = false;

bool is_parent(const file_t *child, const file_t *parent) {
    if (child == parent) {
        return true;
    }
    if (child == MF) {
        return false;
    }
    return is_parent(&file_entries[child->parent], parent);
}

file_t *get_parent(file_t *f) {
    return &file_entries[f->parent];
}

file_t *search_by_name(uint8_t *name, uint16_t namelen) {
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->name && *p->name == apdu.nc && memcmp(p->name + 1, name, namelen) == 0) {
            return p;
        }
    }
    return NULL;
}

file_t *search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
#ifndef ENABLE_EMULATION
    if (fid == EF_PHY) {
        return ef_phy;
    }
#endif
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->fid != 0x0000 && p->fid == fid) {
            if (!parent || (parent && is_parent(p, parent))) {
                if (!sp || sp == SPECIFY_ANY ||
                    (((sp & SPECIFY_EF) && (p->type & (FILE_TYPE_INTERNAL_EF|FILE_TYPE_WORKING_EF))) ||
                     ((sp & SPECIFY_DF) && p->type == FILE_TYPE_DF))) {
                    return p;
                }
            }
        }
    }
    return NULL;
}

file_t *search_file(const uint16_t fid) {
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
    if (ef) {
        return ef;
    }
    return search_dynamic_file(fid);
}

uint8_t make_path_buf(const file_t *pe, uint8_t *buf, uint8_t buflen, const file_t *top) {
    if (!buflen) {
        return 0;
    }
    if (pe == top) { //MF or relative DF
        return 0;
    }
    put_uint16_t(pe->fid, buf);
    return make_path_buf(&file_entries[pe->parent], buf + 2, buflen - 2, top) + 2;
}

uint8_t make_path(const file_t *pe, const file_t *top, uint8_t *path) {
    uint8_t buf[MAX_DEPTH * 2], *p = path;
    put_uint16_t(pe->fid, buf);
    uint8_t depth = make_path_buf(&file_entries[pe->parent], buf + 2, sizeof(buf) - 2, top) + 2;
    for (int d = depth - 2; d >= 0; d -= 2) {
        memcpy(p, buf + d, 2);
        p += 2;
    }
    return depth;
}

file_t *search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent) {
    uint8_t path[MAX_DEPTH * 2];
    if (pathlen > sizeof(path)) {
        return NULL;
    }
    for (file_t *p = file_entries; p != file_last; p++) {
        uint8_t depth = make_path(p, parent, path);
        if (pathlen == depth && memcmp(path, pe_path, depth) == 0) {
            return p;
        }
    }
    return NULL;
}

file_t *currentEF = NULL;
file_t *currentDF = NULL;
const file_t *selected_applet = NULL;
bool isUserAuthenticated = false;

bool authenticate_action(const file_t *ef, uint8_t op) {
    uint8_t acl = ef->acl[op];
    if (acl == 0x0) {
        return true;
    }
    else if (acl == 0xff) {
        return false;
    }
    else if (acl == 0x90 || (acl & 0x9F) == 0x10) {
        // PIN required.
        if (isUserAuthenticated) {
            return true;
        }
        else {
            return false;
        }
    }
    return false;
}

void initialize_flash(bool hard) {
    if (hard) {
        const uint8_t empty[8] = { 0 };
        flash_program_block(end_data_pool, empty, sizeof(empty));
        low_flash_available();
    }
    for (file_t *f = file_entries; f != file_last; f++) {
        if ((f->type & FILE_DATA_FLASH) == FILE_DATA_FLASH) {
            f->data = NULL;
        }
    }
    dynamic_files = 0;
}

void scan_region(bool persistent) {
    uintptr_t endp = end_data_pool, startp = start_data_pool;
    if (persistent) {
        endp = end_rom_pool;
        startp = start_rom_pool;
    }
    for (uintptr_t base = flash_read_uintptr(endp); base >= startp; base = flash_read_uintptr(base)) {
        if (base == 0x0) { //all is empty
            break;
        }

        uint16_t fid = flash_read_uint16(base + sizeof(uintptr_t) + sizeof(uintptr_t));
        printf("[%x] scan fid %x, len %d\n", (unsigned int) base, fid,
               flash_read_uint16(base + sizeof(uintptr_t) + sizeof(uintptr_t) + sizeof(uint16_t)));
        file_t *file = (file_t *) search_by_fid(fid, NULL, SPECIFY_EF);
        if (!file) {
            file = file_new(fid);
        }
        if (file) {
            file->data =
                (uint8_t *) (base + sizeof(uintptr_t) + sizeof(uintptr_t) + sizeof(uint16_t));
        }
        if (flash_read_uintptr(base) == 0x0) {
            break;
        }
    }
}
void wait_flash_finish();
void scan_flash() {
    initialize_flash(false); //soft initialization
    uint32_t r1 = *(uintptr_t *) flash_read(end_rom_pool), r2 = *(uintptr_t *) flash_read(end_rom_pool + sizeof(uintptr_t));
    if ((r1 == 0xffffffff || r1 == 0xefefefef) && (r2 == 0xffffffff || r2 == 0xefefefef)) {
        printf("First initialization (or corrupted!)\n");
        uint8_t empty[sizeof(uintptr_t) * 2 + sizeof(uint32_t)];
        memset(empty, 0, sizeof(empty));
        flash_program_block(end_data_pool, empty, sizeof(empty));
        flash_program_block(end_rom_pool, empty, sizeof(empty));
        //low_flash_available();
        //wait_flash_finish();
    }
    printf("SCAN\n");
    scan_region(true);
    scan_region(false);
}

uint8_t *file_read(const uint8_t *addr) {
    return flash_read((uintptr_t) addr);
}
uint16_t file_read_uint16(const uint8_t *addr) {
    return flash_read_uint16((uintptr_t) addr);
}
uint8_t file_read_uint8_offset(const file_t *ef, const uint16_t offset) {
    return flash_read_uint8((uintptr_t) (file_get_data(ef) + offset));
}
uint8_t file_read_uint8(const file_t *ef) {
    return file_read_uint8_offset(ef, 0);
}

uint8_t *file_get_data(const file_t *tf) {
    if (!tf || !tf->data) {
        return NULL;
    }
    return file_read(tf->data + sizeof(uint16_t));
}

uint16_t file_get_size(const file_t *tf) {
    if (!tf || !tf->data) {
        return 0;
    }
    return file_read_uint16(tf->data);
}

int file_put_data(file_t *file, const uint8_t *data, uint16_t len) {
    return flash_write_data_to_file(file, data, len);
}

file_t *search_dynamic_file(uint16_t fid) {
    for (int i = 0; i < dynamic_files; i++) {
        if (dynamic_file[i].fid == fid) {
            return &dynamic_file[i];
        }
    }
    return NULL;
}

int delete_dynamic_file(file_t *f) {
    if (f == NULL) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    for (int i = 0; i < dynamic_files; i++) {
        if (dynamic_file[i].fid == f->fid) {
            for (int j = i + 1; j < dynamic_files; j++) {
                memcpy(&dynamic_file[j - 1], &dynamic_file[j], sizeof(file_t));
            }
            dynamic_files--;
            return CCID_OK;
        }
    }
    return CCID_ERR_FILE_NOT_FOUND;
}

file_t *file_new(uint16_t fid) {
    file_t *f;
    if ((f = search_file(fid))) {
        return f;
    }
    if (dynamic_files == MAX_DYNAMIC_FILES) {
        return NULL;
    }
    f = &dynamic_file[dynamic_files];
    dynamic_files++;
    file_t file = {
        .fid = fid,
        .parent = 5,
        .name = NULL,
        .type = FILE_TYPE_WORKING_EF,
        .ef_structure = FILE_EF_TRANSPARENT,
        .data = NULL,
        .acl = { 0 }
    };
    memcpy(f, &file, sizeof(file_t));
    //memset((uint8_t *)f->acl, 0x90, sizeof(f->acl));
    return f;
}
uint16_t meta_find(uint16_t fid, uint8_t **out) {
    file_t *ef = search_file(EF_META);
    if (!ef) {
        return 0;
    }
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    asn1_ctx_t ctxi;
    asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = (tag_data[0] << 8 | tag_data[1]);
        if (cfid == fid) {
            if (out) {
                *out = tag_data + 2;
            }
            return tag_len - 2;
        }
    }
    return 0;
}
int meta_delete(uint16_t fid) {
    file_t *ef = search_file(EF_META);
    if (!ef) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    uint8_t *fdata = NULL;
    asn1_ctx_t ctxi;
    asn1_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        uint8_t *tpos = p - tag_len - format_tlv_len(tag_len, NULL) - 1;
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = (tag_data[0] << 8 | tag_data[1]);
        if (cfid == fid) {
            uint16_t new_len = ctxi.len - 1 - tag_len - format_tlv_len(tag_len, NULL);
            if (new_len == 0) {
                flash_clear_file(ef);
            }
            else {
                fdata = (uint8_t *) calloc(1, new_len);
                if (tpos > ctxi.data) {
                    memcpy(fdata, ctxi.data, tpos - ctxi.data);
                }
                if (ctxi.data + ctxi.len > p) {
                    memcpy(fdata + (tpos - ctxi.data), p, ctxi.data + ctxi.len - p);
                }
                int r = file_put_data(ef, fdata, new_len);
                free(fdata);
                if (r != CCID_OK) {
                    return CCID_EXEC_ERROR;
                }
            }
            low_flash_available();
            break;
        }
    }
    return CCID_OK;
}
int meta_add(uint16_t fid, const uint8_t *data, uint16_t len) {
    int r;
    file_t *ef = search_file(EF_META);
    if (!ef) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    uint16_t ef_size = file_get_size(ef);
    uint8_t *fdata = (uint8_t *) calloc(1, ef_size);
    memcpy(fdata, file_get_data(ef), ef_size);
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    asn1_ctx_t ctxi;
    asn1_ctx_init(fdata, ef_size, &ctxi);
    while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = (tag_data[0] << 8 | tag_data[1]);
        if (cfid == fid) {
            if (tag_len - 2 == len) { //an update
                memcpy(p - tag_len + 2, data, len);
                r = file_put_data(ef, fdata, ef_size);
                free(fdata);
                if (r != CCID_OK) {
                    return CCID_EXEC_ERROR;
                }
                return CCID_OK;
            }
            else {   //needs reallocation
                uint8_t *tpos = p - asn1_len_tag(tag, tag_len);
                memmove(tpos, p, fdata + ef_size - p);
                tpos += fdata + ef_size - p;
                volatile uintptr_t meta_offset = tpos - fdata;
                ef_size += len - (tag_len - 2);
                if (len > tag_len - 2) {
                    uint8_t *fdata_new = (uint8_t *) realloc(fdata, ef_size);
                    if (fdata_new != NULL) {
                        fdata = fdata_new;
                    }
                    else {
                        free(fdata);
                        return CCID_ERR_MEMORY_FATAL;
                    }
                }
                uint8_t *f = fdata + meta_offset;
                *f++ = fid & 0xff;
                f += format_tlv_len(len + 2, f);
                *f++ = fid >> 8;
                *f++ = fid & 0xff;
                memcpy(f, data, len);
                r = file_put_data(ef, fdata, ef_size);
                free(fdata);
                if (r != CCID_OK) {
                    return CCID_EXEC_ERROR;
                }
                return CCID_OK;
            }
        }
    }
    fdata = (uint8_t *) realloc(fdata, ef_size + asn1_len_tag(fid & 0x1f, len + 2));
    uint8_t *f = fdata + ef_size;
    *f++ = fid & 0x1f;
    f += format_tlv_len(len + 2, f);
    *f++ = fid >> 8;
    *f++ = fid & 0xff;
    memcpy(f, data, len);
    r = file_put_data(ef, fdata, ef_size + (uint16_t)asn1_len_tag(fid & 0x1f, len + 2));
    free(fdata);
    if (r != CCID_OK) {
        return CCID_EXEC_ERROR;
    }
    return CCID_OK;
}

bool file_has_data(file_t *f) {
    return f != NULL && f->data != NULL && file_get_size(f) > 0;
}

int delete_file(file_t *ef) {
    if (ef == NULL) {
        return CCID_OK;
    }
    meta_delete(ef->fid);
    if (flash_clear_file(ef) != CCID_OK) {
        return CCID_EXEC_ERROR;
    }
    if (delete_dynamic_file(ef) != CCID_OK) {
        return CCID_EXEC_ERROR;
    }
    low_flash_available();
    return CCID_OK;
}
