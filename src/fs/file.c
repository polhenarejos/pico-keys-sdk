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
#include "file.h"
#include "tlv.h"
#include "apdu.h"
#include <stdio.h>

#define MAX_DEPTH 4

#define DYNAMIC_FILE_SLOTS 2309u
#define MAX_DYNAMIC_FILES 2048u
#define DYNAMIC_FID_EMPTY 0x0000u
#define DYNAMIC_FID_DELETED 0xffffu

extern const uintptr_t end_data_pool;
extern const uintptr_t start_data_pool;
extern const uintptr_t end_rom_pool;
extern const uintptr_t start_rom_pool;
#ifndef ENABLE_EMULATION
file_entry_t sef_phy = {.fid = EF_PHY, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff}};
file_t *ef_phy = &sef_phy.file;
#endif

static const file_entry_t *file_static_entry(const file_t *file) {
    if (!file) {
        return NULL;
    }
#ifndef ENABLE_EMULATION
    if (file == ef_phy) {
        return &sef_phy;
    }
#endif
    uintptr_t addr = (uintptr_t)file - offsetof(file_entry_t, file);
    uintptr_t first = (uintptr_t)&file_entries[0];
    uintptr_t last = (uintptr_t)file_last;
    if (addr < first || addr > last || (addr - first) % sizeof(file_entry_t) != 0) {
        return NULL;
    }
    return (const file_entry_t *)addr;
}

uint8_t file_get_type(const file_t *file) {
    const file_entry_t *entry = file_static_entry(file);
    return entry ? entry->type : FILE_TYPE_WORKING_EF;
}

//puts FCI in the RAPDU
void file_process_fci(const file_t *pe, int fmd) {
    const file_entry_t *entry = file_static_entry(pe);
    uint8_t type = file_get_type(pe);
    uint8_t structure = entry ? entry->ef_structure : FILE_EF_TRANSPARENT;
    const uint8_t *name = entry ? entry->name : NULL;

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
        if ((type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            int (*data_fn)(const file_t *, int) = (int (*)(const file_t *, int))(uintptr_t)pe->data;
            uint16_t len = (uint16_t)data_fn(pe, 0);
            res_APDU_size += put_uint16_be(len, res_APDU + res_APDU_size);
        }
        else {
            uint32_t v = file_get_size(pe);
            res_APDU_size += put_uint16_be(v > (uint32_t)UINT16_MAX ? UINT16_MAX : (uint16_t)v, res_APDU + res_APDU_size);
        }
    }
    else {
        memset(res_APDU + res_APDU_size, 0, 2);
        res_APDU_size += 2;
    }

    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size] = 0;
    if (type & FILE_TYPE_INTERNAL_EF) {
        res_APDU[res_APDU_size++] |= 0x08;
    }
    else if (type & FILE_TYPE_WORKING_EF) {
        res_APDU[res_APDU_size++] |= structure & 0x7;
    }
    else if (type & FILE_TYPE_DF) {
        res_APDU[res_APDU_size++] |= 0x38;
    }
    else {
        res_APDU_size++;
    }

    res_APDU[res_APDU_size++] = 0x83;
    res_APDU[res_APDU_size++] = 2;
    res_APDU_size += put_uint16_be(pe->fid, res_APDU + res_APDU_size);
    if (name) {
        res_APDU[res_APDU_size++] = 0x84;
        res_APDU[res_APDU_size++] = MIN(name[0], 16);
        memcpy(res_APDU + res_APDU_size, name + 2, MIN(name[0], 16));
        res_APDU_size += MIN(name[0], 16);
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

static uint16_t dynamic_files = 0;
static file_t dynamic_file[DYNAMIC_FILE_SLOTS];

bool card_terminated = false;

static bool is_parent(const file_entry_t *child, const file_t *parent) {
    if (&child->file == parent) {
        return true;
    }
    if (&child->file == MF) {
        return false;
    }
    return is_parent(&file_entries[child->parent], parent);
}

file_t *get_parent(file_t *f) {
    const file_entry_t *entry = file_static_entry(f);
    uint8_t parent = entry ? entry->parent : 5;
    return &file_entries[parent].file;
}

file_t *file_search_by_name(uint8_t *name, uint16_t namelen) {
    for (file_entry_t *p = file_entries; p != file_last; p++) {
        if (p->name && *p->name == apdu.nc && memcmp(p->name + 1, name, namelen) == 0) {
            return &p->file;
        }
    }
    return NULL;
}

file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
#ifndef ENABLE_EMULATION
    if (fid == EF_PHY) {
        return ef_phy;
    }
#endif
    for (file_entry_t *p = file_entries; p != file_last; p++) {
        if (p->fid != 0x0000 && p->fid == fid) {
            if (!parent || (parent && is_parent(p, parent))) {
                if (!sp || sp == SPECIFY_ANY ||
                    (((sp & SPECIFY_EF) && (p->type & (FILE_TYPE_INTERNAL_EF|FILE_TYPE_WORKING_EF))) ||
                     ((sp & SPECIFY_DF) && p->type == FILE_TYPE_DF))) {
                    return &p->file;
                }
            }
        }
    }
    return NULL;
}

static size_t dynamic_hash(uint16_t fid) {
    return ((uint32_t)fid * 40503u) % DYNAMIC_FILE_SLOTS;
}

static size_t dynamic_hash_step(uint16_t fid) {
    return 1u + (((uint32_t)fid * 97u) % (DYNAMIC_FILE_SLOTS - 1u));
}

static file_t *search_dynamic_file(uint16_t fid) {
    size_t slot = dynamic_hash(fid);
    size_t step = dynamic_hash_step(fid);
    for (size_t probes = 0; probes < DYNAMIC_FILE_SLOTS; probes++) {
        file_t *file = &dynamic_file[slot];
        if (file->fid == DYNAMIC_FID_EMPTY) {
            return NULL;
        }
        if (file->fid == fid) {
            return file;
        }
        slot = (slot + step) % DYNAMIC_FILE_SLOTS;
    }
    return NULL;
}

static file_t *find_dynamic_slot(uint16_t fid) {
    file_t *deleted = NULL;
    size_t slot = dynamic_hash(fid);
    size_t step = dynamic_hash_step(fid);
    for (size_t probes = 0; probes < DYNAMIC_FILE_SLOTS; probes++) {
        file_t *file = &dynamic_file[slot];
        if (file->fid == DYNAMIC_FID_EMPTY) {
            return deleted ? deleted : file;
        }
        if (file->fid == DYNAMIC_FID_DELETED && !deleted) {
            deleted = file;
        }
        slot = (slot + step) % DYNAMIC_FILE_SLOTS;
    }
    return deleted;
}

void file_for_each_dynamic(file_iter_cb cb, void *ctx) {
    for (size_t i = 0; i < DYNAMIC_FILE_SLOTS; i++) {
        if (dynamic_file[i].fid != DYNAMIC_FID_EMPTY &&
            dynamic_file[i].fid != DYNAMIC_FID_DELETED &&
            file_has_data(&dynamic_file[i]) && !cb(&dynamic_file[i], ctx)) {
            break;
        }
    }
}

file_t *file_search(const uint16_t fid) {
    file_t *ef = file_search_by_fid(fid, NULL, SPECIFY_EF);
    if (ef) {
        return ef;
    }
    return search_dynamic_file(fid);
}

static uint8_t make_path_buf(const file_t *pe, uint8_t *buf, uint8_t buflen, const file_t *top) {
    if (!buflen) {
        return 0;
    }
    if (pe == top) { //MF or relative DF
        return 0;
    }
    put_uint16_be(pe->fid, buf);
    return make_path_buf(get_parent((file_t *)pe), buf + 2, buflen - 2, top) + 2;
}

static uint8_t make_path(const file_t *pe, const file_t *top, uint8_t *path) {
    uint8_t buf[MAX_DEPTH * 2], *p = path;
    put_uint16_be(pe->fid, buf);
    uint8_t depth = make_path_buf(get_parent((file_t *)pe), buf + 2, sizeof(buf) - 2, top) + 2;
    for (int d = depth - 2; d >= 0; d -= 2) {
        memcpy(p, buf + d, 2);
        p += 2;
    }
    return depth;
}

file_t *file_search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent) {
    uint8_t path[MAX_DEPTH * 2];
    if (pathlen > sizeof(path)) {
        return NULL;
    }
    for (file_entry_t *p = file_entries; p != file_last; p++) {
        uint8_t depth = make_path(&p->file, parent, path);
        if (pathlen == depth && memcmp(path, pe_path, depth) == 0) {
            return &p->file;
        }
    }
    return NULL;
}

file_t *currentEF = NULL;
file_t *currentDF = NULL;
const file_t *selected_applet = NULL;
bool isUserAuthenticated = false;

bool file_authenticate_action(const file_t *ef, uint8_t op) {
    const file_entry_t *entry = file_static_entry(ef);
    uint8_t acl = entry ? entry->acl[op] : 0x00;
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

void file_initialize_flash(bool hard) {
    if (hard) {
        const uint8_t empty[8] = { 0 };
        flash_program_block(end_data_pool, empty, sizeof(empty));
        flash_commit();
    }
    for (file_entry_t *f = file_entries; f != file_last; f++) {
        if ((f->type & FILE_DATA_FLASH) == FILE_DATA_FLASH) {
            f->data = NULL;
        }
    }
    memset(dynamic_file, 0, sizeof(dynamic_file));
    dynamic_files = 0;
}

extern uintptr_t last_base;
extern uint32_t num_files;
static void scan_region(bool persistent) {
    uintptr_t endp = end_data_pool, startp = start_data_pool;
    if (persistent) {
        endp = end_rom_pool;
        startp = start_rom_pool;
    }
    else {
        last_base = endp;
        num_files = 0;
    }
    for (uintptr_t base = flash_read_uintptr(endp); base >= startp; base = flash_read_uintptr(base)) {
        if (base == 0x0) { //all is empty
            break;
        }

        uint16_t fid = flash_read_uint16(base + sizeof(uintptr_t) + sizeof(uintptr_t));
        uintptr_t length_addr = base + 2 * sizeof(uintptr_t) + sizeof(uint16_t);
        uint16_t stored_length = flash_read_uint16(length_addr);
        uint32_t length = stored_length == FLASH_FILE_EXTENDED_LENGTH ? flash_read_uint32(length_addr + sizeof(uint16_t)) : stored_length;
        printf("[%x] scan fid %x, len %lu\n", (unsigned int)base, fid, (unsigned long)length);
        file_t *file = (file_t *) file_search_by_fid(fid, NULL, SPECIFY_EF);
        if (!file) {
            file = file_new(fid);
        }
        if (file) {
            file->data = (uint8_t *) (base + sizeof(uintptr_t) + sizeof(uintptr_t) + sizeof(uint16_t));
        }
        if (!persistent) {
            num_files++;
        }
        if (flash_read_uintptr(base) == 0x0) {
            if (base < last_base) {
                last_base = base;
            }
            break;
        }
    }
}
void file_scan_flash(void) {
    file_initialize_flash(false); //soft initialization
    uint32_t r1 = (uint32_t)flash_read_uintptr(end_rom_pool);
    uint32_t r2 = (uint32_t)flash_read_uintptr(end_rom_pool + sizeof(uintptr_t));
    if ((r1 == 0xffffffff || r1 == 0xefefefef) && (r2 == 0xffffffff || r2 == 0xefefefef)) {
        printf("First initialization (or corrupted!)\n");
        uint8_t empty[sizeof(uintptr_t) * 2 + sizeof(uint32_t)];
        memset(empty, 0, sizeof(empty));
        flash_program_block(end_data_pool, empty, sizeof(empty));
        flash_program_block(end_rom_pool, empty, sizeof(empty));
        //flash_commit();
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

uint32_t file_read_uint32(const uint8_t *addr) {
    return flash_read_uint32((uintptr_t)addr);
}

uint8_t file_read_uint8_offset(const file_t *ef, const uint16_t offset) {
    uint8_t value = 0;
    file_read_at(ef, offset, &value, sizeof(value));
    return value;
}
uint8_t file_read_uint8(const file_t *ef) {
    return file_read_uint8_offset(ef, 0);
}

uint8_t *file_get_data(const file_t *tf) {
    if (!tf || !tf->data) {
        return NULL;
    }

    size_t length_size = file_read_uint16(tf->data) == FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
    return file_read(tf->data + length_size);
}

uint32_t file_get_size(const file_t *tf) {
    if (!tf || !tf->data) {
        return 0;
    }

    uint16_t length = file_read_uint16(tf->data);
    return length == FLASH_FILE_EXTENDED_LENGTH ? file_read_uint32(tf->data + sizeof(uint16_t)) : length;
}

int file_read_at(const file_t *tf, uint32_t offset, uint8_t *data, size_t len) {
    if (!tf || !tf->data || (!data && len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint32_t size = file_get_size(tf);
    if (offset > size || len > size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (len == 0) {
        return PICOKEYS_OK;
    }

    uint16_t stored_length = file_read_uint16(tf->data);
    size_t length_size = stored_length == FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
    return flash_read_block((uintptr_t)tf->data + length_size + offset, data, len);
}

int file_put_data(file_t *file, const uint8_t *data, uint32_t len) {
    return flash_write_data_to_file(file, data, len);
}

int file_put_data_offset(file_t *file, const uint8_t *data, uint32_t len, uint32_t offset) {
    return flash_write_data_to_file_offset(file, data, len, offset);
}

static int delete_dynamic_file(file_t *f) {
    if (f == NULL) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uintptr_t addr = (uintptr_t)f;
    uintptr_t first = (uintptr_t)&dynamic_file[0];
    uintptr_t end = (uintptr_t)&dynamic_file[DYNAMIC_FILE_SLOTS];
    if (addr < first || addr >= end || (addr - first) % sizeof(file_t) != 0 ||
        f->fid == DYNAMIC_FID_EMPTY || f->fid == DYNAMIC_FID_DELETED) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    f->data = NULL;
    f->fid = DYNAMIC_FID_DELETED;
    dynamic_files--;
    return PICOKEYS_OK;
}

file_t *file_new(uint16_t fid) {
    file_t *f;
    if ((f = file_search(fid))) {
        return f;
    }
    if (fid == DYNAMIC_FID_EMPTY || fid == DYNAMIC_FID_DELETED || dynamic_files >= MAX_DYNAMIC_FILES) {
        return NULL;
    }
    f = find_dynamic_slot(fid);
    if (!f) {
        return NULL;
    }
    f->data = NULL;
    f->fid = fid;
    dynamic_files++;
    return f;
}
uint16_t meta_find(uint16_t fid, uint8_t **out) {
    file_t *ef = file_search(EF_META);
    if (!ef) {
        return 0;
    }
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    tlv_ctx_t ctxi;
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = get_uint16_be(tag_data);
        if (cfid == fid) {
            if (out) {
                *out = tag_data + 2;
            }
            return tag_len - 2;
        }
    }
    return 0;
}
static int meta_delete_internal(uint16_t fid, bool commit) {
    file_t *ef = file_search(EF_META);
    if (!ef) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    uint8_t *fdata = NULL;
    tlv_ctx_t ctxi;
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        uint8_t *tpos = p - tag_len - tlv_format_len(tag_len, NULL) - 1;
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = get_uint16_be(tag_data);
        if (cfid == fid) {
            uint16_t new_len = ctxi.len - 1 - tag_len - tlv_format_len(tag_len, NULL);
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
                if (r != PICOKEYS_OK) {
                    return PICOKEYS_EXEC_ERROR;
                }
            }
            if (commit) {
                flash_commit();
            }
            break;
        }
    }
    return PICOKEYS_OK;
}

int meta_delete(uint16_t fid) {
    return meta_delete_internal(fid, true);
}

int meta_delete_no_commit(uint16_t fid) {
    return meta_delete_internal(fid, false);
}

int meta_add(uint16_t fid, const uint8_t *data, uint16_t len) {
    int r;
    file_t *ef = file_search(EF_META);
    if (!ef) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint16_t ef_size = file_get_size(ef);
    uint8_t *fdata = (uint8_t *) calloc(1, ef_size);
    memcpy(fdata, file_get_data(ef), ef_size);
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    tlv_ctx_t ctxi;
    tlv_ctx_init(fdata, ef_size, &ctxi);
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag_len < 2) {
            continue;
        }
        uint16_t cfid = get_uint16_be(tag_data);
        if (cfid == fid) {
            if (tag_len - 2 == len) { //an update
                memcpy(p - tag_len + 2, data, len);
                r = file_put_data(ef, fdata, ef_size);
                free(fdata);
                if (r != PICOKEYS_OK) {
                    return PICOKEYS_EXEC_ERROR;
                }
                return PICOKEYS_OK;
            }
            else {   //needs reallocation
                uint8_t *tpos = p - tlv_len_tag(tag, tag_len);
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
                        return PICOKEYS_ERR_MEMORY_FATAL;
                    }
                }
                uint8_t *f = fdata + meta_offset;
                *f++ = fid & 0xff;
                f += tlv_format_len(len + 2, f);
                f += put_uint16_be(fid, f);
                memcpy(f, data, len);
                r = file_put_data(ef, fdata, ef_size);
                free(fdata);
                if (r != PICOKEYS_OK) {
                    return PICOKEYS_EXEC_ERROR;
                }
                return PICOKEYS_OK;
            }
        }
    }
    fdata = (uint8_t *) realloc(fdata, ef_size + tlv_len_tag(fid & 0x1f, len + 2));
    uint8_t *f = fdata + ef_size;
    *f++ = fid & 0x1f;
    f += tlv_format_len(len + 2, f);
    f += put_uint16_be(fid, f);
    memcpy(f, data, len);
    r = file_put_data(ef, fdata, ef_size + (uint16_t)tlv_len_tag(fid & 0x1f, len + 2));
    free(fdata);
    if (r != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

bool file_has_data(const file_t *f) {
    return f != NULL && f->data != NULL && file_get_size(f) > 0;
}

int file_delete_no_commit(file_t *ef) {
    if (ef == NULL) {
        return PICOKEYS_OK;
    }
    meta_delete_internal(ef->fid, false);
    if (flash_clear_file(ef) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (delete_dynamic_file(ef) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

int file_delete(file_t *ef) {
    int ret = file_delete_no_commit(ef);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    flash_commit();
    return PICOKEYS_OK;
}

int flash_clear_file(file_t *file) {
    if (file == NULL || file->data == NULL) {
        return PICOKEYS_OK;
    }

    uint32_t len = file_get_size(file);
    uint16_t stored_length = file_read_uint16(file->data);
    size_t length_size = stored_length == FLASH_FILE_EXTENDED_LENGTH ? FLASH_FILE_EXTENDED_LENGTH_SIZE : FLASH_FILE_LEGACY_LENGTH_SIZE;
    uintptr_t payload_addr = (uintptr_t)file->data + length_size;
    uintptr_t base_addr = (uintptr_t)(file->data - sizeof(uintptr_t) - sizeof(uint16_t) - sizeof(uintptr_t));
    uintptr_t prev_addr = flash_read_uintptr(base_addr + sizeof(uintptr_t));
    uintptr_t next_addr = flash_read_uintptr(base_addr);
    //printf("nc %lx->%lx   %lx->%lx\n",prev_addr,flash_read_uintptr(prev_addr),base_addr,next_addr);
    flash_program_uintptr(prev_addr, next_addr);
    flash_program_halfword((uintptr_t) file->data, 0);
    const uint8_t zeros[256] = {0};
    for (uint32_t offset = 0; offset < len;) {
        size_t chunk = MIN(sizeof(zeros), len - offset);
        if (flash_program_block(payload_addr + offset, zeros, chunk) != PICOKEYS_OK) {
            return PICOKEYS_EXEC_ERROR;
        }
        offset += chunk;
    }
    if (next_addr > 0) {
        flash_program_uintptr(next_addr + sizeof(uintptr_t), prev_addr);
    }
    flash_program_uintptr(base_addr, 0);
    flash_program_uintptr(base_addr + sizeof(uintptr_t), 0);
    file->data = NULL;
    if (num_files > 0) {
        num_files--;
    }
    //printf("na %lx->%lx\n",prev_addr,flash_read_uintptr(prev_addr));
    return PICOKEYS_OK;
}
