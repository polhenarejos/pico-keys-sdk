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

#ifndef _FILE_H_
#define _FILE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "compat/compat.h"
#include "phy.h"

#define FILE_TYPE_NOT_KNOWN     0x00
#define FILE_TYPE_DF            0x04
#define FILE_TYPE_INTERNAL_EF   0x02
#define FILE_TYPE_WORKING_EF    0x01
#define FILE_TYPE_BSO           0x10
#define FILE_PERSISTENT         0x20
#define FILE_DATA_FLASH         0x40
#define FILE_DATA_FUNC          0x80

/* EF structures */
#define FILE_EF_UNKNOWN             0x00
#define FILE_EF_TRANSPARENT         0x01
#define FILE_EF_LINEAR_FIXED        0x02
#define FILE_EF_LINEAR_FIXED_TLV    0x03
#define FILE_EF_LINEAR_VARIABLE     0x04
#define FILE_EF_LINEAR_VARIABLE_TLV 0x05
#define FILE_EF_CYCLIC              0x06
#define FILE_EF_CYCLIC_TLV          0x07

#define ACL_OP_DELETE_SELF      0x00
#define ACL_OP_CREATE_DF        0x01
#define ACL_OP_CREATE_EF        0x02
#define ACL_OP_DELETE_CHILD     0x03
#define ACL_OP_WRITE            0x04
#define ACL_OP_UPDATE_ERASE     0x05
#define ACL_OP_READ_SEARCH      0x06

#define ACL_NONE    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define ACL_ALL     { 0 }
#define ACL_RO      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 }
#define ACL_RW      { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define ACL_R_WP    { 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x00 }
#define ACL_WP      { 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0xff }

#define SPECIFY_EF 0x1
#define SPECIFY_DF 0x2
#define SPECIFY_ANY 0x3

#define EF_META     0xE010

#ifdef _MSC_VER
__pragma( pack(push, 1) )
#endif
typedef struct file {
    const uint8_t *name;
    uint8_t *data;              //should include 2 bytes len at begining
    const uint16_t fid;
    uint8_t acl[7];
    const uint8_t parent;       //entry number in the whole table!!
    const uint8_t type;
    const uint8_t ef_structure;
#ifdef ENABLE_EMULATION
    uint32_t _padding;
#endif
}
#ifdef _MSC_VER
__pragma( pack(pop) )
#else
__attribute__ ((packed))
#endif
file_t;

extern file_t *currentEF;
extern file_t *currentDF;
extern const file_t *selected_applet;

extern const file_t *MF;
extern const file_t *file_last;
extern bool card_terminated;

extern file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp);
extern file_t *file_search(const uint16_t fid);
extern file_t *file_search_by_name(uint8_t *name, uint16_t namelen);
extern file_t *file_search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent);
extern bool file_authenticate_action(const file_t *ef, uint8_t op);
extern void file_process_fci(const file_t *pe, int fmd);
extern void file_scan_flash(void);
extern void file_initialize_flash(bool);

extern file_t file_entries[];

extern uint8_t *file_read(const uint8_t *addr);
extern uint16_t file_read_uint16(const uint8_t *addr);
extern uint8_t file_read_uint8(const file_t *ef);
extern uint8_t file_read_uint8_offset(const file_t *ef, const uint16_t offset);
extern bool file_has_data(const file_t *);
extern uint8_t *file_get_data(const file_t *tf);
extern uint16_t file_get_size(const file_t *tf);
extern int file_put_data(file_t *file, const uint8_t *data, uint16_t len);
extern file_t *file_new(uint16_t);
extern int flash_clear_file(file_t *file);
file_t *get_parent(file_t *f);

extern bool isUserAuthenticated;

extern uint16_t meta_find(uint16_t, uint8_t **out);
extern int meta_delete(uint16_t fid);
extern int meta_add(uint16_t fid, const uint8_t *data, uint16_t len);
extern int delete_file(file_t *ef);

#ifndef ENABLE_EMULATION
extern file_t *ef_phy;
#endif

#endif // _FILE_H_
