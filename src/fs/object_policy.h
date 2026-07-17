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

#ifndef _OBJECT_POLICY_H_
#define _OBJECT_POLICY_H_

#include "object_container.h"

#define FILE_OBJECT_POLICY_FORMAT_VERSION 1u
#define FILE_OBJECT_POLICY_HEADER_SIZE 2u
#define FILE_OBJECT_POLICY_RULE_SIZE 14u
#define FILE_OBJECT_POLICY_MAX_RULES 8u
#define FILE_OBJECT_POLICY_MAX_SIZE (FILE_OBJECT_POLICY_HEADER_SIZE + FILE_OBJECT_POLICY_MAX_RULES * FILE_OBJECT_POLICY_RULE_SIZE)
#define FILE_OBJECT_POLICY_NAMESPACE_ANY 0xffffu

#define FILE_OBJECT_OPERATION_READ 0x0001u
#define FILE_OBJECT_OPERATION_ENUMERATE 0x0002u
#define FILE_OBJECT_OPERATION_USE 0x0004u
#define FILE_OBJECT_OPERATION_SIGN 0x0008u
#define FILE_OBJECT_OPERATION_DECRYPT 0x0010u
#define FILE_OBJECT_OPERATION_DERIVE 0x0020u
#define FILE_OBJECT_OPERATION_WRAP 0x0040u
#define FILE_OBJECT_OPERATION_UNWRAP 0x0080u
#define FILE_OBJECT_OPERATION_EXPORT 0x0100u
#define FILE_OBJECT_OPERATION_UPDATE 0x0200u
#define FILE_OBJECT_OPERATION_DELETE 0x0400u
#define FILE_OBJECT_OPERATION_CHANGE_POLICY 0x0800u
#define FILE_OBJECT_OPERATION_ADMIN_RECOVERY 0x1000u
#define FILE_OBJECT_OPERATION_MASK 0x1fffu

#define FILE_OBJECT_FACT_USER_PRESENCE 0x00000001u
#define FILE_OBJECT_FACT_USER_VERIFICATION 0x00000002u
#define FILE_OBJECT_FACT_APP_PIN 0x00000004u
#define FILE_OBJECT_FACT_ADMIN 0x00000008u
#define FILE_OBJECT_FACT_SECURE_MESSAGING 0x00000010u
#define FILE_OBJECT_FACT_INTERNAL_FIRMWARE 0x00000020u
#define FILE_OBJECT_FACT_OWNING_APPLICATION 0x00000040u
#define FILE_OBJECT_FACT_PHYSICAL_CONFIRMATION 0x00000080u
#define FILE_OBJECT_FACT_DEVICE_STATE 0x00000100u
#define FILE_OBJECT_FACT_ONE_TIME_AUTHORIZATION 0x00000200u
#define FILE_OBJECT_FACT_SESSION_BOUND 0x00000400u
#define FILE_OBJECT_FACT_MASK 0x000007ffu

#define FILE_OBJECT_POLICY_RULE_FLAG_MASK 0x0000u

typedef struct file_object_authorization_context {
    uint32_t facts;
    uint32_t session_epoch;
    uint32_t facts_epoch;
    uint16_t caller_namespace;
} file_object_authorization_context_t;

int file_object_policy_validate(const uint8_t *policy, size_t policy_size);
int file_object_policy_hash(const uint8_t *policy, size_t policy_size, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]);
bool file_object_policy_authorize(const uint8_t *policy, size_t policy_size, uint16_t operation, const file_object_authorization_context_t *context);

#endif // _OBJECT_POLICY_H_
