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
#include "object_policy.h"

#include <mbedtls/sha256.h>

#define FILE_OBJECT_POLICY_RULE_OPERATION_OFFSET 0u
#define FILE_OBJECT_POLICY_RULE_REQUIRED_FACTS_OFFSET 2u
#define FILE_OBJECT_POLICY_RULE_FORBIDDEN_FACTS_OFFSET 6u
#define FILE_OBJECT_POLICY_RULE_CALLER_NAMESPACE_OFFSET 10u
#define FILE_OBJECT_POLICY_RULE_FLAGS_OFFSET 12u

static bool file_object_policy_rule_valid(const uint8_t *rule) {
    uint16_t operations = get_uint16_be(rule + FILE_OBJECT_POLICY_RULE_OPERATION_OFFSET);
    uint32_t required_facts = get_uint32_be(rule + FILE_OBJECT_POLICY_RULE_REQUIRED_FACTS_OFFSET);
    uint32_t forbidden_facts = get_uint32_be(rule + FILE_OBJECT_POLICY_RULE_FORBIDDEN_FACTS_OFFSET);
    uint16_t caller_namespace = get_uint16_be(rule + FILE_OBJECT_POLICY_RULE_CALLER_NAMESPACE_OFFSET);
    uint16_t flags = get_uint16_be(rule + FILE_OBJECT_POLICY_RULE_FLAGS_OFFSET);

    if (operations == 0 || (operations & ~FILE_OBJECT_OPERATION_MASK) != 0) {
        return false;
    }
    if (((required_facts | forbidden_facts) & ~FILE_OBJECT_FACT_MASK) != 0 || (required_facts & forbidden_facts) != 0) {
        return false;
    }
    if (caller_namespace == 0 || (flags & ~FILE_OBJECT_POLICY_RULE_FLAG_MASK) != 0) {
        return false;
    }
    return true;
}

int file_object_policy_validate(const uint8_t *policy, size_t policy_size) {
    if (!policy) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (policy_size < FILE_OBJECT_POLICY_HEADER_SIZE || policy[0] != FILE_OBJECT_POLICY_FORMAT_VERSION || policy[1] > FILE_OBJECT_POLICY_MAX_RULES) {
        return PICOKEYS_WRONG_DATA;
    }

    size_t expected_size = FILE_OBJECT_POLICY_HEADER_SIZE + (size_t)policy[1] * FILE_OBJECT_POLICY_RULE_SIZE;
    if (policy_size != expected_size) {
        return PICOKEYS_WRONG_LENGTH;
    }

    for (uint8_t i = 0; i < policy[1]; i++) {
        const uint8_t *rule = policy + FILE_OBJECT_POLICY_HEADER_SIZE + (size_t)i * FILE_OBJECT_POLICY_RULE_SIZE;
        if (!file_object_policy_rule_valid(rule)) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    return PICOKEYS_OK;
}

int file_object_policy_hash(const uint8_t *policy, size_t policy_size, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    if (!hash) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(hash, 0, FILE_OBJECT_POLICY_HASH_SIZE);

    int r = file_object_policy_validate(policy, policy_size);
    if (r != PICOKEYS_OK) {
        return r;
    }

    uint8_t full_hash[32];
    if (mbedtls_sha256(policy, policy_size, full_hash, 0) != 0) {
        memset(full_hash, 0, sizeof(full_hash));
        return PICOKEYS_EXEC_ERROR;
    }
    memcpy(hash, full_hash, FILE_OBJECT_POLICY_HASH_SIZE);
    memset(full_hash, 0, sizeof(full_hash));
    return PICOKEYS_OK;
}

bool file_object_policy_authorize(const uint8_t *policy, size_t policy_size, uint16_t operation, const file_object_authorization_context_t *context) {
    if (file_object_policy_validate(policy, policy_size) != PICOKEYS_OK || !context) {
        return false;
    }
    if (operation == 0 || (operation & ~FILE_OBJECT_OPERATION_MASK) != 0 || (operation & (operation - 1u)) != 0) {
        return false;
    }
    if (context->caller_namespace == 0 || context->caller_namespace == FILE_OBJECT_POLICY_NAMESPACE_ANY || context->session_epoch == 0 || context->session_epoch != context->facts_epoch || (context->facts & ~FILE_OBJECT_FACT_MASK) != 0) {
        return false;
    }

    for (uint8_t i = 0; i < policy[1]; i++) {
        const uint8_t *rule = policy + FILE_OBJECT_POLICY_HEADER_SIZE + (size_t)i * FILE_OBJECT_POLICY_RULE_SIZE;
        uint16_t operations = get_uint16_be(rule + FILE_OBJECT_POLICY_RULE_OPERATION_OFFSET);
        uint32_t required_facts = get_uint32_be(rule + FILE_OBJECT_POLICY_RULE_REQUIRED_FACTS_OFFSET);
        uint32_t forbidden_facts = get_uint32_be(rule + FILE_OBJECT_POLICY_RULE_FORBIDDEN_FACTS_OFFSET);
        uint16_t caller_namespace = get_uint16_be(rule + FILE_OBJECT_POLICY_RULE_CALLER_NAMESPACE_OFFSET);

        if ((operations & operation) != 0 && (caller_namespace == FILE_OBJECT_POLICY_NAMESPACE_ANY || caller_namespace == context->caller_namespace) && (context->facts & required_facts) == required_facts && (context->facts & forbidden_facts) == 0) {
            return true;
        }
    }
    return false;
}
