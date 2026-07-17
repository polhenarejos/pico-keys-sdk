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

#include <assert.h>
#include <stdio.h>

#define TEST_NAMESPACE 0x0001u
#define TEST_OTHER_NAMESPACE 0x0002u

static void test_rule_build(uint8_t *rule, uint16_t operations, uint32_t required_facts, uint32_t forbidden_facts, uint16_t caller_namespace, uint16_t flags) {
    put_uint16_be(operations, rule);
    put_uint32_be(required_facts, rule + 2);
    put_uint32_be(forbidden_facts, rule + 6);
    put_uint16_be(caller_namespace, rule + 10);
    put_uint16_be(flags, rule + 12);
}

static size_t test_policy_build(uint8_t *policy, uint8_t rule_count) {
    policy[0] = FILE_OBJECT_POLICY_FORMAT_VERSION;
    policy[1] = rule_count;
    return FILE_OBJECT_POLICY_HEADER_SIZE + (size_t)rule_count * FILE_OBJECT_POLICY_RULE_SIZE;
}

static file_object_authorization_context_t test_context(uint16_t caller_namespace, uint32_t facts) {
    file_object_authorization_context_t context = {
        .facts = facts,
        .session_epoch = 7,
        .facts_epoch = 7,
        .caller_namespace = caller_namespace
    };
    return context;
}

static void test_default_deny(void) {
    uint8_t policy[FILE_OBJECT_POLICY_HEADER_SIZE];
    size_t policy_size = test_policy_build(policy, 0);
    file_object_authorization_context_t context = test_context(TEST_NAMESPACE, 0);

    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_OK);
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
}

static void test_rules(void) {
    uint8_t policy[FILE_OBJECT_POLICY_HEADER_SIZE + 2 * FILE_OBJECT_POLICY_RULE_SIZE];
    size_t policy_size = test_policy_build(policy, 2);
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE, FILE_OBJECT_OPERATION_READ | FILE_OBJECT_OPERATION_ENUMERATE, 0, FILE_OBJECT_FACT_ADMIN, FILE_OBJECT_POLICY_NAMESPACE_ANY, 0);
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE + FILE_OBJECT_POLICY_RULE_SIZE, FILE_OBJECT_OPERATION_SIGN, FILE_OBJECT_FACT_USER_VERIFICATION | FILE_OBJECT_FACT_SESSION_BOUND, FILE_OBJECT_FACT_ADMIN, TEST_NAMESPACE, 0);

    file_object_authorization_context_t context = test_context(TEST_OTHER_NAMESPACE, 0);
    assert(file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
    assert(file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_ENUMERATE, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_SIGN, &context));

    context = test_context(TEST_NAMESPACE, FILE_OBJECT_FACT_USER_VERIFICATION | FILE_OBJECT_FACT_SESSION_BOUND);
    assert(file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_SIGN, &context));

    context.facts |= FILE_OBJECT_FACT_ADMIN;
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_SIGN, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));

    context = test_context(TEST_OTHER_NAMESPACE, FILE_OBJECT_FACT_USER_VERIFICATION | FILE_OBJECT_FACT_SESSION_BOUND);
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_SIGN, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ | FILE_OBJECT_OPERATION_ENUMERATE, &context));
}

static void test_session_epoch(void) {
    uint8_t policy[FILE_OBJECT_POLICY_HEADER_SIZE + FILE_OBJECT_POLICY_RULE_SIZE];
    size_t policy_size = test_policy_build(policy, 1);
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE, FILE_OBJECT_OPERATION_READ, 0, 0, TEST_NAMESPACE, 0);

    file_object_authorization_context_t context = test_context(TEST_NAMESPACE, 0);
    assert(file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));

    context.facts_epoch--;
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
    context.facts_epoch = context.session_epoch;
    context.session_epoch = 0;
    context.facts_epoch = 0;
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
}

static void test_malformed(void) {
    uint8_t policy[FILE_OBJECT_POLICY_MAX_SIZE + 1];
    size_t policy_size = test_policy_build(policy, 1);
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE, FILE_OBJECT_OPERATION_READ, FILE_OBJECT_FACT_USER_VERIFICATION, FILE_OBJECT_FACT_ADMIN, TEST_NAMESPACE, 0);

    assert(file_object_policy_validate(NULL, policy_size) == PICOKEYS_ERR_NULL_PARAM);
    for (size_t len = 0; len < policy_size; len++) {
        assert(file_object_policy_validate(policy, len) != PICOKEYS_OK);
    }
    assert(file_object_policy_validate(policy, policy_size + 1) == PICOKEYS_WRONG_LENGTH);

    uint8_t saved = policy[0];
    policy[0] = FILE_OBJECT_POLICY_FORMAT_VERSION + 1;
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    policy[0] = saved;

    saved = policy[1];
    policy[1] = FILE_OBJECT_POLICY_MAX_RULES + 1;
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    policy[1] = saved;

    uint8_t *rule = policy + FILE_OBJECT_POLICY_HEADER_SIZE;
    put_uint16_be(0, rule);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    put_uint16_be(FILE_OBJECT_OPERATION_MASK + 1u, rule);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    put_uint16_be(FILE_OBJECT_OPERATION_READ, rule);

    put_uint32_be(FILE_OBJECT_FACT_MASK + 1u, rule + 2);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    put_uint32_be(FILE_OBJECT_FACT_USER_VERIFICATION, rule + 2);
    put_uint32_be(FILE_OBJECT_FACT_USER_VERIFICATION, rule + 6);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    put_uint32_be(FILE_OBJECT_FACT_ADMIN, rule + 6);

    put_uint16_be(0, rule + 10);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
    put_uint16_be(TEST_NAMESPACE, rule + 10);
    put_uint16_be(1, rule + 12);
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_WRONG_DATA);
}

static void test_context_validation(void) {
    uint8_t policy[FILE_OBJECT_POLICY_HEADER_SIZE + FILE_OBJECT_POLICY_RULE_SIZE];
    size_t policy_size = test_policy_build(policy, 1);
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE, FILE_OBJECT_OPERATION_READ, 0, 0, FILE_OBJECT_POLICY_NAMESPACE_ANY, 0);

    file_object_authorization_context_t context = test_context(TEST_NAMESPACE, 0);
    assert(!file_object_policy_authorize(policy, policy_size, 0, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ | FILE_OBJECT_OPERATION_ENUMERATE, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_MASK + 1u, &context));
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, NULL));

    context.caller_namespace = 0;
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
    context.caller_namespace = FILE_OBJECT_POLICY_NAMESPACE_ANY;
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
    context = test_context(TEST_NAMESPACE, FILE_OBJECT_FACT_MASK + 1u);
    assert(!file_object_policy_authorize(policy, policy_size, FILE_OBJECT_OPERATION_READ, &context));
}

static void test_maximum_rules(void) {
    uint8_t policy[FILE_OBJECT_POLICY_MAX_SIZE];
    size_t policy_size = test_policy_build(policy, FILE_OBJECT_POLICY_MAX_RULES);
    for (uint8_t i = 0; i < FILE_OBJECT_POLICY_MAX_RULES; i++) {
        test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE + (size_t)i * FILE_OBJECT_POLICY_RULE_SIZE, FILE_OBJECT_OPERATION_READ, 0, 0, TEST_NAMESPACE, 0);
    }
    assert(policy_size == sizeof(policy));
    assert(file_object_policy_validate(policy, policy_size) == PICOKEYS_OK);
}

static void test_hash(void) {
    uint8_t policy[FILE_OBJECT_POLICY_HEADER_SIZE + FILE_OBJECT_POLICY_RULE_SIZE];
    size_t policy_size = test_policy_build(policy, 1);
    uint8_t first[FILE_OBJECT_POLICY_HASH_SIZE];
    uint8_t second[FILE_OBJECT_POLICY_HASH_SIZE];
    test_rule_build(policy + FILE_OBJECT_POLICY_HEADER_SIZE, FILE_OBJECT_OPERATION_SIGN, FILE_OBJECT_FACT_USER_VERIFICATION, 0, TEST_NAMESPACE, 0);

    assert(file_object_policy_hash(policy, policy_size, first) == PICOKEYS_OK);
    assert(file_object_policy_hash(policy, policy_size, second) == PICOKEYS_OK);
    assert(memcmp(first, second, sizeof(first)) == 0);
    policy[FILE_OBJECT_POLICY_HEADER_SIZE + 1] ^= 0x01;
    assert(file_object_policy_hash(policy, policy_size, second) == PICOKEYS_OK);
    assert(memcmp(first, second, sizeof(first)) != 0);

    memset(second, 0xa5, sizeof(second));
    policy[0] = FILE_OBJECT_POLICY_FORMAT_VERSION + 1;
    assert(file_object_policy_hash(policy, policy_size, second) == PICOKEYS_WRONG_DATA);
    for (size_t i = 0; i < sizeof(second); i++) {
        assert(second[i] == 0);
    }
    assert(file_object_policy_hash(policy, policy_size, NULL) == PICOKEYS_ERR_NULL_PARAM);
}

int main(void) {
    test_default_deny();
    test_rules();
    test_session_epoch();
    test_malformed();
    test_context_validation();
    test_maximum_rules();
    test_hash();
    puts("object_policy_test: OK");
    return 0;
}
