#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "hardware/sha256.h"
#include "pico/bootrom/lock.h"
#include "pico/sha256.h"
#include "pico/time.h"

#define SHA256_PADDING_DATA_BYTES 9
#define SHA256_BLOCK_SIZE_BYTES 64

const absolute_time_t ABSOLUTE_TIME_INITIALIZED_VAR(at_the_end_of_time, INT64_MAX);

bool __weak pico_sha256_lock(pico_sha256_state_t *state)
{
    if (!bootrom_try_acquire_lock(BOOTROM_LOCK_SHA_256)) {
        return false;
    }
    state->locked = true;
    return true;
}

void __weak pico_sha256_unlock(pico_sha256_state_t *state)
{
    assert(state->locked);
    bootrom_release_lock(BOOTROM_LOCK_SHA_256);
    state->locked = false;
}

void pico_sha256_cleanup(pico_sha256_state_t *state)
{
    if (state->locked) {
        pico_sha256_unlock(state);
    }
}

int pico_sha256_try_start(pico_sha256_state_t *state,
                          enum sha256_endianness endianness,
                          bool use_dma)
{
    (void)use_dma;

    memset(state, 0, sizeof(*state));
    if (!pico_sha256_lock(state)) {
        return PICO_ERROR_RESOURCE_IN_USE;
    }

    state->endianness = endianness;
    state->channel = -1;
    sha256_err_not_ready_clear();
    sha256_set_bswap(endianness == SHA256_BIG_ENDIAN);
    sha256_start();
    state->total_data_size = 0;
    return PICO_OK;
}

int pico_sha256_start_blocking_until(pico_sha256_state_t *state,
                                     enum sha256_endianness endianness,
                                     bool use_dma,
                                     absolute_time_t until)
{
    int rc;

    (void)until;

    do {
        rc = pico_sha256_try_start(state, endianness, use_dma);
    } while (rc == PICO_ERROR_RESOURCE_IN_USE);

    return rc;
}

static void write_to_hardware(pico_sha256_state_t *state,
                              const uint8_t *data,
                              size_t data_size_bytes)
{
    if (!state->cache_used && !(((uintptr_t)data) & 3u)) {
        GCC_Like_Pragma("GCC diagnostic ignored \"-Wcast-align\"")
        const uint32_t *data32 = (const uint32_t *)data;

        while (data_size_bytes >= 4) {
            sha256_wait_ready_blocking();
            sha256_put_word(*data32++);
            data_size_bytes -= 4;
        }

        data = (const uint8_t *)data32;
    }

    while (data_size_bytes--) {
        state->cache.bytes[state->cache_used++] = *data++;
        if (state->cache_used == 4) {
            state->cache_used = 0;
            sha256_wait_ready_blocking();
            sha256_put_word(state->cache.word);
        }
    }
}

static void update_internal(pico_sha256_state_t *state,
                            const uint8_t *data,
                            size_t data_size_bytes)
{
    size_t bytes_left;

    assert(state->locked);

    bytes_left = ((state->total_data_size + (SHA256_BLOCK_SIZE_BYTES - 1)) &
                  ~(SHA256_BLOCK_SIZE_BYTES - 1)) -
                 state->total_data_size;
    if (bytes_left > data_size_bytes) {
        bytes_left = data_size_bytes;
    }

    if (bytes_left > 0) {
        write_to_hardware(state, data, bytes_left);
        state->total_data_size += bytes_left;
        data_size_bytes -= bytes_left;
        data += bytes_left;
    }

    if (data_size_bytes > 0) {
        write_to_hardware(state, data, data_size_bytes);
        state->total_data_size += data_size_bytes;
    }
}

static void add_zero_bytes(pico_sha256_state_t *state, size_t data_size_bytes)
{
    uint32_t zero = 0;

    assert(data_size_bytes < INT32_MAX);
    while ((int32_t)data_size_bytes > 0) {
        update_internal(state, (uint8_t *)&zero, MIN(4, data_size_bytes));
        data_size_bytes -= 4;
    }
}

void pico_sha256_update(pico_sha256_state_t *state,
                        const uint8_t *data,
                        size_t data_size_bytes)
{
    update_internal(state, data, data_size_bytes);
}

void pico_sha256_update_blocking(pico_sha256_state_t *state,
                                 const uint8_t *data,
                                 size_t data_size_bytes)
{
    update_internal(state, data, data_size_bytes);
}

static void write_padding(pico_sha256_state_t *state)
{
    uint64_t size;
    size_t user_data_size = state->total_data_size;
    size_t padding_size_bytes;
    const uint8_t one_bit = 0x80;

    size = (state->total_data_size + SHA256_PADDING_DATA_BYTES +
            (SHA256_BLOCK_SIZE_BYTES - 1)) &
           ~(SHA256_BLOCK_SIZE_BYTES - 1);
    padding_size_bytes = size - state->total_data_size;

    update_internal(state, &one_bit, 1);
    add_zero_bytes(state, padding_size_bytes - SHA256_PADDING_DATA_BYTES);

    size = __builtin_bswap64(user_data_size * 8);
    update_internal(state, (uint8_t *)&size, sizeof(uint64_t));
}

static void trusted_sha256_get_result(sha256_result_t *out,
                                      enum sha256_endianness endianness)
{
    for (uint i = 0; i < count_of(out->words); ++i) {
        uint32_t data = sha256_hw->sum[i];
        if (endianness == SHA256_BIG_ENDIAN) {
            data = __builtin_bswap32(data);
        }
        out->words[i] = data;
    }
}

void pico_sha256_finish(pico_sha256_state_t *state, sha256_result_t *out)
{
    assert(state->locked);

    if (out) {
        write_padding(state);
        sha256_wait_valid_blocking();
        trusted_sha256_get_result(out, state->endianness);
    }

    pico_sha256_unlock(state);
}
