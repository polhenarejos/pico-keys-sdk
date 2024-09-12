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

#ifndef _SHA256_ALT_H_
#define _SHA256_ALT_H_

#include "pico_keys.h"
#include "pico/sha256.h"

typedef struct mbedtls_sha256_context {
    pico_sha256_state_t MBEDTLS_PRIVATE(pico_state);
#if defined(MBEDTLS_SHA224_C)
    unsigned char MBEDTLS_PRIVATE(buffer)[64];   /*!< The data block being processed. */
    uint32_t MBEDTLS_PRIVATE(total)[2];          /*!< The number of Bytes processed.  */
    uint32_t MBEDTLS_PRIVATE(state)[8];          /*!< The intermediate digest state.  */
    int MBEDTLS_PRIVATE(is224);                  /*!< Determines which function to use:
                                                    0: Use SHA-256, or 1: Use SHA-224. */
#endif
}
mbedtls_sha256_context;

#endif /* _SHA256_ALT_H_ */
