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

#ifndef _JSON_H_
#define _JSON_H_

#include "cJSON.h"

#define CJSON_ADD_GENERIC(hdl, ptr, item, value) do { \
    if (hdl(ptr, item, value) == NULL) { \
        response->status_code = 500; \
        return 1; \
    } \
} while(0)

#define CJSON_ADD_STRING(ptr, item, value) CJSON_ADD_GENERIC(cJSON_AddStringToObject, (ptr)->json, item, value)
#define CJSON_ADD_NUMBER(ptr, item, value) CJSON_ADD_GENERIC(cJSON_AddNumberToObject, (ptr)->json, item, value)

#endif // _JSON_H_
