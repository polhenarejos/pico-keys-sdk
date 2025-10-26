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

#ifndef _CCID_H_
#define _CCID_H_

extern const uint8_t historical_bytes[];

#define MAX_CMD_APDU_DATA_SIZE (24 + 4 + 512 * 4)
#define MAX_RES_APDU_DATA_SIZE (5 + 9 + 512 * 4)
#define CCID_MSG_HEADER_SIZE    10
#define USB_LL_BUF_SIZE         64

enum ccid_state {
    CCID_STATE_NOCARD,      /* No card available */
    CCID_STATE_START,       /* Initial */
    CCID_STATE_WAIT,        /* Waiting APDU */

    CCID_STATE_EXECUTE,     /* Executing command */
    CCID_STATE_ACK_REQUIRED_0,  /* Ack required (executing)*/
    CCID_STATE_ACK_REQUIRED_1,  /* Waiting user's ACK (execution finished) */

    CCID_STATE_EXITED,      /* CCID Thread Terminated */
    CCID_STATE_EXEC_REQUESTED,  /* Exec requested */
};

extern const uint8_t *ccid_atr;

#endif //_CCID_H_
