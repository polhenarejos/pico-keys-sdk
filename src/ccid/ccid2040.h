/* 
 * This file is part of the Pico CCID distribution (https://github.com/polhenarejos/pico-ccid).
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

#ifndef _CCID2040_H_
#define _CCID2040_H_

#include "ccid.h"
#include "tusb.h"
#include "file.h"
#include "pico/unique_id.h"
#include "pico/util/queue.h"

#define USB_REQ_CCID        0xA1

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    struct app* (*select_aid)();
    int (*unload)();
} app_t;

extern int register_app(app_t * (*)());

extern const uint8_t historical_bytes[];

#define DEBUG_PAYLOAD(p,s) { \
    printf("Payload %s (%d bytes):\r\n", #p,s);\
    for (int i = 0; i < s; i += 16) {\
        printf("%07Xh : ",i+p);\
        for (int j = 0; j < 16; j++) {\
            if (j < s-i) printf("%02X ",(p)[i+j]);\
            else printf("   ");\
            if (j == 7) printf(" ");\
            } printf(":  "); \
        for (int j = 0; j < MIN(16,s-i); j++) {\
            printf("%c",(p)[i+j] == 0x0a || (p)[i+j] == 0x0d ? '\\' : (p)[i+j]);\
            if (j == 7) printf(" ");\
            }\
            printf("\r\n");\
        } printf("\r\n"); \
    }
    
struct apdu {
  uint8_t seq;

  /* command APDU */
  uint8_t *cmd_apdu_head;	/* CLS INS P1 P2 [ internal Lc ] */
  uint8_t *cmd_apdu_data;
  size_t cmd_apdu_data_len;	/* Nc, calculated by Lc field */
  size_t expected_res_size;	/* Ne, calculated by Le field */

  /* response APDU */
  uint16_t sw;
  uint16_t res_apdu_data_len;
  uint8_t *res_apdu_data;
};

#define MAX_CMD_APDU_DATA_SIZE (24+4+512*4)
#define MAX_RES_APDU_DATA_SIZE (5+9+512*4)
#define CCID_MSG_HEADER_SIZE    10
#define USB_LL_BUF_SIZE         64

/* CCID thread */
#define EV_CARD_CHANGE        1
#define EV_TX_FINISHED        2 /* CCID Tx finished  */
#define EV_EXEC_ACK_REQUIRED  4 /* OpenPGPcard Execution ACK required */
#define EV_EXEC_FINISHED      8 /* OpenPGPcard Execution finished */
#define EV_RX_DATA_READY     16 /* USB Rx data available  */
#define EV_PRESS_BUTTON      32

/* SC HSM thread */
#define EV_MODIFY_CMD_AVAILABLE   1
#define EV_VERIFY_CMD_AVAILABLE   2
#define EV_CMD_AVAILABLE          4
#define EV_EXIT                   8
#define EV_BUTTON_PRESSED        16

//Variables set by core1
extern queue_t *ccid_comm;
extern queue_t *card_comm;

enum ccid_state {
    CCID_STATE_NOCARD,		/* No card available */
    CCID_STATE_START,		/* Initial */
    CCID_STATE_WAIT,		/* Waiting APDU */
    
    CCID_STATE_EXECUTE,		/* Executing command */
    CCID_STATE_ACK_REQUIRED_0,	/* Ack required (executing)*/
    CCID_STATE_ACK_REQUIRED_1,	/* Waiting user's ACK (execution finished) */
    
    CCID_STATE_EXITED,		/* CCID Thread Terminated */
    CCID_STATE_EXEC_REQUESTED,	/* Exec requested */
};

#define CLA(a) a.cmd_apdu_head[0]
#define INS(a) a.cmd_apdu_head[1]
#define P1(a) a.cmd_apdu_head[2]
#define P2(a) a.cmd_apdu_head[3]

#define res_APDU apdu.res_apdu_data
#define res_APDU_size apdu.res_apdu_data_len

extern struct apdu apdu;

uint16_t set_res_sw (uint8_t sw1, uint8_t sw2);


static inline const uint16_t make_uint16_t(uint8_t b1, uint8_t b2) {
    return (b1 << 8) | b2;
}
static inline const uint16_t get_uint16_t(const uint8_t *b, uint16_t offset) {
    return make_uint16_t(b[offset], b[offset+1]);
}
static inline const void put_uint16_t(uint16_t n, uint8_t *b) {
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
}

extern const uint8_t *ccid_atr;


#ifdef DEBUG
void stdout_init (void);
#define DEBUG_MORE 1
/*
 * Debug functions in debug.c
 */
void put_byte (uint8_t b);
void put_byte_with_no_nl (uint8_t b);
void put_short (uint16_t x);
void put_word (uint32_t x);
void put_int (uint32_t x);
void put_string (const char *s);
void put_binary (const char *s, int len);

#define DEBUG_INFO(msg)	    put_string (msg)
#define DEBUG_WORD(w)	    put_word (w)
#define DEBUG_SHORT(h)	    put_short (h)
#define DEBUG_BYTE(b)       put_byte (b)
#define DEBUG_BINARY(s,len) put_binary ((const char *)s,len)
#else
#define DEBUG_INFO(msg)
#define DEBUG_WORD(w)
#define DEBUG_SHORT(h)
#define DEBUG_BYTE(b)
#define DEBUG_BINARY(s,len)
#endif

extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern void low_flash_available();
extern int flash_clear_file(file_t *file);

extern pico_unique_board_id_t unique_id;

enum  {
    BLINK_NOT_MOUNTED = (250 << 16) | 250,
    BLINK_MOUNTED     = (250 << 16) | 250,
    BLINK_SUSPENDED   = (500 << 16) | 1000,
    BLINK_PROCESSING  = (50 << 16) | 50,

    BLINK_ALWAYS_ON   = UINT32_MAX,
    BLINK_ALWAYS_OFF  = 0
};
extern void led_set_blink(uint32_t mode);


#define SW_BYTES_REMAINING_00()             set_res_sw (0x61, 0x00)
#define SW_WARNING_STATE_UNCHANGED()        set_res_sw (0x62, 0x00)
#define SW_WARNING_CORRUPTED()              set_res_sw (0x62, 0x81)
#define SW_WARNING_EOF()                    set_res_sw (0x62, 0x82)
#define SW_WARNING_EF_DEACTIVATED()         set_res_sw (0x62, 0x83)
#define SW_WARNING_WRONG_FCI()              set_res_sw (0x62, 0x84)
#define SW_WARNING_EF_TERMINATED()          set_res_sw (0x62, 0x85)

#define SW_WARNING_NOINFO()                 set_res_sw (0x63, 0x00)
#define SW_WARNING_FILLUP()                 set_res_sw (0x63, 0x81)

#define SW_EXEC_ERROR()                     set_res_sw (0x64, 0x00)

#define SW_MEMORY_FAILURE()                 set_res_sw (0x65, 0x81)

#define SW_SECURE_MESSAGE_EXEC_ERROR()      set_res_sw (0x66, 0x00)

#define SW_WRONG_LENGTH()                   set_res_sw (0x67, 0x00)
#define SW_WRONG_DATA()                     set_res_sw (0x67, 0x00)

#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED()  set_res_sw (0x68, 0x81)
#define SW_SECURE_MESSAGING_NOT_SUPPORTED() set_res_sw (0x68, 0x82)

#define SW_COMMAND_INCOMPATIBLE()           set_res_sw (0x69, 0x81)
#define SW_SECURITY_STATUS_NOT_SATISFIED()  set_res_sw (0x69, 0x82)
#define SW_PIN_BLOCKED()                    set_res_sw (0x69, 0x83)
#define SW_DATA_INVALID()                   set_res_sw (0x69, 0x84)
#define SW_CONDITIONS_NOT_SATISFIED()       set_res_sw (0x69, 0x85)
#define SW_COMMAND_NOT_ALLOWED()            set_res_sw (0x69, 0x86)
#define SW_SECURE_MESSAGING_MISSING_DO()    set_res_sw (0x69, 0x87)
#define SW_SECURE_MESSAGING_INCORRECT_DO()  set_res_sw (0x69, 0x88)
#define SW_APPLET_SELECT_FAILED()           set_res_sw (0x69, 0x99)

#define SW_INCORRECT_PARAMS()               set_res_sw (0x6A, 0x80)
#define SW_FUNC_NOT_SUPPORTED()             set_res_sw (0x6A, 0x81)
#define SW_FILE_NOT_FOUND()                 set_res_sw (0x6A, 0x82)
#define SW_RECORD_NOT_FOUND()               set_res_sw (0x6A, 0x83)
#define SW_FILE_FULL()                      set_res_sw (0x6A, 0x84)
#define SW_WRONG_NE()                       set_res_sw (0x6A, 0x85)
#define SW_INCORRECT_P1P2()                 set_res_sw (0x6A, 0x86)
#define SW_WRONG_NC()                       set_res_sw (0x6A, 0x87)
#define SW_REFERENCE_NOT_FOUND()            set_res_sw (0x6A, 0x88)
#define SW_FILE_EXISTS()                    set_res_sw (0x6A, 0x89)

#define SW_WRONG_P1P2()                     set_res_sw (0x6B, 0x00)

#define SW_CORRECT_LENGTH_00()              set_res_sw (0x6C, 0x00)

#define SW_INS_NOT_SUPPORTED()              set_res_sw (0x6D, 0x00)

#define SW_CLA_NOT_SUPPORTED()              set_res_sw (0x6E, 0x00)

#define SW_UNKNOWN()                        set_res_sw (0x6F, 0x00)

#define SW_OK()                             set_res_sw (0x90, 0x00)

#define CCID_OK                              0
#define CCID_ERR_NO_MEMORY                   -1000
#define CCID_ERR_MEMORY_FATAL                -1001
#define CCID_ERR_NULL_PARAM                  -1002
#define CCID_ERR_FILE_NOT_FOUND              -1003
#define CCID_ERR_BLOCKED                     -1004
#define CCID_NO_LOGIN                        -1005
#define CCID_EXEC_ERROR                      -1006
#define CCID_WRONG_LENGTH                    -1007
#define CCID_WRONG_DATA                      -1008
#define CCID_WRONG_DKEK                      -1009
#define CCID_WRONG_SIGNATURE                 -1010
#define CCID_WRONG_PADDING                   -1011
#define CCID_VERIFICATION_FAILED             -1012

extern int walk_tlv(const uint8_t *cdata, size_t cdata_len, uint8_t **p, uint8_t *tag, size_t *tag_len, uint8_t **data);
extern int format_tlv_len(size_t len, uint8_t *out);

#endif