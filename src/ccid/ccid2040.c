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

#include <stdio.h>

// Pico
#include "pico/stdlib.h"

// For memcpy
#include <string.h>

// Include descriptor struct definitions
#include "usb_common.h"
// USB register definitions from pico-sdk
#include "hardware/regs/usb.h"
// USB hardware struct definitions from pico-sdk
#include "hardware/structs/usb.h"
// For interrupt enable and numbers
#include "hardware/irq.h"
// For resetting the USB controller
#include "hardware/resets.h"

#include "pico/multicore.h"
#include "random.h"
#include "ccid2040.h"
#include "hardware/rtc.h"

extern void do_flash();
extern void low_flash_init();

static uint8_t itf_num;

#define USB_CCID_TIMEOUT (50)
static bool waiting_timeout = false;
const uint8_t *ccid_atr = NULL;
static uint32_t timeout = USB_CCID_TIMEOUT;
static uint32_t timeout_cnt = 0;
static uint32_t prev_millis = 0;

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE+20+9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE+20+9)
#endif

#define CCID_SET_PARAMS		0x61 /* non-ICCD command  */
#define CCID_POWER_ON		0x62
#define CCID_POWER_OFF		0x63
#define CCID_SLOT_STATUS	0x65 /* non-ICCD command */
#define CCID_SECURE		0x69 /* non-ICCD command */
#define CCID_GET_PARAMS		0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS	0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK		0x6F
#define CCID_DATA_BLOCK_RET	0x80
#define CCID_SLOT_STATUS_RET	0x81 /* non-ICCD result */
#define CCID_PARAMS_RET		0x82 /* non-ICCD result */

#define CCID_MSG_SEQ_OFFSET	6
#define CCID_MSG_STATUS_OFFSET	7
#define CCID_MSG_ERROR_OFFSET	8
#define CCID_MSG_CHAIN_OFFSET	9
#define CCID_MSG_DATA_OFFSET	10	/* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE	USB_BUF_SIZE

#define CCID_STATUS_RUN		0x00
#define CCID_STATUS_PRESENT	0x01
#define CCID_STATUS_NOTPRESENT	0x02
#define CCID_CMD_STATUS_OK	0x00
#define CCID_CMD_STATUS_ERROR	0x40
#define CCID_CMD_STATUS_TIMEEXT	0x80

#define CCID_ERROR_XFR_OVERRUN	0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8

static app_t apps[4];
static uint8_t num_apps = 0;

app_t *current_app = NULL;

extern void card_thread();

extern void low_flash_init_core1();

int register_app(app_t * (*select_aid)()) {
    if (num_apps < sizeof(apps)/sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        num_apps++;
        return 1;
    }
    return 0;
}

#define CCID_THREAD_TERMINATED 0xffff
#define CCID_ACK_TIMEOUT 0x6600

static uint32_t blink_interval_ms = BLINK_NOT_MOUNTED;

void led_set_blink(uint32_t mode) {
    blink_interval_ms = mode;
}

void execute_tasks();

#include "hardware/structs/ioqspi.h"
#define BUTTON_STATE_ACTIVE   0

bool __no_inline_not_in_flash_func(get_bootsel_button)() {
    const uint CS_PIN_INDEX = 1;

    // Must disable interrupts, as interrupt handlers may be in flash, and we
    // are about to temporarily disable flash access!
    uint32_t flags = save_and_disable_interrupts();

    // Set chip select to Hi-Z
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // Note we can't call into any sleep functions in flash right now
    for (volatile int i = 0; i < 1000; ++i);

    // The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
    // Note the button pulls the pin *low* when pressed.
    bool button_state = (sio_hw->gpio_hi_in & (1u << CS_PIN_INDEX));

    // Need to restore the state of chip select, else we are going to have a
    // bad time when we return to code in flash!
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}

static uint32_t board_button_read(void)
{
    return BUTTON_STATE_ACTIVE == get_bootsel_button();
}

static bool wait_button() {
    uint32_t start_button = board_millis();
    bool timeout = false;
    led_set_blink((1000 << 16) | 100);
    
    while (board_button_read() == false) {
        execute_tasks();
        //sleep_ms(10);
        if (start_button + 15000 < board_millis()) { /* timeout */
            timeout = true;
            break;
        }
    }
    if (!timeout) {
        while (board_button_read() == true) {
            execute_tasks();
            //sleep_ms(10);
            if (start_button + 15000 < board_millis()) { /* timeout */
                timeout = true;
                break;
            }
        }
    }
    led_set_blink(BLINK_PROCESSING);
    return timeout;
}

struct ccid_header {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t *apdu;
} __packed;

queue_t ccid_to_card_q;
queue_t card_to_ccid_q;


uint8_t ccid_status = 1;

void ccid_write_offset(uint16_t size, uint16_t offset) {
    DEBUG_PAYLOAD(usb_get_tx()+offset,size+10);
    usb_write_offset(size+10, offset);
}

void ccid_write(uint16_t size) {
    ccid_write_offset(size, 0);
}

uint8_t rx_copy[4096];
struct apdu apdu;
struct ccid_header *ccid_response;
struct ccid_header *ccid_header;
uint8_t *rdata_gr = NULL;
uint16_t rdata_bk = 0x0;
static int usb_event_handle() {
    uint16_t rx_read = usb_read_available();
    if (rx_read >= 10) {
        struct ccid_header *tccid = usb_get_rx();
        printf("%d %d %x\r\n",tccid->dwLength,rx_read-10,tccid->bMessageType);
        if (tccid->dwLength <= rx_read-10) {
            usb_read(rx_copy, sizeof(rx_copy));
            DEBUG_PAYLOAD(rx_copy,rx_read);
            if (ccid_header->bMessageType == 0x65) {
                ccid_response->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response->dwLength = 0;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = ccid_status;
                ccid_response->abRFU1 = 0;
                ccid_write(0);
            }
            else if (ccid_header->bMessageType == 0x62) {
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_response->bMessageType = 0x80;
                ccid_response->dwLength = size_atr;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = 0;
                ccid_response->abRFU1 = 0;
                printf("1 %x %x %x || %x %x %x\r\n",ccid_response->apdu,apdu.rdata,ccid_response,ccid_header,ccid_header->apdu,apdu.data);
                memcpy(apdu.rdata, ccid_atr+1, size_atr);
                printf("1\r\n");
                multicore_reset_core1();
                printf("1\r\n");
                multicore_launch_core1(card_thread);
                printf("1\r\n");
                led_set_blink(BLINK_MOUNTED);
                ccid_status = 0;
                ccid_write(size_atr);
            }
            else if (ccid_header->bMessageType == 0x63) {
                ccid_status = 1;
                ccid_response->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_response->dwLength = 0;
                ccid_response->bSlot = 0;
                ccid_response->bSeq = ccid_header->bSeq;
                ccid_response->abRFU0 = ccid_status;
                ccid_response->abRFU1 = 0;
                uint32_t flag = EV_EXIT;
                queue_try_add(&ccid_to_card_q, &flag);
                led_set_blink(BLINK_SUSPENDED);
                ccid_write(0);
            }
            else if (ccid_header->bMessageType == 0x6F) {
                apdu.nc = apdu.ne = 0;
                printf("6f %d %x\n",ccid_header->dwLength,ccid_header->apdu);
                DEBUG_PAYLOAD(apdu.header,10);
                if (ccid_header->dwLength == 4) {
                    apdu.nc = apdu.ne = 0;
                    if (apdu.ne == 0)
                        apdu.ne = 256;
                }
                else if (ccid_header->dwLength == 5) {
                    apdu.nc = 0;
                    apdu.ne = apdu.header[4];
                    if (apdu.ne == 0)
                        apdu.ne = 256;
                }
                else if (ccid_header->dwLength == 7) {
                    apdu.nc = 0;
                    apdu.ne = (apdu.header[5] << 8) | apdu.header[6];
                    if (apdu.ne == 0)
                        apdu.ne = 65536;
                }
                else if (apdu.header[4] == 0x0) {
                    apdu.nc = (apdu.header[5] << 8) | apdu.header[6];
                    apdu.data = apdu.header+7;
                    if (apdu.nc+7+2 == ccid_header->dwLength) {
                        apdu.ne = (apdu.header[ccid_header->dwLength-2] << 8) | apdu.header[ccid_header->dwLength-1];
                        if (apdu.ne == 0)
                            apdu.ne = 65536;
                    }
                }
                else {
                    apdu.nc = apdu.header[4];
                    apdu.data = apdu.header+5;
                    apdu.ne = 0;
                    if (apdu.nc+5+2 == ccid_header->dwLength) {
                        apdu.ne = apdu.header[ccid_header->dwLength-1];
                        if (apdu.ne == 0)
                            apdu.ne = 256;
                    }
                }
                printf("apdu.nc %d, apdu.ne %d\r\n",apdu.nc,apdu.ne);
                if (apdu.header[1] == 0xc0) {
                    printf("apdu.ne %d, apdu.rlen %d, bk %x\r\n",apdu.ne,apdu.rlen,rdata_bk);
                    ccid_response = rdata_gr-10;
                    *(uint16_t *)rdata_gr = rdata_bk;
                    if (apdu.rlen <= apdu.ne) {
                        ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
                        ccid_response->dwLength = apdu.rlen+2;
                        ccid_response->bSlot = 0;
                        ccid_response->bSeq = ccid_header->bSeq;
                        ccid_response->abRFU0 = ccid_status;
                        ccid_response->abRFU1 = 0;
                        ccid_write_offset(apdu.rlen+2, rdata_gr-10-usb_get_tx());
                    }
                    else {
                        ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
                        ccid_response->dwLength = apdu.ne+2;
                        ccid_response->bSlot = 0;
                        ccid_response->bSeq = ccid_header->bSeq;
                        ccid_response->abRFU0 = ccid_status;
                        ccid_response->abRFU1 = 0;
                        rdata_gr += apdu.ne;
                        rdata_bk = *rdata_gr;
                        rdata_gr[0] = 0x61;
                        if (apdu.rlen - apdu.ne >= 256)
                            rdata_gr[1] = 0;
                        else
                            rdata_gr[1] = apdu.rlen - apdu.ne;
                        ccid_write_offset(apdu.ne+2, rdata_gr-10-usb_get_tx());
                        apdu.rlen -= apdu.ne;
                    }
                }
                else {
                    apdu.sw = 0;
                    apdu.rlen = 0;
                    ccid_response = usb_get_tx();
                    ccid_response->apdu = usb_get_tx()+10;
                    apdu.rdata = ccid_response->apdu;
                    rdata_gr = apdu.rdata;
                    uint32_t flag = EV_CMD_AVAILABLE;
                    queue_add_blocking(&ccid_to_card_q, &flag);
                    timeout = 0;
            	    timeout_cnt = 0;
            	    waiting_timeout = true;
                }
            }
        }
    }
    /*
    if (usb_read_available() && c->epo->ready) {
        if ()
        uint32_t count = usb_read(endp1_rx_buf, sizeof(endp1_rx_buf));
        //if (endp1_rx_buf[0] != 0x65)
            DEBUG_PAYLOAD(endp1_rx_buf, count);
        //DEBUG_PAYLOAD(endp1_rx_buf, count);
        ccid_rx_ready(count);
    }
    */
    return 0;
}

int process_apdu() {
    led_set_blink(BLINK_PROCESSING);
    if (!current_app) {
        if (INS(apdu) == 0xA4 && P1(apdu) == 0x04 && (P2(apdu) == 0x00 || P2(apdu) == 0x4)) { //select by AID
            for (int a = 0; a < num_apps; a++) {
                if ((current_app = apps[a].select_aid(&apps[a]))) {
                    return set_res_sw(0x90,0x00);
                }
            }
        }
        return set_res_sw(0x6a, 0x82);
    }
    if (current_app->process_apdu)
        return current_app->process_apdu();
    return set_res_sw (0x6D, 0x00);
}

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = (sw1 << 8) | sw2;
    return make_uint16_t(sw1, sw2);
}

static void card_init(void) {
    //gpg_data_scan (flash_do_start, flash_do_end);
    low_flash_init_core1();
}

void card_thread() {
    card_init ();

    while (1) {    
        uint32_t m;
        queue_remove_blocking(&ccid_to_card_q, &m);
        
        if (m == EV_VERIFY_CMD_AVAILABLE || m == EV_MODIFY_CMD_AVAILABLE)
	    {
	        set_res_sw (0x6f, 0x00);
	        goto done;
	    }
        else if (m == EV_EXIT) {
            if (current_app && current_app->unload)
                current_app->unload();
	        break;
	    }

        process_apdu();
        
        done:;
        uint32_t flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_ccid_q, &flag);
    }
    printf("EXIT !!!!!!\r\n");
    if (current_app && current_app->unload)
        current_app->unload();
}

void ccid_task(void) {
    if (usb_is_configured()) {
        if (usb_event_handle() != 0) {
            
        }
        if (timeout == 0) {
    	    timeout = USB_CCID_TIMEOUT;
    	    timeout_cnt++;
        }
        uint32_t m = 0x0;
        bool has_m = queue_try_remove(&card_to_ccid_q, &m);
        if (m != 0)
            printf("\r\n ------ M = %d\r\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                printf("sw %x %d, %d\r\n",apdu.sw,apdu.rlen,apdu.ne);
                apdu.rdata[apdu.rlen] = apdu.sw >> 8;
                apdu.rdata[apdu.rlen+1] = apdu.sw & 0xff;
                waiting_timeout = false;
                if (apdu.rlen <= apdu.ne) {
                    ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
                    ccid_response->dwLength = apdu.rlen+2;
                    ccid_response->bSlot = 0;
                    ccid_response->bSeq = ccid_header->bSeq;
                    ccid_response->abRFU0 = ccid_status;
                    ccid_response->abRFU1 = 0;
                    ccid_write(apdu.rlen+2);
                }
                else {
                    ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
                    ccid_response->dwLength = apdu.ne+2;
                    ccid_response->bSlot = 0;
                    ccid_response->bSeq = ccid_header->bSeq;
                    ccid_response->abRFU0 = ccid_status;
                    ccid_response->abRFU1 = 0;
                    rdata_gr = apdu.rdata+apdu.ne;
                    rdata_bk = *(uint16_t *)rdata_gr;
                    rdata_gr[0] = 0x61;
                    if (apdu.rlen - apdu.ne >= 256)
                        rdata_gr[1] = 0;
                    else
                        rdata_gr[1] = apdu.rlen - apdu.ne;
                    ccid_write(apdu.ne+2);
                    apdu.rlen -= apdu.ne;
                }
                led_set_blink(BLINK_MOUNTED);
            }
            /*
            if (m == EV_RX_DATA_READY) {
        	    c->ccid_state = ccid_handle_data(c);
        	    timeout = 0;
        	    c->timeout_cnt = 0;
        	}
            else if (m == EV_EXEC_FINISHED) {
	            if (c->ccid_state == CCID_STATE_EXECUTE) {
	                exec_done:
            	    if (c->a->sw == CCID_THREAD_TERMINATED) {
                		c->sw1sw2[0] = 0x90;
                		c->sw1sw2[1] = 0x00;
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_EXITED;
                		c->application = 0;
                		return;
            	    }

            	    c->a->cmd_apdu_data_len = 0;
            	    c->sw1sw2[0] = c->a->sw >> 8;
            	    c->sw1sw2[1] = c->a->sw & 0xff;
            	    if (c->a->res_apdu_data_len <= c->a->expected_res_size) {
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	    else {
                		c->state = APDU_STATE_RESULT_GET_RESPONSE;
                		c->p = c->a->res_apdu_data;
                		c->len = c->a->res_apdu_data_len;
                		ccid_send_data_block_gr(c, c->a->expected_res_size);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	}
            	else {
        	        DEBUG_INFO ("ERR05\r\n");
        	    }
        	    led_set_blink(BLINK_MOUNTED);
            }
            else if (m == EV_TX_FINISHED){
        	    if (c->state == APDU_STATE_RESULT)
        	        ccid_reset(c);
        	    else
        	        c->tx_busy = 0;
        	    if (c->state == APDU_STATE_WAIT_COMMAND || c->state == APDU_STATE_COMMAND_CHAINING || c->state == APDU_STATE_RESULT_GET_RESPONSE)
        	        ccid_prepare_receive(c);
        	}
        	else if (m == EV_PRESS_BUTTON) {
        	    uint32_t flag = wait_button() ? EV_BUTTON_TIMEOUT : EV_BUTTON_PRESSED;
        	    queue_try_add(&c->card_comm, &flag);
        	}
        	*/
        }
        else {
            if (waiting_timeout) {
                timeout -= MIN(board_millis()-prev_millis,timeout);
                if (timeout == 0) {
                    if (timeout_cnt == 7) {
        
                    }
                    else {
                        ccid_response->bMessageType = CCID_DATA_BLOCK_RET;
                        ccid_response->dwLength = 0;
                        ccid_response->bSlot = 0;
                        ccid_response->bSeq = ccid_header->bSeq;
                        ccid_response->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
                        ccid_response->abRFU1 = 0;
                        ccid_write(0);
                    }
                }
            }
        }
    }
}

void led_blinking_task() {
#ifdef PICO_DEFAULT_LED_PIN
    static uint32_t start_ms = 0;
    static uint8_t led_state = false;
    static uint8_t led_color = PICO_DEFAULT_LED_PIN;
#ifdef PICO_DEFAULT_LED_PIN_INVERTED
    uint32_t interval = !led_state ? blink_interval_ms & 0xffff : blink_interval_ms >> 16;
#else
    uint32_t interval = led_state ? blink_interval_ms & 0xffff : blink_interval_ms >> 16;
#endif
    

    // Blink every interval ms
    if (board_millis() - start_ms < interval)
        return; // not enough time
    start_ms += interval;

    gpio_put(led_color, led_state);
    led_state ^= 1; // toggle
#endif
}

void led_off_all() {
#ifdef PIMORONI_TINY2040
    gpio_put(TINY2040_LED_R_PIN, 1);
    gpio_put(TINY2040_LED_G_PIN, 1);
    gpio_put(TINY2040_LED_B_PIN, 1);
#else
#ifdef PICO_DEFAULT_LED_PIN
    gpio_put(PICO_DEFAULT_LED_PIN, 0);
#endif
#endif
}

int format_tlv_len(size_t len, uint8_t *out) {
    if (len < 128) {
        if (out)
            *out = len;
        return 1;
    }
    else if (len < 256) {
        if (out) {
            *out++ = 0x81;
            *out++ = len;
        }
        return 2;
    }
    else {
        if (out) {
            *out++ = 0x82;
            *out++ = (len >> 8) & 0xff;
            *out++ = len & 0xff;
        }
        return 3;
    }
    return 0;
}

int walk_tlv(const uint8_t *cdata, size_t cdata_len, uint8_t **p, uint8_t *tag, size_t *tag_len, uint8_t **data) {
    if (!p)
        return 0;
    if (!*p)
        *p = (uint8_t *)cdata;
    if (*p-cdata >= cdata_len)
        return 0;
    uint8_t tg = 0x0;
    size_t tgl = 0;
    tg = *(*p)++;
    tgl = *(*p)++;
    if (tgl == 0x82) {
        tgl = *(*p)++ << 8;
        tgl |= *(*p)++;
    }
    else if (tgl == 0x81) {
        tgl = *(*p)++;
    }
    if (tag)
        *tag = tg;
    if (tag_len)
        *tag_len = tgl;
    if (data)
        *data = *p;
    *p = *p+tgl;
    return 1;
}

void init_rtc() {
    
    rtc_init();
    datetime_t dt = {
            .year  = 2020,
            .month = 1,
            .day   = 1,
            .dotw  = 3, // 0 is Sunday, so 5 is Friday
            .hour  = 00,
            .min   = 00,
            .sec   = 00
    };
    rtc_set_datetime(&dt);
}

extern void neug_task();

pico_unique_board_id_t unique_id;

void execute_tasks() {
    prev_millis = board_millis();
    ccid_task();
    //tud_task(); // tinyusb device task
    led_blinking_task();
}

int main(void) {
    ccid_header = rx_copy;
    ccid_header->apdu = rx_copy+10;
    
    apdu.header = ccid_header->apdu;
        
    ccid_response = usb_get_tx();
    ccid_response->apdu = usb_get_tx()+10;
    apdu.rdata = ccid_response->apdu;
    
    queue_init(&card_to_ccid_q, sizeof(uint32_t), 64);
    queue_init(&ccid_to_card_q, sizeof(uint32_t), 64);

    //board_init();
    stdio_init_all();

#ifdef PIMORONI_TINY2040
    gpio_init(TINY2040_LED_R_PIN);
    gpio_set_dir(TINY2040_LED_R_PIN, GPIO_OUT);
    gpio_init(TINY2040_LED_G_PIN);
    gpio_set_dir(TINY2040_LED_G_PIN, GPIO_OUT);
    gpio_init(TINY2040_LED_B_PIN);
    gpio_set_dir(TINY2040_LED_B_PIN, GPIO_OUT);
#else
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif
#endif

    led_off_all();

    usb_init();

    //prepare_ccid();
    
    random_init();
    
    low_flash_init();
    
    init_rtc();
    
    //ccid_prepare_receive(&ccid);
      
    while (1) {
        execute_tasks();
        neug_task();
        do_flash();
    }

    return 0;
}