/*
 * This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
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

#include "emulation.h"
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "hsm.h"
#include "apdu.h"
#include "usb.h"
#include "ccid/ccid.h"

int sock = 0;

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

int emul_init(char *host, uint16_t port) {
    struct sockaddr_in serv_addr;
    fprintf(stderr, "\n Starting emulation envionrment\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "\nConnection Failed \n");
        return -1;
    }
    int x = fcntl(sock ,F_GETFL, 0);
    fcntl(sock, F_SETFL, x | O_NONBLOCK);
    return 0;
}

uint8_t *driver_prepare_response_emul() {
    apdu.rdata = usb_get_tx(ITF_EMUL);
    return apdu.rdata;
}

int driver_write_emul(const uint8_t *buffer, size_t buffer_size) {
    uint16_t size = htons(buffer_size);
    //DEBUG_PAYLOAD(buffer,buffer_size);
    int ret = 0;
    do {
        ret = send(sock, &size, sizeof(size), 0);
        if (ret < 0)
            msleep(10);
    } while(ret <= 0);
    do {
        ret = send(sock, buffer, (uint16_t)buffer_size, 0);
        if (ret < 0)
            msleep(10);
    } while(ret <= 0);
    return buffer_size;
}

uint32_t emul_write_offset(uint16_t size, uint16_t offset) {
    if (size > 0) {
        //DEBUG_PAYLOAD(usb_get_tx(ITF_EMUL)+offset, size);
        return usb_write_offset(ITF_EMUL, size, offset);
    }
    return 0;
}

uint32_t emul_write(uint16_t size) {
    return emul_write_offset(size, 0);
}

void driver_exec_finished_cont_emul(size_t size_next, size_t offset) {
    emul_write_offset(size_next, offset);
}

int driver_process_usb_packet_emul(uint16_t len) {
    if (len > 0) {
        uint8_t *data = usb_get_rx(ITF_EMUL), *rdata = usb_get_tx(ITF_EMUL);
        if (len == 1) {
            uint8_t c = data[0];
            if (c == 4) {
                if (ccid_atr)
                    memcpy(rdata, ccid_atr+1, ccid_atr[0]);
                emul_write(ccid_atr ? ccid_atr[0] : 0);
            }
        }
        else {
            DEBUG_PAYLOAD(data, len);
            if (apdu_process(ITF_EMUL, data, len) > 0)
                process_apdu();
            apdu_finish();
            size_t ret = apdu_next();
            DEBUG_PAYLOAD(rdata, ret);
            emul_write(ret);
        }
    }
    usb_clear_rx(ITF_EMUL);
    return 0;
}

uint16_t emul_read() {
    uint16_t len = 0;
    fd_set input;
    FD_ZERO(&input);
    FD_SET(sock, &input);
    struct timeval timeout;
    timeout.tv_sec  = 2;
    timeout.tv_usec = 0 * 1000;
    int n = select(sock + 1, &input, NULL, NULL, &timeout);
    if (n == -1) {
        printf("read wrong\n");
        //something wrong
    } else if (n == 0) {
        printf("read timeout\n");
    }
    if (FD_ISSET(sock, &input)) {
        int valread = recv(sock, &len, sizeof(len), 0);
        len = ntohs(len);
        if (len > 0) {
            while (true) {
                valread = recv(sock, usb_get_rx(ITF_EMUL), len, 0);
                if (valread > 0)
                    return valread;
                msleep(10);
            }
        }
    }
    return 0;
}
