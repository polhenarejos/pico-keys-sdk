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
#include <poll.h>

#include "hsm.h"
#include "apdu.h"
#include "usb.h"
#include "ccid/ccid.h"

int ccid_sock = 0;
int hid_server_sock = 0;
int hid_client_sock = -1;

int msleep(long msec) {
    struct timespec ts;
    int res;

    if (msec < 0) {
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
    if ((ccid_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(ccid_sock);
        return -1;
    }

    if (connect(ccid_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(ccid_sock);
        return -1;
    }
    int x = fcntl(ccid_sock, F_GETFL, 0);
    fcntl(ccid_sock, F_SETFL, x | O_NONBLOCK);

    // HID server

    socklen_t yes = 1;
    uint16_t hid_port = port - 1;
    struct sockaddr_in server_sockaddr;

    if ((hid_server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(hid_server_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &yes, sizeof yes) != 0) {
        perror("setsockopt");
        close(hid_server_sock);
        return 1;
    }

#if HAVE_DECL_SO_NOSIGPIPE
    if (setsockopt(hid_server_sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &yes, sizeof yes) != 0) {
        perror("setsockopt");
        close(hid_server_sock);
        return 1;
    }
#endif

    memset(&server_sockaddr, 0, sizeof server_sockaddr);
    server_sockaddr.sin_family = PF_INET;
    server_sockaddr.sin_port = htons(hid_port);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(hid_server_sock, (struct sockaddr *) &server_sockaddr,
                sizeof server_sockaddr) != 0)  {
        perror("bind");
        close(hid_server_sock);
        return 1;
    }

    if (listen(hid_server_sock, 0) != 0) {
        perror("listen");
        close(hid_server_sock);
        return 1;
    }
    return 0;
}

uint8_t *driver_prepare_response_emul(uint8_t itf) {
    apdu.rdata = usb_get_tx(itf);
    return apdu.rdata;
}

int get_sock_itf(uint8_t itf) {
    if (itf == ITF_CCID)
        return ccid_sock;
    else if (itf == ITF_HID)
        return hid_client_sock;
    return -1;
}

int driver_write_emul(uint8_t itf, const uint8_t *buffer, size_t buffer_size) {
    uint16_t size = htons(buffer_size);
    int sock = get_sock_itf(itf);
    // DEBUG_PAYLOAD(buffer,buffer_size);
    int ret = 0;
    do {
        ret = send(sock, &size, sizeof(size), 0);
        if (ret < 0) {
            msleep(10);
        }
    } while (ret <= 0);
    do {
        ret = send(sock, buffer, (uint16_t) buffer_size, 0);
        if (ret < 0) {
            msleep(10);
        }
    } while (ret <= 0);
    return buffer_size;
}

uint32_t emul_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    if (size > 0) {
        //DEBUG_PAYLOAD(usb_get_tx(itf)+offset, size);
        return usb_write_offset(itf, size, offset);
    }
    return 0;
}

uint32_t emul_write(uint8_t itf, uint16_t size) {
    return emul_write_offset(itf, size, 0);
}

void driver_exec_finished_cont_emul(uint8_t itf, size_t size_next, size_t offset) {
    emul_write_offset(itf, size_next, offset);
}

int driver_process_usb_packet_emul(uint8_t itf, uint16_t len) {
    if (len > 0) {
        uint8_t *data = usb_get_rx(itf), *rdata = usb_get_tx(itf);
        if (itf == ITF_CCID) {
            if (len == 1) {
                uint8_t c = data[0];
                if (c == 4) {
                    if (ccid_atr) {
                        memcpy(rdata, ccid_atr + 1, ccid_atr[0]);
                    }
                    emul_write(itf, ccid_atr ? ccid_atr[0] : 0);
                }
            }
            else {
                DEBUG_PAYLOAD(data, len);
                if (apdu_process(itf, data, len) > 0) {
                    process_apdu();
                }
                apdu_finish();
                size_t ret = apdu_next();
                DEBUG_PAYLOAD(rdata, ret);
                emul_write(itf, ret);
            }
        }
        else if (itf == ITF_HID) {

        }
    }
    usb_clear_rx(itf);
    return 0;
}

uint16_t emul_read(uint8_t itf) {
    /* First we look for a client */
    if (itf == ITF_HID && hid_client_sock == -1) {
        struct sockaddr_in client_sockaddr;
        socklen_t client_socklen = sizeof client_sockaddr;

        int timeout;
        struct pollfd pfd;

        pfd.fd = hid_server_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        timeout = (0 * 1000 + 1000 / 1000);

        if (poll(&pfd, 1, timeout) == -1)
            return 0;

        if(pfd.revents & POLLIN)
            hid_client_sock = accept(hid_server_sock, (struct sockaddr *) &client_sockaddr,
                    &client_socklen);
    }
    int sock = get_sock_itf(itf);
    uint16_t len = 0;
    fd_set input;
    FD_ZERO(&input);
    FD_SET(sock, &input);
    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0 * 1000;
    int n = select(sock + 1, &input, NULL, NULL, &timeout);
    if (n == -1) {
        //printf("read wrong [itf:%d]\n", itf);
        //something wrong
    }
    else if (n == 0) {
        //printf("read timeout [itf:%d]\n", itf);
    }
    if (FD_ISSET(sock, &input)) {
        int valread = recv(sock, &len, sizeof(len), 0);
        len = ntohs(len);
        if (len > 0) {
            while (true) {
                valread = recv(sock, usb_get_rx(itf), len, 0);
                if (valread > 0) {
                    return valread;
                }
                msleep(10);
            }
        }
    }
    return 0;
}
