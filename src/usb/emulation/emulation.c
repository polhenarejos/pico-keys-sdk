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

#include "pico_keys.h"
#include "emulation.h"
#include <stdio.h>
#ifndef _MSC_VER
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netinet/tcp.h>
typedef int socket_t;
#include <fcntl.h>
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#else
#include <ws2tcpip.h>
#define O_NONBLOCK _O_NONBLOCK
#define close closesocket
typedef SOCKET socket_t;
typedef int socklen_t;
#define msleep Sleep
#pragma comment(lib, "Ws2_32.lib")
#endif
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "apdu.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "hid/ctap_hid.h"

socket_t ccid_sock = 0;
socket_t hid_server_sock = 0;
socket_t hid_client_sock = INVALID_SOCKET;
extern uint8_t thread_type;
extern const uint8_t *cbor_data;
extern size_t cbor_len;
extern uint8_t cmd;
uint8_t emul_rx[USB_BUFFER_SIZE], emul_tx[USB_BUFFER_SIZE];
uint16_t emul_rx_size = 0, emul_tx_size = 0;
extern int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len);
pthread_t hcore0, hcore1;

#ifndef _MSC_VER
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
#endif

int emul_init(char *host, uint16_t port) {
    struct sockaddr_in serv_addr;
    fprintf(stderr, "\n Starting emulation envionrment\n");
#ifdef _MSC_VER
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("winsock initialization failure\n");
    }
#endif
    if ((ccid_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
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
#ifdef _MSC_VER
    unsigned long on = 1;
    if (0 != ioctlsocket(ccid_sock, FIONBIO, &on)) {
        perror("ioctlsocket FIONBIO");
    }
#else
    int x = fcntl(ccid_sock, F_GETFL, 0);
    fcntl(ccid_sock, F_SETFL, x | O_NONBLOCK);
    int flag = 1;
    setsockopt(ccid_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif

    // HID server

    socklen_t yes = 1;
    uint16_t hid_port = port - 1;
    struct sockaddr_in server_sockaddr;

    if ((hid_server_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        perror("socket");
        return -1;
    }

    if (setsockopt(hid_server_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &yes, sizeof yes) != 0) {
        perror("setsockopt");
        close(hid_server_sock);
        return 1;
    }

#if defined(HAVE_DECL_SO_NOSIGPIPE)
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
             sizeof server_sockaddr) != 0) {
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

socket_t get_sock_itf(uint8_t itf) {
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        return ccid_sock;
    }
#endif
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        return hid_client_sock;
    }
#endif
    return INVALID_SOCKET;
}

uint32_t tud_vendor_n_write(uint8_t itf, const uint8_t *buffer, uint32_t n) {
    uint16_t ret = driver_write_emul(ITF_CCID, buffer, (uint16_t)n);
    tud_vendor_tx_cb(itf, ret);
    return ret;
}

#ifdef USB_ITF_HID
bool tud_hid_n_report(uint8_t itf, uint8_t report_id, const uint8_t *buffer, uint32_t n) {
    (void) itf;
    (void) report_id;
    uint16_t ret = driver_write_emul(ITF_HID, buffer, (uint16_t)n);
    return ret > 0;
}
#endif

uint16_t driver_write_emul(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    uint16_t size = htons(buffer_size);
    socket_t sock = get_sock_itf(itf);
    // DEBUG_PAYLOAD(buffer,buffer_size);
    int ret = 0;
    do {
        ret = send(sock, (const char *)&size, sizeof(size), 0);
        if (ret == SOCKET_ERROR) {
            msleep(10);
        }
    } while (ret <= 0);
    do {
        ret = send(sock, (const char *)buffer, buffer_size, 0);
        if (ret == SOCKET_ERROR) {
            msleep(10);
        }
    } while (ret <= 0);
    emul_tx_size = buffer_size;
    return buffer_size;
}

void driver_exec_finished_cont_emul(uint8_t itf, uint16_t size_next, uint16_t offset) {
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        driver_exec_finished_cont_hid(itf, size_next, offset);
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        driver_write_emul(itf, emul_tx + offset, size_next);
    }
#endif
}

uint16_t emul_read(uint8_t itf) {
    /* First we look for a client */
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        struct sockaddr_in client_sockaddr;
        socklen_t client_socklen = sizeof client_sockaddr;

        int timeout;
        struct pollfd pfd;

        pfd.fd = hid_server_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        timeout = (0 * 1000 + 1000 / 1000);

        if (poll(&pfd, 1, timeout) == -1) {
            return 0;
        }

        if (pfd.revents & POLLIN) {
            if (hid_client_sock > 0) {
                close(hid_client_sock);
            }
            hid_client_sock = accept(hid_server_sock, (struct sockaddr *) &client_sockaddr, &client_socklen);
            if (hid_client_sock != INVALID_SOCKET) {
                printf("hid_client connected! %d\n", hid_client_sock);
            }
        }
        /*if (send_buffer_size > 0) {
            last_write_result[itf] = WRITE_PENDING;
            tud_hid_report_complete_cb(ITF_HID, complete_report, complete_len);
        }*/
    }
#endif
    socket_t sock = get_sock_itf(itf);
    //printf("get_sockt itf %d - %d\n", itf, sock);
    uint16_t len = 0;
    fd_set input;
    FD_ZERO(&input);
#ifdef _WIN32
    __pragma(warning(push))
    __pragma(warning(disable:4548))
#endif
    FD_SET(sock, &input);
#ifdef _WIN32
    __pragma(warning(pop))
#endif
    struct timeval timeout;
    int valread = 0;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0 * 1000;
    int n = select((int)(sock + 1), &input, NULL, NULL, &timeout);
    if (n == -1) {
        //printf("read wrong [itf:%d]\n", itf);
        //something wrong
    }
    else if (n == 0) {
        //printf("read timeout [itf:%d]\n", itf);
    }
    if (FD_ISSET(sock, &input)) {
        valread = recv(sock, (char *)&len, sizeof(len), 0);
        len = ntohs(len);
        if (len > 0) {
            while (true) {
                valread = recv(sock, (char *)emul_rx + emul_rx_size, len, 0);
                if (valread > 0) {
                    if (len == 1) {
                        uint8_t c = emul_rx[0];
                        if (c == 4) {
                            driver_write_emul(itf, ccid_atr ? ccid_atr + 1 : NULL, ccid_atr ? ccid_atr[0] : 0);
                        }
                    }
#ifdef USB_ITF_CCID
                    else if (itf == ITF_CCID) {
                        uint16_t sent = 0;
                        DEBUG_PAYLOAD(emul_rx, len);
                        apdu.rdata = emul_tx;
                        if ((sent = apdu_process(itf, emul_rx, len)) > 0) {
                            process_apdu();
                            apdu_finish();
                        }
                        if (sent > 0) {
                            uint16_t ret = apdu_next();
                            DEBUG_PAYLOAD(apdu.rdata, ret);
                            driver_write_emul(itf, apdu.rdata, ret);
                        }
                    }
#endif
                    else {
                        emul_rx_size += valread;
                    }
                    return (uint16_t)emul_rx_size;
                }
                msleep(10);
            }
        }
    }
    //else
    //    printf("no input for sock %d - %d\n", itf, sock);
    return emul_rx_size;
}

void emul_task() {
#ifdef USB_ITF_CCID
    emul_read(ITF_CCID);
#endif
#ifdef USB_ITF_HID
    emul_read(ITF_HID);
#endif
}
