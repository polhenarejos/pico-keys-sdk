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
#include "pico_time.h"
#ifdef ESP_PLATFORM
#include <sys/time.h>
#endif

#ifdef _MSC_VER
#include <windows.h>
struct timezone
{
    __int32  tz_minuteswest; /* minutes W of Greenwich */
    bool  tz_dsttime;     /* type of dst correction */
};
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    (void)tzp;
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
int settimeofday(const struct timeval* tp, const struct timezone* tzp)
{
    (void)tzp;
    SYSTEMTIME st;
    FILETIME ft;
    uint64_t time;

    time = ((uint64_t)tp->tv_sec * 10000000L) + ((uint64_t)tp->tv_usec * 10) + ((uint64_t)116444736000000000ULL);
    ft.dwLowDateTime = (uint32_t)(time & 0xFFFFFFFF);
    ft.dwHighDateTime = (uint32_t)(time >> 32);
    FileTimeToSystemTime(&ft, &st);
    return SetSystemTime(&st);
}
#endif

#ifdef ENABLE_EMULATION
bool set_rtc = true;
#else
bool set_rtc = false;
#endif

bool has_set_rtc(void) {
    return set_rtc;
}

void set_rtc_time(time_t t) {
#ifdef PICO_PLATFORM
    struct timespec tv = {.tv_sec = t, .tv_nsec = 0};
    aon_timer_set_time(&tv);
#else
    struct timeval tv = {.tv_sec = t, .tv_usec = 0};
    settimeofday(&tv, NULL);
#endif
    set_rtc = true;
}

time_t get_rtc_time(void) {
#ifdef PICO_PLATFORM
    struct timespec tv;
    aon_timer_get_time(&tv);
    return tv.tv_sec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
#endif
}

void init_rtc(void) {
#ifdef PICO_PLATFORM
    struct timespec tv = {0};
    tv.tv_sec = 1577836800; // 2020-01-01
    aon_timer_start(&tv);
#endif
}
