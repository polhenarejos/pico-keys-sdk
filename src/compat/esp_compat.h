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

#ifndef __ESP_COMPAT_H_
#define __ESP_COMPAT_H_

#ifdef ESP_PLATFORM

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
typedef QueueHandle_t queue_t;
#define queue_init(a,b,c) do { *(a) = xQueueCreate(c, b); } while(0)
#define queue_add_blocking(a,b) xQueueSend(*(a), b, portMAX_DELAY)
#define queue_remove_blocking(a,b) xQueueReceive(*(a), b, portMAX_DELAY)
#define queue_try_add(a,b) xQueueSend(*(a), b, 0)
#define queue_is_empty(a) (uxQueueMessagesWaiting(*(a)) == 0)
#define queue_try_remove(a,b) xQueueReceive(*(a), b, 0)
extern TaskHandle_t hcore0, hcore1;
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define ESP32_CORE0 0
#define ESP32_CORE1 1
#else
#define ESP32_CORE0 tskNO_AFFINITY
#define ESP32_CORE1 tskNO_AFFINITY
#endif
static inline void task_wrapper(void *arg) {
    void* (*func)(void*) = (void* (*)(void*))arg;
    func(NULL);
    vTaskDelete(NULL);
}
#define multicore_launch_func_core1(func) xTaskCreatePinnedToCore(task_wrapper, "core1", 4096*ITF_TOTAL*2, (void *)func, CONFIG_TINYUSB_TASK_PRIORITY - 2, &hcore1, ESP32_CORE1)
#define multicore_reset_core1() do { if (hcore1) { eTaskState e = eTaskGetState(hcore1); if (e <= eSuspended) { vTaskDelete(hcore1); }} }while(0)
#define sleep_ms(a) vTaskDelay(a / portTICK_PERIOD_MS)
static inline uint32_t board_millis(void) {
    return ( ( ((uint64_t) xTaskGetTickCount()) * 1000) / configTICK_RATE_HZ );
}
typedef SemaphoreHandle_t mutex_t;
typedef SemaphoreHandle_t semaphore_t;
#define mutex_init(a) do { *(a) = xSemaphoreCreateMutex();} while(0)
#define mutex_try_enter(a,b) xSemaphoreTake(*(a), 0)
#define mutex_enter_blocking(a) xSemaphoreTake(*(a), portMAX_DELAY)
#define mutex_exit(a) xSemaphoreGive(*(a))
#define sem_init(a,b,c) do { *(a) = xSemaphoreCreateCounting(c, b); } while(0)
#define sem_release(a) xSemaphoreGive(*(a))
#define sem_acquire_blocking(a) xSemaphoreTake(*(a), portMAX_DELAY)
#define multicore_lockout_victim_init() (void)0
static inline bool multicore_lockout_start_timeout_us(int a) { if (hcore1) { vTaskSuspend(hcore1); } return true; }
static inline bool multicore_lockout_end_timeout_us(int a) { if (hcore1) { vTaskResume(hcore1); } return true; }

#endif

#endif
