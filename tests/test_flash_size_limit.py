#!/usr/bin/env python3
"""Host-only regression for low_flash_init; no SDK build or hardware simulation.

Compile the actual initializer and option guard from low_flash.c with small ROM,
JEDEC and partition stubs. The flash sizing/marker logic is not reimplemented.
Run: python3 tests/test_flash_size_limit.py (requires a GCC/Clang-compatible CC).
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/fs/low_flash.c").read_text()
START = SOURCE.index("#ifdef PICO_RP2040\nvoid phymarker_write(void);")
INIT = SOURCE[START:SOURCE.index("void low_flash_init_core1(void)", START)]
PREFIX = SOURCE[:SOURCE.index("#define TOTAL_FLASH_PAGES")]
GUARD_START = PREFIX.find("#ifdef PICO_FLASH_SIZE_LIMIT_BYTES")
GUARD = PREFIX[GUARD_START:] if GUARD_START >= 0 else ""

STUBS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define FLASH_SECTOR_SIZE 0x1000u
#define TOTAL_FLASH_PAGES 6
#if defined(PICO_RP2040) || defined(PICO_RP2350)
#define PICO_PLATFORM 1
#define XIP_BASE 0x10000000u
#else
#define XIP_BASE 0u
#endif
uint32_t FLASH_SIZE_BYTES;
typedef struct { unsigned unused; } page_flash_t;
page_flash_t flash_pages[TOTAL_FLASH_PAGES];
int mtx_flash;
static unsigned capacity, marker_calls, bounds_calls;
static uint32_t observed_start, observed_end;
static jmp_buf panic_target;
#ifndef TEST_PHYMARKER_START
#define TEST_PHYMARKER_START 0x10100000u
#endif
uintptr_t __phymarker_start = TEST_PHYMARKER_START;
void mutex_init(int *m) { *m = 1; }
void phymarker_write(void) { marker_calls++; }
_Noreturn void panic(const char *msg) { (void)msg; longjmp(panic_target, 1); }
void flash_set_bounds(uint32_t start, uint32_t end) {
    observed_start = start; observed_end = end; bounds_calls++;
}
void flash_do_cmd(const uint8_t *tx, uint8_t *rx, size_t n) {
    (void)tx; (void)n; rx[3] = (uint8_t)capacity;
}
#define PT_INFO_PARTITION_LOCATION_AND_FLAGS 0u
#define PT_INFO_SINGLE_PARTITION 0u
#define PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS 0x0000ffffu
#define PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB 0
#define PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS 0xffff0000u
#define PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB 16
int rom_load_partition_table(uint8_t *p, size_t n, bool b) {
    (void)p; (void)n; (void)b; return 0;
}
int rom_get_partition_table_info(uint32_t *p, unsigned n, unsigned flags) {
    (void)n; (void)flags;
    p[1] = 768u | (1023u << 16); /* partition [3 MiB, 4 MiB) */
#ifdef TEST_PARTITION_FALLBACK
    return 0;
#else
    return 3;
#endif
}
void reset_usb_boot(unsigned a, unsigned b) { (void)a; (void)b; abort(); }
typedef struct { uint32_t size; } esp_partition_t;
static const esp_partition_t test_partition = {0x300000u};
const esp_partition_t *part0;
uint8_t *map;
int fd_map;
typedef int esp_partition_mmap_handle_t;
#define ESP_PARTITION_MMAP_DATA 0
const esp_partition_t *esp_partition_find_first(unsigned a, unsigned b, const char *s) {
    (void)a; (void)b; (void)s; return &test_partition;
}
int esp_partition_mmap(const esp_partition_t *p, unsigned a, unsigned b,
                      unsigned c, const void **m, esp_partition_mmap_handle_t *h) {
    (void)p; (void)a; (void)b; (void)c; (void)m; (void)h; return 0;
}
"""
MAIN = r"""
int main(int argc, char **argv) {
    assert(argc == 6);
    capacity = (unsigned)strtoul(argv[1], NULL, 0);
    bool expect_panic = strtoul(argv[2], NULL, 0) != 0;
    if (setjmp(panic_target)) {
        assert(expect_panic && marker_calls == 0 && bounds_calls == 0);
        return 0;
    }
    low_flash_init();
    assert(!expect_panic && bounds_calls == 1);
    assert(observed_start == strtoul(argv[3], NULL, 0));
    assert(observed_end == strtoul(argv[4], NULL, 0));
    assert(marker_calls == strtoul(argv[5], NULL, 0));
    assert(observed_start < observed_end);
    return 0;
}
"""

class FlashSizeLimitTests(unittest.TestCase):
    def compile_case(self, defines, *, reject=False, guard_only=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        src, exe = Path(temp.name)/"test.c", Path(temp.name)/"test"
        src.write_text(STUBS + GUARD + ("int main(void) {return 0;}\n" if guard_only else INIT + MAIN))
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
            "-fno-sanitize-recover=all", *["-D" + d for d in defines], str(src), "-o", str(exe)]
        result = subprocess.run(command, text=True, capture_output=True, timeout=30)
        if reject:
            self.assertNotEqual(result.returncode, 0, f"unsafe option accepted: {defines}")
            self.assertIn("PICO_FLASH_SIZE_LIMIT_BYTES", result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
        return exe

    def run_case(self, exe, capacity, panic, start=0, end=0, markers=0):
        result = subprocess.run([str(exe), str(capacity), str(int(panic)), hex(start), hex(end), str(markers)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_physical_marker_full_page_write(self):
        marker = SOURCE[SOURCE.index("#ifdef PICO_RP2040\ntypedef struct {\n    uint64_t magic;"):]
        stubs = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define PICO_RP2040 1
#define FLASH_SECTOR_SIZE 4096u
#define FLASH_PAGE_SIZE 256u
#define XIP_BASE 0x10000000u
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
static uint8_t data_page[FLASH_PAGE_SIZE], written[FLASH_PAGE_SIZE];
static unsigned erased, programmed, restored;
static uint32_t expected_offset;
static struct { uint8_t id[8]; } pico_serial = {{1,2,3,4,5,6,7,8}};
typedef struct { const uint8_t *data; size_t len; } const_byte_array_t;
#define CONST_BYTE_ARRAY(p, n) ((const_byte_array_t){(p), (n)})
uint32_t crc32c(const_byte_array_t data) { (void)data; return 0x12345678u; }
uint32_t save_and_disable_interrupts(void) { return 42; }
void restore_interrupts(uint32_t n) { assert(n == 42); restored++; }
void flash_range_erase(uint32_t offset, size_t size) {
    assert(offset == expected_offset && size == FLASH_SECTOR_SIZE); erased++;
}
void flash_range_program(uint32_t offset, const uint8_t *data, size_t size) {
    assert(offset == expected_offset && size == FLASH_PAGE_SIZE);
    assert(erased == programmed + 1); memcpy(written, data, size); programmed++;
}
"""
        main = r"""
int main(void) {
    uint64_t mock_flash[FLASH_SECTOR_SIZE / sizeof(uint64_t)];
    memset(mock_flash, 0xff, sizeof(mock_flash));
    memset(data_page, 0x5a, sizeof(data_page));
    __phymarker_start = (uintptr_t)mock_flash;
    expected_offset = (uint32_t)__phymarker_start - XIP_BASE;
    phymarker_write();
    assert(erased == 1 && programmed == 1 && restored == 1);
    phymarker_t pm; memcpy(&pm, written, sizeof(pm));
    assert(pm.magic == PHYSICAL_MARKER_MAGIC && pm.version == 1 && pm.flags == 0);
    assert(pm.crc32 == 0x12345678u && memcmp(pm.uid, pico_serial.id, sizeof(pm.uid)) == 0);
    for (size_t i = sizeof(pm); i < sizeof(written); i++) assert(written[i] == 0xff);
    mock_flash[0] = PHYSICAL_MARKER_MAGIC;
    phymarker_write();
    assert(erased == 1 && programmed == 1 && restored == 1);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"marker.c", Path(tmp)/"marker"
            src.write_text(stubs + marker + main)
            result = subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                "-fno-sanitize-recover=all", str(src), "-o", str(exe)],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(exe)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rp2040_default_and_capped_layouts(self):
        for limit in [None, "0x200000", "2097152", "0x400000", "0x800000", "0x1000000"]:
            with self.subTest(limit=limit):
                defs = ["PICO_RP2040=1"] + ([] if limit is None else ["PICO_FLASH_SIZE_LIMIT_BYTES="+limit])
                exe = self.compile_case(defs)
                for capacity in [21, 22, 23, 24]:
                    size = min(1 << capacity, int(limit, 0)) if limit else 1 << capacity
                    self.run_case(exe, capacity, False, 0x10000000+max(size//2, 0x101000), 0x10000000+size, 1)

    def test_invalid_capacity_fails_before_marker_or_bounds(self):
        for limit in [None, "0x200000"]:
            exe = self.compile_case(["PICO_RP2040=1"] + ([] if limit is None else ["PICO_FLASH_SIZE_LIMIT_BYTES="+limit]))
            for capacity in [0, 20, 25, 31, 32, 255]:
                with self.subTest(limit=limit, capacity=capacity):
                    self.run_case(exe, capacity, True)

    def test_marker_at_end_rejected_before_write(self):
        exe = self.compile_case(["PICO_RP2040=1", "TEST_PHYMARKER_START=0x101ff000u"])
        self.run_case(exe, 21, True)

    def test_invalid_limits_fail_to_compile(self):
        for limit in ["0", "-1", "0x100000", "0x101000", "0x1ff000", "0x200001", "0x201000", "0x300000", "0x2000000"]:
            with self.subTest(limit=limit):
                self.compile_case(["PICO_RP2040=1", "PICO_FLASH_SIZE_LIMIT_BYTES="+limit], reject=True)

    def test_unsupported_platforms_reject_cap(self):
        for platform in [["PICO_RP2350=1"], ["ESP_PLATFORM=1"], ["ENABLE_EMULATION=1"], [],
                         ["PICO_RP2040=0"], ["PICO_RP2040=1", "PICO_RP2350=1"],
                         ["PICO_RP2040=1", "ESP_PLATFORM=1"], ["PICO_RP2040=1", "ENABLE_EMULATION=1"]]:
            with self.subTest(platform=platform):
                self.compile_case(platform+["PICO_FLASH_SIZE_LIMIT_BYTES=0x200000"], reject=True, guard_only=True)

    def test_rp2350_uncapped_partition_and_fallback(self):
        for fallback, start in [(False, 0x10300000), (True, 0x10200000)]:
            exe = self.compile_case(["PICO_RP2350=1"] + (["TEST_PARTITION_FALLBACK=1"] if fallback else []))
            self.run_case(exe, 22, False, start, 0x103fe000)

    def test_esp32_uncapped_partition(self):
        exe = self.compile_case(["ESP_PLATFORM=1"])
        self.run_case(exe, 22, False, 0, 0x300000)

    def test_emulation_without_cap_has_no_option_guard_error(self):
        self.compile_case(["ENABLE_EMULATION=1"], guard_only=True)

if __name__ == "__main__":
    unittest.main(verbosity=2)
