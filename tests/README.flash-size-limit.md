# Flash-size cap regression tests

Run `python3 tests/test_flash_size_limit.py` from the SDK checkout. Requires
Python 3 and a GCC/Clang-compatible `CC` (default `cc`) with UndefinedBehaviorSanitizer.
The test compiles the actual `low_flash_init()` and option guard extracted from
`src/fs/low_flash.c`; JEDEC, ROM partition lookup and marker writes are stubs.
This is a host regression harness, **not** a Pico/ESP32 SDK build or a hardware test.

`PICO_FLASH_SIZE_LIMIT_BYTES` is opt-in and RP2040-only. It must be a power of two
from 2 MiB through 16 MiB (hex or decimal C integer constant). Other platforms
fail compilation rather than silently applying or ignoring the cap. ESP32 and
emulation also reject the CMake option during configuration. Without the option,
RP2350 partition selection and ESP32 partition sizing are unchanged.

RP2040 requires a JEDEC capacity between 2 MiB and 16 MiB. Unsupported capacities
fail closed before the capacity shift, physical-marker write or bounds publication.
The half-flash pool still starts after the physical-marker sector when necessary:
a 2 MiB effective size yields offsets `[0x101000, 0x200000)`; uncapped 4 MiB yields
`[0x200000, 0x400000)`. The cap never increases detected capacity.

The suite covers those layouts, supported caps, invalid values/platforms, invalid
JEDEC capacities, invalid marker bounds, uncapped RP2350 partition/fallback and
uncapped ESP32 sizing. Emulation is checked only for option-guard compatibility.
It does not establish partition-table correctness or flash I/O behavior on hardware.

Existing reported hardware evidence is limited to YD-RP2040 4MB with a 2 MiB cap
and the original marker-offset fix. The follow-up guards and marker-call ordering
have not been retested on hardware; neither RP2350 nor ESP32 hardware is claimed.

Changing the cap changes persistent-storage locations. Use a blank key or make a
recoverable flash backup first; do not alternate capped/uncapped firmware on a
provisioned key. Moving the lower bound past the marker can exclude existing
records on a 2 MiB key whose pool reached that first sector. No storage migration
or automatic erase is added by this change.

The adjacent marker writer now initializes a full 256-byte page to `0xFF` and
passes the page size rather than `sizeof(pointer)` to `flash_range_program`.
A host test uses the real marker writer to verify length, padding, UID fields and
the existing-magic no-write path. CRC computation and flash I/O remain stubbed;
no hardware persistence or readback claim is made.
