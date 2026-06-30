ASSERT(!DEFINED(__picokeys_plugin_flash_base) || __flash_binary_end <= __picokeys_plugin_flash_base,
       "pico_fido flash image overlaps the premium plugin region")

ASSERT(!DEFINED(__picokeys_plugin_ram_base) || __end__ <= __picokeys_plugin_ram_base,
       "pico_fido RAM image overlaps the premium plugin RAM region")

ASSERT(!DEFINED(__picokeys_plugin_ram_base) || !DEFINED(__picokeys_plugin_ram_size) ||
       ((__picokeys_plugin_ram_base + __picokeys_plugin_ram_size) <= 0x20080000),
       "premium plugin RAM region exceeds RP2350 main RAM")

__HeapLimit = DEFINED(__picokeys_plugin_ram_base) ? __picokeys_plugin_ram_base : __HeapLimit;
