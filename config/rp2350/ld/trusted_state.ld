SECTIONS
{
    __trusted_state_ram_base = DEFINED(__trusted_state_fixed_base) ?
        __trusted_state_fixed_base :
        0x20070000;
    .trusted_data __trusted_state_ram_base : AT (ALIGN(__trusted_load_end, 16))
    {
        . = ALIGN(16);
        __trusted_data_start = .;
        libtrusted_mbedtls.a:(.trusted.data .trusted.data.*)
        . = ALIGN(16);
        __trusted_data_end = .;
    }
    __trusted_data_load_start = LOADADDR(.trusted_data);
    __trusted_data_load_end = LOADADDR(.trusted_data) + SIZEOF(.trusted_data);
    .trusted_bss ALIGN(__trusted_data_end, 16) (NOLOAD) :
    {
        . = ALIGN(16);
        __trusted_bss_start = .;
        libtrusted_mbedtls.a:(.trusted.bss .trusted.bss.*)
        . = ALIGN(16);
        __trusted_bss_end = .;
    }
}
ASSERT(__trusted_bss_end >= __trusted_data_start, "trusted state symbols are invalid")
ASSERT(__trusted_state_ram_base >= 0x20000000, "trusted state RAM base is below RP2350 SRAM")
ASSERT(__trusted_bss_end <= 0x20080000, "trusted state exceeds RP2350 main SRAM window")
INSERT AFTER .trusted_region;

