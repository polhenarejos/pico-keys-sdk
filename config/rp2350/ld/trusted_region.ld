SECTIONS
{
    __trusted_region_min_flash_base = ALIGN(LOADADDR(.flash_end) + SIZEOF(.flash_end), 16);
    __trusted_region_flash_base = DEFINED(__trusted_region_fixed_base) ?
        __trusted_region_fixed_base :
        __trusted_region_min_flash_base;

    .trusted_region __trusted_region_flash_base :
    {
        . = ALIGN(16);
        __trusted_start = .;

        libtrusted_mbedtls.a:(.trusted.text .trusted.text.* .trusted.gnu.linkonce.t.*)

        . = ALIGN(16);
        libtrusted_mbedtls.a:(.trusted.rodata .trusted.rodata.* .trusted.srodata .trusted.srodata.* .trusted.gnu.linkonce.r.*)

        . = ALIGN(16);
        __trusted_end = .;
    }

    __trusted_load_start = LOADADDR(.trusted_region);
    __trusted_load_end = LOADADDR(.trusted_region) + SIZEOF(.trusted_region);
    __flash_binary_end = __trusted_end;
}

ASSERT(__trusted_end >= __trusted_start, "trusted region symbols are invalid")
ASSERT(!DEFINED(__trusted_region_fixed_base) ||
       (__trusted_region_fixed_base >= __trusted_region_min_flash_base),
       "PICOKEYS_TRUSTED_REGION_FLASH_BASE is below the end of the regular flash image")

INSERT AFTER .flash_end;
