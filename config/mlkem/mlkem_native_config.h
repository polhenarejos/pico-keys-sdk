#pragma once

/* Disable all native/asm backends */
#define MLK_NO_NATIVE_BACKENDS 1

/* No CBMC */
#undef CBMC

/* Platform characteristics */
#define MLK_LITTLE_ENDIAN 1

/* Memory model */
#define MLK_NO_MALLOC 1
