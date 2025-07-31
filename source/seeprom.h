#include <stdint.h>
#include "common.h"

#define SEEPROM_WORD_COUNT 128

#define SEEPROM_COUNTER_STRUCT(name, thestruct...) \
    struct __attribute__((packed)) __s_##name \
        thestruct \
    ; \
    \
    typedef union name { \
        struct __attribute__((packed)) \
            thestruct \
        ; \
        struct { \
            uint16_t sumdata[(sizeof(struct __s_##name)) / 2]; \
            uint16_t checksum; \
        }; \
    } name ;

SEEPROM_COUNTER_STRUCT(Boot2Counter, { uint8_t boot2version, unk1, unk2, padding; uint32_t update_tag; });
SEEPROM_COUNTER_STRUCT(SFFSCounter,  { uint32_t generation; });

#undef SEEPROM_COUNTER_STRUCT

typedef union {
	struct __attribute__((packed)) {
		uint32_t     ms_id;
		uint32_t     ca_id;
		uint32_t     ng_key_id;
		uint8_t      ng_signature[2][30];
		Boot2Counter boot2_counters[2];
		SFFSCounter  sffs_counters[3];
		uint8_t      padding[6];
		uint32_t     korean_key[4];
		uint8_t      padding2[116];
		uint16_t     prng_seed[2];
		uint8_t      padding3[4];
	};
    uint16_t data[SEEPROM_WORD_COUNT];
} WiiSEEPROM;
CHECK_STRUCT_SIZE(WiiSEEPROM, 0x100);

int seeprom_read(unsigned offset, unsigned count, uint16_t out[count]);
#ifdef SEEPROM_ENABLE_WRITE
int seeprom_write(unsigned offset, unsigned count, const uint16_t in[count]);
#endif
