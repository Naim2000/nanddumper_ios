#include <stdint.h>
#include "common.h"

#define FLASH_SHIFTM(x, s) ((x) << (s))
#define FLASH_SHIFT(s) FLASH_SHIFTM(1, s)
#define FLASH_SHIFTD(x, s) ((x) >> (s))

// All the 32 bit integers are in log2
typedef struct FlashSizeInfo {
	uint32_t nand_size;             // 29 (512MiB)
	uint32_t block_size;            // 17 (128KiB)
	uint32_t page_size;             // 11 (2KiB)
	uint32_t spare_size;            // 6 (64B)
	uint32_t spare_misc_size;       // 5 (32B)
	uint16_t block_copy_mask;
	uint16_t supports_page_copy;
	uint16_t check_byte_ofs;        // 0
	/* implicit padding */
} FlashSizeInfo;
CHECK_STRUCT_SIZE(FlashSizeInfo, 0x1C);

enum FlashCommandType: uint32_t {
	FLASH_CMD_DELETE,
	FLASH_CMD_WRITE,
	FLASH_CMD_READ,
	FLASH_CMD_COPY, // ?
	FLASH_CMD_MAX
};

enum FlashErrorCode: int {
	FLASH_EIO       =  -1,
	FLASH_EINVAL    =  -4,
	FLASH_EMAX      =  -5,
	FLASH_UNKNOWN   =  -9, // I call this one "system call error"
	FLASH_ENOTREADY = -10,
	FLASH_ECC       = -11,
	FLASH_ECC_CRIT  = -12,
	FLASH_BADBLOCK  = -13,
};

struct FlashErrorLog {
	uint32_t page;
	enum FlashCommandType command;
	enum FlashErrorCode ret;
};

enum {
	FLASH_MAX_ERRORS = 0x20,
};

typedef struct FlashCommandLog {
	unsigned int successes[FLASH_CMD_MAX];
	int error_overflow;
	int error_index;
	struct FlashErrorLog errors[FLASH_MAX_ERRORS];
} FlashCommandLog;
CHECK_STRUCT_SIZE(FlashCommandLog, 0x198);

int Flash_Init(void);
int Flash_Close(void);
int Flash_GetSizeInfo(FlashSizeInfo* out);
int Flash_GetCommandLog(FlashCommandLog* out);
int Flash_ReadPage(unsigned int idx, bool spare, uint8_t* out);
int Flash_ReadBlock(unsigned int idx, bool spare, uint8_t* out);
int Flash_CheckBlock(unsigned int idx);
