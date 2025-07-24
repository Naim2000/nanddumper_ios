#include "common.h"
#include "mini_seeprom.h"
#include "otp.h"

typedef struct KeysBin {
	char		comment[256];
	WiiOTP		otp;
	char		padding[128];
	seeprom_t	seeprom;
	char		padding2[256];
} KeysBin;
CHECK_STRUCT_SIZE(KeysBin, 0x400);

int build_keys(KeysBin *);
