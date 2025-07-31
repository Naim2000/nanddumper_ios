#include "common.h"
#include "otp.h"
#include "seeprom.h"

typedef struct KeysBin {
	char		comment[256];
	WiiOTP		otp;
	char		padding[128];
	WiiSEEPROM	seeprom;
	char		padding2[256];
} KeysBin;
CHECK_STRUCT_SIZE(KeysBin, 0x400);

int build_keys(KeysBin *);
