#include <stdint.h>
#include "common.h"
#include "otp.h"

/* infected by dacotaco variable name capitalization */
static volatile struct OTPRegister {
	union {
		uint32_t Command;
		struct {
			uint32_t Read : 1;
			uint32_t : 26;
			uint32_t Address : 5;
		};
	};
	uint32_t Data;
} *const OTP = (volatile struct OTPRegister *const)0xCD8001EC;
CHECK_STRUCT_SIZE(struct OTPRegister, 8);

int otp_read(unsigned offset, unsigned count, uint32_t out[count]) {
	if (offset + count > OTP_WORD_COUNT || !out)
		return 0;

	for (unsigned i = 0; i < count; i++) {
		OTP->Command = 0x80000000 | (offset + i);
		out[i] = OTP->Data;
	}

	return count;
}
