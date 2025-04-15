#include <ogc/machine/processor.h>

#include "otp.h"

#define HW_OTPCOMMAND	0x0D8001EC
#define HW_OTPDATA		0x0D8001F0

int otp_read(unsigned offset, unsigned count, uint32_t out[count]) {
	if (offset + count > OTP_WORD_COUNT || !out)
		return 0;

	for (unsigned i = 0; i < count; i++) {
		write32(HW_OTPCOMMAND, 0x80000000 | (offset + i));
		out[i] = read32(HW_OTPDATA);
	}

	return count;
}
