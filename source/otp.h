#include <stdint.h>

#define OTP_WORD_COUNT 32

typedef union {
	struct {
		uint32_t boot1_hash[5];
		uint32_t common_key[4];
		uint32_t device_id;
		union {
			uint8_t device_private_key[30];
			struct {
				uint32_t pad[7];
				uint32_t nandfs_hmac_key[5];
			};
		};
		uint32_t nandfs_key[4];
		uint32_t backup_key[4];
		uint32_t pad2[2];
	};
	uint32_t data[OTP_WORD_COUNT];
} WiiOTP;

int otp_read(unsigned offset, unsigned count, uint32_t out[count]);
