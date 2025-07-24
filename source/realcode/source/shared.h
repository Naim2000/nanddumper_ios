#include <stdint.h>

#define REALCODE_DEVICE_NAME "/dev/realcode"

struct codepatch_params {
	void*     start;
	uint32_t  len;
};
