#include <stdint.h>
#include <unistd.h>
#include <ogc/ipc.h>

#include "realcode.h"
#include "common.h"
#include "sha.h"
#include "realcode_bin.h"
#include "realcode/source/shared.h"

static unsigned char realcode_stack[0x1000] [[gnu::aligned(0x20)]];
static int fd = IPC_ENOENT;

int realcode_init() {
	if (fd >= 0)
		return 0;

	int ret = do_sha_exploit(realcode_bin, true, 0, realcode_stack, sizeof realcode_stack, 0x7F, 0);
	if (ret < 0)
		return ret;

	int try = 500;
	while (fd == IPC_ENOENT) {
		ret = fd = IOS_Open(REALCODE_DEVICE_NAME, 0);
		usleep(50);
		if (!try--)
			break;
	}

	return ret;
}

void* IOS_VirtualToPhysical(void* addr) {
	// Pointer is not checked by IPC if size == 0
	return (void *)IOS_Ioctl(fd, 0, (void *)addr, 0, 0, 0);
}

void IOS_InvalidateDCache(const void* addr, uint32_t len) {
	uint32_t params[2] = { (uint32_t)addr, len };
	IOS_Ioctl(fd, 2, params, sizeof params, 0, 0);
}

void IOS_FlushDCache(void* addr, uint32_t len) {
	uint32_t params[2] = { (uint32_t)addr, len };
	IOS_Ioctl(fd, 3, params, sizeof params, 0, 0);
}

void IOS_InvalidateICache(void) {
	IOS_Ioctl(fd, 1, 0, 0, 0, 0);
}

int realcode_patch(void* start, unsigned len, const void* pattern, unsigned pattern_len, const void* patch, unsigned patch_len) {
	struct codepatch_params params = { .start = start, .len = len };
	ioctlv vectors[3] = {
		{ &params, sizeof params },
		{ (void *)pattern, pattern_len },
		{ (void *)patch, patch_len },
	};

	return IOS_Ioctlv(fd, 0xC0DE, patch ? 3 : 2, 0, vectors);
}
