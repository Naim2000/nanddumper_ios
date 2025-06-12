#include <ogc/ipc.h>
#include "sha.h"

int Sha_Init(ShaContext* ctx) {
	ioctlv vectors[3] = {};

	vectors[1].data = ctx;
	if ((uintptr_t)ctx < 0xFFF00000)
		vectors[1].len  = sizeof *ctx;

	return IOS_Ioctlv(0x10001, 0, 1, 2, vectors);
}

int Sha_Update(ShaContext* ctx, void* data, unsigned size) {
	int ret = 0;
	ioctlv vectors[3] = {};


	vectors[1].data = ctx;
	vectors[1].len  = sizeof *ctx;

	for (unsigned x = 0; x < size;) {
		unsigned len = size - x;
		if (len > 0x10000)
			len = 0x10000;

		vectors[0].data = data + x;
		vectors[0].len  = len;

		ret = IOS_Ioctlv(0x10001, 1, 1, 2, vectors);
		if (ret < 0)
			break;

		x += len;
	}

	return ret;
}

int Sha_Finish(ShaContext* ctx, uint32_t* hash) {
	ioctlv vectors[3] = {};

	vectors[1].data = ctx;
	vectors[1].len  = sizeof *ctx;

	vectors[2].data = hash;
	vectors[2].len  = sizeof(uint32_t[5]);

	return IOS_Ioctlv(0x10001, 2, 1, 2, vectors);
}
