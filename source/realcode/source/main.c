#include <ioscore.h>
#include <string.h>
#include <ios/processor.h>
#include <ios/ipc.h>
#include <ios/errno.h>

#include "shared.h"

static volatile u32 *const HW_REG_BASE = (volatile u32 *)0x0D800000;
static volatile u16 *const DDR_REG_BASE = (volatile u16 *)0x0D8B4000;

#define HW_REG_READ(x)		(HW_REG_BASE[(x) / 4])
#define DDR_REG_READ(x)		(DDR_REG_BASE[(x) / 2])

#define HW_REG_WRITE(x, v)	HW_REG_BASE[(x) / 4] = (v)
#define DDR_REG_WRITE(x, v)	DDR_REG_BASE[(x) / 2] = (v)

__attribute__((target("arm")))
void disable_ppc_protections(void) {
	// disable AHBPROT for PPC
	HW_REG_WRITE(0x64, HW_REG_READ(0x64) | 0x80000DFE);

	// enable SRAM access for PPC
	HW_REG_WRITE(0x60, HW_REG_READ(0x60) | 0x8);

	// disable MEM2 protection
	DDR_REG_WRITE(0x20A, 0);
}

/* https://developer.arm.com/documentation/ddi0198/e/instruction-memory-barrier/example-imb-sequences?lang=en */
__attribute__((target("arm")))
void kill_icache(void) {
	__asm__ ( "mcr p15, 0, %0, c7, c5, 0" : : "r"(0));
}


void* memmem(const void* start, size_t len, const void* pattern, size_t pattern_len) {
	const u8* start8 = (const u8*)start;
	const u8* pattern8 = (const u8 *)pattern;

	for (size_t i = 0; i < len; i++) {
		if (start8[i] == *pattern8 && memcmp(start8 + i, pattern, pattern_len) == 0) {
			return (void *)(start8 + i);
		}
	}

	return NULL;
}

int main() {
	int ret;
	s32 queueid;
	u32 mbox[4];
	IpcMessage* req = NULL;

	disable_ppc_protections();

	OSSetUID(15, 0);
	OSSetGID(15, 0);

	ret = queueid = OSCreateMessageQueue(mbox, 4);
	if (ret < 0)
		return ret;

	ret = OSRegisterResourceManager(REALCODE_DEVICE_NAME, queueid);
	if (ret < 0)
		return ret;

	while (OSReceiveMessage(queueid, &req, 0) == 0) {
		if (!req)
			continue;

		ret = IPC_EINVAL;
		switch (req->Request.Command) {
			case IOS_OPEN: {
				ret = 0;

				if (memcmp(req->Request.Data.Open.Filepath, REALCODE_DEVICE_NAME, sizeof (REALCODE_DEVICE_NAME)) != 0)
					ret = IPC_ENOENT;
			} break;

			case IOS_CLOSE: {
				ret = 0;
			} break;

			case IOS_IOCTL: {
				IoctlMessage* ioctl = &req->Request.Data.Ioctl;
				const u32* inbuf = (const u32 *)ioctl->InputBuffer;
				// u32* outbuf = (u32 *)ioctl->IoBuffer;

				switch (ioctl->Ioctl) {
					case 0: {
						ret = (s32)OSVirtualToPhysical((u32)inbuf);
					} break;

					case 1: {
						kill_icache();
						ret = 0;
					} break;

					case 2: {
						OSDCInvalidateRange((void *)inbuf[0], inbuf[1]);
						ret = 0;
					} break;

					case 3: {
						OSDCFlushRange((void *)inbuf[0], inbuf[1]);
					}
				}
			} break;

			case IOS_IOCTLV: {
				IoctlvMessage* ioctlv = &req->Request.Data.Ioctlv;
				IoctlvMessageData* vectors = ioctlv->Data;
				switch (ioctlv->Ioctl) {
					case 0xC0DE: {
						if (ioctlv->InputArgc < 2) {
							ret = IPC_EINVAL;
							break;
						}

						struct codepatch_params* params = (struct codepatch_params *)vectors[0].Data;
						IoctlvMessageData* pattern = &vectors[1], *patch = NULL;
						if (ioctlv->InputArgc > 2)
							patch = &vectors[2];

						void* ptr_start = params->start;
						void* ptr_end   = params->start + params->len;
						ret = 0;

						while (ptr_start < ptr_end) {
							ptr_start = memmem(ptr_start, (size_t)(ptr_end - ptr_start), pattern->Data, pattern->Length);
							if (!ptr_start)
								break;

							if (!patch) {
								ret = (s32)ptr_start;
								break;
							}

							memcpy(ptr_start, patch->Data, patch->Length);
							OSDCFlushRange(ptr_start, patch->Length);
							ret++;
							ptr_start += patch->Length;
						}
					} break;
				}
			} break;
		}

		OSResourceReply(req, ret);
	}

	return 0;
}
