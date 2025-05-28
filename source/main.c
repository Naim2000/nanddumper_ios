#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <time.h>
#include <ogc/machine/processor.h>
#include <ogc/system.h>
#include <ogc/cache.h>
#include <ogc/lwp_watchdog.h>
#include <ogc/ios.h>
#include <ogc/ipc.h>
#include <ogc/es.h>

#ifndef NANDDUMPER_READ_TEST
#include <fat.h>
#endif

#include "common.h"
#include "video.h"
#include "pad.h"
#ifndef NANDDUMPER_READ_TEST
#include "fatMounter.h"
#endif
#include "sha.h"
#include "otp.h"
#include "mini_seeprom.h"
#include "vwii_sram_otp.h"
#include "realcode_bin.h"
#include "stage0_bin.h"

#define STR(X) __stringify(X)

#define HW_AHBPROT		0x0D800064
#define MEM2_PROT		0x0D8B420A
#define LT_CHIPREVID	0x0D8005A0
#define IS_WIIU			((read32(LT_CHIPREVID) & 0xFFFF0000) == 0xCAFE0000)

void __exception_setreload(unsigned seconds);
int  __CONF_GetTxt(const char *name, char *buf, int length);

typedef struct FlashSizeInfo {
	// log2
	int   nand_size, block_size, page_size, spare_size, spare_misc_size;
	short block_copy_mask;
	short supports_page_copy;
	short check_byte_ofs;
	// short padding;
} FlashSizeInfo;
CHECK_STRUCT_SIZE(FlashSizeInfo, 0x1C);

typedef struct KeysBin {
	char		comment[256];
	WiiOTP		otp;
	char		padding[128];
	seeprom_t	seeprom;
	char		padding2[256];
} KeysBin;
CHECK_STRUCT_SIZE(KeysBin, 0x400);

#if 0

typedef struct IOS_Context {
	uint32_t cpsr;
	union {
		struct {
			uint32_t _[13];
			void*    sp;
			void*    lr;
			void*    pc;
		};
		struct {
			uint32_t r[16];
		};
	};
} IOS_Context;
CHECK_STRUCT_SIZE(IOS_Context, 0x44);

typedef struct IOS_Thread {
	struct IOS_Context userContext;
	struct IOS_Thread* next;
	int                initialPriority;
	int                priority;
	unsigned int       state;
	unsigned int       pid;
	int                detached;
	int                returnValue;
	void*              joinQueue;
	void*              threadQueue;
	struct IOS_Context syscallContext;
	void*              syscallStackTop;
} IOS_Thread;
CHECK_STRUCT_SIZE(IOS_Thread, 0xB0);

static volatile IOS_Thread* const iosThreads = (volatile IOS_Thread* const)0xCD4E0000;

static void print_thread(int i) {
	volatile IOS_Thread* thread = &iosThreads[i];

	printf("======== IOS_Thread %i ========\n", i);
	printf("State=%u, Max priority=%02x, Current priority=%02x, cpsr=%08x\n", thread->state, thread->initialPriority, thread->priority, thread->userContext.cpsr);

	volatile IOS_Context* ctx = &thread->userContext;
	// printf("==== User context ====\n");
	//printf("cpsr   %08X sp       %08X lr       %08X\n", ctx->cpsr, (uintptr_t)ctx->sp, (uintptr_t)ctx->lr);
	printf("rO-r7  %08X %08X %08X %08X %08X %08X %08X %08X \n", ctx->r[0], ctx->r[1], ctx->r[2],  ctx->r[3],  ctx->r[4],  ctx->r[5],  ctx->r[6],  ctx->r[7]);
	printf("r8-r15 %08X %08X %08X %08X %08X %08X %08X %08X \n", ctx->r[8], ctx->r[9], ctx->r[10], ctx->r[11], ctx->r[12], ctx->r[13], ctx->r[14], ctx->r[15]);

	ctx = &thread->syscallContext;
	printf("==== Syscall context ====\n");
	//printf("cpsr   %08X sp       %08X lr       %08X pc       %08X\n", ctx->cpsr, (uintptr_t)ctx->sp, (uintptr_t)ctx->lr, (uintptr_t)ctx->pc);
	printf("rO-r7  %08X %08X %08X %08X %08X %08X %08X %08X \n", ctx->r[0], ctx->r[1], ctx->r[2],  ctx->r[3],  ctx->r[4],  ctx->r[5],  ctx->r[6],  ctx->r[7]);
	printf("r8-r15 %08X %08X %08X %08X %08X %08X %08X %08X \n", ctx->r[8], ctx->r[9], ctx->r[10], ctx->r[11], ctx->r[12], ctx->r[13], ctx->r[14], ctx->r[15]);
}

#endif

/*
 * https://github.com/mkw-sp/mkw-sp/blob/main/common/IOS.cc#L192
 * thank you mkwcat (<3)
 */
int do_sha_exploit(const void* entry, bool thumb, void* sp, unsigned stack_size, uint32_t argument) {
	uint32_t* mem1 = (uint32_t *)0x80000000;
	const uint32_t* stage0 = (uint32_t *)stage0_bin;

	int threadid = 0;

	for (int i = 0; i < stage0_bin_size / 4; i++) {
		uint32_t v = stage0[i];
		if (v == 0x70696B61) // entrypoint
			v = MEM_VIRTUAL_TO_PHYSICAL(entry) | thumb;
		else if (v == 0x5555AAAA) // argument
			v = argument;
		else if (v == 0x53505350) // stack pointer
			v = MEM_VIRTUAL_TO_PHYSICAL(sp);
		else if (v == 0x535A535A) // stack size
			v = stack_size;
		else if (v == 0x67452301) // threadid
			v = MEM_VIRTUAL_TO_PHYSICAL(&threadid);

		mem1[i] = v;
	}

	IOS_Write(-1, mem1, stage0_bin_size);
	int ret = Sha_Init((void *)0xFFFE0028);
	if (ret == 0) {
		// uint64_t time = gettime();
		int timer = 500;
		while (!(ret = read32((uintptr_t)&threadid))) {
			usleep(1000);
			if (!timer--) {
				puts("timeout while waiting on IOS thread to spawn");
				return -1;
			}
		}
		// printf("thread spawned in %ums\n", diff_msec(time, gettime()));
	}

	return ret;
}

int patch_flash_access() {
	int fd = IOS_Open("/dev/flash", 0);
	if (fd >= 0) {
		if (IOS_GetVersion() != 246)
			puts("(/dev/flash is already accessible, how?)");

		IOS_Close(fd);
		return 0;
	}

	uint32_t inbuf[4], outbuf[4];
	int haxxfd = IOS_Open("/dev/realcode", 0);
	if (haxxfd < 0) {
		print_error("IOS_Open(/dev/realcode)", haxxfd);
		return haxxfd;
	}

	inbuf[0] = 0x20000000;
	IOS_Ioctl(haxxfd, 0, inbuf, 4, outbuf, 4);
	void* fs_text = MEM_PHYSICAL_TO_K0(outbuf[0]);

	static const uint16_t patternA[] = { // new
		0x2300, // mov r3, #0
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
		        // bl FS_OpenInterface
	};

	static const uint16_t patternB[] = { // old
		0x4643, // mov r3, r8
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
		        // bl FS_OpenInterface
	};

	static const uint16_t pattern2[] = {
		0x68ab, // ldr r3, [r5, #0x8] @ request->open.uid
		0x2b00, // cmp r3, #0x0 @ (root)
		0xd002, // beq 0x8
		0x2001, // mov r0,#1
		0x4240, // rsb r0,r0 @ -1 (EPERM)
		0xe008, // b 0xa
		        // bl FS_OpenBoot2
	};

	uint16_t* pc = memmem(fs_text, 0x8000, patternA, sizeof patternA);
	if (!pc) {
		pc = memmem(fs_text, 0x8000, patternB, sizeof patternB);
		if (!pc) {
			puts("Could not find stubbed /dev/flash check");
			return -1;
		}
	}

	pc += 3;

	/* https://graphics.stanford.edu/~seander/bithacks.html#FixedSignExtend */
	int x = ((pc[0] & 0x7FF) << 11) | (pc[1] & 0x7FF);
	int m = 1 << 21;
	int dst = (x ^ m) - m;

	uint16_t* FS_OpenFlash = pc + 2 + dst;
	// printf("FS_OpenFlash = %p\n", FS_OpenFlash);

	pc = memmem(pc, 0x100, pattern2, sizeof pattern2);
	if (!pc) {
		puts("Where is the /dev/boot2 uid check?");
		return -2;
	}
	pc += 6;

	char* thestring = memmem(fs_text, 0x8000, "\0boot2", sizeof("\0boot2"));
	if (!thestring++) {
		puts("Could not find the string");
		return -3;
	}

	dst = FS_OpenFlash - (pc + 2);
	pc[0] = 0xF000 | ((dst >> 11) & 0x7FF);
	pc[1] = 0xF800 | (dst & 0x7FF);
	DCFlushRange(pc, 4);

	strcpy(thestring, "flash");
	DCFlushRange(thestring, 8);

	// invalidate icache
	inbuf[0] = MEM_VIRTUAL_TO_PHYSICAL(pc);
	IOS_Ioctl(haxxfd, 1, inbuf, 4, 0, 0);

	// invalidate dcache
	inbuf[0] = MEM_VIRTUAL_TO_PHYSICAL(fs_text);
	inbuf[1] = 0x8000;
	IOS_Ioctl(haxxfd, 2, inbuf, 8, 0, 0);

	// Restore.
	// pc[0] = old[0];
	// pc[1] = old[1];
	// DCFlushRange(pc, 4);

	IOS_Close(haxxfd);
	return 0;
}

static bool page_is_erased(unsigned char* page, FlashSizeInfo* size) {
	uint32_t* spare32 = (uint32_t *)(page + (1 << size->page_size) + (1 << size->spare_size));
	for (int i = 1 << (size->page_size - 9); i; i--) {
		if (spare32[-i] != 0xFFFFFFFF)
			return false;
	}

	return true;
}

#ifndef NANDDUMPER_READ_TEST
int do_nand_backup(const char* nand_path, const char* keys_path, const char comment[256])
#else
int do_nand_backup()
#endif
{
	int ret, fd;
	FlashSizeInfo nandsize = {};
	unsigned int buffer_cnt = 8;
	unsigned int page_spare_sz, pages_per_block, block_spare_sz, n_blocks, buffer_sz;
	unsigned char *buffer = NULL;
#ifndef NANDDUMPER_READ_TEST
	KeysBin keys = {};

	strcpy(keys.comment, comment);
	otp_read(0, OTP_WORD_COUNT, keys.otp.data);
	/*
	 * On the Wii U, there is no SEEPROM. Or rather, it doesn't have the data anyone would expect from a Wii NAND dump. (NG key id & signature, like, the other half of the device cert)
	 * That data is stored in bank 6 of the OTP. But we can't read the extra banks of the OTP from here. So instead, c2w reads that data from OTP and places it at the top of SRAM, and vIOS works with that instead. So let's work with that instead.
	 */
	if (IS_WIIU) {
		keys.seeprom.ms_id = vwii_sram_otp->ms_id;
		keys.seeprom.ca_id = vwii_sram_otp->ca_id;
		keys.seeprom.ng_key_id = vwii_sram_otp->ng_key_id;
		memcpy(keys.seeprom.ng_sig, vwii_sram_otp->ng_sig, sizeof(keys.seeprom.ng_sig));

		// For the effect. Otherwise, I would just build the entire thing from the device certificate
		memcpy(keys.seeprom.korean_key, vwii_sram_otp->korean_key, sizeof(keys.seeprom.korean_key));
	} else {
		seeprom_read(&keys.seeprom, 0, SEEPROM_SIZE);
	}

	FILE* fp = NULL;
	fp = fopen(keys_path, "wb");
	if (!fp) {
		perror("fopen(keys.bin)");
		return -errno;
	}

	ret = fwrite(&keys, sizeof keys, 1, fp);
	fclose(fp);
	fp = NULL;
	if (!ret) {
		perror("fwrite(keys.bin)");
		return -errno;
	}
#endif
	fd = ret = IOS_Open("/dev/flash", 0);
	if (ret < 0) {
		print_error("IOS_Open(/dev/flash)", ret);
		return ret;
	}

	ret = IOS_Ioctl(fd, 1, NULL, 0, &nandsize, sizeof(FlashSizeInfo));
	if (ret < 0) {
		print_error("/dev/flash ioctl 1", ret);
		goto out;
	}

	page_spare_sz   = (1 << nandsize.page_size) + (1 << nandsize.spare_size);
	pages_per_block = nandsize.block_size - nandsize.page_size;
	block_spare_sz  = page_spare_sz << pages_per_block;
	n_blocks        = 1 << (nandsize.nand_size - nandsize.block_size);
	buffer_sz       = block_spare_sz * buffer_cnt;

	buffer = aligned_alloc(0x40, buffer_sz);
	if (!buffer) {
		puts("Memory allocation failed");
		ret = -ENOMEM;
		goto out;
	}

#ifndef NANDDUMPER_READ_TEST
	struct statvfs fs;
	ret = statvfs(nand_path, &fs);
	if (ret < 0) {
		perror("statvfs");
		goto out;
	}

	unsigned int file_sz = block_spare_sz * n_blocks;
	if ((fs.f_bsize * fs.f_bfree) <= file_sz) {
		printf("Not enough space available on %.*s\n", strcspn(nand_path, ":/") + 1, nand_path);
		printf("At least %uMiB free space is required!\n", file_sz >> 20);
		goto out;
	}

	fp = fopen(nand_path, "wb");
	if (!fp) {
		perror("fopen");
		goto out;
	}

	if (fseek(fp, file_sz, SEEK_SET) < 0) {
		perror("fseek");
		goto cancel_backup;
	}

	if (!fwrite(&keys, sizeof keys, 1, fp) /* force expand the file(?) */) {
		perror("fwrite");
		goto cancel_backup;
	}

	fseek(fp, 0, SEEK_SET);

	ShaContext sha = {};
	uint32_t hash[5] = {};
	Sha_Init(&sha);

	uint64_t want_exit_time = 0;
#endif

	uint64_t start = gettime();
	uint64_t lastupdate = 0;
	puts("Press HOME/START/EJECT to stop.");

	for (unsigned int i = 0; i < n_blocks; i++) {
		unsigned char *ptr_block = buffer + ((i % buffer_cnt) * block_spare_sz);

		if (diff_msec(lastupdate, gettime()) >= 250 || (i + 1) == n_blocks) {
			lastupdate = gettime();

			// int barwidth = conX - (5 /* ___% */ + 2 /* [] */ + 1 /* to avoid new line lol */);
			int barwidth = conX - ( 16 /* [ XXXX / XXXX ] */ + 1);
			float prog = (i + 1) / (float)n_blocks;
			int r = prog * barwidth;

			// printf("% 3i%% [%.*s%*s]\r", (int)(prog * 100), r, thestring, barwidth - r, "");
			printf("[ %4u / %4u ] \x1b[42;1m%*s\x1b[40m%*s\r", i + 1, n_blocks, r, "", barwidth - r, "");
		}
		// printf("\rBlock progress: [ %i/%i ] @ %.2fs   ", i + 1, n_blocks, diff_msec(start, gettime()) / 1.0e+3);

		for (unsigned int j = 0; j < (1 << pages_per_block); j++) {
			unsigned char* ptr_page = ptr_block + (j * page_spare_sz);

			IOS_Seek(fd, (i << pages_per_block) + j, SEEK_SET); // ret < 0 will not automatically advance the page for us
			ret = IOS_Read(fd, ptr_page, page_spare_sz);


			// FS checks this in the first 2 pages of a block
			if (j < 2) {
				uint8_t check_byte = ptr_page[(1 << nandsize.page_size) + nandsize.check_byte_ofs];
				if ((ret == page_spare_sz || ret == -11 || ret == -12) && check_byte != 0xFF) {
					clearln();
					printf("Block %u: Marked as bad (%u, %02hhX)\n", i, j, check_byte);
					memset(ptr_block, 0, block_spare_sz);
					break;
				}
			}

			if (ret != page_spare_sz) {
				switch (ret) {
					case -11:
						clearln();
						printf("Block %u: Corrected page %u\n", i, j);
						break;

					case -12:
						if (page_is_erased(ptr_page, &nandsize))
							break;

						clearln();
						printf("Block %u: Uncorrectable page %u\n", i, j);
						break;

					case -1:
						clearln();
						printf("NAND error (what? block %u, page %u)", i, j);
						break;

					default:
						clearln();
						printf("Unknown error %i (block %u, page %u)\n", ret, i, j);
						break;
				}
			}
		}

#ifndef NANDDUMPER_READ_TEST
		Sha_Update(&sha, ptr_block, block_spare_sz);
		unsigned write_cnt = (i % buffer_cnt) + 1;
		if (write_cnt == buffer_cnt || i + 1 >= n_blocks) {
			// Time to write

			// Retrying is not worth it
			if (!fwrite(buffer, block_spare_sz * write_cnt, 1, fp)) {
				perror("\nfwrite");
				goto cancel_backup;
/*
				int wait = tries * 15;

				printf("Trying again in %us. Press any button to skip wait. (try %i/%i)\n", wait, tries, max);
				uint64_t current = gettime();
				while (diff_sec(current, gettime()) < wait) {
					input_scan();
					if (input_read(0))
						break;

					// don't rush
					usleep(1000);
				}

				puts("Trying again.");
*/
			}
		}
#endif

		input_scan();
		if (input_read(INPUT_START | INPUT_EJECT)) {
			// Time to exit
#ifdef NANDDUMPER_READ_TEST
			goto cancel_backup;
#else
			uint64_t time_now = gettime();
			unsigned int time_diff = diff_sec(want_exit_time, time_now);
			if ((time_diff - 1) <= 14) {
				clearln();
				puts("Cancelled by user.");
				goto cancel_backup;
			}

			clearln();
			puts("\x1b[30;1m(Press that again in 1-15s.)\x1b[39m"); // grey
			want_exit_time = time_now;
#endif
		}

	}

	putchar('\n');
#ifndef NANDDUMPER_READ_TEST
	memcpy(buffer, &keys, sizeof keys);
	Sha_Update(&sha, buffer, sizeof keys);
	Sha_Finish(&sha, hash);

	fwrite(buffer, sizeof keys, 1, fp);
	fclose(fp);

	// printf("\n\nFinal SHA1 hash: %08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
	{
		char* sha_path = alloca(strlen(nand_path) + 16);
		strcpy(sha_path, nand_path);
		strcat(sha_path, ".sha1");
		FILE* fp_sha = fopen(sha_path, "wb");
		if (!fp_sha) {
			perror("fopen(.sha1)");
		} else {
			fwrite(hash, sizeof hash, 1, fp_sha);
			fclose(fp_sha);
		}

		const char* ptr_fname = strrchr(nand_path, '/');
		if (!ptr_fname++) ptr_fname = nand_path;

		strcpy(sha_path + (ptr_fname - nand_path), "sha1sums.txt");
		fp_sha = fopen(sha_path, "a");
		if (!fp_sha) {
			perror("fopen(sha1sums.txt)");
		} else {
			fprintf(fp_sha, "%08x%08x%08x%08x%08x *%s\n", hash[0], hash[1], hash[2], hash[3], hash[4], ptr_fname);
			fclose(fp_sha);
		}
	}
#endif

	printf("Time elapsed: %.3fs\n", diff_msec(start, gettime()) / 1.0e+3);
out:
	IOS_Close(fd);
	free(buffer);
	return ret;

cancel_backup:
#ifndef NANDDUMPER_READ_TEST
	printf("Deleting %s. Sorry.\n", nand_path);
	fclose(fp);
	remove(nand_path);
#endif
	goto out;
}

#define BACKUP_DIR "/wii/backups"
int main(void) {
	__exception_setreload(30);

#ifdef NANDDUMPER_READ_TEST
	puts("\x1b[42mnanddumper@IOS " STR(NANDDUMPER_REVISION) " by thepikachugamer\x1b[40m");
#else
	puts("nanddumper@IOS " STR(NANDDUMPER_REVISION) " by thepikachugamer");
#endif

#ifdef NANDDUMPER_FORCE_IOS
	IOS_ReloadIOS(NANDDUMPER_FORCE_IOS);
#else
	IOS_ReloadIOS(IOS_GetVersion());
#endif
	// branch galore
	printf("running on IOS%uv%u (v%u.%u)\n\n", IOS_GetVersion(), IOS_GetRevision(), IOS_GetRevisionMajor(), IOS_GetRevisionMinor());
	usleep(1e+4);

	input_init();

	void* sp = (void *)0x90100000;

	int ret = do_sha_exploit(realcode_bin, false, sp, 0x1000, 0);
	if (ret < 0) {
		print_error("do_sha_exploit", ret);
		goto out;
	}

	// wait for our device to appear
	{
		int fd = -1, timer = 100;
		while ((ret = fd = IOS_Open("/dev/realcode", 0)) == -6) {
			usleep(100);
			if (!timer--) {
				break;
			}
		}

		if (fd < 0) {
			print_error("IOS_Open(/dev/realcode)", fd);
			goto out;
		}

		IOS_Close(fd);
	}

	write16(MEM2_PROT, false);
	ret = patch_flash_access();
	if (ret < 0)
		goto out;


#ifndef NANDDUMPER_READ_TEST
	uint32_t    device_id = 0xFFFFFFFF;
	char        code[4];
	char        serno[10];
	char        serial[20] = "UNKNOWN";
	char        model[16]  = "UNKNOWN";
	const char *type = IS_WIIU ? "vWii (Wii U)" : "Wii/Wii Mini";
	char        comment[256];

	otp_read(9, 1, &device_id);

	/* get the serial... */
	if (!IS_WIIU && __CONF_GetTxt("MODEL", model, sizeof model) > 0) {
		if (memcmp(model, "RVD", 3) == 0)
			type = "NDEV 2.x";
		else if (memcmp(model, "RVT", 3) == 0)
			type = "NDEV 1.x/Revolution Arcade(!?)";
		else if (memcmp(model, "RVL-001", 7) == 0)
			type = "Wii";
		else if (memcmp(model, "RVL-101", 7) == 0)
			type = "Wii Family Edition";
		else if (memcmp(model, "RVL-201", 7) == 0)
			type = "Wii Mini";
	}

	if (__CONF_GetTxt("CODE", code, sizeof code) > 0 &&  __CONF_GetTxt("SERNO", serno, sizeof serno) > 0) {
		snprintf(serial, sizeof serial, "%s%s", code, serno);

		int i, check = 0;
		for (i = 0; i < 8; i++) {
			uint8_t digit = serno[i] - '0';
			if (digit >= 10) {
				strcat(serial, " (?\?)");
				break;
			}

			if (i & 1)
				digit += (digit << 1);

			check += digit;
		}
		if (i == 8) {
			check = (10 - (check % 10)) % 10;
			if (serno[i] - '0' != check)
				strcat(serial, " (?)");
		}
	}

	printf(
		"Console model: %s [%s]\n"
		"Console ID:    %08x\n"
		"Serial number: %s\n\n", type, model, device_id, serial
	);

	/* get the time... */
	time_t tm = 0;
	struct tm dt = {};
	char datestr[30];

	time(&tm);
	localtime_r(&tm, &dt);
	sprintf(datestr, "%02d%02d%02d", dt.tm_year - 100, dt.tm_mon + 1, dt.tm_mday);

	serial[strcspn(serial, " (?)")] = '\0';
	snprintf(comment, sizeof comment,
		"nanddumper@IOS by thepikachugamer\n"
		"Console model: %s [%s]\n"
		"Console ID: %08x\n"
		"Serial number: %s\n\n"

		"thank you mkwcat <3\n", type, model, device_id, serial
	);

	FATDevice* dev = NULL;
	if (!FATMount(&dev)) {
		puts("FATMount failed. Nothing much to do here anymore.");
		puts("Well, maybe a read test? Lol.");
		goto out;
	}

	if (!dev) {
		puts("[*] Choose a device to dump the NAND to.");

		int x = 0;
		while (true) {
			clearln();
			printf("\r[*] Device: < %s > ", devices[x].friendlyName);
			uint32_t buttons = input_wait(0);
			if (buttons & INPUT_LEFT) {
				if (x == 0) x = fat_num_devices;
				x--;
			}
			else if (buttons & (INPUT_RIGHT | INPUT_POWER)) {
				if (++x == fat_num_devices) x = 0;
			}
			else if (buttons & (INPUT_A | INPUT_RESET)) {
				dev = &devices[x];
				break;
			}
			else if (buttons & (INPUT_START | INPUT_EJECT)) {
				break;
			}
		}

		putchar('\n');
		putchar('\n');
	}

	if (!dev) {
		puts("Operation cancelled by user.");
		goto out_nowait;
	}

	char paths[2][128];
	// ehh, why was i numbering the keys file // why was i dating it as well ....
	sprintf(paths[1], "%s:" BACKUP_DIR "/%s_keys.bin", dev->name, serial);
	for (char *base = paths[1], *ptr = base; (ptr = strchr(ptr, '/')) != NULL; ptr++)
	{
		*ptr = 0;
		if (mkdir(base, 0644) < 0 && errno != EEXIST) {
			perror(base);
			ret = -errno;
			goto out;
		}
		*ptr = '/';
	}

	for (int i = 0; i < 100; i++) {
		struct stat st;

		sprintf(paths[0], "%s:" BACKUP_DIR "/%s_%s_nand_%02d.bin", dev->name, datestr, serial, i);

		if (stat(paths[0], &st) < 0)
			break;
	}

	puts("Start the NAND backup now?");
	puts("Press HOME/START/EJECT to cancel. Press any other button to continue.\n");
	usleep(1e+5);
	if (input_wait(0) & (INPUT_START | INPUT_EJECT))
		goto out_nowait;

	printf("Saving to %s\n", paths[0]);

	ret = do_nand_backup(paths[0], paths[1], comment);
	goto out;
#else
	ret = do_nand_backup();
	goto out;
#endif
out_nowait:
#ifndef NANDDUMPER_READ_TEST
	FATUnmount();
#endif
	input_shutdown();

	return ret;
out:
	puts("Press any button to exit.");
	input_wait(0);
	goto out_nowait;
}
