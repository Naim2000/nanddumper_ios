#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ogc/machine/processor.h>
#include <ogc/lwp_watchdog.h>
#include <fat.h>

#include "common.h"
#include "video.h"
#include "pad.h"
#include "sha.h"
#include "otp.h"
#include "mini_seeprom.h"
#include "vwii_sram_otp.h"
#include "realcode_bin.h"

#define HW_AHBPROT		0x0D800064
#define MEM2_PROT		0x0D8B420A
#define LT_CHIPREVID	0x0D8005A0
#define IS_WIIU			((read32(LT_CHIPREVID) & 0xFFFF0000) == 0xCAFE0000)


uint16_t* const IOSVersion = (uint16_t* const)0x80003140;

void __exception_setreload(unsigned seconds);

typedef struct FlashErrorLog {
	int page, command, ret;
} FlashErrorLog;

typedef struct FlashComandLog {
	int deletes, writes, reads, copies; /* ? */
	int error_over_idx, error_idx;
	FlashErrorLog errors[32];
} FlashComandLog;
_Static_assert(sizeof(FlashComandLog) == 0x198, "FlashComandLog");

typedef struct FlashSizeInfo {
	// log2
	int   nand_size, block_size, page_size, spare_size, ecc_size, /* ? */ unknown;
	short check_byte_ofs;
	short padding;
} FlashSizeInfo;
_Static_assert(sizeof(FlashSizeInfo) == 0x1C, "FlashSizeInfo");

typedef struct KeysBin {
	char		comment[256];
	WiiOTP		otp;
	char		padding[128];
	seeprom_t	seeprom;
	char		padding2[256];
} KeysBin;
_Static_assert(sizeof(KeysBin) == 0x400, "KeysBin");

// thank you mkwcat (<3)
int do_the_haxx(void) {
	IOS_ReloadIOS(21);
	// IOS_ReloadIOS(*IOSVersion);
	usleep(100000);

	uint32_t* mem1 = (uint32_t *)0x80000000;

	// put in some code
	mem1[0] = 0x4903468D;	/* ldr r1, =0x10100000; mov sp, r1; */
	mem1[1] = 0x49034788;	/* ldr r1, =entrypoint; blx r1; */
	/* Overwrite reserved handler to loop infinitely */
	mem1[2] = 0x49036209; 	/* ldr r1, =0xFFFF0014; str r1, [r1, #0x20]; */
	mem1[3] = 0x47080000;	/* bx r1 */
	mem1[4] = 0x10100000;	/* temporary stack */
	mem1[5] = MEM_VIRTUAL_TO_PHYSICAL(realcode_bin);
	mem1[6] = 0xFFFF0014;	/* reserved handler */

	IOS_Write(-1, mem1, 0x40);
	int ret = Sha_Init((ShaContext *)0xFFFE0028);
	if (ret < 0) {
		print_error("/dev/sha exploit", ret);
		return ret;
	}

	int clock = 1000;
	while (!read32(HW_AHBPROT)) {
		usleep(1000);
		if (!clock--) {
			printf("clocked out (waiting on AHBPROT)\n");
			return -1;
		}
	}

	write16(MEM2_PROT, 0);
	return 0;
}

int patch_flash_access(void) {
	void* mem2_ptr_cur = (void *)0x933E0000;
	void* mem2_ptr_end = (void *)0x94000000;

	// new
	uint16_t patternA[] = {
		0x2300, // mov r3, #0
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
	/*	0xf7ff, 0xfe00		bl FS_OpenInterface */
	};

	// old
	uint16_t patternB[] = {
		0x4643, // mov r3, r8
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
	};

	uint16_t* FS_OpenInterface = NULL;
	uint16_t* pc = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, patternA, sizeof patternA);
	if (!pc) {
		puts("I guess this is IOS <40?");
		pc = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, patternB, sizeof patternB);
		if (!pc) {
			puts("Still could not find stubbed /dev/flash check");
			return -1;
		}
	}

	pc += 3;
	int dst = ((pc[0] & 0x7FF) << 11) | (pc[1] & 0x7FF);
	dst |= -(dst & (1 << 21));

	FS_OpenInterface = pc + dst + 2;
	// printf("%p: %04hx %04hx\n", pc, pc[0], pc[1]);
	// printf("FS_OpenInterface => %p\n", FS_OpenInterface);

	uint16_t pattern2[] = {
		0x68ab, // ldr r3, [r5, #0x8] @ request->open.uid
		0x2b00, // cmp r3, #0x0
		0xd002, // beq 0x8
		0x2001, // mov r0,#1
		0x4240, // rsb r0,r0
		0xe008, // b 0xa
	/*	0xf7fa, 0xfcb7		bl FS_OpenBoot2 */
	};

	pc = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, pattern2, sizeof pattern2);
	if (!pc) {
		puts("Where is the /dev/boot2 uid check?");
		return -2;
	}

	pc += 6;
	// printf("%p: %04hx %04hx\n", pc, pc[0], pc[1]); // bl FS_OpenBoot2

	// Replace the branch.
	dst = FS_OpenInterface - (pc + 2);
	pc[0] = 0xF400 | ((dst >> 11) & 0x7FF);
	pc[1] = 0xF800 | (dst & 0x7FF);
	DCFlushRange(pc, 4);
	// printf("%p: %04hx %04hx\n", pc, pc[0], pc[1]);

	/* I can never seem to get this working if I try replace it with flash. */
	/*
	// Cosmetics
	const char pattern3[] = "fs\0\0boot2";
	char* ptr = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, pattern3, sizeof(pattern3));
	if (!ptr) {
		puts("Where is the boot2 string !?");
		return -3;
	}

	// memcpy(ptr + 4, "flash", 5);
	// DCFlushRange(ptr, 10);
	*/
	return 0;
}

static bool page_is_erased(unsigned char* page, FlashSizeInfo* size) {
	uint32_t* spare32 = (uint32_t *)(page + (1 << size->page_size));
	for (int i = 0; i < (1 << (size->spare_size - 2)); i++) {
		if (spare32[i] != 0xFFFFFFFF)
			return false;
	}

	return true;
}

int do_nand_backup(const char* nand_path, const char* keys_path, const char comment[256]) {
	int ret, fd;
	FlashSizeInfo nandsize = {};
	unsigned int buffer_cnt = 3, buffer_cnt_mask = (1 << buffer_cnt) - 1;
	unsigned int page_spare_sz, pages_per_block, block_spare_sz, n_blocks, buffer_sz;
	unsigned char *buffer = NULL;
	ShaContext sha = {};
	uint32_t hash[5] = {};
	FILE* fp = NULL;
	KeysBin keys = {};

	strcpy(keys.comment, comment);
	otp_read(0, OTP_WORD_COUNT, keys.otp.data);
	/*
	 * On the Wii U, there is no SEEPROM. Or rather, it doesn't have the data anyone would expect from a Wii NAND dump. (NG key id & signature, like, the other half of the device cert)
	 * That data is stored in bank 6 of the OTP. But we can't read the extra banks of the OTP from here. So instead, c2w reads that data from OTP and places it at the top of SRAM, and vIOS works with that instead. So let's work with that instead.
	 */
	if (IS_WIIU) {
		vwii_sram_otp_t sram_otp = {};
		vwii_sram_otp_read(&sram_otp, 0, SRAM_OTP_SIZE);

#if 1
		printf("* from the SRAM OTP: Root-%08x-%08x\n", sram_otp.ca_id, sram_otp.ms_id);
#endif

		keys.seeprom.ms_id = sram_otp.ms_id;
		keys.seeprom.ca_id = sram_otp.ca_id;
		keys.seeprom.ng_key_id = sram_otp.ng_key_id;
		memcpy(keys.seeprom.ng_sig, sram_otp.ng_sig, sizeof(keys.seeprom.ng_sig));
		// For the effect. Otherwise, I would just build the entire thing from the device certificate
		memcpy(keys.seeprom.korean_key, sram_otp.korean_key, sizeof(keys.seeprom.korean_key));
	} else {
		seeprom_read(&keys.seeprom, 0, SEEPROM_SIZE);
	}

	fp = fopen(keys_path, "wb");
	if (!fp) {
		perror(keys_path);
		return -errno;
	}

	if (!fwrite(&keys, sizeof keys, 1, fp)) {
		perror(keys_path);
		fclose(fp);
		return -errno;
	}

	fd = ret = IOS_Open("/dev/boot2", 0);
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
	buffer_sz       = block_spare_sz << buffer_cnt;

	buffer = aligned_alloc(0x40, buffer_sz);
	if (!buffer) {
		puts("Memory allocation failed");
		goto out;
	}

	fp = fopen(nand_path, "wb");
	if (!fp) {
		perror(nand_path);
		goto out;
	}

	if (fseek(fp, (block_spare_sz * n_blocks) + sizeof keys, SEEK_END) < 0) {
		perror(nand_path);
		fclose(fp);
		fp = NULL;
		remove(nand_path);
		goto out;
	}

	fseek(fp, 0, SEEK_SET);

	Sha_Init(&sha);
	uint64_t start = gettime();
	for (unsigned int i = 0; i < n_blocks; i++) {
		unsigned char *ptr_block = buffer + ((i & buffer_cnt_mask) * block_spare_sz);

		printf("\rBlock progress: %i/%i // %.3fs  ", i + 1, n_blocks, diff_msec(start, gettime()) / 1000.f);

		IOS_Seek(fd, i << pages_per_block, SEEK_SET);
		ret = IOS_Ioctl(fd, 4, NULL, 0, NULL, 0);

		if (ret < 0) {
			if (ret == -13) {
				printf("Block %u is marked as bad\n", i);
			} else {
				printf("check block %u => %i\n", i, ret);
			}

			memset(ptr_block, 0, block_spare_sz);
			goto skip_read;
		}

		for (unsigned int j = 0; j < (1 << pages_per_block); j++) {
			IOS_Seek(fd, (i << pages_per_block) + j, SEEK_SET); // ret < 0 will not automatically advance the page for us
			ret = IOS_Read(fd, ptr_block + (j * page_spare_sz), page_spare_sz);
			if (ret == page_spare_sz)
				continue;

			switch (ret) {
				case -11:
					ret = 0;
					printf("Corrected page %u\n", j);
					break;
				case -12:
					if (page_is_erased(ptr_block + (j * page_spare_sz), &nandsize)) {
						ret = 0;
						continue;
					}

					printf("Uncorrectable page %u\n", j);
					break;
				default:
					printf("Unknown error %i from page %u\n", ret, j);
					break;
			}
		}

skip_read:
		Sha_Update(&sha, ptr_block, block_spare_sz);
		if (((i & buffer_cnt_mask) == buffer_cnt_mask && !fwrite(buffer, buffer_sz, 1, fp))) {
			perror("fwrite");
			fclose(fp);
			fp = NULL;
			remove(nand_path);
			goto out;
		}
	}

	memcpy(buffer, &keys, sizeof keys);
	Sha_Update(&sha, buffer, sizeof keys);
	fwrite(buffer, sizeof keys, 1, fp);
	fclose(fp);
	fp = NULL;

	Sha_Finish(&sha, hash);
	printf("\n\nFinal SHA1 hash: %08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
	printf("Time elapsed: %.3fs\n", diff_msec(start, gettime()) / 1000.0f);
	{
		char* sha_path = alloca(strlen(nand_path) + 6);
		strcpy(sha_path, nand_path);
		strcat(sha_path, ".sha1");
		FILE* fp_sha = fopen(sha_path, "wb");
		if (!fp_sha) {
			perror(sha_path);
		} else {
			fwrite(hash, sizeof hash, 1, fp_sha);
			fclose(fp_sha);
		}
	}

out:
	IOS_Close(fd);
	free(buffer);
	if (fp) fclose(fp);

	return ret;
}

void CryptSettingTxt(const char* in, char* out)
{
	uint32_t key = 0x73B5DBFA;

	for (int i = 0; i < 0x100; i++) {
		out[i] = in[i] ^ key;
		key = (key << 1) | (key >> 31);
	}
}

int GetSettingValue(int len; const char* setting, const char* item, char out[len], int len) {
	const char* ptr = setting;

	while (ptr - setting < 0x100) {
		const char* value = strchr(ptr, '=');
		const char* endptr = strchr(ptr, '\r') ?: strchr(ptr, '\n');

		if (!value || !endptr)
			break;

		int nlen = value++ - ptr;
		int vlen = endptr - value;

		if (nlen == strlen(item) && memcmp(ptr, item, nlen) == 0) {
			if (vlen >= len) {
				printf("Item %s is too large (=%.*s)\n", item, vlen, value);
				return 0;
			}

			memcpy(out, value, vlen);
			out[vlen] = '\0';
			return vlen;
		}

		while (isspace((int)*++endptr))
			;

		ptr = endptr;
	}

	printf("Could not find item %s\n", item);
	return 0;
}

#define BACKUP_DIR "/private/wii/backups"
int main(int argc, char **argv) {
	int ret;
	uint32_t device_id;
	char     settingbuf[0x100] = {};
	char     serial[16] = {};

	__exception_setreload(30);
	puts("nanddumper@IOS by thepikachugamer");

	ret = do_the_haxx();
	if (ret < 0)
		return ret;

	printf("running on IOS%u v%u (v%u.%u)\n\n", IOSVersion[0], IOSVersion[1], IOSVersion[1] >> 8, IOSVersion[1] & 0xFF);

	printf("Console type: %s\n", IS_WIIU ? "vWii (Wii U)" : "Wii (or Mini!)");

	ret = patch_flash_access();
	if (ret < 0)
		return ret;

	/* get the time... */
	time_t tm = 0;
	struct tm dt = {};
	char tstr[30];

	time(&tm);
	localtime_r(&tm, &dt);
	sprintf(tstr, "%02d%02d%02d", dt.tm_year - 100, dt.tm_mon + 1, dt.tm_mday);

	/* get the serial... */
	ret = ES_GetDeviceID(&device_id);
	if (ret < 0) {
		print_error("ES_GetDeviceID", ret);
		return ret;
	}
	sprintf(serial, "NG%08x", device_id);
	printf("Console ID: %08x\n", device_id);

	int fd = ret = IOS_Open("/title/00000001/00000002/data/setting.txt", 1);
	if (ret < 0) {
		print_error("IOS_Open(setting.txt)", ret);
	}
	else {
		ret = IOS_Read(fd, settingbuf, sizeof settingbuf);
		IOS_Close(fd);
		if (ret != sizeof settingbuf) {
			print_error("IOS_Read(setting.txt)", ret);
		}
		else {
			CryptSettingTxt(settingbuf, settingbuf);
			ret = GetSettingValue(settingbuf, "CODE", serial, 4);
			if (!ret || !GetSettingValue(settingbuf, "SERNO", serial + ret, sizeof serial - ret)) {
				puts("Unable to determine serial number!");
			} else {
				printf("Serial number: %s\n", serial);
			}
		}

	}

	if (!fatInitDefault()) {
		puts("fatInitDefault failed. Nothing much to do here anymore.");
		return -1;
	}

	char paths[2][128];
	sprintf(paths[0], BACKUP_DIR "/%s_%s_nand.bin", tstr, serial);
	sprintf(paths[1], BACKUP_DIR "/%s_%s_keys.bin", tstr, serial);

	for (char *base = paths[0], *ptr = base; (ptr = strchr(ptr, '/')) != NULL; ptr++)
	{
		*ptr = 0;
		ret = mkdir(base, 0644);
		*ptr = '/';

		if (ret < 0 && errno != EEXIST) {
			perror(base);
			return -errno;
		}
	}

	char comment[256];
	sprintf(comment,
		"nanddumper@IOS by thepikachugamer\n"
		"Console type: %s\n"
		"Console ID: %08x\n"
		"Serial number: %s\n\n"

		"thank you mkwcat <3\n", IS_WIIU ? "vWii (Wii U)" : "Wii (or Mini!)", device_id, serial);

	printf("Saving to %s\n", paths[0]);
	return do_nand_backup(paths[0], paths[1], comment);
}

__attribute__((destructor))
void finished() {
	initpads();
	// puts("\nmain() exited with some code. idk what");
	puts("Press any button to exit.");
	// sleep(5);
	wait_button(0);
}
