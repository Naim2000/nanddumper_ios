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

#define HW_AHBPROT		0x0D800064
#define MEM2_PROT		0x0D8B420A
#define LT_CHIPREVID	0x0D8005A0
#define IS_WIIU			((read32(LT_CHIPREVID) & 0xFFFF0000) == 0xCAFE0000)

void __exception_setreload(unsigned seconds);

typedef struct FlashSizeInfo {
	// log2
	int   nand_size, block_size, page_size, spare_size, ecc_size, /* ? */ unknown;
	short check_byte_ofs;
	short padding;
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

// thank you mkwcat (<3)
int do_the_haxx(void) {
#ifdef NANDDUMPER_FORCE_IOS
	printf("Forcing IOS %d\n", NANDDUMPER_FORCE_IOS);
	IOS_ReloadIOS(NANDDUMPER_FORCE_IOS);
#else
	IOS_ReloadIOS(IOS_GetVersion());
#endif
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
	uint32_t* MEM2Size = (uint32_t *)0x80003118;

	void* mem2_ptr_cur = (void *)MEM2Size[2]; // End of MEM2 addressable to PPC.
	void* mem2_ptr_end = (void *)(0x90000000 + *MEM2Size); // Physical MEM2 size.
	uint16_t* pc = NULL;

	// new
	uint16_t patternA[] = {
		0x2300, // mov r3, #0
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
		/*         bl FS_OpenInterface */
	};

	// old
	uint16_t patternB[] = {
		0x4643, // mov r3, r8
		0x2b01, // cmp r3, #1
		0xd102, // bne 0x8
	};

	if (IOS_GetVersion() >= 40)
		pc = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, patternA, sizeof patternA);
	else
		pc = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, patternB, sizeof patternB);


	if (!pc) {
		puts("Could not find stubbed /dev/flash check. It's not actually enabled, is it?");
		int fd = IOS_Open("/dev/flash", 0);
		if (fd >= 0) {
			IOS_Close(fd);
			puts("... Oh, it really is...");
			return 0;
		}
		return -1;
	}

	pc += 3;
	int dst = ((pc[0] & 0x7FF) << 11) | (pc[1] & 0x7FF);
	dst |= -(dst & (1 << 21));

	uint16_t* FS_OpenInterface = pc + dst + 2;
	// printf("FS_OpenInterface => %p\n", FS_OpenInterface);

	uint16_t pattern2[] = {
		0x68ab, // ldr r3, [r5, #0x8] @ request->open.uid
		0x2b00, // cmp r3, #0x0
		0xd002, // beq 0x8
		0x2001, // mov r0,#1
		0x4240, // rsb r0,r0 @ -1 (EPERM)
		0xe008, // b 0xa
		/*         bl FS_OpenBoot2 */
	};

	pc = memmem(pc, mem2_ptr_end - (void *)pc, pattern2, sizeof pattern2);
	if (!pc) {
		puts("Where is the /dev/boot2 uid check?");
		return -2;
	}

	pc += 6;
	// printf("FS_OpenBoot2 call => %p\n", pc);

	// Replace the branch.
	dst = FS_OpenInterface - (pc + 2);
	pc[0] = 0xF400 | ((dst >> 11) & 0x7FF);
	pc[1] = 0xF800 | (dst & 0x7FF);
	DCFlushRange(pc, 6);

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

int do_nand_backup(
#ifndef NANDDUMPER_READ_TEST
	const char* nand_path, const char* keys_path,
#endif
	const char comment[256]
) {
	int ret, fd;
	FlashSizeInfo nandsize = {};
	unsigned int buffer_cnt = 3, buffer_cnt_mask = (1 << buffer_cnt) - 1;
	unsigned int page_spare_sz, pages_per_block, block_spare_sz, n_blocks, buffer_sz, file_sz;
	unsigned char *buffer = NULL;
	ShaContext sha = {};
	uint32_t hash[5] = {};
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

#if 0
		printf("* from the SRAM OTP: Root-CA%08x-MS%08x\n", sram_otp.ca_id, sram_otp.ms_id);
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

#ifndef NANDDUMPER_READ_TEST
	FILE* fp = NULL;
	fp = fopen(keys_path, "wb");
	if (!fp) {
		perror(keys_path);
		return -errno;
	}

	ret = fwrite(&keys, sizeof keys, 1, fp);
	fclose(fp);
	if (!ret) {
		perror(keys_path);
		return -errno;
	}
#endif
	fd = ret = IOS_Open("/dev/flash", 0);
	if (ret < 0) {
		// print_error("IOS_Open(/dev/flash)", ret);
		fd = ret = IOS_Open("/dev/boot2", 0); // Pay attention to how the patch works.
		if (ret < 0) {
			print_error("IOS_Open(/dev/boot2)*", ret);
			return ret;
		}
	}

	// safety test
	if (IOS_Ioctl(fd, 4, NULL, 0, NULL, 0) == -4) {
		puts("Hey, this is not /dev/flash....");
		IOS_Close(fd);
		return -4;
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
	file_sz         = block_spare_sz * n_blocks;

	buffer = aligned_alloc(0x40, buffer_sz);
	if (!buffer) {
		puts("Memory allocation failed");
		goto out;
	}
#ifndef NANDDUMPER_READ_TEST
	struct statvfs fs;
	ret = statvfs(nand_path, &fs);
	if (ret < 0) {
		perror("statvfs");
		return -errno;
	}

	if ((fs.f_bsize * fs.f_bfree) <= file_sz) {
		printf("Not enough space available on %.*s\n", strchr(nand_path, '/') - nand_path, nand_path);
		printf("At least %uMB free space is required!\n", file_sz >> 20);
		goto out;
	}

	fp = fopen(nand_path, "wb");
	if (!fp) {
		perror(nand_path);
		goto out;
	}

	if (fseek(fp, file_sz, SEEK_END) < 0 || !fwrite(&keys, sizeof keys, 1, fp) /* force expand the file(?) */) {
		perror(nand_path);
		fclose(fp);
		fp = NULL;
		remove(nand_path);
		goto out;
	}

	fseek(fp, 0, SEEK_SET);
#else
	puts("Press RESET to stop. It only takes like 100 seconds, though");
#endif
	Sha_Init(&sha);
	uint64_t start = gettime();
	for (unsigned int i = 0; i < n_blocks; i++) {
		unsigned char *ptr_block = buffer + ((i & buffer_cnt_mask) * block_spare_sz);
		bool is_bad = false;

		printf("\rBlock progress: %i/%i // %.3fs  ", i + 1, n_blocks, diff_msec(start, gettime()) / 1000.f);

		IOS_Seek(fd, i << pages_per_block, SEEK_SET);
		ret = IOS_Ioctl(fd, 4, NULL, 0, NULL, 0);

		if (ret < 0) {
			if (ret == -13) {
				printf("Block %u is marked as bad\n", i);
			} else {
				printf("check block %u => %i\n", i, ret);
			}

			is_bad = true;
			// memset(ptr_block, 0, block_spare_sz);
			// goto skip_read;
		}

		for (unsigned int j = 0; j < (1 << pages_per_block); j++) {
			IOS_Seek(fd, (i << pages_per_block) + j, SEEK_SET); // ret < 0 will not automatically advance the page for us
			ret = IOS_Read(fd, ptr_block + (j * page_spare_sz), page_spare_sz);
			if (ret == page_spare_sz || is_bad)
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

// skip_read:
		Sha_Update(&sha, ptr_block, block_spare_sz);
#ifndef NANDDUMPER_READ_TEST
		if (((i & buffer_cnt_mask) == buffer_cnt_mask && !fwrite(buffer, buffer_sz, 1, fp))) {
			perror("fwrite");
			fclose(fp);
			fp = NULL;
			remove(nand_path);
			goto out;
		}
#else
		if (SYS_ResetButtonDown())
			break;
#endif
	}

#ifndef NANDDUMPER_READ_TEST
	memcpy(buffer, &keys, sizeof keys);
	Sha_Update(&sha, buffer, sizeof keys);
	fwrite(buffer, sizeof keys, 1, fp);
	fclose(fp);
	fp = NULL;
#endif

	Sha_Finish(&sha, hash);
#ifndef NANDDUMPER_READ_TEST
	printf("\n\nFinal SHA1 hash: %08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
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
#endif

	printf("Time elapsed: %.3fs\n", diff_msec(start, gettime()) / 1000.0f);
out:
	IOS_Close(fd);
	free(buffer);
#ifndef NANDDUMPER_READ_TEST
	if (fp) fclose(fp);
#endif
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

#define BACKUP_DIR "/wii/backups"
int main(int argc, char **argv) {
	int         ret;
	uint32_t    device_id;
	char        settingbuf[0x100] = {};
	char        serial[20] = "UNKNOWN";
	char        model[32] = "UNKNOWN";
	const char *type = IS_WIIU ? "vWii (Wii U)" : "Wii/Wii Mini";
	char        comment[256];

	__exception_setreload(30);
	puts("nanddumper@IOS by thepikachugamer");

#ifdef NANDDUMPER_READ_TEST
	puts("\x1b[42m Read test build! \x1b[40m");
#endif

	ret = do_the_haxx();
	if (ret < 0)
		goto out;

	uint16_t iosRev = IOS_GetRevision();
	printf("running on IOS%u v%u (v%u.%u)\n\n", IOS_GetVersion(), iosRev, iosRev >> 8, iosRev & 0xFF);

	// printf("Console type: %s\n", IS_WIIU ? "vWii (Wii U)" : "Wii (or Mini!)");

	ret = patch_flash_access();
	if (ret < 0)
		goto out;

	ret = ES_GetDeviceID(&device_id);
	if (ret < 0) {
		print_error("ES_GetDeviceID", ret);
		goto out;
	}

	/* get the serial... */
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

			if (GetSettingValue(settingbuf, "MODEL", model, sizeof model) && !IS_WIIU) {
				if (memcmp(model, "RVT", 3) == 0)
					type = "NDEV";
				else if (memcmp(model, "RVL-001", 7) == 0)
					type = "Wii";
				else if (memcmp(model, "RVL-101", 7) == 0)
					type = "Wii Family Edition";
				else if (memcmp(model, "RVL-201", 7) == 0)
					type = "Wii Mini";
			}

			char code[4];
			char serno[10];

			if (GetSettingValue(settingbuf, "CODE", code, sizeof code) && GetSettingValue(settingbuf, "SERNO", serno, sizeof serno)) {
				snprintf(serial, sizeof serial, "%s%s", code, serno);

				int i, check = 0;
				for (i = 0; i < 8; i++) {
					uint8_t digit = serno[i] - '0';
					if (digit >= 10) {
						strcat(serial, "(?\?)");
						break;
					}

					if (i & 1)
						digit += (digit << 1);

					check += digit;
				}
				if (i == 8) {
					check = (10 - (check % 10)) % 10;
					if (serno[i] - '0' != check)
						strcat(serial, "(?)");
				}
			}
		}
	}

	printf(
		"Console model: %s [%s]\n"
		"Console ID:    %08x\n"
		"Serial number: %s\n\n", type, model, device_id, serial
	);


	snprintf(comment, sizeof comment,
		"nanddumper@IOS by thepikachugamer\n"
		"Console model: %s [%s]\n"
		"Console ID: %08x\n"
		"Serial number: %s\n\n"

		"thank you mkwcat <3\n", type, model, device_id, serial
	);

#ifndef NANDDUMPER_READ_TEST
	/* get the time... */
	time_t tm = 0;
	struct tm dt = {};
	char datestr[30];

	time(&tm);
	localtime_r(&tm, &dt);
	sprintf(datestr, "%02d%02d%02d", dt.tm_year - 100, dt.tm_mon + 1, dt.tm_mday);


	FATDevice* dev = NULL;
	if (!FATMount(&dev)) {
		puts("FATMount failed. Nothing much to do here anymore.");
		puts("Well, maybe a read test? Lol.");
		goto out;
	}

	if (!dev) {
		input_init();
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
		input_shutdown();

		putchar('\n');
		putchar('\n');
	}

	if (!dev) {
		puts("Operation cancelled by user.");
		goto out_nowait;
	}

	char paths[2][128];
	// ehh, why was i numbering the keys file
	sprintf(paths[1], "%s:" BACKUP_DIR "/%s_%s_keys.bin", dev->name, datestr, serial);
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
	usleep(10000);
	if (input_wait(0) & (INPUT_START | INPUT_EJECT))
		goto out_nowait;

	printf("Saving to %s\n", paths[0]);

	ret = do_nand_backup(paths[0], paths[1], comment);
#else
	ret = do_nand_backup(comment);
#endif
out:
	input_init();
	puts("Press any button to exit.");
	input_wait(0);
out_nowait:
#ifndef NANDDUMPER_READ_TEST
	FATUnmount();
#endif
	input_shutdown();

	return ret;
}
