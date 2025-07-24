#include <string.h>
#include <ogc/ipc.h>

#include "flash.h"

enum FlashCommand {
	FLASH_IOCTL_GET_SIZE    = 1,
	FLASH_IOCTL_GET_LOG     = 2,
	FLASH_IOCTL_ERASE_BLOCK = 3,
	FLASH_IOCTL_CHECK_BLOCK = 4,
};

static int fd = -1;
static struct FlashSizeInfo size_info;

int Flash_Init(void) {
	int ret;

	if (fd >= 0)
		return 0;

	ret = fd = IOS_Open("/dev/flash", 0);
	if (ret < 0)
		return ret;

	ret = IOS_Ioctl(fd, FLASH_IOCTL_GET_SIZE, NULL, 0, &size_info, sizeof(FlashSizeInfo));
	if (ret < 0) {
		IOS_Close(fd);
		fd = -1;
		return ret;
	}

	return 0;
}

int Flash_Close(void) {
	if (fd < 0)
		return FLASH_ENOTREADY;

	IOS_Close(fd);
	fd = -1;
	memset(&size_info, 0, sizeof(FlashSizeInfo));
	return 0;
}

int Flash_GetSizeInfo(struct FlashSizeInfo* out) {
	if (fd < 0)
		return FLASH_ENOTREADY;

	if (!out)
		return FLASH_EINVAL;

	*out = size_info;
	return 0;
}

int Flash_GetCommandLog(struct FlashCommandLog* out) {
	if (fd < 0)
		return FLASH_ENOTREADY;

	if (!out)
		return FLASH_EINVAL;

	return IOS_Ioctl(fd, FLASH_IOCTL_GET_LOG, NULL, 0, out, sizeof(FlashCommandLog));
}

static bool page_is_erased(uint8_t* page, bool spare) {
	if (spare) {
		uint32_t* ecc = (uint32_t *)(page + FLASH_SHIFT(size_info.page_size) + FLASH_SHIFT(size_info.spare_size));
		int n_ecc = FLASH_SHIFT(size_info.page_size - 9); // 9: 512 bytes per ECC entry

		for (int i = n_ecc; i; i--) {
			if (~ecc[-i])
				return false;
		}
	} else {
		uint32_t* page32 = (uint32_t *)page;

		for (int i = 0; i < FLASH_SHIFT(size_info.page_size); i++)
			if (~page32[i])
				return false;
	}

	return true;
}

int Flash_ReadPage(unsigned int idx, bool spare, uint8_t* out) {
	int ret;

	if (fd < 0)
		return FLASH_ENOTREADY;

	if (FLASH_SHIFTD(idx, size_info.nand_size - size_info.page_size) || out == NULL)
		return FLASH_EINVAL;

	unsigned page_sz = FLASH_SHIFT(size_info.page_size);
	if (spare)
		page_sz += FLASH_SHIFT(size_info.spare_size);

	ret = IOS_Seek(fd, idx, SEEK_SET);
	if (ret < 0) // !?
		return ret;

	ret = IOS_Read(fd, out, page_sz);
	if (ret == page_sz || (ret == FLASH_ECC_CRIT && page_is_erased(out, spare)))
		ret = 0;

	return ret;
}

int Flash_ReadBlock(unsigned int idx, bool spare, uint8_t* out) {
	int ret;

	if (fd < 0)
		return FLASH_ENOTREADY;

	if (FLASH_SHIFTD(idx, size_info.nand_size - size_info.block_size) || out == NULL)
		return FLASH_EINVAL;

	unsigned n_pages = FLASH_SHIFT(size_info.block_size - size_info.page_size);
	unsigned page_sz = FLASH_SHIFT(size_info.page_size);
	if (spare)
		page_sz += FLASH_SHIFT(size_info.spare_size);

	ret = IOS_Seek(fd, FLASH_SHIFTM(idx, size_info.block_size - size_info.page_size), SEEK_SET);
	if (ret < 0) // !?
		return ret;

	uint8_t (*pages)[page_sz] = (uint8_t (*)[page_sz])out;
	ret = 0;
	for (unsigned i = 0; i < n_pages; i++) {
		int lret = IOS_Read(fd, pages[i], page_sz);
		if (lret < 0) {
			// seek to the next page manually
			IOS_Seek(fd, 1, SEEK_CUR);

			switch (lret) {
				case FLASH_ECC_CRIT: {
					if (!page_is_erased(pages[i], spare))
						ret = lret;
				} break;

				case FLASH_ECC: {
					if (ret != FLASH_ECC_CRIT)
						ret = lret;
				} break;

				case FLASH_EIO: {
					return lret;
				} break;

				default: {
					return lret;
				} break;
			}
		}

		// we can call the check block ioctl, OR, we can do what it does while just reading the block!! wow!!
		if (spare) {
			if (i < 2) {
				uint8_t check_byte = pages[i][FLASH_SHIFT(size_info.page_size) + size_info.check_byte_ofs];
				if (check_byte != 0xFF) {
					memset(out, 0, page_sz * n_pages);
					return FLASH_BADBLOCK;
				}
			}
		}
	}

	return ret;
}

int Flash_CheckBlock(unsigned int idx) {
	int ret;

	if (fd < 0)
		return FLASH_ENOTREADY;

	if (FLASH_SHIFTD(idx, size_info.nand_size - size_info.block_size))
		return FLASH_EINVAL;

	ret = IOS_Seek(fd, FLASH_SHIFTM(idx, size_info.block_size - size_info.page_size), SEEK_SET);
	if (ret >= 0)
		ret = IOS_Ioctl(fd, FLASH_IOCTL_CHECK_BLOCK, NULL, 0, NULL, 0);

	return ret;
}
