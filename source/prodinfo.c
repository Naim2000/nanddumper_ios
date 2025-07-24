#include <stdio.h>
#include <ogc/console.h>
#include <string.h>
#include <ctype.h>
#include <ogc/isfs.h>
#include <ogc/es.h>

#define SETTING_TXT_PATH "/title/00000001/00000002/data/setting.txt"
#define SETTING_TXT_SIZE 0x100

static int InfoReady = 0;
static char SettingBuffer[SETTING_TXT_SIZE] [[gnu::aligned(0x20)]]; // ISFS demands.
static const uint32_t key_unrolled[32 / 4] = {
	0xfaf4e9d3, 0xa74e9c39, 0x73e7ce9d, 0x3b76edda, 0xb56bd7ae, 0x5dbb76ed, 0xdbb76fdf, 0xbf7ffefd
};

static void ProductInfo_DecryptBuffer(const char* in, char* out)
{
	const uint32_t* in32 = (const uint32_t *)in;
	uint32_t* out32 = (uint32_t *)out;

	for (int i = 0; i < (32 / 4); i++) {
		for (int j = i; j < (SETTING_TXT_SIZE / 4); j += (32 / 4))
			out32[j] = in32[j] ^ key_unrolled[i];
	}

	memset(out + strnlen(in, SETTING_TXT_SIZE), '\0', SETTING_TXT_SIZE - strnlen(in, SETTING_TXT_SIZE));
}

int ProductInfo_Init(void) {
	int ret, fd;

	if (InfoReady)
		return 0;

	ret = fd = ISFS_Open(SETTING_TXT_PATH, ISFS_OPEN_READ);
	if (ret < 0)
		return ret;

	ret = ISFS_Read(fd, SettingBuffer, SETTING_TXT_SIZE);
	ISFS_Close(fd);
	if (ret < 0)
		return ret;

	else if (ret != SETTING_TXT_SIZE)
		return -1;

	ProductInfo_DecryptBuffer(SettingBuffer, SettingBuffer);

	InfoReady = 1;
	return 0;
}

// The way official software does this is, interesting. The file is kept encrypted in memory (ofc) and then they use a state-machine-whatever to step through the bytes of the buffer. We don't have to do allat though! Or, we won't.
// I will note that it seems to like
// <https://github.com/koopthekoopa/wii-ipl/blob/main/libs/RVL_SDK/src/sc/scapi_prdinfo.c#L77C1-L77C57>
//             if (((ptext ^ type[typeOfs]) & 0xDF) == 0) {
// have case insensitivity? interesting. (0xDF is ~0x20)
int ProductInfo_Find(int len; const char* item, char out[len], int len) {
	if (!InfoReady || !item || !out || !len)
		return 0;

	const char* ptr = SettingBuffer;
	while (*ptr && ptr - SettingBuffer < SETTING_TXT_SIZE) {
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

char* ProductInfo_GetSerial(char serial[24]) {
	char code[4], serno[12];

	if (!serial)
		return NULL;

	if (!InfoReady)
		return strcpy(serial, "Info not ready!");

	if (!ProductInfo_Find("CODE", code, sizeof code) || !ProductInfo_Find("SERNO", serno, sizeof serno))
		return strcpy(serial, "UNKNOWN");

	snprintf(serial, 24, "%s%s", code, serno);

	/* https://3dbrew.org/wiki/Serials */
	int i, check = 0;
	for (i = 0; i < 8; i++) {
		unsigned digit = serno[i] - '0';
		if (digit >= 10) {
			printf(CONSOLE_ESC(37;2m) "Invalid serial 'number' %s" CONSOLE_RESET "\n", serial);
			break;
		}

		if (i & 1) // odd position
			digit += (digit << 1); // * 3

		check += digit;
	}

	if (i == 8) {
		check = (10 - (check % 10)) % 10;
		if (serno[i] - '0' != check)
			printf(CONSOLE_ESC(37;2m) "Invalid serial number %s" CONSOLE_RESET "\n", serial);
	}


	return serial;
}

#define CASE_CONSOLE_MODEL(model, len, v, name) \
	if (memcmp(model, v, strlen(v)) == 0) \
		return name;

static bool ProductInfo_IsRVA(void) {
	int fd = ISFS_Open("/title/00000001/00000002/data/RVA.txt", 0);
	ISFS_Close(fd);

	return (fd >= 0);
}

const char* ProductInfo_GetConsoleType(char model[16]) {
	char _model[16] = {};

	if (!model)
		model = _model;

	if (!InfoReady) {
		strcpy(model, "Info not ready!");
		return "Info not ready!";
	}

	int len = ProductInfo_Find("MODEL", model, 16); // pointer, cannot use sizeof. [16] is really just a hint
	if (!len) {
		strcpy(model, "UNKNOWN");
		return "UNKNOWN";
	}

	// Status update!! Wii System Transfer checks the device ID. I was right lol. Not too invasive to put it in here.
	{
		uint32_t device_id = 0;
		if (ES_GetDeviceID(&device_id) == 0 && (device_id >> 28) == 0x2)
			return "vWii (Wii U)";
	}
	CASE_CONSOLE_MODEL(model, ret, "RVL-001", "Wii");
	CASE_CONSOLE_MODEL(model, ret, "RVL-101", "Wii Family Edition");
	CASE_CONSOLE_MODEL(model, ret, "RVL-201", "Wii Mini");
	CASE_CONSOLE_MODEL(model, ret, "RVT", ProductInfo_IsRVA() ? "Revolution Arcade(?!)" : "NDEV 1.x(?)");
	CASE_CONSOLE_MODEL(model, ret, "RVD", "NDEV 2.x");

	return "UNKNOWN";
}
