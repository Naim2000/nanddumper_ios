#include <stdio.h>
#include <ogc/console.h>
#include <unistd.h>
#include <errno.h>
#include <fat.h>
#include <gctypes.h>
#include <sdcard/wiisd_io.h>
#include <ogc/usbstorage.h>

#include "fatMounter.h"

// static FATDevice* active = NULL;
FATDevice devices[] = {
	{ "Wii SD card slot",			"sd",	&__io_wiisd },
	{ "USB mass storage device",	"usb",	&__io_usbstorage },
};
unsigned fat_num_devices = (sizeof(devices) / sizeof(FATDevice));

bool FATMount(FATDevice** preferred) {
	int i = 0;

	if (preferred) *preferred = NULL;

	for (FATDevice* dev = devices; dev < devices + fat_num_devices; dev++) {
		dev->state = 0;
		dev->disk->startup();
		if (dev->disk->isInserted()) {
			// dev->state = 1;
			printf("[+] Mounting \"%s\" ... ", dev->friendlyName);
			if (fatMountSimple(dev->name, dev->disk)) {
				dev->state = 1;
				*preferred = dev;
				i++;
				// puts(CONSOLE_GREEN "OK!" CONSOLE_RESET); // This looks awful on a thin font. damn.
				puts("OK!");
			}
			else {
				// puts(CONSOLE_RED "Failed!" CONSOLE_RESET);
				puts("Failed!");

				dev->disk->shutdown();
			}
		}
		else dev->disk->shutdown();
	}

	if (i == 0) {
		puts(CONSOLE_ESC(37;2m) "[-] No storage devices are attached..." CONSOLE_RESET);
		return false;
	}
	else if (i == 1) {
		return true;
	}
	else {
		*preferred = NULL;
		/*
		if (__system_argv->argvMagic == ARGV_MAGIC && __system_argv->argc) {
			for (FATDevice* dev = devices; dev < devices + fat_num_devices; dev++) {
				if (strncmp(__system_argv->argv[0], dev->name, strlen(dev->name)) == 0) {
					*preferred = dev;
				}
			}
		}
		*/
	}

	return true;
}

void FATUnmount() {
	for (FATDevice* dev = devices; dev < devices + fat_num_devices; dev++) {
		if (dev->state > 0) {
			fatUnmount(dev->name);
			dev->disk->shutdown();
			dev->state = 0;
		}
	}
}

// const char* GetActiveDeviceName() { return active? active->name : NULL; }

