#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fat.h>
#include <gctypes.h>
#include <sdcard/wiisd_io.h>
#include <ogc/usbstorage.h>

#include "fatMounter.h"

#include <ogc/libversion.h>
#if ((_V_MAJOR_ > 2) || (_V_MINOR_ > 11) || (_V_PATCH_ > 0))
#pragma message "Me too :) add some cool colors please!!"
#endif

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
				puts("OK!");
			}
			else {
				puts("Failed!");
				dev->disk->shutdown();
			}
		}
		else dev->disk->shutdown();
	}

	if (i == 0) {
		puts("\x1b[30;1m[-] No storage devices are attached...\x1b[39m");
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

