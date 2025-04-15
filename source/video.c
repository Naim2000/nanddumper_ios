#include <stdio.h>
#include <stdlib.h>
#include <ogc/system.h>
#include <ogc/cache.h>
#include <ogc/video.h>
#include <ogc/color.h>
#include <ogc/consol.h>

#include "video.h"

static void* xfb = NULL;
static GXRModeObj vmode = {};

int conX, conY;

// from LoadPriiloader
__attribute__((constructor))
void init_video() {
	VIDEO_Init();

	// setup view size
	VIDEO_GetPreferredMode(&vmode);
	vmode.viWidth = 672;

	// set correct middlepoint of the screen
    if ((vmode.viTVMode >> 2) == VI_PAL) {
		vmode.viXOrigin = (VI_MAX_WIDTH_PAL - vmode.viWidth) / 2;
		vmode.viYOrigin = (VI_MAX_HEIGHT_PAL - vmode.viHeight) / 2;
	}
	else {
		vmode.viXOrigin = (VI_MAX_WIDTH_NTSC - vmode.viWidth) / 2;
		vmode.viYOrigin = (VI_MAX_HEIGHT_NTSC - vmode.viHeight) / 2;
	}

	size_t fbSize = __builtin_align_up(VIDEO_GetFrameBufferSize(&vmode), 0x20);
	xfb = aligned_alloc(0x20, fbSize);
	DCInvalidateRange(xfb, fbSize);
	xfb = (void*)((uintptr_t)xfb | SYS_BASE_UNCACHED);

	VIDEO_SetBlack(true);
	VIDEO_Configure(&vmode);
	VIDEO_Flush();
	VIDEO_WaitVSync();

	// Initialise the console
	CON_InitEx(&vmode, (vmode.viWidth - CONSOLE_WIDTH) / 2,
					   (vmode.viHeight - CONSOLE_HEIGHT) / 2,
					   CONSOLE_WIDTH, CONSOLE_HEIGHT);
	CON_GetMetrics(&conX, &conY);

	VIDEO_ClearFrameBuffer(&vmode, xfb, COLOR_BLACK);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(false);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if (vmode.viTVMode & VI_NON_INTERLACE)
		VIDEO_WaitVSync();
}

void clear() {
	VIDEO_WaitVSync();
//	VIDEO_ClearFrameBuffer(&vmode, xfb, COLOR_BLACK);
	printf("%s", "\x1b[2J");
}

void clearln() {
	putchar('\r');
	for (int i = 1; i < conX; i++)
		putchar(' ');

	putchar('\r');
	fflush(stdout);
}
