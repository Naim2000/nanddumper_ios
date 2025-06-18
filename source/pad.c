#include <stdio.h>
#include <unistd.h>

#include "pad.h"

static int input_initialized = 0;

#define INPUT_WIIMOTE
#define INPUT_GCN
// #define INPUT_USB_KEYBOARD
#define INPUT_USE_FACEBTNS


#ifdef INPUT_WIIMOTE
#include <wiiuse/wpad.h>
#endif

#ifdef INPUT_GCN
#include <ogc/pad.h>
#endif

#ifdef INPUT_USB_KEYBOARD
#include <wiikeyboard/usbkeyboard.h>
#endif

#ifdef INPUT_USE_FACEBTNS
#include <ogc/lwp_watchdog.h>

/* eh. we have AHB access. Lol. */
#include <ogc/machine/processor.h>
#endif

#ifdef INPUT_USB_KEYBOARD
/* USB Keyboard stuffs */
static lwp_t kbd_thread_hndl = LWP_THREAD_NULL;
static volatile bool kbd_thread_should_run = false;
static uint32_t kbd_buttons;

uint16_t keyboardButtonMap[0x100] = {
	[0x1B] = INPUT_X,
	[0x1C] = INPUT_Y,

	[0x28] = INPUT_A,
	[0x29] = INPUT_START, // ESC
	[0x2A] = INPUT_B,

	[0x2D] = 0, // -
	[0x2E] = 0, // +

	[0x4A] = INPUT_START,

	[0x4F] = INPUT_RIGHT,
	[0x50] = INPUT_LEFT,
	[0x51] = INPUT_DOWN,
	[0x52] = INPUT_UP,

	[0x56] = 0, // - (Numpad)
	[0x57] = 0, // + (Numpad)
	[0x58] = INPUT_A,
};

// from Priiloader (/tools/Dacoslove/source/Input.cpp (!?))
void KBEventHandler(USBKeyboard_event event)
{
	if (event.type != USBKEYBOARD_PRESSED && event.type != USBKEYBOARD_RELEASED)
		return;

	// OSReport("event=%#x, keycode=%#x", event.type, event.keyCode);
	uint32_t button = keyboardButtonMap[event.keyCode];

	if (event.type == USBKEYBOARD_PRESSED)
		kbd_buttons |= button;
	else
		kbd_buttons &= ~button;
}

void* kbd_thread(void* userp) {
	while (kbd_thread_should_run) {
		if (!USBKeyboard_IsConnected() && USBKeyboard_Open(KBEventHandler)) {
			for (int i = 0; i < 3; i++) { USBKeyboard_SetLed(i, 1); usleep(250000); }
		}

		USBKeyboard_Scan();
		usleep(400);
	}

	return NULL;
}

#endif

#ifdef INPUT_USE_FACEBTNS
#define HW_GPIO_IN			0x0D8000E8
#define HW_GPIO_POWER		(1 << 0)
#define HW_GPIO_EJECT		(1 << 6)
#if 0
/* Eh, let's not use interrupts at all. It was nice knowing you, though */

#define HW_PPCIRQFLAG		0x0D000030
#define HW_PPCIRQMASK		0x0D000034

#define HW_IRQ_GPIO			(1 << 11)
#define HW_IRQ_GPIOB		(1 << 10)
#define HW_IRQ_RST			(1 << 17)
#define HW_IRQ_IPC			(1 << 30)


// #define HW_GPIO_INTFLAG		0x0D8000F0
// #define HW_GPIO_OWNER		0x0D8000FC

// note to self: this interrupt will get fired A LOT

void gpio_handler(void) {
	uint32_t time_start = gettime();
	uint32_t down = read32(HW_GPIO_IN) & (HW_GPIO_EJECT | HW_GPIO_POWER);

	if (down == 0 || diff_msec(face_lastinput, time_start) < 200)
		return;

	if (down & HW_GPIO_EJECT) {
		puts("pressed EJECT");
		face_input = INPUT_EJECT;
		face_lastinput = time_start;
	}
	else if (down & HW_GPIO_POWER) {
		puts("pressed POWER");
		face_input = INPUT_POWER;
		face_lastinput = time_start;
	}
}

void rst_handler(void) {
	uint64_t time_start = gettime();

	if (diff_msec(face_lastinput, time_start) < 200)
		return;

	while (SYS_ResetButtonDown()) {
		uint64_t time_now = gettime();
		if (diff_usec(time_start, time_now) >= 100) {
			puts("pressed RESET");
			face_input = INPUT_RESET;
			face_lastinput = time_now;
			break;
		}
	}
}

raw_irq_handler_t ipc_handler = NULL;
void hollywood_irq_handler(uint32_t irq, void *ctx) {
	uint32_t flag = read32(HW_PPCIRQFLAG);

	if (flag & HW_IRQ_IPC) {
		ipc_handler(irq, ctx);
	}

	if (flag & HW_IRQ_RST) {
		write32(HW_PPCIRQFLAG, HW_IRQ_RST);
		// printf("RST interrupt down=%i\n", SYS_ResetButtonDown());
		rst_handler();
	}
/*
	if (flag & HW_IRQ_GPIO) {
		write32(HW_GPIO_INTFLAG, 0xFFFFFF);
		write32(HW_PPCIRQFLAG, HW_IRQ_GPIO);
		// printf("GPIOB interrupt flag=%08x mask=%08x in=%08x\n", read32(HW_GPIOB_INTFLAG), read32(HW_GPIOB_INTMASK), read32(HW_GPIOB_IN));
		gpio_handler();
	}
*/
}

#endif /* 0 */
#endif
void input_init() {
	if (input_initialized)
		return;

#ifdef INPUT_WIIMOTE
	WPAD_Init();
#endif

#ifdef INPUT_GCN
	PAD_Init();
#endif

#ifdef INPUT_USB_KEYBOARD
	USB_Initialize();
	USBKeyboard_Initialize();
	kbd_thread_should_run = true;
	LWP_CreateThread(&kbd_thread_hndl, kbd_thread, 0, 0, 0x800, 0x60);
#endif

	input_initialized = 1;
}

void input_scan() {
#ifdef INPUT_WIIMOTE
	WPAD_ScanPads();
#endif

#ifdef INPUT_GCN
	PAD_ScanPads();
#endif
}

void input_shutdown() {
	if (!input_initialized)
		return;

#ifdef INPUT_WIIMOTE
	WPAD_Shutdown();
#endif

#ifdef INPUT_USB_KEYBOARD
	kbd_thread_should_run = false;
	usleep(400);
	USBKeyboard_Close();
	USBKeyboard_Deinitialize();
	if (kbd_thread_hndl != LWP_THREAD_NULL)
		LWP_JoinThread(kbd_thread_hndl, 0);

	kbd_thread_hndl = LWP_THREAD_NULL;
#endif

	input_initialized = 0;
}

uint32_t input_wait(uint32_t mask) {
	uint32_t ret = 0;

	do {
		input_scan();
	} while ((ret = input_read(mask)) == 0);

	return ret;
}

uint32_t input_read(uint32_t mask) {
	uint32_t button = 0;

	if (!mask) mask = ~0;

#ifdef INPUT_WIIMOTE
	uint32_t wm_down = WPAD_ButtonsDown(0);

	if (wm_down & (WPAD_BUTTON_A | WPAD_CLASSIC_BUTTON_A)) button |= INPUT_A;
	if (wm_down & (WPAD_BUTTON_B | WPAD_CLASSIC_BUTTON_B)) button |= INPUT_B;
	if (wm_down & (WPAD_BUTTON_1 | WPAD_CLASSIC_BUTTON_X)) button |= INPUT_X;
	if (wm_down & (WPAD_BUTTON_2 | WPAD_CLASSIC_BUTTON_Y)) button |= INPUT_Y;

	if (wm_down & (WPAD_BUTTON_UP | WPAD_CLASSIC_BUTTON_UP)) button |= INPUT_UP;
	if (wm_down & (WPAD_BUTTON_DOWN | WPAD_CLASSIC_BUTTON_DOWN)) button |= INPUT_DOWN;
	if (wm_down & (WPAD_BUTTON_LEFT | WPAD_CLASSIC_BUTTON_LEFT)) button |= INPUT_LEFT;
	if (wm_down & (WPAD_BUTTON_RIGHT | WPAD_CLASSIC_BUTTON_RIGHT)) button |= INPUT_RIGHT;

	if (wm_down & WPAD_BUTTON_HOME) button |= INPUT_START;
#endif

#ifdef INPUT_GCN
	uint32_t gcn_down = PAD_ButtonsDown(0);

	if (gcn_down & PAD_BUTTON_A) button |= INPUT_A;
	if (gcn_down & PAD_BUTTON_B) button |= INPUT_B;
	if (gcn_down & PAD_BUTTON_X) button |= INPUT_X;
	if (gcn_down & PAD_BUTTON_Y) button |= INPUT_Y;

	if (gcn_down & PAD_BUTTON_UP) button |= INPUT_UP;
	if (gcn_down & PAD_BUTTON_DOWN) button |= INPUT_DOWN;
	if (gcn_down & PAD_BUTTON_LEFT) button |= INPUT_LEFT;
	if (gcn_down & PAD_BUTTON_RIGHT) button |= INPUT_RIGHT;

	if (gcn_down & PAD_BUTTON_START) button |= INPUT_START;
#endif

#ifdef INPUT_USB_KEYBOARD
	button |= kbd_buttons;
	kbd_buttons = 0;
#endif

#ifdef INPUT_USE_FACEBTNS
	uint64_t time_now = gettime();
	static uint64_t last_input = 0;
	if (!last_input || diff_msec(last_input, time_now) >= 200) {
		if (SYS_ResetButtonDown()) {
			button |= INPUT_RESET;
			last_input = time_now;
		}

		else if (read32(HW_GPIO_IN) & HW_GPIO_POWER) {
			button |= INPUT_POWER;
			last_input = time_now;
		}

		else if (read32(HW_GPIO_IN) & HW_GPIO_EJECT) {
			button |= INPUT_EJECT;
			last_input = time_now;
		}
	}
#endif

	return button & mask;
}



