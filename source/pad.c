#include <stdio.h>
#include <unistd.h>
#include <gccore.h>
#include <ogc/lwp_watchdog.h>
#include <ogc/pad.h>
#include <ogc/stm.h>
#include <wiikeyboard/usbkeyboard.h>

#include "pad.h"

#define INPUT_WIIMOTE
#define INPUT_GCN
// #define INPUT_USB_KEYBOARD
#define INPUT_USE_FACEBTNS

static int input_initialized = 0;

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
static uint64_t stm_lastinput;
static uint32_t stm_input;
void STMEventHandler(uint32_t event) {
	uint64_t now = gettime();

	if (diff_msec(stm_lastinput, now) < 200) {
		// printf("stm input is too early\n");
		return;
	}

	stm_lastinput = now;
	if (event == STM_EVENT_POWER)
		stm_input = INPUT_POWER;
	else if (event == STM_EVENT_RESET && SYS_ResetButtonDown())
		stm_input = INPUT_RESET;
	else
		stm_input = 0;

	// printf("event = %u stm_input = %x\n", event, stm_input);
}
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
	LWP_CreateThread(&kbd_thread_hndl, kbd_thread, 0, 0, 0x800, 0x7F);
#endif

#ifdef INPUT_USE_FACEBTNS
	STM_RegisterEventHandler(STMEventHandler);
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
	if (stm_input) {
		// printf("detected stm input\n");
		if (diff_msec(stm_lastinput, gettime()) < 200)
			button |= stm_input;
		// else
			// printf("stm input is too late");

		stm_input = 0;
	}
#endif

	return button & mask;
}



