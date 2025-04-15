#include <unistd.h>
#include <gccore.h>
#include <ogc/pad.h>
#include <wiikeyboard/usbkeyboard.h>

#include "pad.h"

static uint32_t pad_buttons;

/* USB Keyboard stuffs */
static lwp_t kbd_thread_hndl = LWP_THREAD_NULL;
static volatile bool kbd_thread_should_run = false;
static uint32_t kbd_buttons;

// from Priiloader (/tools/Dacoslove/source/Input.cpp (!?))
void KBEventHandler(USBKeyboard_event event)
{
	if (event.type != USBKEYBOARD_PRESSED && event.type != USBKEYBOARD_RELEASED)
		return;

	// OSReport("event=%#x, keycode=%#x", event.type, event.keyCode);
	uint32_t button = 0;

	switch (event.keyCode) {
		case 0x52: // Up
			button = WPAD_BUTTON_UP;
			break;
		case 0x51: // Down
			button = WPAD_BUTTON_DOWN;
			break;
		case 0x50: // Left
			button = WPAD_BUTTON_LEFT;
			break;
		case 0x4F: // Right
			button = WPAD_BUTTON_RIGHT;
			break;
		case 0x28: // Enter
		case 0x58: // Enter (Numpad)
			button = WPAD_BUTTON_A;
			break;
		case 0x2A: // Backspace
			button = WPAD_BUTTON_B;
			break;
		case 0x1B: // X
			button = WPAD_BUTTON_1;
			break;
		case 0x1C: // Y
			button = WPAD_BUTTON_2;
			break;
		case 0x2E: // +
		case 0x57: // + (Numpad)
			button = WPAD_BUTTON_PLUS;
			break;
		case 0x2D: // -
		case 0x56: // - (Numpad)
		case 0x4C: // Delete
			button = WPAD_BUTTON_MINUS;
			break;
		case 0x29: // ESC
		case 0x4A: // Home
			button = WPAD_BUTTON_HOME;
			break;

		default:
			break;
	}

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

// __attribute__((constructor))
void initpads() {
	WPAD_Init();
	PAD_Init();
	USB_Initialize();
	USBKeyboard_Initialize();

//	kbd_thread_should_run = true;
//	LWP_CreateThread(&kbd_thread_hndl, kbd_thread, 0, 0, 0x800, 0x7F);
}

void scanpads() {
	WPAD_ScanPads();
	PAD_ScanPads();
	pad_buttons = WPAD_ButtonsDown(0);
	u16 gcn_down = PAD_ButtonsDown(0);

	pad_buttons |= kbd_buttons;
	kbd_buttons = 0;
	if (SYS_ResetButtonDown()) pad_buttons |= WPAD_BUTTON_HOME;

	if (gcn_down & PAD_BUTTON_A) pad_buttons |= WPAD_BUTTON_A;
	if (gcn_down & PAD_BUTTON_B) pad_buttons |= WPAD_BUTTON_B;
	if (gcn_down & PAD_BUTTON_X) pad_buttons |= WPAD_BUTTON_1;
	if (gcn_down & PAD_BUTTON_Y) pad_buttons |= WPAD_BUTTON_2;
	if (gcn_down & PAD_BUTTON_START) pad_buttons |= WPAD_BUTTON_HOME | WPAD_BUTTON_PLUS;
	if (gcn_down & PAD_BUTTON_UP) pad_buttons |= WPAD_BUTTON_UP;
	if (gcn_down & PAD_BUTTON_DOWN) pad_buttons |= WPAD_BUTTON_DOWN;
	if (gcn_down & PAD_BUTTON_LEFT) pad_buttons |= WPAD_BUTTON_LEFT;
	if (gcn_down & PAD_BUTTON_RIGHT) pad_buttons |= WPAD_BUTTON_RIGHT;
}

__attribute__((destructor))
void stoppads() {
	WPAD_Shutdown();

	kbd_thread_should_run = false;
	usleep(400);
	USBKeyboard_Close();
	USBKeyboard_Deinitialize();
	if (kbd_thread_hndl != LWP_THREAD_NULL)
		LWP_JoinThread(kbd_thread_hndl, 0);

	kbd_thread_hndl = LWP_THREAD_NULL;

}

uint32_t wait_button(uint32_t button) {
	scanpads();
	while (!(pad_buttons & (button? button : ~0)) )
		scanpads();

	return pad_buttons & (button? button : ~0);
}

uint32_t buttons_down(uint32_t button) {
	return pad_buttons & (button? button : ~0);
}



