#include <stdint.h>
#include <wiiuse/wpad.h>

void initpads();
void scanpads();
void stoppads();
uint32_t wait_button(uint32_t);
uint32_t buttons_down(uint32_t);
