#include <stdint.h>

enum {
    INPUT_A         = 1 << 0,
    INPUT_B         = 1 << 1,
    INPUT_X         = 1 << 2,
    INPUT_Y         = 1 << 3,

    INPUT_UP        = 1 << 4,
    INPUT_DOWN      = 1 << 5,
    INPUT_LEFT      = 1 << 6,
    INPUT_RIGHT     = 1 << 7,

    INPUT_START     = 1 << 8,

    INPUT_EJECT     = 1 << 29,
    INPUT_POWER     = 1 << 30,
    INPUT_RESET     = 1 << 31,
};

void input_init();
void input_shutdown();
void input_scan();
uint32_t input_read(uint32_t mask);
uint32_t input_wait(uint32_t mask);
