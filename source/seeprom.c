#include <ogc/irq.h>

#include "seeprom.h"

static volatile uint32_t* const HW_REG_BASE = (volatile uint32_t *)0xcd800000;

#define HW_REG_READ(x) (HW_REG_BASE[(x) / 4])
#define HW_REG_WRITE(x, v) (HW_REG_BASE[(x) / 4] = (v))

/* https://wiibrew.org/wiki/Hollywood/GPIOs */

#define HW_REG_GPIO1OUT 0xe0
#define HW_REG_GPIO1IN  0xe8

#define EEP_CS		(1 << 10)
#define EEP_CLK		(1 << 11)
#define EEP_MOSI	(1 << 12)
#define EEP_MISO	(1 << 13)

// This function does not seem to be in any headers
extern void udelay(int us);
static inline void seeprom_delay() {
	udelay(5);
}

static inline void set_bits(int reg, unsigned mask, bool set) {
	// don't say it don't say it
	uint32_t v1 = HW_REG_READ(reg);
	uint32_t v2 = set ? (v1 | mask) : (v1 & ~mask);

	if (v1 ^ v2)
		HW_REG_WRITE(reg, v2);
}

static inline void seeprom_clk(bool set) {
	set_bits(HW_REG_GPIO1OUT, EEP_CLK, set);
}

static inline void seeprom_cs(bool set) {
	set_bits(HW_REG_GPIO1OUT, EEP_CS, set);
}

static inline void seeprom_mosi(bool set) {
	set_bits(HW_REG_GPIO1OUT, EEP_MOSI, set);
}

static inline bool seeprom_miso(void) {
	return (bool)(HW_REG_READ(HW_REG_GPIO1IN) & EEP_MISO);
}

/*
 * https://www.microchip.com/en-us/product/93C56A
 * https://ww1.microchip.com/downloads/aemDocuments/documents/OTH/ApplicationNotes/ApplicationNotes/00993a.pdf
 * Ofc i'm actually just following IOS's footsteps but this doc lines up nice and well
 */

#define CMD_WIDTH 11
#define CMD_READ(addr)		(0b110 << 8 | ((addr) & 0xFF))
#define CMD_WRITE(addr)		(0b101 << 8 | ((addr) & 0xFF))
#define CMD_ERASE			(0b10010 << 6)
#define CMD_EWEN			(0b10011 << 6)
#define CMD_EWDS			(0b10000 << 6)

static uint32_t seeprom_recv(unsigned n_bits) {
	if ((uint32_t)(1 << n_bits) == 0)
		return 0;

	uint32_t ret = 0;
	while (n_bits--) {
		seeprom_clk(false);
		seeprom_cs(true);
		seeprom_delay();
		seeprom_clk(true);
		seeprom_delay();

		ret |= seeprom_miso() << n_bits;
	}

	return ret;
}

static void seeprom_send(unsigned n_bits, uint32_t value) {
	if ((uint32_t)(1 << n_bits) == 0)
		return;

	while (n_bits--) {
		seeprom_clk(false);
		seeprom_cs(true);
		seeprom_mosi((bool)(value & (1 << n_bits)));
		seeprom_delay();
		seeprom_clk(true);
		seeprom_delay();
	}
}

static void seeprom_zero(unsigned count) {
	while (count) {
		seeprom_clk(false);
		seeprom_cs(false); // Lol, how come this one is a direct write and then the enable one is a separate call
		seeprom_mosi(false);
		seeprom_delay();
		seeprom_clk(true);
		seeprom_delay();

		count--;
	}
	seeprom_clk(false);
}

static uint16_t seeprom_get(unsigned offset) {
	seeprom_send(CMD_WIDTH, CMD_READ(offset));
	uint16_t ret = seeprom_recv(16);
	seeprom_zero(2);

	return ret;
}

int seeprom_read(unsigned offset, unsigned count, uint16_t out[count]) {
	if (offset + count > SEEPROM_WORD_COUNT || !out)
		return 0;

	uint32_t level = IRQ_Disable();
	for (unsigned i = 0; i < count; i++) {
		out[i] = seeprom_get(offset + i);
	}
	IRQ_Restore(level);

	return count;
}

#ifdef SEEPROM_ENABLE_WRITE
static bool seeprom_wait(void) {
	int timeout = 100;
	while (timeout--) {
		uint32_t v = seeprom_recv(10);
		if (v & 1) break;
	}
	seeprom_zero(2);

	return (timeout > 0);
}

static inline void seeprom_unlock(bool unlock) {
	seeprom_send(CMD_WIDTH, unlock ? CMD_EWEN : CMD_EWDS);
	seeprom_zero(2);
}

static bool seeprom_set(unsigned offset, uint16_t value) {
	seeprom_send(CMD_WIDTH + 16, (CMD_WRITE(offset) << 16) | value);
	seeprom_zero(2);
	return seeprom_wait();
}

int seeprom_write(unsigned offset, unsigned count, const uint16_t* in) {
	if (offset + count > SEEPROM_WORD_COUNT || !in)
		return 0;

	uint32_t level = IRQ_Disable();
	{
		seeprom_unlock(true);

		unsigned i;
		for (i = 0; i < count; i++) {
			if (!seeprom_set(offset + i, in[i]))
				break;
		}

		seeprom_unlock(false);
	}
	IRQ_Restore(level);

	return i;
}

#endif /* SEEPROM_ENABLE_WRITE */
