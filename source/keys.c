#include <string.h>
#include "common.h"
#include "keys.h"
#include "sys.h"

// #define KEYS_USE_DEVCERT

#ifdef KEYS_USE_DEVCERT
#include <ogc/es.h>
#include "es_structs.h"
#else
/*
 * undefined4 SEEPROM_readShort(int param_1,uint *param_2)
 * {
 *     *param_2 = (uint)vWiiSEEPROM[param_1]; // <-- fffe7f00
 *     return 0;
 * }
 *
 * yeah ok
 */
static const WiiSEEPROM* const vwii_seeprom = (const WiiSEEPROM *)0xCD4E7F00;
#endif


int build_keys(KeysBin* keys) {
	otp_read(0, OTP_WORD_COUNT, keys->otp.data);

#ifdef KEYS_USE_DEVCERT
	DeviceCert certificate;
	int ret = ES_GetDeviceCert((void *)&certificate);
	if (ret != 0) {
		print_error("ES_GetDeviceCert", ret);
		return ret;
	}

	memcpy(keys->seeprom.ng_signature, certificate.signature.signature, sizeof(keys->seeprom.ng_signature));

	if (sscanf(certificate.signature.issuer, "Root-CA%08x-MS%08x", &keys->seeprom.ca_id, &keys->seeprom.ms_id) != 2) {
		errorf("Invalid device certificate signer %s", certificate.signature.issuer);
		return -1;
	}

	char name[] = "NGxxxxxxxx";
	sprintf(name, "NG%08x", keys->otp.device_id);
	if (memcmp(certificate.header.name, name, sizeof name) != 0) {
		errorf("Device cert sanity check fail (%s =/= %s)", name, certificate.header.name);
		return -1;
	}

	keys->seeprom.ng_key_id = certificate.header.keyid;
#else
	/*
	 * On the Wii U, there is no SEEPROM. Or rather, it doesn't have the data anyone would expect from a Wii NAND dump. (NG key id & signature, like, the other half of the device cert)
	 * That data is stored in bank 6 of the OTP. But we can't read the extra banks of the OTP from here. So instead, c2w reads that data from OTP and places it at the top of SRAM, and vIOS works with that instead. So let's work with that instead.
	 */
	if (IS_WIIU) {
		printf("from the SRAM: Root-CA%08x-MS%08x, prng_seed=[%04hx %04hx]\n", vwii_seeprom->ca_id, vwii_seeprom->ms_id, vwii_seeprom->prng_seed[0], vwii_seeprom->prng_seed[1]);
		keys->seeprom = *vwii_seeprom;
	} else {
		seeprom_read(0, SEEPROM_WORD_COUNT, keys->seeprom.data);
	}
#endif
	return 0;
}
