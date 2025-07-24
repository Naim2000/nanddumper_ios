#include "common.h"
#include "keys.h"
#include <string.h>

#define KEYS_USE_DEVCERT /* No RNG seed lol. It does give us uhhh. Determinism, though. */

#ifdef KEYS_USE_DEVCERT
#include <ogc/es.h>
#include "es_structs.h"
#else
#include "sys.h"
#include "vwii_sram_otp.h"
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

	memcpy(keys->seeprom.ng_sig, certificate.signature.signature, sizeof(keys->seeprom.ng_sig));

	if (sscanf(certificate.signature.issuer, "Root-CA%08x-MS%08x", &keys->seeprom.ca_id, &keys->seeprom.ms_id) != 2) {
		errorf("Invalid device certificate signer %s", certificate.signature.issuer);
		return -1;
	}

	char name[] = "NGxxxxxxxx";
    sprintf(name, "NG%08x", keys->otp.device_id);
    if (memcmp(certificate.header.name, name, sizeof name) != 0) {
        errorf("Device certificate sanity check fail (%s =/= %s)", name, certificate.header.name);
        return -1;
    }

	keys->seeprom.ng_key_id = certificate.header.keyid;
#else
	/*
	 * On the Wii U, there is no SEEPROM. Or rather, it doesn't have the data anyone would expect from a Wii NAND dump. (NG key id & signature, like, the other half of the device cert)
	 * That data is stored in bank 6 of the OTP. But we can't read the extra banks of the OTP from here. So instead, c2w reads that data from OTP and places it at the top of SRAM, and vIOS works with that instead. So let's work with that instead.
	 */
	if (IS_WIIU) {
		keys->seeprom.ms_id = vwii_sram_otp->ms_id;
		keys->seeprom.ca_id = vwii_sram_otp->ca_id;
		keys->seeprom.ng_key_id = vwii_sram_otp->ng_key_id;
		memcpy(keys->seeprom.ng_sig, vwii_sram_otp->ng_sig, sizeof(keys->seeprom.ng_sig));

		// For the effect. Otherwise, I would just build the entire thing from the device certificate
		memcpy(keys->seeprom.korean_key, vwii_sram_otp->korean_key, sizeof(keys->seeprom.korean_key));
	} else {
		seeprom_read(&keys->seeprom, 0, SEEPROM_SIZE);
	}
#endif

	return 0;
}
