/*
 * From xyzzy-mod by DarkMatterCore. Original xyzzy by bushing
 * https://github.com/DarkMatterCore/xyzzy-mod/blob/master/source/vwii_sram_otp.h
 *
 * Sort of, anyways. The vwii_sram_otp_read() business is a waste of time
 */

#ifndef __VWII_SRAM_OTP_H__
#define __VWII_SRAM_OTP_H__

// #define SRAM_OTP_MIRR   0xD407F00
// #define SRAM_OTP_SIZE   0x80

typedef struct {
    u32 ms_id; // 0x00000002
    u32 ca_id; // 0x00000001
    u32 ng_key_id;
    u8 ng_sig[60];
    /* locked out, seemingly */
    u8 korean_key[16];
    u8 nss_device_cert[32];
} vwii_sram_otp_t;

static const vwii_sram_otp_t* const vwii_sram_otp = (const vwii_sram_otp_t *)0xCD407F00; // not volatile. not changing any time soon ha

// u16 vwii_sram_otp_read(void *dst, u16 offset, u16 size);

#endif /* __VWII_SRAM_OTP_H__ */
