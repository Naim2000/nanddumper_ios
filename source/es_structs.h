#pragma once
#include "common.h"

typedef enum SignatureType: uint32_t {
    SIG_RSA4096_SHA1 = 0x00010000,
    SIG_RSA2048_SHA1 = 0x00010001,
    SIG_ECC233_SHA1  = 0x00010002,
} SignatureType;

typedef enum KeyType: uint32_t {
    KEY_RSA2048 = 0x00000001,
    KEY_ECC233  = 0x00000002,
} KeyType;

typedef struct {
    SignatureType   type;
    uint8_t         signature[0x200];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureRSA4096;
CHECK_STRUCT_SIZE(SignatureRSA4096, 0x280);

typedef struct {
    SignatureType   type;
    uint8_t         signature[0x100];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureRSA2048;
CHECK_STRUCT_SIZE(SignatureRSA2048, 0x180);

typedef struct {
    SignatureType   type;
    union {
        struct { uint8_t r[30], s[30]; };
        uint8_t signature[60];
    };
    uint8_t         padding[0x40];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureECC;
CHECK_STRUCT_SIZE(SignatureECC, 0xC0);

typedef struct {
    KeyType  type;
    char     name[0x40];
    uint32_t keyid;
} CertHeader;

typedef struct {
    uint8_t modulus[0x100];
    uint8_t exponent[4];
} KeyRSA2048;

typedef union {
    struct { uint8_t x[30], y[30]; };
    uint8_t xy[60];
} KeyECC;

typedef struct {
    SignatureRSA4096 signature;
    CertHeader       header;
    KeyRSA2048       key;
} CertRSA4096RSA2048, CACert;
CHECK_STRUCT_SIZE(CertRSA4096RSA2048, 0x400);

typedef struct {
    SignatureRSA2048 signature;
    CertHeader       header;
    KeyRSA2048       key;
} CertRSA2048RSA2048, SignerCert, CPCert, XSCert;
CHECK_STRUCT_SIZE(CertRSA2048RSA2048, 0x300);

typedef struct {
    SignatureRSA2048 signature;
    CertHeader       header;
    KeyECC           key;
} CertRSA2048ECC, MSCert;
CHECK_STRUCT_SIZE(CertRSA2048ECC, 0x240);

typedef struct {
    SignatureECC signature;
    CertHeader   header;
    KeyECC       key;
} CertECC, NGCert, DeviceCert, APCert;
CHECK_STRUCT_SIZE(CertECC, 0x180);

typedef enum: uint32_t {
    None        = 0,
    TimeLimit   = 1, // seconds
    None2       = 3,
    LaunchCount = 4,
} TicketLimitType;

typedef struct {
    TicketLimitType type;
    uint32_t        max;
} TicketLimit;

typedef struct {
    SignatureRSA2048 signature;
    KeyECC   public_key;
    uint8_t  verison;
    uint8_t  reserved[2];
    uint8_t  title_key[16];
    uint8_t  padding;
    uint64_t ticket_id;
    uint32_t console_id;
    uint64_t title_id;
    uint8_t  access_mask[2];
    uint8_t  padding2[2];
    uint32_t permitted_title_mask;
    uint32_t permitted_title;
    uint8_t  reserved2;
    uint8_t  common_key_index;
    uint8_t  reserved3[0x2F];
    uint8_t  reserved4; // audit
    uint8_t  content_access_permissions[0x40];
    uint8_t  padding3[2];
    TicketLimit limits[8];
} __attribute__((packed, aligned(4))) Ticket;
CHECK_STRUCT_SIZE(Ticket, 0x2A4);

typedef struct {
    uint32_t cid;
    uint16_t index;
    uint16_t type;
    uint64_t size;
    uint8_t  hash[20];
} __attribute__((packed)) TitleMetadataContent, TMDContent;
CHECK_STRUCT_SIZE(TitleMetadataContent, 0x24);

typedef struct {
    SignatureRSA2048 signature;
    uint8_t  version;
    uint8_t  reserved[2];
    uint8_t  vwii_title;
    uint64_t sys_version;
    uint64_t title_id;
    uint32_t title_type;
    uint16_t group_id;
    uint8_t  reserved2[2];
    uint16_t region;
    uint8_t  ratings[16];
    uint8_t  reserved3[12];
    uint8_t  ipc_mask[12];
    uint8_t  reserved4[18];
    uint32_t access_rights;
    uint16_t title_version;
    uint16_t num_contents;
    uint16_t boot_index;
    uint16_t minor_version;
    TitleMetadataContent contents[];
} __attribute__((packed)) TitleMetadata, TMD;
CHECK_STRUCT_SIZE(TitleMetadata, 0x1E4);
#define S_TMD_SIZE(x) (offsetof(TitleMetadata, contents[((TitleMetadata *)(x))->num_contents]))
