#define LT_CHIPREVID	0xCD8005A0
#define IS_WIIU			((*(volatile unsigned int *)LT_CHIPREVID & 0xFFFF0000) == 0xCAFE0000)
