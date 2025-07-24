#include <stdio.h>
#include <inttypes.h>

int main() {
	uint32_t key = 0x73B5DBFA;
	uint8_t key_unroll[0x20] = {};

	for (int i = 0; i < 0x20; i++) {
		key_unroll[i] = key;
		key = (key << 1) | (key >> 31);
	}

	FILE* fp = fopen("key_unrolled.bin", "wb");
	fwrite(key_unroll, sizeof key_unroll, 1, fp);
	fclose(fp);

	return 0;
}
