#include <stdint.h>

typedef struct {
	uint32_t state[5];
	uint32_t length[2];
} ShaContext;
_Static_assert(sizeof(ShaContext) == 0x1C, "ShaContext");

int Sha_Init(ShaContext* ctx);
int Sha_Update(ShaContext* ctx, void* data, unsigned size);
int Sha_Finish(ShaContext* ctx, uint32_t* hash);
