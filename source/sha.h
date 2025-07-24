#include <stdint.h>
#include "common.h"

typedef struct {
	uint32_t state[5];
	uint32_t length[2];
} ShaContext;
CHECK_STRUCT_SIZE(ShaContext, 0x1C);

int Sha_Init(ShaContext* ctx);
int Sha_Update(ShaContext* ctx, void* data, unsigned size);
int Sha_Finish(ShaContext* ctx, uint32_t* hash);
int do_sha_exploit(const void *entrypoint, bool thumb, void *argument, void *stack_base, unsigned stack_size, int8_t priority, uint32_t pid);
