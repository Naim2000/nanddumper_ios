#include <types.h>
#include <ios/syscalls.h>

#include "shared.h"

typedef struct IOS_Context {
	u32 cpsr;
	union {
		struct {
			u32   _[13];
			void* sp;
			void* lr;
			void* pc;
		};
		struct {
			u32 r[16];
		};
	};
} IOS_Context;
CHECK_SIZE(IOS_Context, 0x44);

typedef struct IOS_Thread {
	struct IOS_Context userContext;
	struct IOS_Thread* next;
	int                initialPriority;
	int                priority;
	unsigned int       state;
	unsigned int       pid;
	int                detached;
	int                returnValue;
	void*              joinQueue;
	void*              threadQueue;
	struct IOS_Context syscallContext;
	void*              syscallStackTop;
} IOS_Thread;
CHECK_SIZE(IOS_Thread, 0xB0);

// this assumption is correct if we made it here
static IOS_Thread* const Threads = (IOS_Thread *)0xFFFE0000;

__attribute__((target("thumb")))
void _start(struct thread_parameters* params) {
	int threadid = OSCreateThread(params->entrypoint, params->argument, params->stack_top, params->stack_size, params->priority, true);

	if (threadid > 0) {
		IOS_Thread* thread = &Threads[threadid];

		thread->userContext.cpsr |= 0x0000001F;
		thread->pid = params->pid;
		OSStartThread(threadid);
	}

	*params->threadid_out = threadid;
	OSDCFlushRange(params->threadid_out, sizeof threadid);
}
