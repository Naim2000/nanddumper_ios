struct thread_parameters {
	int (*entrypoint)(void* argument);
	void *argument;
	void *stack_top;
	u32   stack_size;
	u32   priority;
	u32   pid;
	int  *threadid_out;
};
