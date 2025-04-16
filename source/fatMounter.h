#include <stdbool.h>

// Inspired by YAWM ModMii Edition
typedef struct {
	const char*           friendlyName;
	const char*           name;
	const DISC_INTERFACE* disk;
	int                   state;
} FATDevice;
extern FATDevice devices[];
extern unsigned fat_num_devices;

bool FATMount(FATDevice** preferred);
void FATUnmount();
// const char* GetActiveDeviceName();
