#include <Windows.h>
#include <stdio.h>

#define IOCTL_WRITE_MSR 0x9C402088

#define TARGET_DEVICE "\\\\.\\GLOBALROOT\\Device\\WinRing0_1_2_0"

typedef struct _OLS_WRITE_MSR_INPUT {
	ULONG			Register;
	ULARGE_INTEGER	Value;
} OLS_WRITE_MSR_INPUT, *POLS_WRITE_MSR_INPUT;

int main(int argc, char** argv);