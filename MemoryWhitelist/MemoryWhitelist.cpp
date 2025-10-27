// Purpose is to whitelist executable regions of your program & to use that to locate mapped regions

#include <windows.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <unordered_set>

#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NTAPI NtQueryVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
);

struct MemoryRegion {
	uintptr_t address;
	size_t size;
	DWORD state;
	DWORD allocProt;
	DWORD curProt;
};
std::unordered_set<uintptr_t> whitelist{};// shouldnt keep this static

#pragma region Utils

__forceinline bool isWhitelist(uintptr_t tAddress) {
	return whitelist.find(tAddress) != whitelist.end();
}

__forceinline bool isExecutable(DWORD prot) {
	if (prot & PAGE_EXECUTE ||
		prot & PAGE_EXECUTE_READ ||
		prot & PAGE_EXECUTE_READWRITE ||
		prot & PAGE_EXECUTE_WRITECOPY)
		return true;
	return false;
}

#pragma endregion

std::vector<MemoryRegion> get_memory_regions() {
	MEMORY_BASIC_INFORMATION mbi;
	size_t address = 0;
	std::vector<MemoryRegion> regions{};
	regions.reserve(30000);

	while (true) {
		SIZE_T retLen = 0;
		NTSTATUS status = NtQueryVirtualMemory(
			GetCurrentProcess(),
			(PVOID)address,
			0,
			&mbi,
			sizeof(mbi),
			&retLen
		);
		if (status < 0) break;

		MemoryRegion region;
		region.address = (uintptr_t)mbi.BaseAddress;
		region.size = mbi.RegionSize;
		region.state = mbi.State;
		region.allocProt = mbi.AllocationProtect;
		region.curProt = mbi.Protect;

		regions.emplace_back(region);
		if (mbi.RegionSize == 0) break;
		address += mbi.RegionSize;
	}

	std::sort(regions.begin(), regions.end(), [](const MemoryRegion& a, const MemoryRegion& b) {
		return a.address < b.address;
	});

	return regions;
}

// TODO: call this when ur program loads properly (or whatever)
// also if your gonna load a new module you should whitelist it
__forceinline void WhitelistBase() {
	std::vector<MemoryRegion> regions = get_memory_regions();

	for (auto region : regions)
		whitelist.insert(region.address);
}

// not meant to "stop" injection just to keep them busy for a bit lowk
__forceinline void VerifyWhitelist() {
	std::vector<MemoryRegion> regions = get_memory_regions();

	for (auto region : regions) {
		// skip whitelisted pages
		if (isWhitelist(region.address))
			continue;

		// skip read/write regions
		if (!isExecutable(region.allocProt))
			continue;

		// if its an injectable we can crash it by setting the region permissions
		if (isExecutable(region.curProt)) {
			std::cout << "Memory mapped of size 0x" << std::hex << region.size << std::endl;

			DWORD oldProt; // grr
			VirtualProtect((LPVOID)region.address, region.size, PAGE_READWRITE, &oldProt);
		}
	}
}

int main()
{
	WhitelistBase();

	std::cout << "Prepared & looking for mapped regions\n";
	while (true) {
		Sleep(1000 / 24);

		VerifyWhitelist();
	}
}
