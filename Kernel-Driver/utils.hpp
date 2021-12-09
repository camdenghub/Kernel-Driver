#pragma once
#include <tuple>
#include <random>
#include <cstdint>
#include <memory>
#include "windows_exports.hpp"

using process_reference = std::unique_ptr<std::remove_pointer_t<PEPROCESS>, decltype(&ObfDereferenceObject)>;
using driver_reference = std::unique_ptr<std::remove_pointer_t<PDRIVER_OBJECT>, decltype(&ObfDereferenceObject)>;

namespace utils
{
	void* trampoline_at(void* base_address)
	{
		static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

		const auto nt_header = RtlImageNtHeader(base_address);

		if (!nt_header)
			return nullptr;

		const auto section_array = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

		for (auto section = 0; section < nt_header->FileHeader.NumberOfSections; section++)
		{
			const auto current = section_array[section];

			if (current.VirtualAddress == 0 || current.Misc.VirtualSize == 0)
				continue;

			if (!(current.Characteristics & 0x20000000) || !(current.Characteristics & 0x08000000))
				continue;

			const auto section_address = reinterpret_cast<char*>(base_address) + current.VirtualAddress;

			for (auto i = section_address; i < (section_address + current.SizeOfRawData) - 1; ++i)
			{
				if (!i)
					continue;

				if (*reinterpret_cast<std::uint16_t*>(i) == 0xe1ff)
					return i;
			}
		}

		return nullptr;
	}

	process_reference reference_process_by_pid(std::uintptr_t pid)
	{
		static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

		PEPROCESS process{ };

		if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process)))
			return process_reference(nullptr, nullptr);

		return process_reference(process, &ObfDereferenceObject);
	}
}