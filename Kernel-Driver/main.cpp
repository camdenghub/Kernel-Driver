#include "windows_exports.hpp"
#include "utils.hpp"
#include "shared_structs.hpp"
#include "raid_extension.hpp"

#include <string>
#include <memory>
#include <stdio.h>
#include <string>
#include <iostream>

void write_to_local_memory(PEPROCESS local_process, void* data, void* data_local, std::uint64_t size)
{
	if (!data)
		return;

	if (!local_process)
		return;


	static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uint64_t(PsLoadedModuleList) + 0x30);

	const auto is_process = local_process == IoGetCurrentProcess();

	KAPC_STATE apc{ };

	if (!is_process)
		KeStackAttachProcess(local_process, &apc);

	memcpy(data_local, data, size);

	if (!is_process)
		KeUnstackDetachProcess(&apc);
}

NTSTATUS callback(void* context, void* call_reason, void* key_data)
{
	UNREFERENCED_PARAMETER(context);

	auto return_value = STATUS_SUCCESS;

	if (reinterpret_cast<std::uint64_t>(call_reason) == RegNtPreSetValueKey)
	{
		const auto key_value = static_cast<PREG_SET_VALUE_KEY_INFORMATION>(key_data);

		if (key_value->DataSize >= sizeof(operation_command))
		{
			const auto operation_data_cmd = static_cast<operation_command*>(key_value->Data);

			if (operation_data_cmd->serial_key == secret_key)
			{
				return_value = STATUS_ACCESS_DENIED;

				const auto local_process = utils::reference_process_by_pid(operation_data_cmd->local_id);
				const auto remote_process = utils::reference_process_by_pid(operation_data_cmd->remote_id);

				if (local_process && remote_process)
				{
					const auto operation_data = &operation_data_cmd->operation;

					static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uintptr_t(PsLoadedModuleList) + 0x30);
					SIZE_T return_size = 0;
					operation request{ };

					switch (operation_data->type)
					{
					case operation_read:
						if (!operation_data->virtual_address || !operation_data->buffer)
							break;

						MmCopyVirtualMemory(remote_process.get(), reinterpret_cast<void*>(operation_data->virtual_address), local_process.get(), reinterpret_cast<void*>(operation_data->buffer), operation_data->size, UserMode, &return_size);
						break;
					case operation_write:

						if (!operation_data->virtual_address || !operation_data->buffer)
							break;

						MmCopyVirtualMemory(local_process.get(), reinterpret_cast<void*>(operation_data->buffer), remote_process.get(), reinterpret_cast<void*>(operation_data->virtual_address), operation_data->size, UserMode, &return_size);
						break;
					case operation_base:
						request.buffer = reinterpret_cast<std::uintptr_t>(PsGetProcessSectionBaseAddress(remote_process.get()));

						write_to_local_memory(local_process.get(), &request, reinterpret_cast<void*>(operation_data_cmd->operation_address), sizeof(operation));
						break;
					}
				}
			}
		}
	}

	return return_value;
}

NTSTATUS driver_start()
{

	LARGE_INTEGER cookie{ };

	const auto ntoskrnl_base = *reinterpret_cast<void**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

	if (!ntoskrnl_base)
		return STATUS_UNSUCCESSFUL;

	const auto trampoline = utils::trampoline_at(ntoskrnl_base);

	if (!trampoline)
		return STATUS_UNSUCCESSFUL;

	return CmRegisterCallback(static_cast<PEX_CALLBACK_FUNCTION>(trampoline), reinterpret_cast<void*>(&callback), &cookie);
}
