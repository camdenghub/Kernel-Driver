#pragma once
#include <cstdint>

static constexpr std::uintptr_t secret_key = 0xfDFF4Da3;

enum operation_type
{
	operation_read = 0,
	operation_write,
	operation_base
};

struct operation
{
	std::uintptr_t virtual_address;
	std::uintptr_t size;
	std::uintptr_t buffer;
	std::uint32_t new_protection;
	std::uint32_t old_protection;
	operation_type type;
};

struct operation_command
{
	std::uintptr_t local_id;
	std::uintptr_t remote_id;
	std::uintptr_t serial_key;
	operation operation;
	std::uintptr_t operation_address;
};