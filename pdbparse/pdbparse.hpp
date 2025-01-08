#pragma once
#include <string_view>
#include "structs.hpp"

namespace pdb_parse
{
	//parse the module's symbols and then return the virtual address of a function
	uintptr_t get_address_from_symbol(std::string_view function_name, const module_t &module_info, bool is_wow64);
	std::string get_symbol_from_address(uintptr_t address, const module_t& module_info, bool is_wow64);

	//clear stored info
	void clear_info();
}