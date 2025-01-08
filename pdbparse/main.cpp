//example: parse the wow64 and win32 (if x64) ntdlls for ApiSetResolveToHost and LdrpHandleTlsData which are not exported but present in the pdb, then output their addresses
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <iomanip>
#include "pdbparse.hpp"
//undefined on x86, define it here so we can use constexpr if statements instead of ugly macros
#ifndef _M_X64
#define _M_X64 0
#endif

//helper function to parse a module
static module_t get_module_info(std::string_view path, bool is_wow64)
{
	//read raw bytes
	const auto file = CreateFile(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (!file || file == INVALID_HANDLE_VALUE)
		return module_t();

	//get file size
	const auto file_size = GetFileSize(file, nullptr);

	if (!file_size)
		return module_t();

	//allocate dll bytes and read it
	auto module_on_disk = std::make_unique<uint8_t[]>(file_size);
	ReadFile(file, (LPVOID)module_on_disk.get(), file_size, nullptr, nullptr);

	//set image headers
	auto dos_header = (IMAGE_DOS_HEADER*)module_on_disk.get();
	auto image_headers = (void*)(module_on_disk.get() + dos_header->e_lfanew);

	auto image_headers32 = (IMAGE_NT_HEADERS32*)image_headers;
	auto image_headers64 = (IMAGE_NT_HEADERS64*)image_headers;

	CloseHandle(file);

	//map sections
	IMAGE_SECTION_HEADER *sections_array = nullptr;
	int section_count = 0;

	std::unique_ptr<uint8_t[]> module_in_memory = nullptr;
	if (is_wow64)
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers32->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers32 + 1);
		section_count = image_headers32->FileHeader.NumberOfSections;
	}
	else
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers64->OptionalHeader.SizeOfImage);
		sections_array = (IMAGE_SECTION_HEADER*)(image_headers64 + 1);
		section_count = image_headers64->FileHeader.NumberOfSections;
	}

	for (int i = 0; i < section_count; i++)
	{
		if (sections_array[i].Characteristics & 0x800)
			continue;

		memcpy_s(module_in_memory.get() + sections_array[i].VirtualAddress, sections_array[i].SizeOfRawData, module_on_disk.get() + sections_array[i].PointerToRawData, sections_array[i].SizeOfRawData);
	}

	return module_t(0, module_on_disk, module_in_memory, dos_header, path, image_headers);
}

static void output_function_address(std::string_view function_name, const module_t &module_info, bool is_wow64)
{
	const auto function_address = pdb_parse::get_address_from_symbol(function_name, module_info, is_wow64);

	if (function_address)
		std::cout << function_name << " found: 0x" << std::setfill('0') << std::setw(16) << std::hex << function_address << std::endl;
	else
		std::cout << function_name << " not found!" << std::endl;
};

static void output_function_name(uintptr_t function_address, const module_t& module_info, bool is_wow64)
{
	// 再通过地址反查函数名
	const auto function_name = pdb_parse::get_symbol_from_address(function_address, module_info, is_wow64);

	if (!function_name.empty())
	{
		std::cout << "Reverse lookup: 0x" << std::setfill('0')
			<< std::setw(16) << std::hex << function_address
			<< " -> " << function_name << std::endl;
	}
	else
	{
		std::cout << "Failed to reverse lookup address 0x"
			<< std::setfill('0') << std::setw(16) << std::hex
			<< function_address << std::endl;
	}
}

static void test_symbol_functions(std::string_view function_name, const module_t& module_info, bool is_wow64)
{
	// 先通过函数名获取地址
	const auto function_address = pdb_parse::get_address_from_symbol(function_name, module_info, is_wow64);

	if (function_address)
	{
		std::cout << "Forward lookup: " << function_name << " -> 0x"
			<< std::setfill('0') << std::setw(16) << std::hex
			<< function_address << std::endl;

		// 再通过地址反查函数名
		const auto resolved_name = pdb_parse::get_symbol_from_address(function_address, module_info, is_wow64);

		if (!resolved_name.empty())
		{
			std::cout << "Reverse lookup: 0x" << std::setfill('0')
				<< std::setw(16) << std::hex << function_address
				<< " -> " << resolved_name << std::endl;

			// 验证名称是否匹配
			if (resolved_name != function_name)
			{
				std::cout << "Warning: Symbol name mismatch!" << std::endl;
			}
		}
		else
		{
			std::cout << "Failed to reverse lookup address 0x"
				<< std::setfill('0') << std::setw(16) << std::hex
				<< function_address << std::endl;
		}
	}
	else
	{
		std::cout << "Failed to find address for " << function_name << std::endl;
	}
	std::cout << std::endl;
}

static void print_usage() {
    std::cout << "Usage: Either drag and drop an exe/dll onto this program, or input the path manually." << std::endl;
    std::cout << "Then input either:" << std::endl;
    std::cout << "1. A function name (e.g. FEngineLoop::Tick)" << std::endl;
    std::cout << "2. A function address (starting with 0x/0X)" << std::endl;
}

static bool is_hex_address(const std::string& input) {
    return (input.length() > 2 &&
        (input.substr(0, 2) == "0x" || input.substr(0, 2) == "0X"));
}

static uintptr_t parse_hex_address(const std::string& input) {
    try {
        return std::stoull(input.substr(2), nullptr, 16);
    }
    catch (...) {
        return 0;
    }
}

uintptr_t base_address = 0;
int main(int argc, char** argv)
{
    std::string module_path;

    // 处理命令行参数或要求用户输入
    if (argc > 1) {
        module_path = argv[1];
    }
    else {
        print_usage();
        std::cout << "\nPlease input module path: ";
        std::getline(std::cin, module_path);
    }

    // 移除路径两端的引号（如果有）
    if (module_path.front() == '"' && module_path.back() == '"') {
        module_path = module_path.substr(1, module_path.length() - 2);
    }

    // 检查文件是否存在
    if (GetFileAttributes(module_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "Error: File not found!" << std::endl;
        std::cin.get();
        return 1;
    }

    // 判断是32位还是64位
    bool is_wow64 = false;
    {
        FILE* file = fopen(module_path.c_str(), "rb");
        if (file) {
            IMAGE_DOS_HEADER dos_header;
            fread(&dos_header, sizeof(dos_header), 1, file);

            IMAGE_NT_HEADERS32 nt_headers;
            fseek(file, dos_header.e_lfanew, SEEK_SET);
            fread(&nt_headers, sizeof(nt_headers), 1, file);

            is_wow64 = nt_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
            fclose(file);
        }
    }

    // 加载模块
    const auto module_info = get_module_info(module_path, is_wow64);
    if (!module_info) {
        std::cout << "Error: Failed to load module!" << std::endl;
        std::cin.get();
        return 1;
    }

    while (true) {
        std::cout << "\nEnter function name or address (0x...), or 'exit' to quit: ";
        std::string input;
        std::getline(std::cin, input);

        if (input.empty() || input == "exit") {
            break;
        }

        if (is_hex_address(input)) {
            // 处理函数地址查询
            uintptr_t address = parse_hex_address(input);
            if (!address) {
                std::cout << "Error: Invalid address format!" << std::endl;
                continue;
            }

            if (base_address == 0)
            {
                std::cout << "Enter module base address (0x...) or press Enter if address is already an RVA: ";
                std::string base_input;
                std::getline(std::cin, base_input);

                if (!base_input.empty()) {
                    if (!is_hex_address(base_input)) {
                        std::cout << "Error: Invalid base address format!" << std::endl;
                        continue;
                    }

                    base_address = parse_hex_address(base_input);
                }
            }

            if (address > base_address) {
                address -= base_address;
                std::cout << "Converted to RVA: 0x" << std::hex << address << std::dec << std::endl;
            }
            

            // 查找函数名
            const auto function_name = pdb_parse::get_symbol_from_address(
                address + module_info.module_base, module_info, is_wow64);

            if (!function_name.empty()) {
                std::cout << "Found symbol: " << function_name << std::endl;
            }
            else {
                std::cout << "No symbol found for address 0x" << std::hex << address << std::dec << std::endl;
            }
        }
        else {
            // 处理函数名查询
            const auto function_address = pdb_parse::get_address_from_symbol(input, module_info, is_wow64);

            if (function_address) {
                std::cout << "Symbol address: 0x" << std::hex << function_address << std::dec << std::endl;
                std::cout << "RVA: 0x" << std::hex << (function_address - module_info.module_base) << std::dec << std::endl;
            }
            else {
                std::cout << "Symbol not found!" << std::endl;
            }
        }
    }

    return 0;
}