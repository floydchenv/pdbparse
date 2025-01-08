#include "pdbparse.hpp"
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <atlbase.h>
#include <dia2.h>
#include <iomanip>
#include <urlmon.h>
#include <algorithm>

//codeview debug struct, there is no fucking documentation so i had to search a bit
//big thanks to https://jpassing.com/2009/04/22/uniquely-identifying-a-modules-build/
struct codeviewInfo_t
{
	ULONG CvSignature;
	GUID Signature;
	ULONG Age;
	char PdbFileName[ANYSIZE_ARRAY];
};

//access using module path, has pair with first being map of functions and their RVAs, and second being pdb path
static std::unordered_map<std::string, std::pair<std::unordered_map<std::string, uintptr_t>, std::string>, std::hash<std::string>, map_compatator> cached_info;

//try to find the module's pdb path, first with the pdb name specified, then with the expected path in the tmp folder
//if that fails, it's downloaded from the microsoft symbol store (or whatever symbol server you want)
static std::string get_pdb_path(const module_t &module_info, bool is_wow64)
{
	auto &pdb_path = cached_info[module_info.path].second;

	//check if we've parsed this already
	if (!pdb_path.empty())
		return pdb_path;

	auto does_file_exist = [](std::string_view path) { return GetFileAttributes(path.data()) != INVALID_FILE_ATTRIBUTES; };

	//try same dir
	auto same_dir_pdb_path = module_info.path.substr(0, module_info.path.length() - 4) + ".pdb";
	if (does_file_exist(same_dir_pdb_path))
	{
		pdb_path = same_dir_pdb_path;
		return pdb_path;
	}

	//get tmp folder
	static std::string tmp_folder_path;

	if (tmp_folder_path.empty())
	{
		char folder_buff[MAX_PATH];
		GetTempPath(MAX_PATH, folder_buff);

		tmp_folder_path = folder_buff;
	}


	//determine PDB path by checking debug directory
	const uintptr_t debug_directory = (is_wow64 ? module_info.ImageHeaders.image_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress : module_info.ImageHeaders.image_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

	if (debug_directory)
	{
		//loop through debug shit until we find one for IMAGE_DEBUG_TYPE_CODEVIEW
		for (auto current_debug_dir = (IMAGE_DEBUG_DIRECTORY*)(module_info.module_in_memory.get() + debug_directory); current_debug_dir->SizeOfData; current_debug_dir++)
		{
			if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;

			const auto codeview_info = (codeviewInfo_t*)(module_info.module_on_disk.get() + current_debug_dir->PointerToRawData);

			//is the given pdb filename valid?
			if (does_file_exist(codeview_info->PdbFileName))
			{
				pdb_path = codeview_info->PdbFileName;
				break;
			}

			//check if it's been downloaded before
			//this 'extention path' is used for symbol downloading (URL), so i also make this for the path
			//pdbname.pdb\guid\pdbname.pdb
			std::stringstream pdb_extention_path;
			pdb_extention_path << codeview_info->PdbFileName << "\\";

			//convert GUID into a string
			pdb_extention_path << std::setfill('0') << std::setw(8) << std::hex << codeview_info->Signature.Data1 << std::setw(4) << std::hex << codeview_info->Signature.Data2 << std::setw(4) << std::hex << codeview_info->Signature.Data3;

			for (const auto i : codeview_info->Signature.Data4)
				pdb_extention_path << std::setw(2) << std::hex << +i;

			//append a 1 because microsoft does it?? idk
			pdb_extention_path << "1\\" << codeview_info->PdbFileName;

			const auto expected_pdb_path = tmp_folder_path + pdb_extention_path.str();
			if (does_file_exist(expected_pdb_path))
			{
				pdb_path = expected_pdb_path;
				break;
			}

			//download it from the symbol server if we dont have it
			//first create the subdiectory with the pdb name
			CreateDirectory((tmp_folder_path + codeview_info->PdbFileName).c_str(), nullptr);

			//then create the guid directory
			CreateDirectory(expected_pdb_path.substr(0, expected_pdb_path.find_last_of('\\')).c_str(), nullptr);

			//symbol server to use
			constexpr auto symbol_server = "http://msdl.microsoft.com/download/symbols/";

			//download it
			if (URLDownloadToFile(nullptr, (symbol_server + pdb_extention_path.str()).c_str(), expected_pdb_path.c_str(), 0, nullptr) != S_OK)
				break;

			//check if it was actually downloaded
			if (does_file_exist(expected_pdb_path))
				pdb_path = expected_pdb_path;

			break;
		}
	}

	return pdb_path;
}

uintptr_t pdb_parse::get_address_from_symbol(std::string_view function_name, const module_t &module_info, bool is_wow64)
{
	if (!module_info)
		return 0;

	//init com stuff
	{
		static auto has_initialized = false;

		if (!has_initialized)
		{
			CoInitialize(nullptr);
			has_initialized = true;
		}
	}

	auto &function_address = cached_info[module_info.path].first[function_name.data()];

	//check if we've already found this function
	if (function_address)
		return function_address + module_info.module_base;

	const auto pdb_path = get_pdb_path(module_info, is_wow64);

	if (pdb_path.empty())
		return 0;

	//this is potentially used twice, might aswell find it once (info.txt in the pdb's folder)
	const auto symbol_info_path = pdb_path.substr(0, pdb_path.find_last_of("\\") + 1) + "info.txt";

	//check if we've ever found this before in another session
	{
		std::ifstream file(symbol_info_path);
		if (file.is_open())
		{
			std::string current_line_buffer;

			//fmt: FunctionName address (in hex)
			while (std::getline(file, current_line_buffer))
			{
				std::stringstream current_line(current_line_buffer);

				//get function name
				current_line >> current_line_buffer;

				if (current_line_buffer == function_name)
				{
					uintptr_t address = 0;
					current_line >> std::hex >> address;

					function_address = address;
					return address + module_info.module_base;
				}
			}

			file.close();
		}
	}

	//find debug info from pdb file
	CComPtr<IDiaDataSource> source;

	if (FAILED(CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&source)))
		return 0;

	{
		wchar_t wide_path[MAX_PATH];
		memset(wide_path, 0, MAX_PATH * 2);

		MultiByteToWideChar(CP_ACP, 0, pdb_path.c_str(), (int)pdb_path.length(), wide_path, MAX_PATH);
		if (FAILED(source->loadDataFromPdb(wide_path)))
			return 0;
	}

	CComPtr<IDiaSession> session;
	if (FAILED(source->openSession(&session)))
		return 0;

	CComPtr<IDiaSymbol> global;
	if (FAILED(session->get_globalScope(&global)))
		return 0;

	CComPtr<IDiaEnumSymbols> enum_symbols;
	CComPtr<IDiaSymbol> current_symbol;
	ULONG celt = 0;

	{
		//while it's never used, the maximum function name length for a C++ compiler 'should be atleast 1024 characters', according to stackoverflow, with MSVC and intel's compiler supporting 2048,
		//and GCC supporting an unlimited amount.
		constexpr auto max_name_length = 1024;

		wchar_t wide_function_name[max_name_length];
		memset(wide_function_name, 0, max_name_length * 2);

		MultiByteToWideChar(CP_ACP, 0, function_name.data(), (int)function_name.length(), wide_function_name, max_name_length);

		//filter the results so it only gives us symbols with the name we want
		if (FAILED(global->findChildren(SymTagNull, wide_function_name, nsNone, &enum_symbols)))
			return 0;
	}

	//loop just in case? ive only ever seen this need to be a conditional
	while (SUCCEEDED(enum_symbols->Next(1, &current_symbol, &celt)) && celt == 1)
	{
		DWORD relative_function_address;

		if (FAILED(current_symbol->get_relativeVirtualAddress(&relative_function_address)))
			continue;

		if (!relative_function_address)
			continue;

		function_address = relative_function_address;

		std::ofstream file(symbol_info_path, std::ios_base::app);
		if (file.is_open())
		{
			file << function_name << ' ' << std::hex << relative_function_address << std::endl;
			file.close();
		}

		return relative_function_address + module_info.module_base;
	}

	return 0;
}

std::string pdb_parse::get_symbol_from_address(uintptr_t address, const module_t& module_info, bool is_wow64)
{
	if (!module_info || !address)
		return "";

	// ��ȡģ���С
	size_t module_size = is_wow64 ?
		module_info.ImageHeaders.image_headers32->OptionalHeader.SizeOfImage :
		module_info.ImageHeaders.image_headers64->OptionalHeader.SizeOfImage;

	// ����ַ�Ƿ���ģ�鷶Χ��
	if (address < module_info.module_base ||
		address >(module_info.module_base + module_size))
		return "";

	// Convert absolute address to RVA
	uintptr_t relative_address = address - module_info.module_base;

	// First check cached info
	auto& module_cache = cached_info[module_info.path];
	for (const auto& [func_name, func_rva] : module_cache.first)
	{
		if (func_rva == relative_address)
		{
			//return func_name;
		}
	}

	// Init COM stuff
	{
		static auto has_initialized = false;
		if (!has_initialized)
		{
			CoInitialize(nullptr);
			has_initialized = true;
		}
	}

	const auto pdb_path = get_pdb_path(module_info, is_wow64);
	if (pdb_path.empty())
		return "";

	// Create DIA objects
	CComPtr<IDiaDataSource> source;
	if (FAILED(CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource), (void**)&source)))
		return "";

	{
		wchar_t wide_path[MAX_PATH];
		memset(wide_path, 0, MAX_PATH * 2);
		MultiByteToWideChar(CP_ACP, 0, pdb_path.c_str(), (int)pdb_path.length(),
			wide_path, MAX_PATH);
		if (FAILED(source->loadDataFromPdb(wide_path)))
			return "";
	}

	CComPtr<IDiaSession> session;
	if (FAILED(source->openSession(&session)))
		return "";

	// Find symbol by RVA
	CComPtr<IDiaSymbol> symbol;
	if (FAILED(session->findSymbolByRVA(relative_address, SymTagNull, &symbol)))
		return "";

	// Get symbol name
	BSTR name_bstr;
	if (FAILED(symbol->get_name(&name_bstr)))
		return "";

	// Convert BSTR to string
	std::string symbol_name;
	{
		char buffer[1024];
		WideCharToMultiByte(CP_UTF8, 0, name_bstr, -1, buffer,
			sizeof(buffer), NULL, NULL);
		symbol_name = buffer;
		SysFreeString(name_bstr);
	}

	// Cache the result
	if (!symbol_name.empty())
		module_cache.first[symbol_name] = relative_address;

	return symbol_name;
}

void pdb_parse::clear_info()
{
	cached_info.clear();
}