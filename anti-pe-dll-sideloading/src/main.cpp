//notes 
/*
* https://github.com/HoShiMin/formatPE/blob/main/formatPE/Pe/Pe.hpp
*/

//win includes
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

namespace fs = std::filesystem;


//ext includes
//#include "../ext/pe.hpp" //later use!

//PE check (mz + pe\0\0)
bool isPE(const fs::path& path)
{
	//load file in raw binary mode
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		printf("unable to locate file. \n");
		return false;
	}

	//mz = dos signature
	//dos header check
	//first two bytes are always IMAGE_DOS_HEADER.e_magic (4D 5A -> 'MZ')
	char mz[2]{};
	file.read(mz, 2);
	if (mz[0] != 'M' || mz[1] != 'Z')
		return false;
	
	//e_lfanew | IMAGE_DOS_HEADER.e_lfanew
	file.seekg(0x3C, std::ios::beg);
	uint32_t peOffset = 0;
	file.read(reinterpret_cast<char*>(&peOffset), sizeof(peOffset));

	//pe sig check
	file.seekg(peOffset, std::ios::beg);
	char pe[4]{};
	file.read(pe, 4);

	return (pe[0] == 'P' && pe[1] == 'E' && pe[2] == 0 && pe[3] == 0);
}

//pe DLL check (IMAGE_FILE_DLL)
bool isDLL(const fs::path& path)
{
	std::ifstream file(path, std::ios::binary);
	if (!file)
		return false;

	//e_lfanew
	file.seekg(0x3C, std::ios::beg);
	uint32_t peOffset = 0;
	file.read(reinterpret_cast<char*>(&peOffset), sizeof(peOffset));


	file.seekg(peOffset + 4 + 18, std::ios::beg);
	uint16_t characteristics = 0;
	file.read(reinterpret_cast<char*>(&characteristics), sizeof(characteristics));

	//IMAGE_FILE_DLL = 0x2000
	return (characteristics & 0x2000) != 0;
}

bool isSignedTrust(const fs::path& path) {
	
		WINTRUST_FILE_INFO fileInfo{};
		fileInfo.cbStruct = sizeof(fileInfo);
		fileInfo.pcwszFilePath = path.c_str();

		WINTRUST_DATA trustData{};
		trustData.cbStruct = sizeof(trustData);
		trustData.dwUIChoice = WTD_UI_NONE;
		trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		trustData.dwUnionChoice = WTD_CHOICE_FILE;
		trustData.pFile = &fileInfo;
		trustData.dwStateAction = WTD_STATEACTION_VERIFY;
		trustData.dwProvFlags =
			WTD_CACHE_ONLY_URL_RETRIEVAL |
			WTD_REVOCATION_CHECK_NONE;

		GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		LONG status = WinVerifyTrust(nullptr, &policy, &trustData);

		// always close the state data
		trustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(nullptr, &policy, &trustData);

		return status == ERROR_SUCCESS;
	
}

int main() {
	
#ifdef _DEBUG
	//todo: soon
	printf("DEBUG MODE! \n");
	printf("Loading test DLL. \n");

	HMODULE hMod = LoadLibraryA("dDLL_safe.dll");
	if (!hMod) {
		printf("Failed to load dll\n");
		DWORD err = GetLastError();
		printf("Error code: %lu\n", err);
	}
#endif

	std::string path = fs::current_path().string();
	
	//loop through folder, find regular files
	for (const auto& entry : fs::directory_iterator(path)) {
		if (!entry.is_regular_file())
			continue;

		std::string filePath = entry.path().string();
		std::string fileName = entry.path().filename().string();
		//check found files for PE signatures and certs.
		if (isPE(filePath)) {
			if (!isSignedTrust(filePath)) {
				//TODO: Wait for user to accept execution
				printf("%s is NOT signed! \n", fileName.c_str());
			}

			if (isDLL(filePath)) {
				//todo: hook ALL LL like functions and block execution
				printf("%s is DLL\n", fileName.c_str());
			}
		}
	}
	std::cin.get();
	return 0;
}
