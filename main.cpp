// FindTheSqlMagicCode.cpp : 定义控制台应用程序的入口点。
//

#include <windows.h>
#include <strsafe.h>
#include <Dbghelp.h>
#include <shlwapi.h>
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"shlwapi.lib")
#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDGREEN    "\033[1m\033[32m"      /* Bold Green */

#include <vector>
#include <set>
#include <iostream>
#include <fstream>
using namespace std;

// CodeView header 
typedef struct CV_HEADER 
{
	DWORD CvSignature; // NBxx
	LONG  Offset;      // Always 0 for NB10
} * PCV_HEADER;

// CodeView NB10 debug information 
// (used when debug information is stored in a PDB 2.00 file) 
typedef struct CV_INFO_PDB20 
{
	CV_HEADER  Header; 
	DWORD      Signature;       // seconds since 01.01.1970
	DWORD      Age;             // an always-incrementing value 
	BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
} * PCV_INFO_PDB20;

// CodeView RSDS debug information 
// (used when debug information is stored in a PDB 7.00 file) 
typedef struct CV_INFO_PDB70 
{
	DWORD      CvSignature; 
	GUID       Signature;       // unique identifier 
	DWORD      Age;             // an always-incrementing value 
	BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
} * PCV_INFO_PDB70;


LPBYTE GetRVAOffset(LPBYTE pBuffer, DWORD dwVirtualOffset)  
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	PIMAGE_NT_HEADERS32  pNtHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + pDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64  pNtHeader64 = (PIMAGE_NT_HEADERS64)(pBuffer + pDosHeader->e_lfanew);
	BOOL bIsX64 = pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	int nSectionNum = bIsX64 ? pNtHeader64->FileHeader.NumberOfSections : pNtHeader32->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pBuffer + pDosHeader->e_lfanew + (bIsX64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

	// search for absolute offset
	for( int i = 0; i < nSectionNum; i++)
	{
		DWORD dwStart = pSection->VirtualAddress;  
		if( dwStart <= dwVirtualOffset && dwVirtualOffset < dwStart + pSection->SizeOfRawData){  
			return pBuffer + pSection->PointerToRawData + (dwVirtualOffset - dwStart);  
		}
		pSection++;
	}

	return 0;  
} 

DWORD GetImageSize(LPBYTE pBuffer, BOOL& bIsX64)  
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	PIMAGE_NT_HEADERS32  pNtHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + pDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64  pNtHeader64 = (PIMAGE_NT_HEADERS64)(pBuffer + pDosHeader->e_lfanew);
	bIsX64 = pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	DWORD SizeOfImage = bIsX64 ? pNtHeader64->OptionalHeader.SizeOfImage: pNtHeader32->OptionalHeader.SizeOfImage;

	return SizeOfImage;  
} 

WCHAR*  CharToWchar(CHAR* sSour)
{
	size_t len = strlen(sSour) + 1;
	size_t converted = 0;
	WCHAR *wzDest = NULL;
	wzDest = (WCHAR*)new WCHAR[len];
	mbstowcs_s(&converted, wzDest, len, sSour, _TRUNCATE);
	return wzDest;
}

char*  WCharToChar(WCHAR* wzSour)
{
	ULONG ulLength = 0;
	char* szDest = NULL;

	if (wzSour != NULL)
	{
		ulLength = WideCharToMultiByte(CP_ACP,NULL, wzSour,-1,NULL,0,NULL,FALSE);
		szDest = new char[ulLength + 1];
		if (szDest == NULL)
		{
			return NULL;
		}
		memset(szDest, 0, ulLength + 1);
		WideCharToMultiByte(CP_OEMCP, NULL, wzSour, -1, szDest, ulLength, NULL, FALSE);
	}
	return szDest;
}


BOOL GetPdbFileInfo(LPCWSTR lpszFilePath
					, LPWSTR szPdbFileName
					, DWORD dwPdbFileNameCch
					, LPWSTR szPdbGuid
					, DWORD dwPdbGuidCch
					, LPWSTR szChecksum
					, DWORD dwChecksumCch
					)
{

	DWORD dwTotalRead = 0, dwRead = 0;
	DWORD dwSize = 0;
	BOOL bFound = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPBYTE pBuffer = NULL;
	do
	{
		// read the file into memory
		HANDLE hFile = ::CreateFileW( lpszFilePath
			, GENERIC_READ
			, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
			, NULL
			, OPEN_EXISTING
			, FILE_ATTRIBUTE_NORMAL
			, NULL
			);
		if( hFile == INVALID_HANDLE_VALUE )
		{
			break;
		}

		dwSize = GetFileSize( hFile, NULL);
		if( dwSize < 4096 ) // hardcode for file size limit
		{
			break;
		}

		pBuffer = (LPBYTE)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
		if(!pBuffer)
		{
			break;
		}



		while( dwTotalRead < dwSize &&
			ReadFile( hFile, pBuffer + dwTotalRead, dwSize - dwTotalRead, &dwRead, NULL) )
		{
			dwTotalRead += dwRead;
		}


	}while(0);

	if(hFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
	}

	if(pBuffer == NULL)
	{
		return FALSE;
	}

	if(dwTotalRead != dwSize)
	{ 
		if(pBuffer)
		{
			HeapFree( GetProcessHeap(), 0, pBuffer);
		}
		return FALSE;
	}

	LPWSTR lpszpdbInfo = NULL;

	// locate the DEBUG section
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if( pDosHeader->e_magic == IMAGE_DOS_SIGNATURE )
	{
		PIMAGE_DATA_DIRECTORY pDataDic;
		PIMAGE_NT_HEADERS32  pNtHeader32 = (PIMAGE_NT_HEADERS32)(pBuffer + pDosHeader->e_lfanew);
		PIMAGE_NT_HEADERS64  pNtHeader64 = (PIMAGE_NT_HEADERS64)(pBuffer + pDosHeader->e_lfanew);
		if( pNtHeader32->Signature == IMAGE_NT_SIGNATURE )
		{
			BOOL bIsX64 = pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
			if( !bIsX64 )
				pDataDic = &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
			else
				pDataDic = &pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];


			if( pDataDic && pDataDic->Size > 0 )
			{
				//The number of entries in the debug directory can be obtained by dividing the size of the debug directory (as specified in the optional header’s data directory entry) by the size of IMAGE_DEBUG_DIRECTORY structure.
				int nNumberOfEntries = pDataDic->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
				PIMAGE_DEBUG_DIRECTORY pDebugDic = (PIMAGE_DEBUG_DIRECTORY)GetRVAOffset( pBuffer, pDataDic->VirtualAddress);

				for( int i = 0; i < nNumberOfEntries && !bFound ; i++)
				{
					// CodeView debug information (stored in the executable) or Program Database debug information (stored in PDB file)
					if( pDebugDic->Type == IMAGE_DEBUG_TYPE_CODEVIEW )
					{
						LPBYTE pDebugData = pBuffer + pDebugDic->PointerToRawData;
						DWORD dwCVSignature = *(LPDWORD)pDebugData; 
						if( dwCVSignature == CV_SIGNATURE_RSDS  )
						{
							PCV_INFO_PDB70 pCvInfo = (PCV_INFO_PDB70)pDebugData; 
							StringCbPrintfW( szPdbGuid, dwPdbFileNameCch
								, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%d"
								, pCvInfo->Signature.Data1
								, pCvInfo->Signature.Data2
								, pCvInfo->Signature.Data3
								, pCvInfo->Signature.Data4[0]
							, pCvInfo->Signature.Data4[1]
							, pCvInfo->Signature.Data4[2]
							, pCvInfo->Signature.Data4[3]
							, pCvInfo->Signature.Data4[4]
							, pCvInfo->Signature.Data4[5]
							, pCvInfo->Signature.Data4[6]
							, pCvInfo->Signature.Data4[7]
							, pCvInfo->Age
								);

							lpszpdbInfo = CharToWchar((LPSTR)pCvInfo->PdbFileName);
							StringCbCopy( szPdbFileName, dwPdbFileNameCch, lpszpdbInfo);
							delete[]lpszpdbInfo;

							if( bIsX64 )
							{
								StringCbPrintfW( szChecksum, dwChecksumCch
									, L"%x%x"
									, pNtHeader64->FileHeader.TimeDateStamp
									, pNtHeader64->OptionalHeader.SizeOfImage
									);
							}
							else
							{
								StringCbPrintfW( szChecksum, dwChecksumCch
									, L"%x%x"
									, pNtHeader32->FileHeader.TimeDateStamp
									, pNtHeader32->OptionalHeader.SizeOfImage
									);
							}

							bFound = TRUE;
						}
					}

					pDebugDic++;
				}
			}
		}
	}

	HeapFree( GetProcessHeap(), 0, pBuffer);

	return bFound;
}


DWORD  RunTheSymchk(LPWSTR szCommandLine)
{
	DWORD dwMbrId = 0;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	BOOL bResult = ::CreateProcess(NULL,szCommandLine , NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	if (!bResult)
		return 0;

	if (WaitForSingleObject(pi.hProcess,180*1000) == WAIT_TIMEOUT)
		return 0;

	int dwCode = 0;
	if (!GetExitCodeProcess(pi.hProcess,(DWORD*)&dwCode))
	{

		return 0;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 1;
}

#define WINDBG_INSTALLPATH L"D:\\Windows Kits\\10\\Debuggers\\x64"
#define NT_SYMBOLS_DIR L"d:\\symbols\\"
#define NT_SYMBOLS_FORMATS L"SRV*%ws*http://msdl.microsoft.com/download/symbols"
#define TEST_PATH L"D:\\Documents\\D_IDA\\SHClient\\SHClient.exe"
#define SYMCHCKCMD_LINE_FORMATS L"%ws\\symchk.exe  /r  %ws  /s %ws"
#define LDR_IS_DATAFILE(handle)      (((ULONG_PTR)(handle)) &  (ULONG_PTR)1)
#define LDR_IS_IMAGEMAPPING(handle)  (((ULONG_PTR)(handle)) & (ULONG_PTR)2)
#define LDR_IS_RESOURCE(handle)      (LDR_IS_IMAGEMAPPING(handle) || LDR_IS_DATAFILE(handle))
#if 0
// #define SYMBOL_NAME  L"PsspDumpThread"
// #define SYMBOL_NAME  L"DownloadAndStagePayloads"
#define SYMBOL_NAME  L"*Payload*"
#define ENUM_PATH  L"D:\\Documents\\TestScanPath"
#define ENEABLE_DEEP_CALL 1
#else
#define SYMBOL_NAME  L"*Payload*"
#define ENUM_PATH  L"C:\\Windows\\System32"
#define ENEABLE_DEEP_CALL 1
#endif
// PSYM_ENUMERATESYMBOLS_CALLBACKW PsymEnumeratesymbolsCallback;


void* GetNtdllBase()
{
#if defined(_WIN64)
	ULONG64 peb = __readgsqword(0x60);
#else
	ULONG64 peb = __readfsdword(0x30);
#endif

	ULONG64 ldr = *(ULONG64*)(peb + 0x18);
	PLIST_ENTRY modlist = *(PLIST_ENTRY*)(ldr + 0x10); // 第二个加载的 dll 就是 ntdll
	return *(void**)((ULONG64)modlist->Flink + 0x30); // 获取第二个 listEntry 之后，再获取
}

vector<std::pair<wstring, wstring>> g_FindReslt;
BOOL CALLBACK PsymEnumeratesymbolsCallback(
	_In_ PSYMBOL_INFOW pSymInfo,
	_In_ ULONG SymbolSize,
	_In_opt_ PVOID UserContext
)
{
	wprintf(GREEN L"%s->%s, Size:%d\n" WHITE, (WCHAR*)UserContext, pSymInfo->Name, SymbolSize);

	g_FindReslt.emplace_back(std::make_pair<wstring, wstring>((WCHAR*)UserContext, pSymInfo->Name));

	return TRUE;
}

int IsExeOrDll(const WCHAR* path)
{
	const WCHAR* patterns[] = { L"*.exe", L"*.dll", NULL };
#if 0
	if (PathMatchSpecW(path, patterns[0]) == TRUE)
		return 1;
#endif
	if (PathMatchSpecW(path, patterns[1]) == TRUE)
		return 2;
	return  0;
}

int g_idx = 0;

void FindAllDlls(const WCHAR* Path, int iDeep)
{
	if (iDeep > 6)
	{
		return;
	}

	WCHAR TargetPath[MAX_PATH] = {};
	WCHAR szTempPath[MAX_PATH] = { 0 };
	LPCWSTR lpszFilePath = TEST_PATH;
	//仅测试用 大量字符串申请用堆而不是栈
	DWORD dwLastError = 0;
	DWORD ModuleSize = 0;
	WCHAR szPdbFileName[MAX_PATH] = { 0 };
	WCHAR szPdbGuid[MAX_PATH] = { 0 };
	WCHAR szChecksum[MAX_PATH] = { 0 };
	WCHAR szCommandLine[MAX_PATH] = { 0 };
	WCHAR szNtSymbolUrl[MAX_PATH] = { 0 };
	WCHAR szPdbSymbolPath[MAX_PATH] = { 0 };
	LPSTR lpszPdbPath = NULL;
	WCHAR szSymbolName[MAX_SYM_NAME];
	DWORD dwSizeOfSymbol = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR);
	PBYTE pBuffer = new BYTE[dwSizeOfSymbol];
	PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)pBuffer;
	HMODULE hModuleBase = NULL;
	PBYTE pModuleBase = NULL;
	PBYTE pSymAdr = NULL;
	PBYTE lpDestCall = NULL;
	LPWSTR lpszCFile = NULL;
	MEMORY_BASIC_INFORMATION MbInfo = { 0 };

	BOOL bIsX64 = FALSE;
	StringCbCopy(TargetPath, MAX_PATH, Path);
	StringCbCat(TargetPath, MAX_PATH, L"\\*.*");

	WIN32_FIND_DATA fd = { 0 };
	HANDLE hFind = FindFirstFile(TargetPath, &fd);
	do
	{

		if (StrCmpCW(L"AppVStreamingUX.exe", fd.cFileName) == 0)
		{
			cout << endl;
		}
		if (StrCmpCW(L"SIHClient.exe", fd.cFileName) == 0)
		{
			cout << endl;
		}

		if (hFind != INVALID_HANDLE_VALUE)
		{
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				int iFileExFlag = 0;
				const WCHAR* filename = fd.cFileName;


				if (!(iFileExFlag = IsExeOrDll(filename)))
				{
					continue;
				}

				szTempPath[0] = 0;
				StringCbCopy(szTempPath, MAX_PATH, Path);
				// szTempPath[wcslen(szTempPath)] = 0;
				PathAppend(szTempPath, fd.cFileName);
				lpszFilePath = szTempPath;
				GetPdbFileInfo(lpszFilePath, szPdbFileName, MAX_PATH, szPdbGuid, MAX_PATH, szChecksum, MAX_PATH);

				StringCbPrintf(szNtSymbolUrl, MAX_PATH * sizeof(WCHAR), NT_SYMBOLS_FORMATS, NT_SYMBOLS_DIR);
				StringCbPrintf(szCommandLine, MAX_PATH * sizeof(WCHAR), SYMCHCKCMD_LINE_FORMATS, WINDBG_INSTALLPATH, lpszFilePath, szNtSymbolUrl);

				StringCbCopy(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), NT_SYMBOLS_DIR);
				StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbFileName);
				StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), L"\\");
				StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbGuid);
				StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), L"\\");
				StringCbCat(szPdbSymbolPath, MAX_PATH * sizeof(WCHAR), szPdbFileName);
				// if (iFileExFlag == 1)
				{
					std::cout << (iFileExFlag == 1 ? MAGENTA : CYAN);
					wprintf(L"%d Load:%ws\r\n", g_idx++, lpszFilePath);
					std::cout << WHITE;
				}
				hModuleBase = LoadLibraryExW(lpszFilePath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
				pModuleBase = (PBYTE)hModuleBase;

				BOOL bNeedUnload = TRUE;
				if (GetModuleHandle(filename))
				{
					bNeedUnload = FALSE;
				}

				if (LDR_IS_RESOURCE(hModuleBase))
				{
					ULONG_PTR  ulTemp = (ULONG_PTR)hModuleBase;
					ulTemp = ulTemp - 2;
					pModuleBase = (PBYTE)ulTemp;
				}

				if (pModuleBase == NULL)
				{
					continue;
				}

				ModuleSize = GetImageSize((LPBYTE)pModuleBase, bIsX64);
#if 0
				if (!bIsX64)
				{
					FreeLibrary(hModuleBase);
					continue;
				}
#endif
				if (!PathFileExists(szPdbSymbolPath))
				{
					RunTheSymchk(szCommandLine);
				}

				DWORD64 baseAddr = 0;
				lpszPdbPath = WCharToChar(szPdbSymbolPath);

				// if (!SymLoadModule64(GetCurrentProcess(), NULL, (STRSAFE_LPCSTR)lpszPdbPath, NULL, (DWORD64)pModuleBase, ModuleSize))
				if (!(baseAddr = SymLoadModuleExW(GetCurrentProcess(), NULL, (PCWSTR)szPdbSymbolPath, NULL, (DWORD64)pModuleBase, ModuleSize, NULL, 0)))
				{
					dwLastError = GetLastError();
					delete[] lpszPdbPath;
					FreeLibrary(hModuleBase);
					SymUnloadModule(GetCurrentProcess(), (DWORD64)pModuleBase);
					continue;
				}

				delete[] lpszPdbPath;


				pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);;
				pSymbol->MaxNameLen = MAX_SYM_NAME;
				if (!SymFromNameW(GetCurrentProcess(), SYMBOL_NAME, pSymbol))
				{
					dwLastError = GetLastError();
					FreeLibrary(hModuleBase);
					continue;
				}

				if (!SymEnumSymbolsW(GetCurrentProcess(), baseAddr, SYMBOL_NAME, PsymEnumeratesymbolsCallback, (PVOID)lpszFilePath))
				{
					dwLastError = GetLastError();
					FreeLibrary(hModuleBase);
					continue;
				}

				// g_FindReslt.emplace_back(lpszFilePath);
				// wprintf(MAGENTA L"FileX64:%ws\r\n" WHITE, lpszFilePath);

#if 0
				pSymAdr = (PBYTE)pSymbol->Address;

				if (VirtualQuery(pSymAdr, &MbInfo, sizeof(MbInfo)) == sizeof(MbInfo))
				{
					if (MbInfo.State != MEM_COMMIT)
					{
						dwLastError = GetLastError();
						FreeLibrary(hModuleBase);
						continue;
					}
				}

				for (int i = 0; i < 0x150; i++)
				{
					if (*(pSymAdr + i) == 0x4c && *(pSymAdr + i + 1) == 0x8d && *(pSymAdr + i + 2) == 0x5)
					{

						int jmpadr = *(int*)(pSymAdr + i + 3);
						jmpadr = jmpadr + 7;
						lpDestCall = jmpadr + pSymAdr + i;
						lpszCFile = CharToWchar((char*)lpDestCall);
						wprintf(L"Find:%ws %ws\r\n", lpszFilePath, lpszCFile);
						break;
					}
				}
#endif

				FreeLibrary(hModuleBase);

			}
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (StrCmpCW(fd.cFileName, L".") != 0 && StrCmpCW(fd.cFileName, L"..") != 0)
				{
					// 构造子目录的路径
					TCHAR subDirectory[MAX_PATH];
					StringCbCopy(subDirectory, MAX_PATH, Path);
					StringCbCat(subDirectory, MAX_PATH, L"\\");
					StringCbCat(subDirectory, MAX_PATH, fd.cFileName);

					// 递归调用FindAllDlls
					if (ENEABLE_DEEP_CALL)
					{
						FindAllDlls(subDirectory, iDeep + 1);
					}
				}
			}
		}
	} while (FindNextFile(hFind, &fd));

	FindClose(hFind);
}

BOOL EnableXXXPrivilege(LPCTSTR pszPrivilegeName)
{
	HANDLE hToken;
	LUID seXXXNameValue;
	TOKEN_PRIVILEGES tkp;

	// enable the SeXXXPrivilege
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		wprintf(L"OpenProcessToken() failed, Error = %d  %s is not available.\n", GetLastError(), pszPrivilegeName);
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, pszPrivilegeName, &seXXXNameValue))
	{
		wprintf(L"LookupPrivilegeValue() failed, Error = %d %s is not available.\n", GetLastError(), pszPrivilegeName);
		CloseHandle(hToken);
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = seXXXNameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		wprintf(L"AdjustTokenPrivileges() failed, Error = %d %s is not available.\n", GetLastError(), pszPrivilegeName);
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

// 将wstring转换成string
string wstring2string(wstring wstr)
{
	string result;
	//获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
	int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
	char* buffer = new char[len + 1];
	//宽字节编码转换成多字节编码  
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
	buffer[len] = '\0';
	//删除缓冲区并返回值  
	result.append(buffer);
	delete[] buffer;
	return result;
}

void OutputToFile(std::vector<std::pair<wstring, wstring>>& vec)
{
	ofstream outfile("output.txt");

	if (!outfile.is_open()) {
		std::cerr << "无法打开文件" << std::endl;
		return;
	}

	for (auto res : g_FindReslt)
	{
		outfile << wstring2string(res.first) << "\t" << wstring2string(res.second) << endl;
	}

	// 关闭文件
	outfile.close();
}

int main(int argc, char* argv[])
{
	PVOID OldValue;
	if (Wow64DisableWow64FsRedirection(&OldValue))
		std::cout << "File system redirection disabled." << std::endl;
	wcout << WHITE << endl;

	EnableXXXPrivilege(SE_DEBUG_NAME);

	if (!SymInitializeW(GetCurrentProcess(), NULL, FALSE))
	{
		return 0;
	}

	DWORD dwSymOpt = SymGetOptions();

	int iDeep = 0;
	FindAllDlls(ENUM_PATH, iDeep);

	cout << endl<< endl;
	/*
	for (auto res : g_FindReslt)
	{
		wcout << RED << res.first << "\t" << res.second << endl;
	}
	*/

	wcout << WHITE << endl;
	
	// 重新启用文件系统重定向
	if (Wow64RevertWow64FsRedirection(OldValue)) {
		std::cout << "File system redirection re-enabled." << std::endl;
	}
	else {
		std::cerr << "Failed to re-enable file system redirection." << std::endl;
	}

	OutputToFile(g_FindReslt);

	// 程序执行完成后，将控制台窗口置顶
	HWND consoleWindow = GetConsoleWindow(); // 获取控制台窗口句柄
	ShowWindow(consoleWindow, SW_SHOW); // 显示控制台窗口
	SetForegroundWindow(consoleWindow); // 将控制台窗口置顶

	return 0;
}

