#pragma once

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <random>

constexpr auto MAX_IMPORT_DELAY_MS = 6 * 1000;
constexpr auto OBFUSCATE_IMPORTS = 1;

constexpr DWORD KERNEL32_DLL_HASH = 0x6DDB9555;
constexpr DWORD LOAD_LIBRARY_W_HASH = 0xB7072FF1;
constexpr DWORD GET_PROC_ADDRESS_HASH = 0xDECFC1BF;
constexpr DWORD VIRTUAL_ALLOC_HASH = 0x097BC257;
constexpr DWORD FLUSH_INSTRUCTION_CACHE_HASH = 0xEFB7BF9D;
constexpr DWORD VIRTUAL_PROTECT_HASH = 0xE857500D;
constexpr DWORD SLEEP_HASH = 0x0E07CD7E;

// Function pointer typedefs from MSDN
using LOAD_LIBRARY_W = HMODULE(WINAPI *)(LPCWSTR);
using GET_PROC_ADDRESS = ULONG_PTR(WINAPI *)(HMODULE, LPCSTR);
using VIRTUAL_ALLOC = LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD);
using FLUSH_INSTRUCTION_CACHE = BOOL(WINAPI *)(HANDLE, LPCVOID, SIZE_T);
using VIRTUAL_PROTECT = BOOL(WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD);
using SLEEP = VOID(WINAPI *)(DWORD);

// Payload function pointer typedefs
using DLL_MAIN = BOOL(WINAPI *)(HMODULE, DWORD, LPVOID);
using USER_FUNCTION = BOOL(WINAPI *)(LPVOID, DWORD);

// Complete WinAPI PEB structs
struct _MY_PEB_LDR_DATA {
  ULONG Length;
  BOOL Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
};
using MY_PEB_LDR_DATA = _MY_PEB_LDR_DATA;
using PMY_PEB_LDR_DATA = _MY_PEB_LDR_DATA *;

struct _MY_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
};
using MY_LDR_DATA_TABLE_ENTRY = _MY_LDR_DATA_TABLE_ENTRY;
using PMY_LDR_DATA_TABLE_ENTRY = _MY_LDR_DATA_TABLE_ENTRY *;

struct _IMAGE_RELOC {
  WORD offset : 12;
  WORD type : 4;
};
using IMAGE_RELOC = _IMAGE_RELOC;
using PIMAGE_RELOC = _IMAGE_RELOC *;

PBYTE GetModuleAddressFromHash(DWORD dwHash);
HMODULE GetExportAddrFromHash(PBYTE pbModule, DWORD dwHash, const std::mt19937 &eng);
PIMAGE_NT_HEADERS64 GetNtHeaders(PBYTE pbImage);

void CopyHeadersAndSections(ULONG_PTR pNewImageBase, PBYTE pbImage, PIMAGE_NT_HEADERS64 pNtHeaders);
BOOL ProcessRelocations(ULONG_PTR pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, ULONG_PTR ulpDelta);
BOOL PatchImportAddressTable(ULONG_PTR pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, LOAD_LIBRARY_W pLoadLibraryW, GET_PROC_ADDRESS pGetProcAddress, SLEEP pSleep, const std::mt19937 &eng);
void FinalizeRelocations(ULONG_PTR pNewImageBase, PIMAGE_NT_HEADERS64 pNtHeaders, VIRTUAL_PROTECT pVirtualProtect, FLUSH_INSTRUCTION_CACHE pFlushInstructionCache);
