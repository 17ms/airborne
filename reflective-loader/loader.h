#pragma once
#include <windows.h>
#include <subauth.h>

#define IMPORT_DELAY 6 * 1000 * 1000
#define HASH_KEY 5381

#define KERNEL32_DLL_HASH 0x6DDB9555
// #define NTDLL_DLL_HASH 0x1EDAB0ED
#define LOAD_LIBRARY_A_HASH 0xB7072FDB // TODO: change to LoadLibraryW
#define GET_PROC_ADDRESS_HASH 0xDECFC1BF
#define VIRTUAL_ALLOC_HASH 0x097BC257
#define FLUSH_INSTRUCTION_CACHE_HASH 0xEFB7BF9D
#define VIRTUAL_PROTECT_HASH 0xE857500D
#define SLEEP_HASH 0x0E07CD7E

typedef BOOL(WINAPI *DLLMAIN)(HMODULE, DWORD, LPVOID);

typedef struct _MY_PEB_LDR_DATA
{
    ULONG Length;
    BOOL Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

DWORD CalculateHash(UNICODE_STRING *BaseDllName);

HMODULE GetModuleAddrFromHash(DWORD dwHash);
FARPROC GetExportAddrFromHash(HMODULE hModule, DWORD dwHash);

void CopySections(PBYTE pNewImageBase, PVOID pImage, PIMAGE_NT_HEADERS64 pNtHeaders);
BOOL ProcessRelocations(PBYTE pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, ULONG_PTR ulpDelta);
BOOL PatchImportAddressTable(PBYTE pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, FARPROC pGetProcAddress);
void FinalizeRelocations(PBYTE pNewImageBase, PIMAGE_NT_HEADERS64 pNtHeaders, FARPROC pVirtualProtect, FARPROC pFlushInstructionCache);
