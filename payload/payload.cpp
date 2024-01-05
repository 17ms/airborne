#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <windows.h>

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        CreateProcessW(L"C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, NULL, NULL);
    }

    return TRUE;
}

BOOL PrintMessage(LPVOID lpUserData, DWORD dwUserDataSize)
{
    auto lpText = static_cast<LPCWSTR>(lpUserData);
    MessageBoxW(NULL, lpText, L"Hello World!", MB_OK);

    return TRUE;
}
