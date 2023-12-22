#include <windows.h>

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        CreateProcessW(L"C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, NULL, NULL);
    }

    return TRUE;
}

BOOL SayHello(LPVOID lpUserData, DWORD nUserDataLen)
{
    MessageBoxW(NULL, L"Hello from payload!", L"Hello World!", MB_OK);
    return TRUE;
}

BOOL SayCustom(LPVOID lpUserData, DWORD nUserDataLen)
{
    MessageBoxW(NULL, (LPCWSTR)lpUserData, L"Hello World!", MB_OK);
    return TRUE;
}
