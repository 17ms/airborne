#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>

#define HASH_KEY 5381
#define BOOTSTRAP_LEN 79

// Utils
void PrintHelp(char **argv);
BOOL GetFileContents(std::string filePath, LPBYTE *fileContents, DWORD *fileSize);
BOOL WriteFileContents(std::string filePath, LPBYTE fileContents, DWORD fileSize);
DWORD CalculateHash(const std::string &source);
