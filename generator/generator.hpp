#pragma once

#include <windows.h>
#include <string>

#define BOOTSTRAP_LEN 79

// Utils
BOOL GetFileContents(std::string filePath, LPBYTE *fileContents, DWORD *fileSize);
BOOL WriteFileContents(std::string filePath, LPBYTE fileContents, DWORD fileSize);

void PrintHelp(char **argv);