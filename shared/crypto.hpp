#pragma once

#include <windows.h>
#include <string>

constexpr auto HASH_KEY = 5381;

std::string GenerateUuid();
DWORD CalculateHash(const std::string &source);
DWORD CalculateHash(const UNICODE_STRING &baseDllName);
