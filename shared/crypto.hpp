#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <random>

constexpr auto HASH_KEY = 5381;

std::vector<BYTE> GenerateKey(size_t keysize);
void XorCipher(std::vector<BYTE> &data, const std::vector<BYTE> &key);
DWORD CalculateHash(const std::string &source);
DWORD CalculateHash(const UNICODE_STRING &baseDllName);
