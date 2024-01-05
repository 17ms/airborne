#include <winternl.h>
#include <random>
#include <sstream>

#include "crypto.hpp"

std::string GenerateUuid()
{
    // Source: https://stackoverflow.com/a/60198074/15310712

    std::stringstream ss;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    ss << std::hex;

    auto generateHex = [&](int count)
    {
        for (int i = 0; i < count; ++i)
        {
            ss << dis(gen);
        }
    };

    generateHex(8);
    ss << "-";
    generateHex(4);
    ss << "-4";
    generateHex(3);
    ss << "-";
    ss << dis2(gen);
    generateHex(3);
    ss << "-";
    generateHex(12);

    return ss.str();
}

DWORD CalculateHash(const std::string &source)
{
    auto dwHash = HASH_KEY;

    for (char ch : source)
    {
        if (ch == '\0')
        {
            continue;
        }

        if (ch >= 'a' && ch <= 'z')
        {
            ch -= 0x20;
        }

        // Casting might be unnecessary
        dwHash = ((dwHash << 5) + dwHash) + static_cast<DWORD>(ch);
    }

    return dwHash;
}

DWORD CalculateHash(const UNICODE_STRING &baseDllName)
{
    auto pwszBaseDllName = baseDllName.Buffer;
    auto dwHash = HASH_KEY;

    char ch;

    for (auto i = 0; i < baseDllName.MaximumLength; i++)
    {
        ch = pwszBaseDllName[i];

        if (ch == '\0')
        {
            continue;
        }

        if (ch >= 'a' && ch <= 'z')
        {
            ch -= 0x20;
        }

        // Casting might be unnecessary
        dwHash = ((dwHash << 5) + dwHash) + static_cast<DWORD>(ch);
    }

    return dwHash;
}
